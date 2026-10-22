//! The cached placement of a sequence (spec/crdt.md §6): built by one whole pass
//! (`linearize::place_idx`), then followed through joins that add elements, move them or change
//! flags and content; any other change drops it and the next use rebuilds it.
//!
//! Rows sit in blocks of a few hundred with their visible counts, so finding a row by dot (a map
//! to its block in dot order), by position or by visible index, and splicing a run in, cost
//! O(√n) instead of a scan and a shift of the whole order.
//!
//! Rows carry their depth, so a subtree is the rows up to the next one no deeper (blocks whose
//! rows are all deeper are skipped), and a block-level shift lets a subtree move as whole blocks.
//!
//! A new element anchored at HEAD or at an element (its row's last) goes right after its anchor,
//! past the anchor's children whose edge stamps beat its own, with their subtrees. It closes no
//! cycle (nothing anchors at it unless a write waits for its dot, which falls back), so no
//! demotion changes. A single element whose chosen edge changes (a move) has its subtree cut out
//! and put in the same way at its new anchor, in write-stamp order. A flag or content write
//! moves nothing; only visibility changes. A write over part of a range record, or a new anchor
//! inside one, cuts the row where a whole pass cuts the node (`cut_row`).
//!
//! Whole-pass fallbacks (the cache is dropped):
//! - a record that is neither new nor over held elements: a reset, a record partly new, a new
//!   `Derived` record (it splits records of its base source), a new record of more than one
//!   element or not a plain creation (one anchored at itself included), a new element anchored
//!   at an absent `Derived` dot (a virtual anchor on `END`), position writes on a range record
//!   (`plan`, `plan_one`, `plan_pieces`);
//! - a new element some write was waiting for, one anchored at a new element other than the end
//!   of a run (`follow`);
//! - more new runs, moves and row cuts in one delta than max(√n, 64), or their placements
//!   costing more than about a whole pass (max(n, 1024) rows and blocks looked at; `follow`,
//!   `slot`);
//! - a move of an element on a cycle a demotion broke (`Lin::cyc`; otherwise the old demotions
//!   stay forced, §6.2), one gaining or losing a write that names an unknown element (an absent
//!   `Derived` one included), or losing one that names an element inside a range record (its
//!   node may join the next again) (`moved`); a row cut on such a cycle (`cut_row`);
//! - a move of an element or to an anchor that is not placed, or one closing a cycle (the anchor
//!   inside the subtree, checked per step) (`place_moved`);
//! - 256 or more newer siblings at the anchor (`slot`), or a sibling there whose old write fell
//!   out of its top two (a move in the same delta; `child_stamp`).

use crate::linearize::{Placed, place_idx};
use crate::seq::{Anchor, SeqContent, SeqElem, is_visible};
use crate::seq_span::{Elems, Recs, nth, piece};
use crate::stamp::{Dot, Stamp};
use std::collections::{HashMap, HashSet};
use std::ops::Range;
use std::sync::Arc;

/// Rows per block: about √n (at most this), growing with the placement; a block splits in two
/// above twice that.
const BLOCK: usize = 256;
/// Work units (rows or blocks looked at) charged per sibling skipped by `slot`.
const STEP: usize = 8;
/// Newer siblings (with their subtrees) skipped past an anchor to place a run or a moved
/// subtree; this many or more rebuild.
const SIBS: usize = 256;

#[cfg(test)]
thread_local! {
    /// Work units charged by `follow` and `Lin::build` calls on this thread (tests).
    static PROBE: std::cell::Cell<(usize, usize)> = const { std::cell::Cell::new((0, 0)) };
}

/// Work units `follow` charged and whole passes `Lin::build` made on this thread since the last
/// call; resets both (tests).
#[cfg(test)]
pub(crate) fn probe() -> (usize, usize) {
    PROBE.with(|p| p.replace((0, 0)))
}

/// One placed node.
#[derive(Clone, Debug)]
pub(crate) struct Row {
    /// First element. A visible element is a node of its own.
    pub dot: Dot,
    /// Elements in the node.
    pub span: u64,
    /// Whether the node is created (a chain); else its elements are bare anchors or flag-only,
    /// each placed on its own.
    pub created: bool,
    /// The element the chosen edge names (the parent node's last element): `None` for HEAD,
    /// `END` and a virtual `Derived` anchor.
    pub parent: Option<Dot>,
    /// Whether the chosen edge names HEAD (else the node is below `parent`, on `END` or below a
    /// virtual `Derived` anchor).
    pub head: bool,
    /// Whether the node is visible (§5.7 Read).
    pub shown: bool,
    /// A visible text element's char.
    pub ch: Option<char>,
    /// Depth in the tree, less the block's shift (HEAD's children, `END` nodes and the
    /// children of a virtual anchor are at 0).
    depth: i64,
}

impl PartialEq for Row {
    fn eq(&self, o: &Row) -> bool {
        (&self.dot, self.span, self.created, &self.parent, self.head, self.shown, self.ch) == (&o.dot, o.span, o.created, &o.parent, o.head, o.shown, o.ch)
    }
}
impl Eq for Row {}

/// Visibility and visible char of an element (§5.7 Read).
fn shows(e: &SeqElem, text: bool) -> (bool, Option<char>) {
    let shown = is_visible(e, text);
    let ch = match e.content {
        SeqContent::Char(c) if shown => Some(c),
        _ => None,
    };
    (shown, ch)
}

#[derive(Clone, Debug, Default)]
struct Block {
    rows: Vec<Row>,
    shown: usize,
    /// Least row depth (unshifted).
    min: i64,
}

impl Block {
    fn new(rows: Vec<Row>) -> Block {
        let mut b = Block { rows, shown: 0, min: 0 };
        b.recount();
        b
    }
    fn recount(&mut self) {
        self.shown = self.rows.iter().filter(|r| r.shown).count();
        self.min = self.rows.iter().map(|r| r.depth).min().unwrap_or(i64::MAX);
    }
}

/// The placement of every placed node (deleted, content-less and bare anchors included) in
/// order; hidden ones (unknown anchor, §6.1) are absent. Blocks live in an arena (stable ids,
/// so the dot map survives splits) and `order` lists them in order. A copy shares the blocks
/// until it changes one. Each block's depths are shifted by its `shift`, so a subtree moves as
/// whole blocks.
#[derive(Clone, Debug)]
pub(crate) struct Placement {
    blocks: Vec<Arc<Block>>,
    shift: Vec<i64>,
    /// Arena ids no longer in `order`.
    free: Vec<usize>,
    order: Vec<usize>,
    len: usize,
    shown: usize,
    /// Rows per block (about √n, raised as rows are added).
    cap: usize,
}

impl PartialEq for Placement {
    fn eq(&self, o: &Placement) -> bool {
        self.len == o.len && self.shown == o.shown && self.iter_depth().eq(o.iter_depth())
    }
}
impl Eq for Placement {}

impl Placement {
    fn from_rows(rows: Vec<Row>) -> Placement {
        let len = rows.len();
        let cap = len.isqrt().clamp(4, BLOCK);
        let mut blocks: Vec<Arc<Block>> = Vec::with_capacity(len / cap + 1);
        let mut it = rows.into_iter().peekable();
        while it.peek().is_some() || blocks.is_empty() {
            blocks.push(Arc::new(Block::new(it.by_ref().take(cap).collect())));
        }
        let shown = blocks.iter().map(|b| b.shown).sum();
        let order = (0..blocks.len()).collect();
        Placement { shift: vec![0; blocks.len()], blocks, free: Vec::new(), order, len, shown, cap }
    }

    /// By dot, from a placement by index.
    pub(crate) fn of(p: &Placed, text: bool) -> Placement {
        let last = |i: usize| p.nodes.get(i).map(|n| nth(&n.dot, n.elem.span - 1));
        // preorder: a parent's depth is known before its children's
        let mut depth = vec![0i64; p.nodes.len()];
        let rows = p
            .order
            .iter()
            .filter_map(|i| {
                let n = p.nodes.get(*i)?;
                let (shown, ch) = shows(&n.elem, text);
                let parent = p.parent.get(*i).copied().flatten().filter(|j| *j < p.nodes.len());
                let d = parent.and_then(|j| depth.get(j)).map_or(0, |d| d + 1);
                if let Some(x) = depth.get_mut(*i) {
                    *x = d;
                }
                Some(Row {
                    dot: n.dot.clone().into_owned(),
                    span: n.elem.span,
                    created: n.elem.created.is_some(),
                    parent: parent.and_then(last),
                    head: p.head.get(*i).copied().unwrap_or(false),
                    shown,
                    ch,
                    depth: d,
                })
            })
            .collect();
        Placement::from_rows(rows)
    }

    fn block(&self, b: usize) -> &[Row] {
        self.blocks.get(b).map_or(&[], |x| &x.rows)
    }

    fn shift_of(&self, b: usize) -> i64 {
        self.shift.get(b).copied().unwrap_or(0)
    }

    /// Visible nodes.
    pub(crate) fn shown(&self) -> usize {
        self.shown
    }

    /// Every node in order.
    #[cfg(test)]
    pub(crate) fn iter(&self) -> impl Iterator<Item = &Row> + '_ {
        self.order.iter().flat_map(|b| self.block(*b))
    }

    /// Every node in order with its depth.
    fn iter_depth(&self) -> impl Iterator<Item = (&Row, i64)> + '_ {
        self.order.iter().flat_map(|b| self.block(*b).iter().map(|r| (r, r.depth + self.shift_of(*b))))
    }

    /// Block (order position) and offset of position `i`.
    fn locate(&self, mut i: usize) -> Option<(usize, usize)> {
        for (k, b) in self.order.iter().enumerate() {
            let n = self.block(*b).len();
            if i < n {
                return Some((k, i));
            }
            i -= n;
        }
        None
    }

    /// Block and offset of position `q` (the end: past the last block's rows).
    fn at_pos(&mut self, q: usize) -> (usize, usize) {
        if let Some((k, o)) = self.locate(q)
            && let Some(b) = self.order.get(k)
        {
            return (*b, o);
        }
        if let Some(b) = self.order.last() {
            return (*b, self.block(*b).len());
        }
        let b = self.alloc(Block::new(Vec::new()), 0);
        self.order.push(b);
        (b, 0)
    }

    /// The nodes from position `i` on.
    pub(crate) fn iter_from(&self, i: usize) -> impl Iterator<Item = &Row> + '_ {
        let (k, o) = self.locate(i).unwrap_or((self.order.len(), 0));
        let first = self.order.get(k).map_or(&[][..], |b| self.block(*b).get(o..).unwrap_or_default());
        first.iter().chain(self.order.get(k + 1..).unwrap_or_default().iter().flat_map(|b| self.block(*b)))
    }

    /// Visible node `k` in order.
    pub(crate) fn vis_nth(&self, mut k: usize) -> Option<&Row> {
        for b in &self.order {
            let x = self.blocks.get(*b)?;
            if k < x.shown {
                return x.rows.iter().filter(|r| r.shown).nth(k);
            }
            k -= x.shown;
        }
        None
    }

    /// Visible nodes in order.
    pub(crate) fn vis(&self) -> impl Iterator<Item = &Row> + '_ {
        self.order.iter().filter_map(|b| self.blocks.get(*b)).filter(|x| x.shown > 0).flat_map(|x| x.rows.iter().filter(|r| r.shown))
    }

    /// Visible nodes before position `i`.
    pub(crate) fn rank(&self, i: usize) -> usize {
        let (k, o) = self.locate(i).unwrap_or((self.order.len(), 0));
        let before: usize = self.order.get(..k).unwrap_or_default().iter().filter_map(|b| self.blocks.get(*b)).map(|x| x.shown).sum();
        let here = self.order.get(k).map_or(0, |b| self.block(*b).iter().take(o).filter(|r| r.shown).count());
        before + here
    }

    /// The nodes after rows `r` whose parent is one of them (`inr`: their last elements), in
    /// order: the subtrees hanging below a range from outside it (§5.7 move, `outside`), each
    /// skipped whole.
    pub(crate) fn hanging(&self, r: Range<usize>, inr: &HashSet<&Dot>) -> Vec<Dot> {
        let mut out = Vec::new();
        let mut c = self.norm(self.cursor(r.end));
        while let Some((row, d)) = self.row_c(c) {
            if !row.parent.as_ref().is_some_and(|x| inr.contains(x)) {
                break;
            }
            out.push(row.dot.clone());
            c = self.past(c, d, &mut 0);
        }
        out
    }

    /// The last visible node before position `i`.
    pub(crate) fn shown_before(&self, i: usize) -> Option<&Row> {
        let (k, o) = self.locate(i).unwrap_or((self.order.len(), 0));
        let here = self.order.get(k).map_or(&[][..], |b| self.block(*b).get(..o).unwrap_or_default());
        here.iter().rev().find(|r| r.shown).or_else(|| {
            let before = self.order.get(..k).unwrap_or_default();
            before.iter().rev().filter_map(|b| self.blocks.get(*b)).find(|x| x.shown > 0).and_then(|x| x.rows.iter().rev().find(|r| r.shown))
        })
    }

    /// Position of the first row of block `b`.
    fn base(&self, b: usize) -> usize {
        self.order.iter().take_while(|x| **x != b).map(|x| self.block(*x).len()).sum()
    }

    /// The first position after `i` whose depth is at most `d` (with `d` the depth at `i`: the
    /// end of its subtree), or the end. Skips blocks whose rows are all deeper.
    fn end_of(&self, i: usize, d: i64) -> usize {
        self.past(self.cursor(i), d, &mut 0).at
    }

    /// The cursor at position `i` (past the last row at the end).
    fn cursor(&self, i: usize) -> Cursor {
        let (k, o) = self.locate(i).unwrap_or((self.order.len(), 0));
        Cursor { k, o, at: i.min(self.len) }
    }

    /// `c`, moved off the end of its block.
    fn norm(&self, mut c: Cursor) -> Cursor {
        while let Some(b) = self.order.get(c.k)
            && c.o >= self.block(*b).len()
        {
            c.k += 1;
            c.o = 0;
        }
        c
    }

    /// The row at `c` (normalized) and its depth.
    fn row_c(&self, c: Cursor) -> Option<(&Row, i64)> {
        let b = *self.order.get(c.k)?;
        self.block(b).get(c.o).map(|r| (r, r.depth + self.shift_of(b)))
    }

    /// From the row at `c` (normalized), the first later row whose depth is at most `d`, or the
    /// end; blocks whose rows are all deeper are skipped. Adds the blocks and rows looked at to
    /// `work`.
    fn past(&self, c: Cursor, d: i64, work: &mut usize) -> Cursor {
        let mut at = c.at - c.o;
        for (j, b) in self.order.iter().enumerate().skip(c.k) {
            let (Some(x), s) = (self.blocks.get(*b), self.shift_of(*b)) else { continue };
            *work += 1;
            if j == c.k || x.min.saturating_add(s) <= d {
                let from = if j == c.k { c.o + 1 } else { 0 };
                let found = x.rows.iter().skip(from).position(|r| r.depth + s <= d);
                *work += found.map_or(x.rows.len().saturating_sub(from), |q| q + 1);
                if let Some(q) = found {
                    return self.norm(Cursor { k: j, o: from + q, at: at + from + q });
                }
            }
            at += x.rows.len();
        }
        Cursor { k: self.order.len(), o: 0, at: self.len }
    }

    /// A new arena block.
    fn alloc(&mut self, b: Block, shift: i64) -> usize {
        let b = Arc::new(b);
        match self.free.pop() {
            Some(id) => {
                if let Some(x) = self.blocks.get_mut(id) {
                    *x = b;
                }
                if let Some(x) = self.shift.get_mut(id) {
                    *x = shift;
                }
                id
            }
            None => {
                self.blocks.push(b);
                self.shift.push(shift);
                self.blocks.len() - 1
            }
        }
    }

    /// Splits the block holding position `i` so that a block starts there; the order index of
    /// that block (`order.len()` at the end).
    fn split(&mut self, i: usize, at: Option<&mut DotMap>) -> usize {
        let Some((k, o)) = self.locate(i) else { return self.order.len() };
        if o == 0 {
            return k;
        }
        let Some(b) = self.order.get(k).copied() else { return self.order.len() };
        let Some(x) = self.blocks.get_mut(b).map(Arc::make_mut) else { return self.order.len() };
        let tail = x.rows.split_off(o);
        x.recount();
        let id = self.alloc(Block::new(tail), self.shift_of(b));
        if let Some(m) = at {
            for r in self.block(id) {
                m.set(r.dot.clone(), id);
            }
        }
        self.order.insert(k + 1, id);
        k + 1
    }

    /// Merges the block at order index `k + 1` into the one at `k` when both fit in one.
    fn merge(&mut self, k: usize, at: Option<&mut DotMap>) {
        let (Some(a), Some(b)) = (self.order.get(k).copied(), self.order.get(k + 1).copied()) else { return };
        if self.block(a).len() + self.block(b).len() > self.cap {
            return;
        }
        let d = self.shift_of(b) - self.shift_of(a);
        let tail: Vec<Row> = self.block(b).iter().map(|r| Row { depth: r.depth + d, ..r.clone() }).collect();
        if let Some(m) = at {
            for r in &tail {
                m.set(r.dot.clone(), a);
            }
        }
        if let Some(x) = self.blocks.get_mut(a).map(Arc::make_mut) {
            x.rows.extend(tail);
            x.recount();
        }
        if let Some(x) = self.blocks.get_mut(b) {
            *x = Arc::default();
        }
        self.free.push(b);
        self.order.remove(k + 1);
    }

    /// Moves the rows `x` (a subtree) to before position `q` (outside them; at either end of `x`
    /// they stay), adding `dd` to their depths. Whichever of `x` and the rows it passes is
    /// smaller moves row by row; when both are big, `x` moves as whole blocks.
    fn relocate(&mut self, x: Range<usize>, q: usize, dd: i64, mut at: Option<&mut DotMap>) {
        if q == x.start || q == x.end {
            self.reshift(x, dd);
            return;
        }
        let n = x.len();
        let y = if q < x.start { q..x.start } else { x.end..q };
        if n <= y.len() && n <= self.cap {
            let q = if q > x.end { q - n } else { q };
            let rows: Vec<Row> = self.take(x, at.as_deref_mut()).into_iter().map(|r| Row { depth: r.depth + dd, ..r }).collect();
            let (b, o) = self.at_pos(q);
            self.insert(b, o, rows, at);
        } else if y.len() <= self.cap {
            self.reshift(x.clone(), dd);
            let to = if q < x.start { x.end - y.len() } else { x.start };
            let rows = self.take(y, at.as_deref_mut());
            let (b, o) = self.at_pos(to);
            self.insert(b, o, rows, at);
        } else {
            let q = if q > x.end { q - n } else { q };
            let ids = self.cut(x.start, x.end, at.as_deref_mut());
            self.paste(q, ids, dd, at);
        }
    }

    /// Adds `dd` to the depths of the rows `x`, by block shift where a block lies inside; the
    /// blocks and rows looked at.
    fn reshift(&mut self, x: Range<usize>, dd: i64) -> usize {
        if dd == 0 {
            return 0;
        }
        let (mut at, mut work) = (0, 0);
        for k in 0..self.order.len() {
            work += 1;
            let Some(b) = self.order.get(k).copied() else { break };
            let n = self.block(b).len();
            let (lo, hi) = (x.start.max(at), x.end.min(at + n));
            if lo == at && hi == at + n {
                if let Some(s) = self.shift.get_mut(b) {
                    *s += dd;
                }
            } else if lo < hi
                && let Some(blk) = self.blocks.get_mut(b).map(Arc::make_mut)
            {
                for r in blk.rows.get_mut(lo - at..hi - at).unwrap_or_default() {
                    r.depth += dd;
                }
                blk.recount();
                work += n;
            }
            at += n;
            if at >= x.end {
                break;
            }
        }
        work
    }

    /// Takes the rows `x` out (depths unshifted); the dot map keeps naming their old blocks
    /// until they are put back. A block left below half the block size merges with a
    /// neighbour where both fit in one.
    fn take(&mut self, x: Range<usize>, mut at: Option<&mut DotMap>) -> Vec<Row> {
        let mut out = Vec::with_capacity(x.len());
        while out.len() < x.len() {
            let Some((k, o)) = self.locate(x.start) else { break };
            let Some(b) = self.order.get(k).copied() else { break };
            let s = self.shift_of(b);
            let want = x.len() - out.len();
            let Some(blk) = self.blocks.get_mut(b).map(Arc::make_mut) else { break };
            let end = (o + want).min(blk.rows.len());
            let before = blk.shown;
            out.extend(blk.rows.drain(o..end).map(|r| Row { depth: r.depth + s, ..r }));
            blk.recount();
            self.shown -= before - blk.shown;
            self.len -= end - o;
            let left = blk.rows.len();
            if left == 0 {
                self.order.remove(k);
                self.free.push(b);
            } else if left < self.cap / 2 {
                let n = self.order.len();
                if k > 0 {
                    self.merge(k - 1, at.as_deref_mut());
                }
                if self.order.len() == n {
                    self.merge(k, at.as_deref_mut());
                }
            }
        }
        out
    }

    /// Takes the rows at positions `i..e` out, as whole blocks (by arena id).
    fn cut(&mut self, i: usize, e: usize, mut at: Option<&mut DotMap>) -> Vec<usize> {
        let ke = self.split(e, at.as_deref_mut());
        let n = self.order.len();
        let ki = self.split(i, at.as_deref_mut());
        let ke = ke + (self.order.len() - n);
        let ids: Vec<usize> = self.order.drain(ki..ke).collect();
        for b in &ids {
            let x = self.blocks.get(*b).map_or((0, 0), |x| (x.rows.len(), x.shown));
            self.len -= x.0;
            self.shown -= x.1;
        }
        if ki > 0 {
            self.merge(ki - 1, at);
        }
        ids
    }

    /// Puts blocks `ids` (from `cut`) in before position `q`, their depths raised by `dd`.
    fn paste(&mut self, q: usize, ids: Vec<usize>, dd: i64, mut at: Option<&mut DotMap>) {
        let k = self.split(q, at.as_deref_mut());
        let m = ids.len();
        for b in &ids {
            if let Some(s) = self.shift.get_mut(*b) {
                *s += dd;
            }
            let x = self.blocks.get(*b).map_or((0, 0), |x| (x.rows.len(), x.shown));
            self.len += x.0;
            self.shown += x.1;
        }
        self.order.splice(k..k, ids);
        if m > 0 {
            self.merge(k + m - 1, at.as_deref_mut());
        }
        if k > 0 {
            self.merge(k - 1, at);
        }
    }

    /// Splices `rows` in before offset `o` of block `b`, splitting it when it grows past twice the
    /// block size;
    /// `at` (dot to block) follows. Row depths are absolute.
    fn insert(&mut self, b: usize, o: usize, rows: Vec<Row>, at: Option<&mut DotMap>) {
        let n = rows.len();
        let mut at = at;
        if let Some(m) = at.as_deref_mut() {
            for r in &rows {
                m.set(r.dot.clone(), b);
            }
        }
        let s = self.shift_of(b);
        let Some(x) = self.blocks.get_mut(b).map(Arc::make_mut) else { return };
        let o = o.min(x.rows.len());
        let before = x.shown;
        x.rows.splice(o..o, rows.into_iter().map(|r| Row { depth: r.depth - s, ..r }));
        x.recount();
        let shown = x.shown - before;
        self.len += n;
        self.cap = self.cap.max(self.len.isqrt().min(BLOCK));
        self.shown += shown;
        if x.rows.len() <= 2 * self.cap {
            return;
        }
        // into pieces of about `cap` rows (a long run would otherwise leave one huge block)
        let pieces = x.rows.len().div_ceil(self.cap);
        let size = x.rows.len().div_ceil(pieces);
        let mut tails = Vec::new();
        while x.rows.len() > size {
            tails.push(x.rows.split_off(x.rows.len() - size));
        }
        x.recount();
        let first = self.order.iter().position(|y| *y == b).map_or(self.order.len(), |k| k + 1);
        for (k, tail) in (first..).zip(tails.into_iter().rev()) {
            let id = self.alloc(Block::new(tail), s);
            if let Some(m) = at.as_deref_mut() {
                for r in self.block(id) {
                    m.set(r.dot.clone(), id);
                }
            }
            self.order.insert(k, id);
        }
    }
}

/// A place in the placement: order index, offset in that block, position.
#[derive(Clone, Copy)]
struct Cursor {
    k: usize,
    o: usize,
    at: usize,
}

/// Row (first dot) to block, in dot order, so the row holding a dot is the one starting at or
/// before it. Sorted chunks of about √n entries (at least 64), each shared until a copy changes
/// it: a copy clones only the chunks it writes.
#[derive(Clone, Debug, Default)]
struct DotMap {
    chunks: Vec<Arc<Vec<(Dot, usize)>>>,
    len: usize,
}

impl DotMap {
    fn sorted(v: Vec<(Dot, usize)>) -> DotMap {
        let len = v.len();
        let size = DotMap::size(len);
        let mut chunks = Vec::with_capacity(len / size + 1);
        let mut it = v.into_iter().peekable();
        while it.peek().is_some() {
            chunks.push(Arc::new(it.by_ref().take(size).collect()));
        }
        DotMap { chunks, len }
    }
    fn size(len: usize) -> usize {
        len.isqrt().max(64)
    }
    /// The chunk holding `d` or where it would go.
    fn chunk(&self, d: &Dot) -> usize {
        self.chunks.partition_point(|c| c.first().is_some_and(|x| x.0 <= *d)).saturating_sub(1)
    }
    /// The entry at or before `d`.
    fn at_or_before(&self, d: &Dot) -> Option<(&Dot, usize)> {
        let c = self.chunks.get(self.chunk(d))?;
        let i = c.partition_point(|x| x.0 <= *d).checked_sub(1)?;
        c.get(i).map(|x| (&x.0, x.1))
    }
    fn get(&self, d: &Dot) -> Option<usize> {
        self.at_or_before(d).filter(|x| x.0 == d).map(|x| x.1)
    }
    fn set(&mut self, d: Dot, b: usize) {
        if self.chunks.is_empty() {
            self.chunks.push(Arc::default());
        }
        let k = self.chunk(&d);
        let Some(c) = self.chunks.get_mut(k).map(Arc::make_mut) else { return };
        match c.binary_search_by(|x| x.0.cmp(&d)) {
            Ok(i) => {
                if let Some(x) = c.get_mut(i) {
                    x.1 = b;
                }
            }
            Err(i) => {
                c.insert(i, (d, b));
                self.len += 1;
                if c.len() > 2 * DotMap::size(self.len) {
                    let tail = c.split_off(c.len() / 2);
                    self.chunks.insert(k + 1, Arc::new(tail));
                }
            }
        }
    }
    #[cfg(test)]
    fn len(&self) -> usize {
        self.len
    }
}

#[derive(Clone, Debug)]
pub(crate) struct Lin {
    pub p: Placement,
    /// Anchors naming no element.
    waiting: HashSet<Dot>,
    /// Nodes on a cycle a demotion broke (§6.2): a position change there rebuilds.
    cyc: HashSet<Dot>,
    /// The block of each row's first dot.
    at: DotMap,
}

impl PartialEq for Lin {
    fn eq(&self, o: &Lin) -> bool {
        self.p == o.p && self.waiting == o.waiting && self.cyc == o.cyc
    }
}
impl Eq for Lin {}

/// How the cache follows one record of a delta, decided against the state before it joins.
pub(crate) enum Plan {
    /// A new element created at `anchor`; whether the anchor's element is held, and the element
    /// after it when both are inside a range record (a row starts there once it is anchored at).
    New { stamp: Stamp, anchor: Anchor, known: bool, cut: Option<Dot> },
    /// Flag, content or (a single element's) position writes to the record of this span,
    /// whose creation stays as it was; `pos` are its position writes before.
    Held { span: u64, pos: Vec<(Stamp, Anchor)>, created: bool },
    /// A row starts at this element: a record split there (whether or not the record changed
    /// anything).
    Cut,
}

/// The element after `x` when both are inside record `(k, r)`: where a node splits once
/// something anchors at `x`.
fn inside(k: &Dot, r: &SeqElem, x: &Dot) -> Option<Dot> {
    (x.ctr - k.ctr + 1 < r.span).then(|| nth(x, 1))
}

/// Where a run goes: before position `.0`; `None` below a hidden node.
type Slot = Option<usize>;

impl Lin {
    pub(crate) fn build(elems: &Elems, text: bool) -> Lin {
        #[cfg(test)]
        PROBE.with(|p| p.set((p.get().0, p.get().1 + 1)));
        let placed = place_idx(elems);
        let p = Placement::of(&placed, text);
        let cyc = placed.cyc.iter().filter_map(|i| placed.nodes.get(*i)).map(|n| n.dot.clone().into_owned()).collect();
        let at = Lin::map_of(&placed, p.cap);
        Lin { p, waiting: placed.waiting, cyc, at }
    }

    /// Rows, blocks and block size (tests).
    #[cfg(test)]
    pub(crate) fn shape(&self) -> (usize, usize, usize) {
        (self.p.len, self.p.order.len(), self.p.cap)
    }

    /// The dot map of a placement just built from `placed` (blocks of `cap` rows in order), from
    /// its nodes, which are in dot order: no sort.
    fn map_of(placed: &Placed, cap: usize) -> DotMap {
        let mut block = vec![usize::MAX; placed.nodes.len()];
        for (q, i) in placed.order.iter().enumerate() {
            if let Some(b) = block.get_mut(*i) {
                *b = q / cap;
            }
        }
        let v = placed.nodes.iter().zip(block).filter(|x| x.1 != usize::MAX).map(|(n, b)| (n.dot.clone().into_owned(), b)).collect();
        DotMap::sorted(v)
    }

    /// Block and offset of the node starting at `d`.
    fn loc(&self, d: &Dot) -> Option<(usize, usize)> {
        let b = self.at.get(d)?;
        Some((b, self.p.block(b).iter().position(|r| r.dot == *d)?))
    }

    /// The dot map names each row's block, and the counts add up (tests).
    #[cfg(test)]
    pub(crate) fn map_ok(&self) -> bool {
        let p = &self.p;
        let counts = p.order.iter().all(|b| p.blocks.get(*b).is_some_and(|x| x.shown == x.rows.iter().filter(|r| r.shown).count() && x.min == x.rows.iter().map(|r| r.depth).min().unwrap_or(i64::MAX)));
        let m = &self.at;
        let map = m.len() == p.len && p.order.iter().all(|b| p.block(*b).iter().all(|r| m.get(&r.dot) == Some(*b)));
        let arena = p.order.len() + p.free.len() == p.blocks.len() && p.blocks.len() == p.shift.len();
        counts && map && arena && p.len == p.iter().count() && p.shown == p.vis().count()
    }

    /// Chunks of the dot map not shared with `o`'s, and all chunks (tests).
    #[cfg(test)]
    pub(crate) fn map_unshared(&self, o: &Lin) -> (usize, usize) {
        let (a, b) = (&self.at, &o.at);
        (a.chunks.iter().filter(|c| !b.chunks.iter().any(|x| Arc::ptr_eq(c, x))).count(), a.chunks.len())
    }

    /// Position of the node starting at `d`.
    pub(crate) fn index(&self, d: &Dot) -> Option<usize> {
        let (b, o) = self.loc(d)?;
        Some(self.p.base(b) + o)
    }

    /// The plans for joining record `(dot, de)` into `elems`, pushed to `out`; `false`: rebuild.
    pub(crate) fn plan(&self, elems: &dyn Recs, dot: &Dot, de: &SeqElem, out: &mut Vec<(Dot, Plan)>) -> bool {
        match elems.find(dot) {
            Some((k, r)) if k != dot || r.span != de.span => self.plan_pieces(elems, dot, de, out),
            _ => match self.plan_one(elems, dot, de) {
                Some(p) => {
                    out.push((dot.clone(), p));
                    true
                }
                None => false,
            },
        }
    }

    /// A record over held elements that does not line up with the state's records: `join_one`
    /// splits the state's records at its bounds (`Plan::Cut`) and joins it piece by piece into
    /// each; a plan per piece. `false` where part of it is new.
    fn plan_pieces(&self, elems: &dyn Recs, dot: &Dot, de: &SeqElem, out: &mut Vec<(Dot, Plan)>) -> bool {
        let last = nth(dot, de.span - 1);
        let Some(rs) = elems.starting(dot, &last) else { return false };
        let mut pieces = Vec::new();
        if let Some((k, r)) = elems.find(dot)
            && k != dot
        {
            out.push((dot.clone(), Plan::Cut));
            let off = dot.ctr - k.ctr;
            pieces.push(piece(k, r, off, (r.span - off).min(de.span)));
        }
        // a `Derived(S, c)` record between two `S` records is not part of it
        pieces.extend(rs.into_iter().filter(|(k, _)| k.src == dot.src).map(|(k, r)| piece(k, r, 0, r.span.min(last.ctr - k.ctr + 1))));
        let mut next = dot.ctr;
        for (pd, pe) in pieces {
            if pd.ctr != next {
                return false;
            }
            next = pd.ctr.saturating_add(pe.span);
            let (_, dp) = piece(dot, de, pd.ctr - dot.ctr, pe.span);
            if dp.created.as_ref().is_some_and(|c| pe.created.as_ref() != Some(c)) || pe.span != 1 && !dp.pos.iter().all(|p| pe.pos.iter().any(|q| q.0 == p.0)) {
                return false;
            }
            out.push((pd, Plan::Held { span: pe.span, pos: pe.pos, created: pe.created.is_some() }));
        }
        // the state's record holding the element after it is split there too
        let end = nth(dot, de.span);
        if elems.find(&end).is_some_and(|(k, _)| *k != end) {
            out.push((end, Plan::Cut));
        }
        next == last.ctr.saturating_add(1)
    }

    /// The plan for joining record `(dot, de)` into `elems` (new, or lining up with the state's
    /// record there); `None`: rebuild.
    fn plan_one(&self, elems: &dyn Recs, dot: &Dot, de: &SeqElem) -> Option<Plan> {
        match elems.find(dot) {
            None => {
                if de.span != 1 || dot.src.is_derived() {
                    return None;
                }
                let (stamp, anchor) = de.created.clone()?;
                // anchored at itself: a cycle of one (§6.2), which the whole pass demotes
                if stamp.dot != *dot || de.pos.len() != 1 || de.pos.first().is_none_or(|(s, a)| *s != stamp || *a != anchor) || anchor == Anchor::Dot(dot.clone()) {
                    return None;
                }
                let (known, cut) = match &anchor {
                    Anchor::Head => (true, None),
                    Anchor::Dot(x) => match elems.find(x) {
                        Some((k, r)) => (true, inside(k, r, x)),
                        // a virtual anchor on `END` (§6.1): it would split nodes of its source
                        None if x.src.is_derived() => return None,
                        None => (false, None),
                    },
                };
                Some(Plan::New { stamp, anchor, known, cut })
            }
            Some((k, r)) => {
                if k != dot || r.span != de.span || de.created.as_ref().is_some_and(|c| r.created.as_ref() != Some(c)) {
                    return None;
                }
                // new position writes only on a single element
                if r.span != 1 && !de.pos.iter().all(|p| r.pos.iter().any(|q| q.0 == p.0)) {
                    return None;
                }
                Some(Plan::Held { span: r.span, pos: r.pos.clone(), created: r.created.is_some() })
            }
        }
    }

    /// Follows a joined delta by its records' plans, in dot order; `false`: rebuild. New
    /// elements are spliced in as runs where they place, moved elements' subtrees are cut out
    /// and put in where they now place, flag and content writes flip visibility.
    pub(crate) fn follow(&mut self, elems: &dyn Recs, text: bool, plans: Vec<(Dot, Plan)>) -> bool {
        let mut work = 0;
        let ok = self.follow_in(elems, text, plans, &mut work);
        #[cfg(test)]
        PROBE.with(|p| p.set((p.get().0 + work, p.get().1)));
        ok
    }

    /// `follow`, charging the rows and blocks it looks at to `work`.
    fn follow_in(&mut self, elems: &dyn Recs, text: bool, plans: Vec<(Dot, Plan)>, work: &mut usize) -> bool {
        // runs of new elements by the existing node (`None`: HEAD) they follow, with the first
        // element's edge stamp
        let mut runs: Vec<(Option<Dot>, Stamp, Vec<Dot>)> = Vec::new();
        // the run holding each new element; `None`: hidden
        let mut new: HashMap<Dot, Option<usize>> = HashMap::new();
        let mut flags: Vec<Dot> = Vec::new();
        // elements whose chosen edge changed: (edge stamp, element, anchor)
        let mut moves: Vec<(Stamp, Dot, Anchor)> = Vec::new();
        // elements a row must start at
        let mut cuts: Vec<Dot> = Vec::new();
        for (dot, plan) in plans {
            if let Plan::Cut = plan {
                cuts.push(dot);
                continue;
            }
            let Some(r) = elems.get(&dot) else { return false };
            match plan {
                Plan::Cut => {}
                Plan::New { stamp, anchor, known, cut } => {
                    // a write waiting for this dot now gets placed: rebuild
                    if r.span != 1 || r.created.as_ref() != Some(&(stamp.clone(), anchor.clone())) || r.pos.len() != 1 || r.pos.first().is_none_or(|(s, a)| *s != stamp || *a != anchor) || self.waiting.contains(&dot) {
                        return false;
                    }
                    let key = match anchor {
                        Anchor::Head => None,
                        Anchor::Dot(x) => Some(x),
                    };
                    if !known {
                        // hidden until its anchor arrives (§6.1)
                        self.waiting.extend(key);
                        new.insert(dot, None);
                        continue;
                    }
                    cuts.extend(cut);
                    let run = match key.as_ref().and_then(|x| new.get(x)) {
                        // below a hidden new element
                        Some(None) => None,
                        // right after a new element, which must end its run
                        Some(Some(i)) => {
                            let Some((_, _, run)) = runs.get_mut(*i) else { return false };
                            if run.last() != key.as_ref() {
                                return false;
                            }
                            run.push(dot.clone());
                            Some(*i)
                        }
                        // a child of an existing node: a run of its own
                        None => {
                            runs.push((key, stamp, vec![dot.clone()]));
                            Some(runs.len() - 1)
                        }
                    };
                    new.insert(dot, run);
                }
                Plan::Held { span, pos, created } => {
                    if r.span != span || r.created.is_some() != created {
                        return false;
                    }
                    if r.pos != pos {
                        match self.moved(elems, &dot, &pos, &r.pos, &mut cuts) {
                            Some(m) => moves.extend(m),
                            None => return false,
                        }
                    }
                    // a range record has no content: never visible
                    if span == 1 {
                        flags.push(dot);
                    }
                }
            }
        }
        // a bounded number of placements, each O(√n) plus the sibling subtrees it skips: past
        // about a whole pass's worth of rows and blocks looked at a rebuild is cheaper
        if runs.len() + moves.len() + cuts.len() > self.p.len.isqrt().max(64) {
            return false;
        }
        let each = self.p.order.len() + self.p.cap;
        for x in cuts {
            *work += each;
            if !self.cut_row(&x, work) || *work > self.p.len.max(1024) {
                return false;
            }
        }
        for (key, stamp, run) in runs {
            *work += each;
            let Some(slot) = self.slot(elems, &key, &stamp, usize::MAX..usize::MAX, work) else { return false };
            // below a hidden node: hidden too
            let Some(q) = slot else { continue };
            let Some(d0) = self.depth_below(&key) else { return false };
            let mut head = key.is_none();
            let mut parent = key;
            let rows: Vec<Row> = run
                .into_iter()
                .enumerate()
                .map(|(k, d)| {
                    let (shown, ch) = elems.get(&d).map_or((false, None), |e| shows(e, text));
                    let row = Row { dot: d.clone(), span: 1, created: true, parent: parent.take(), head: std::mem::take(&mut head), shown, ch, depth: d0 + k as i64 };
                    parent = Some(d);
                    row
                })
                .collect();
            let (b, o) = self.p.at_pos(q);
            self.p.insert(b, o, rows, Some(&mut self.at));
        }
        // in the order the writes were made (a mover re-anchors the outside nodes first)
        moves.sort();
        for (stamp, dot, anchor) in moves {
            *work += each;
            if !self.place_moved(elems, &dot, stamp, anchor, work) {
                return false;
            }
        }
        for dot in flags {
            let Some((b, o)) = self.loc(&dot) else { continue };
            let (now, ch) = elems.get(&dot).map_or((false, None), |e| shows(e, text));
            let Some(x) = self.p.blocks.get_mut(b).map(Arc::make_mut) else { return false };
            let Some(row) = x.rows.get_mut(o) else { return false };
            row.ch = ch;
            if row.shown == now {
                continue;
            }
            row.shown = now;
            if now {
                x.shown += 1;
                self.p.shown += 1;
            } else {
                x.shown = x.shown.saturating_sub(1);
                self.p.shown = self.p.shown.saturating_sub(1);
            }
        }
        true
    }

    /// The edge change of single element `dot` whose position writes went from `old` to `now`:
    /// `Some(None)` if its chosen edge stays; `None`: rebuild. A write gained naming an element
    /// inside a range record cuts a row after it (`cuts`); rebuilds if a write gained or lost
    /// names an unknown element (an absent `Derived` one: a virtual anchor), a write lost names
    /// an element inside a range record (its node may join the next again), or the element is
    /// on a broken cycle (§6.2: its demotion may change).
    fn moved(&self, elems: &dyn Recs, dot: &Dot, old: &[(Stamp, Anchor)], now: &[(Stamp, Anchor)], cuts: &mut Vec<Dot>) -> Option<Option<(Stamp, Dot, Anchor)>> {
        if self.cyc.contains(dot) {
            return None;
        }
        let gained = now.iter().filter(|p| !old.contains(p)).map(|p| (true, p));
        let lost = old.iter().filter(|p| !now.contains(p)).map(|p| (false, p));
        for (gain, (_, a)) in gained.chain(lost) {
            let Anchor::Dot(x) = a else { continue };
            let (k, r) = elems.find(x)?;
            match inside(k, r, x) {
                Some(c) if gain => cuts.push(c),
                Some(_) => return None,
                None => {}
            }
        }
        let (stamp, anchor) = now.first()?.clone();
        Some((old.first().map(|p| &p.0) != Some(&stamp)).then(|| (stamp, dot.clone(), anchor)))
    }

    /// Block and offset of the row holding element `x`.
    fn holder(&self, x: &Dot) -> Option<(usize, usize)> {
        let (k, b) = self.at.at_or_before(x)?;
        let o = self.p.block(b).iter().position(|r| r.dot == *k)?;
        let r = self.p.block(b).get(o)?;
        (r.dot.src == x.src && x.ctr - r.dot.ctr < r.span).then_some((b, o))
    }

    /// The row holding element `x` (placed), by block and offset, if `x` is its last element.
    fn ending(&self, x: &Dot) -> Option<(usize, usize)> {
        let (b, o) = self.holder(x)?;
        let r = self.p.block(b).get(o)?;
        (x.ctr - r.dot.ctr + 1 == r.span).then_some((b, o))
    }

    /// Starts a row at element `x` where a placed row holds it past its first element, as a whole
    /// pass cuts the node: a creation chain's second piece is the only child of the first (whose
    /// last element nothing anchored at), so it follows it one level deeper with the rest of the
    /// subtree; the pieces of a range without creation sit on `END` side by side. `false`:
    /// rebuild (the row is on a broken cycle).
    fn cut_row(&mut self, x: &Dot, work: &mut usize) -> bool {
        let Some((b, o)) = self.holder(x) else { return true };
        let Some(row) = self.p.block(b).get(o).cloned() else { return false };
        if row.dot == *x {
            return true;
        }
        if self.cyc.contains(&row.dot) {
            return false;
        }
        let off = x.ctr - row.dot.ctr;
        let d = row.depth + self.p.shift_of(b);
        let i = self.p.base(b) + o;
        if let Some(r) = self.p.blocks.get_mut(b).map(Arc::make_mut).and_then(|x| x.rows.get_mut(o)) {
            r.span = off;
        }
        let dd = i64::from(row.created);
        if row.created {
            let e = self.p.past(self.p.norm(self.p.cursor(i)), d, work).at;
            *work += self.p.reshift(i + 1..e, 1);
        }
        let second = Row { dot: x.clone(), span: row.span - off, created: row.created, parent: row.created.then(|| nth(&row.dot, off - 1)), head: false, shown: false, ch: None, depth: d + dd };
        self.p.insert(b, o + 1, vec![second], Some(&mut self.at));
        true
    }

    /// Depth of a child of `key` (`None`: HEAD); `None` if it is not placed.
    fn depth_below(&self, key: &Option<Dot>) -> Option<i64> {
        let Some(x) = key else { return Some(0) };
        let (b, o) = self.ending(x)?;
        Some(self.p.block(b).get(o)?.depth + self.p.shift_of(b) + 1)
    }

    /// Moves the subtree of `dot` below `anchor` with edge stamp `stamp`; `false`: rebuild (the
    /// element or the anchor is not placed, or the anchor is in the subtree: a cycle).
    fn place_moved(&mut self, elems: &dyn Recs, dot: &Dot, stamp: Stamp, anchor: Anchor, work: &mut usize) -> bool {
        let Some((b, o)) = self.loc(dot) else { return false };
        let Some(d) = self.p.block(b).get(o).map(|r| r.depth + self.p.shift_of(b)) else { return false };
        let i = self.p.base(b) + o;
        let e = self.p.end_of(i, d);
        let key = match anchor {
            Anchor::Head => None,
            Anchor::Dot(x) => {
                match self.ending(&x).map(|(b, o)| self.p.base(b) + o) {
                    Some(ix) if ix < i || ix >= e => {}
                    _ => return false,
                }
                Some(x)
            }
        };
        let (Some(Some(q)), Some(nd)) = (self.slot(elems, &key, &stamp, i..e, work), self.depth_below(&key)) else { return false };
        self.p.relocate(i..e, q, nd - d, Some(&mut self.at));
        let Some((b, o)) = self.loc(dot) else { return false };
        let Some(row) = self.p.blocks.get_mut(b).map(Arc::make_mut).and_then(|x| x.rows.get_mut(o)) else { return false };
        row.head = key.is_none();
        row.parent = key;
        true
    }

    /// Where a node whose edge (stamp `stamp`) names `key` (`None`: HEAD) goes: after the anchor
    /// and its children with greater edge stamps, with their subtrees (§6.1 sibling order), and
    /// at HEAD before the `END` nodes, as if the rows `skip` (the node's own subtree) were out;
    /// `None`: rebuild.
    fn slot(&self, elems: &dyn Recs, key: &Option<Dot>, stamp: &Stamp, skip: Range<usize>, work: &mut usize) -> Option<Slot> {
        let (mut c, d, want) = match key {
            None => (self.p.norm(Cursor { k: 0, o: 0, at: 0 }), -1, Anchor::Head),
            Some(x) => {
                let Some((b, o)) = self.holder(x) else { return Some(None) };
                let r = self.p.block(b).get(o)?;
                if x.ctr - r.dot.ctr + 1 != r.span {
                    return None;
                }
                let d = r.depth + self.p.shift_of(b);
                let k = self.p.order.iter().position(|y| *y == b)?;
                (self.p.norm(Cursor { k, o: o + 1, at: self.p.base(b) + o + 1 }), d, Anchor::Dot(x.clone()))
            }
        };
        for _ in 0..SIBS {
            if c.at == skip.start {
                c = self.p.norm(self.p.cursor(skip.end));
            }
            let Some((r, rd)) = self.p.row_c(c) else { return Some(Some(c.at)) };
            // past the anchor's subtree, or (at HEAD) at the `END` nodes
            if rd <= d || key.is_none() && !r.head || child_stamp(elems, r, &want)? < *stamp {
                return Some(Some(c.at));
            }
            // a record lookup per sibling: about as dear as a few rows of a whole pass
            *work += STEP;
            c = self.p.past(c, rd, work);
            if *work > self.p.len.max(1024) {
                return None;
            }
        }
        None
    }
}

/// The edge stamp of node `row` towards `want`: its greatest position write naming it (a
/// demoted edge is the `prev` one, §6.2; a node a delta moves away keeps its old write there as
/// `prev` until it is re-placed, else this is `None` and the caller rebuilds).
fn child_stamp(elems: &dyn Recs, row: &Row, want: &Anchor) -> Option<Stamp> {
    let e = elems.elem(&row.dot)?;
    e.pos.iter().find(|(_, a)| a == want).map(|(s, _)| s.clone())
}
