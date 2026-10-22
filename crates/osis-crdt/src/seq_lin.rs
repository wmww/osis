//! The cached placement of a sequence (spec/crdt.md §6): built by one whole pass
//! (`linearize::place_idx`), then followed through joins that add elements or change flags and
//! content; any other change drops it and the next use rebuilds it.
//!
//! Rows sit in blocks of a few hundred with their visible counts, so finding a row by dot (a map
//! to its block, built on first use), by position or by visible index, and splicing a run in,
//! cost O(√n) instead of a scan and a shift of the whole order.
//!
//! Rows carry their depth, so a subtree is the rows up to the next one no deeper (blocks whose
//! rows are all deeper are skipped), and a block-level shift lets a subtree move as whole blocks.
//!
//! A new element anchored at HEAD or at a single-element record goes right after its anchor,
//! past the anchor's children whose edge stamps beat its own, with their subtrees. It closes no
//! cycle (nothing anchors at it unless a write waits for its dot, which falls back), so no
//! demotion changes. A single element whose chosen edge changes (a move) has its subtree cut out
//! and put in the same way at its new anchor; a cycle (the anchor inside the subtree) and an
//! element on a cycle broken before fall back, so the demotions stay those of a whole pass. A
//! flag or content write moves nothing; only visibility changes. Everything else (resets, range
//! splits, `Derived` dots) falls back to a whole pass.

use crate::linearize::{Placed, place_idx};
use crate::seq::{Anchor, SeqContent, SeqElem, is_visible};
use crate::seq_span::{Elems, Recs, nth};
use crate::stamp::{Dot, Stamp};
use std::collections::{HashMap, HashSet};
use std::ops::Range;
use std::sync::{Arc, OnceLock};

/// Rows per block: about √n (at most this), growing with the placement; a block splits in two
/// above twice that.
const BLOCK: usize = 256;
/// Newer siblings (with their subtrees) skipped past an anchor to place a run or a moved
/// subtree; more rebuild.
const SIBS: usize = 256;

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
    /// Chosen parent node (by first element): `None` for HEAD and `END`.
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
        let first = |i: usize| p.nodes.get(i).map(|n| n.dot.clone().into_owned());
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
                    parent: parent.and_then(first),
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

    /// The row at position `i` and its depth.
    fn row_at(&self, i: usize) -> Option<(&Row, i64)> {
        let (k, o) = self.locate(i)?;
        let b = *self.order.get(k)?;
        self.block(b).get(o).map(|r| (r, r.depth + self.shift_of(b)))
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
        let Some((k, o)) = self.locate(i) else { return self.len };
        let mut at = i - o;
        for (j, b) in self.order.iter().enumerate().skip(k) {
            let (Some(x), s) = (self.blocks.get(*b), self.shift_of(*b)) else { continue };
            if j == k || x.min.saturating_add(s) <= d {
                let from = if j == k { o + 1 } else { 0 };
                if let Some(q) = x.rows.iter().skip(from).position(|r| r.depth + s <= d) {
                    return at + from + q;
                }
            }
            at += x.rows.len();
        }
        self.len
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
            let rows: Vec<Row> = self.take(x).into_iter().map(|r| Row { depth: r.depth + dd, ..r }).collect();
            let (b, o) = self.at_pos(q);
            self.insert(b, o, rows, at);
        } else if y.len() <= self.cap {
            self.reshift(x.clone(), dd);
            let to = if q < x.start { x.end - y.len() } else { x.start };
            let rows = self.take(y);
            let (b, o) = self.at_pos(to);
            self.insert(b, o, rows, at);
        } else {
            let q = if q > x.end { q - n } else { q };
            let ids = self.cut(x.start, x.end, at.as_deref_mut());
            self.paste(q, ids, dd, at);
        }
    }

    /// Adds `dd` to the depths of the rows `x`, by block shift where a block lies inside.
    fn reshift(&mut self, x: Range<usize>, dd: i64) {
        if dd == 0 {
            return;
        }
        let mut at = 0;
        for k in 0..self.order.len() {
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
            }
            at += n;
            if at >= x.end {
                break;
            }
        }
    }

    /// Takes the rows `x` out (depths unshifted); the dot map keeps naming their old blocks
    /// until they are put back.
    fn take(&mut self, x: Range<usize>) -> Vec<Row> {
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
            if blk.rows.is_empty() {
                self.order.remove(k);
                self.free.push(b);
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

    /// Splices `rows` in before offset `o` of block `b`, splitting it when it grows too big;
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
        let tail = x.rows.split_off(x.rows.len() / 2);
        x.recount();
        let id = self.alloc(Block::new(tail), s);
        if let Some(m) = at {
            for r in self.block(id) {
                m.set(r.dot.clone(), id);
            }
        }
        let k = self.order.iter().position(|y| *y == b).map_or(self.order.len(), |k| k + 1);
        self.order.insert(k, id);
    }
}

/// Dot to block, cheap to copy: a shared base plus the entries set since, folded in once they
/// pass √n (at least 64), so a copy clones few.
#[derive(Clone, Debug, Default)]
struct DotMap {
    base: Arc<HashMap<Dot, usize>>,
    new: HashMap<Dot, usize>,
}

impl DotMap {
    fn get(&self, d: &Dot) -> Option<usize> {
        self.new.get(d).or_else(|| self.base.get(d)).copied()
    }
    fn set(&mut self, d: Dot, b: usize) {
        self.new.insert(d, b);
        if self.new.len() > self.base.len().isqrt().max(64) {
            Arc::make_mut(&mut self.base).extend(self.new.drain());
        }
    }
    #[cfg(test)]
    fn len(&self) -> usize {
        self.base.len() + self.new.keys().filter(|k| !self.base.contains_key(*k)).count()
    }
}

#[derive(Clone, Debug)]
pub(crate) struct Lin {
    pub p: Placement,
    /// Anchors naming no element.
    waiting: HashSet<Dot>,
    /// Nodes on a cycle a demotion broke (§6.2): a position change there rebuilds.
    cyc: HashSet<Dot>,
    /// The block of each row's first dot, built on first lookup.
    at: OnceLock<DotMap>,
}

impl PartialEq for Lin {
    fn eq(&self, o: &Lin) -> bool {
        self.p == o.p && self.waiting == o.waiting && self.cyc == o.cyc
    }
}
impl Eq for Lin {}

/// How the cache follows one record of a delta, decided against the state before it joins.
pub(crate) enum Plan {
    /// A new element created at `anchor`; whether the anchor's element is held.
    New { stamp: Stamp, anchor: Anchor, known: bool },
    /// Flag, content or (a single element's) position writes to the record of this span,
    /// whose creation stays as it was; `pos` are its position writes before.
    Held { span: u64, pos: Vec<(Stamp, Anchor)>, created: bool },
}

/// Where a run goes: before position `.0`; `None` below a hidden node.
type Slot = Option<usize>;

impl Lin {
    pub(crate) fn build(elems: &Elems, text: bool) -> Lin {
        let placed = place_idx(elems);
        let p = Placement::of(&placed, text);
        let cyc = placed.cyc.iter().filter_map(|i| placed.nodes.get(*i)).map(|n| n.dot.clone().into_owned()).collect();
        Lin { p, waiting: placed.waiting, cyc, at: OnceLock::new() }
    }

    fn map(&self) -> &DotMap {
        self.at.get_or_init(|| {
            let mut m = HashMap::with_capacity(self.p.len);
            for b in &self.p.order {
                for r in self.p.block(*b) {
                    m.insert(r.dot.clone(), *b);
                }
            }
            DotMap { base: Arc::new(m), new: HashMap::new() }
        })
    }

    /// Block and offset of the node starting at `d`.
    fn loc(&self, d: &Dot) -> Option<(usize, usize)> {
        let b = self.map().get(d)?;
        Some((b, self.p.block(b).iter().position(|r| r.dot == *d)?))
    }

    /// The dot map, if built, names each row's block, and the counts add up (tests).
    #[cfg(test)]
    pub(crate) fn map_ok(&self) -> bool {
        let p = &self.p;
        let counts = p.order.iter().all(|b| p.blocks.get(*b).is_some_and(|x| x.shown == x.rows.iter().filter(|r| r.shown).count() && x.min == x.rows.iter().map(|r| r.depth).min().unwrap_or(i64::MAX)));
        let map = self.at.get().is_none_or(|m| m.len() == p.len && p.order.iter().all(|b| p.block(*b).iter().all(|r| m.get(&r.dot) == Some(*b))));
        let arena = p.order.len() + p.free.len() == p.blocks.len() && p.blocks.len() == p.shift.len();
        counts && map && arena && p.len == p.iter().count() && p.shown == p.vis().count()
    }

    /// Position of the node starting at `d`.
    pub(crate) fn index(&self, d: &Dot) -> Option<usize> {
        let (b, o) = self.loc(d)?;
        Some(self.p.base(b) + o)
    }

    /// The plans for joining record `(dot, de)` into `elems`, pushed to `out`; `false`: rebuild.
    pub(crate) fn plan(&self, elems: &dyn Recs, dot: &Dot, de: &SeqElem, out: &mut Vec<(Dot, Plan)>) -> bool {
        match elems.find(dot) {
            Some((k, r)) if k == dot && r.span < de.span => self.plan_cover(elems, dot, de, out),
            _ => match self.plan_one(elems, dot, de) {
                Some(p) => {
                    out.push((dot.clone(), p));
                    true
                }
                None => false,
            },
        }
    }

    /// A flag-only range record (a decoded delete) over several state records of one source that
    /// it covers exactly: a flag plan per record (`join_one` cuts it at their bounds).
    fn plan_cover(&self, elems: &dyn Recs, dot: &Dot, de: &SeqElem, out: &mut Vec<(Dot, Plan)>) -> bool {
        if de.created.is_some() || !de.pos.is_empty() || !matches!(de.content, SeqContent::None) {
            return false;
        }
        let last = nth(dot, de.span - 1);
        let mut next = dot.ctr;
        let Some(rs) = elems.starting(dot, &last) else { return false };
        for (k, r) in rs {
            if k.src != dot.src || k.ctr != next {
                return false;
            }
            next = k.ctr.saturating_add(r.span);
            out.push((k.clone(), Plan::Held { span: r.span, pos: r.pos.clone(), created: r.created.is_some() }));
        }
        next == last.ctr.saturating_add(1)
    }

    /// The plan for joining record `(dot, de)` into `elems`; `None`: rebuild.
    fn plan_one(&self, elems: &dyn Recs, dot: &Dot, de: &SeqElem) -> Option<Plan> {
        match elems.find(dot) {
            None => {
                if de.span != 1 || dot.src.is_derived() {
                    return None;
                }
                let (stamp, anchor) = de.created.clone()?;
                if stamp.dot != *dot || de.pos.len() != 1 || de.pos.first().is_none_or(|(s, a)| *s != stamp || *a != anchor) {
                    return None;
                }
                let known = match &anchor {
                    Anchor::Head => true,
                    Anchor::Dot(x) if x.src.is_derived() => return None,
                    Anchor::Dot(x) => match elems.find(x) {
                        Some((_, r)) if r.span != 1 => return None,
                        r => r.is_some(),
                    },
                };
                Some(Plan::New { stamp, anchor, known })
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
        // runs of new elements by the existing node (`None`: HEAD) they follow, with the first
        // element's edge stamp
        let mut runs: Vec<(Option<Dot>, Stamp, Vec<Dot>)> = Vec::new();
        // the run holding each new element; `None`: hidden
        let mut new: HashMap<Dot, Option<usize>> = HashMap::new();
        let mut flags: Vec<Dot> = Vec::new();
        // elements whose chosen edge changed: (edge stamp, element, anchor)
        let mut moves: Vec<(Stamp, Dot, Anchor)> = Vec::new();
        for (dot, plan) in plans {
            let Some(r) = elems.get(&dot) else { return false };
            match plan {
                Plan::New { stamp, anchor, known } => {
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
                        match self.moved(elems, &dot, &pos, &r.pos) {
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
        for (key, stamp, run) in runs {
            let Some(slot) = self.slot(elems, &key, &stamp, usize::MAX..usize::MAX) else { return false };
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
            self.p.insert(b, o, rows, self.at.get_mut());
        }
        // in the order the writes were made (a mover re-anchors the outside nodes first)
        moves.sort();
        for (stamp, dot, anchor) in moves {
            if !self.place_moved(elems, &dot, stamp, anchor) {
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
    /// `Some(None)` if its chosen edge stays; `None`: rebuild. Rebuilds if a write gained or lost
    /// names an element inside a range record (the nodes split differently), an unknown or
    /// `Derived` element, or the element is on a broken cycle (§6.2: its demotion may change).
    fn moved(&self, elems: &dyn Recs, dot: &Dot, old: &[(Stamp, Anchor)], now: &[(Stamp, Anchor)]) -> Option<Option<(Stamp, Dot, Anchor)>> {
        if dot.src.is_derived() || self.cyc.contains(dot) {
            return None;
        }
        let gained = now.iter().filter(|p| !old.contains(p));
        let lost = old.iter().filter(|p| !now.contains(p));
        for (_, a) in gained.chain(lost) {
            if let Anchor::Dot(x) = a
                && (x.src.is_derived() || !elems.find(x).is_some_and(|(_, r)| r.span == 1))
            {
                return None;
            }
        }
        let (stamp, anchor) = now.first()?.clone();
        Some((old.first().map(|p| &p.0) != Some(&stamp)).then(|| (stamp, dot.clone(), anchor)))
    }

    /// Depth of a child of `key` (`None`: HEAD); `None` if it is not placed.
    fn depth_below(&self, key: &Option<Dot>) -> Option<i64> {
        let Some(x) = key else { return Some(0) };
        let (b, o) = self.loc(x)?;
        Some(self.p.block(b).get(o)?.depth + self.p.shift_of(b) + 1)
    }

    /// Moves the subtree of `dot` below `anchor` with edge stamp `stamp`; `false`: rebuild (the
    /// element or the anchor is not placed, or the anchor is in the subtree: a cycle).
    fn place_moved(&mut self, elems: &dyn Recs, dot: &Dot, stamp: Stamp, anchor: Anchor) -> bool {
        let Some((b, o)) = self.loc(dot) else { return false };
        let Some(d) = self.p.block(b).get(o).map(|r| r.depth + self.p.shift_of(b)) else { return false };
        let i = self.p.base(b) + o;
        let e = self.p.end_of(i, d);
        let key = match anchor {
            Anchor::Head => None,
            Anchor::Dot(x) => {
                match self.index(&x) {
                    Some(ix) if ix < i || ix >= e => {}
                    _ => return false,
                }
                Some(x)
            }
        };
        let (Some(Some(q)), Some(nd)) = (self.slot(elems, &key, &stamp, i..e), self.depth_below(&key)) else { return false };
        self.p.relocate(i..e, q, nd - d, self.at.get_mut());
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
    fn slot(&self, elems: &dyn Recs, key: &Option<Dot>, stamp: &Stamp, skip: Range<usize>) -> Option<Slot> {
        let (mut j, d, want) = match key {
            None => (0, -1, Anchor::Head),
            Some(x) => {
                let Some((b, o)) = self.loc(x) else { return Some(None) };
                let d = self.p.block(b).get(o)?.depth + self.p.shift_of(b);
                (self.p.base(b) + o + 1, d, Anchor::Dot(x.clone()))
            }
        };
        for _ in 0..SIBS {
            if j == skip.start {
                j = skip.end;
            }
            let Some((r, rd)) = self.p.row_at(j) else { return Some(Some(j)) };
            // past the anchor's subtree, or (at HEAD) at the `END` nodes
            if rd <= d || key.is_none() && !r.head || child_stamp(elems, r, &want)? < *stamp {
                return Some(Some(j));
            }
            j = self.p.end_of(j, rd);
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
