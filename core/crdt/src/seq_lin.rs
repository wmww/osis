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
//! past the anchor's children whose sibling keys beat its own, with their subtrees. It closes no
//! cycle (nothing anchors at it unless a write waits for its dot, which falls back), so no
//! demotion changes. A single element whose chosen edge changes (a move) has its subtree cut out
//! and put in the same way at its new anchor, in write-stamp order. A flag or content write
//! moves nothing; only visibility changes. A write over part of a range record, or a new anchor
//! inside one, cuts the row where a whole pass cuts the node (`cut_row`).
//!
//! A placement may be held in part (`Partial`, `seq_place::SeqPlace`: a node keeps the rows and
//! the dot map in its store): blocks and dot-map chunks are stubs (counts, least depth, first
//! dot) until loaded, and record lookups outside the pages loaded are misses. Whatever needs a
//! stub's rows, a stub chunk's entries or a missing record notes a miss and fails (a follow
//! returns `false`, so the sequence drops it; an op's result is void); neighbouring stubs are
//! not merged (block bounds do not change the order). The caller loads what was missed and runs
//! it again.
//!
//! Whole-pass fallbacks (the cache is dropped; one held in part is dropped instead):
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
//! - 256 or more newer siblings at the anchor (`slot`), or a sibling there with no position
//!   write naming it (`Sibs::key`; a node the delta moves sits by its old chosen write until
//!   re-placed).

use crate::linearize::{Placed, place_idx};
use crate::seq::{Anchor, PosW, SeqContent, SeqElem, is_creation, is_visible, sib_key};
use crate::seq_place::{PlaceBlock, PlaceDiff, PlaceRow, PlaceTop};
use crate::seq_span::{Elems, Recs, nth, piece};
use crate::stamp::{Dot, Stamp};
use std::borrow::Cow;
use std::collections::{BTreeSet, HashMap, HashSet};
use std::ops::Range;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

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

/// What a placement held in part is missing (a node keeps the rows and the dot map in its
/// store and loads them as needed, notes/node.md Paged state): the blocks and dot-map chunks
/// looked at whose rows are not loaded, and the record lookups outside the pages loaded
/// (`cover`). Whatever misses fails (a follow returns `false`, an op's result is void); the
/// caller loads what was missed and runs it again. Shared by the copies of one placement.
#[derive(Debug, Default)]
pub(crate) struct Partial(Mutex<Missed>);

#[derive(Debug, Default, Clone)]
pub(crate) struct Missed {
    pub blocks: BTreeSet<usize>,
    /// Dot-map chunks by first dot (`None`: the first chunk).
    pub chunks: BTreeSet<Option<Dot>>,
    /// Record lookups outside the cover: the dot range looked at.
    pub recs: Vec<(Dot, Dot)>,
    /// Every record was looked at.
    pub all: bool,
    /// `all` came from a whole pass (a follow or placement failing for a reason other than a
    /// miss), not a look at every record.
    pub whole: bool,
    /// Misses so far.
    pub count: usize,
    /// Work units charged by follows.
    pub work: usize,
    /// Dot ranges whose records are loaded, sorted and merged (`None`: unbounded).
    cover: Vec<(Option<Dot>, Option<Dot>)>,
}

impl Partial {
    pub(crate) fn with<T>(&self, f: impl FnOnce(&mut Missed) -> T) -> T {
        let mut g = self.0.lock().unwrap_or_else(|e| e.into_inner());
        f(&mut g)
    }
    fn block(&self, b: usize) {
        self.with(|m| {
            m.count += 1;
            m.blocks.insert(b);
        })
    }
    fn chunk(&self, lo: Option<&Dot>) {
        self.with(|m| {
            m.count += 1;
            m.chunks.insert(lo.cloned());
        })
    }
    /// Notes a look at every record.
    pub(crate) fn all(&self) {
        self.with(|m| {
            m.count += 1;
            m.all = true;
        })
    }
    /// Notes a whole pass over the records held: void; a look at every record unless blocks,
    /// chunks or records were missed (loading those may let the next run follow instead).
    pub(crate) fn whole_pass(&self) {
        self.with(|m| {
            m.count += 1;
            if m.blocks.is_empty() && m.chunks.is_empty() && m.recs.is_empty() {
                m.all = true;
                m.whole = true;
            }
        })
    }
    pub(crate) fn count(&self) -> usize {
        self.with(|m| m.count)
    }
    /// Whether the records of `a..=b` are loaded; else notes a miss.
    pub(crate) fn covers(&self, a: &Dot, b: &Dot) -> bool {
        self.with(|m| {
            let i = m.cover.partition_point(|(lo, _)| lo.as_ref().is_none_or(|lo| lo <= a));
            let ok = i.checked_sub(1).and_then(|i| m.cover.get(i)).is_some_and(|(_, hi)| hi.as_ref().is_none_or(|hi| b < hi));
            if !ok {
                m.count += 1;
                m.recs.push((a.clone(), b.clone()));
            }
            ok
        })
    }
    /// Sets the dot ranges whose records are loaded (`[lo, hi)`, `None` unbounded).
    pub(crate) fn set_cover(&self, mut ranges: Vec<(Option<Dot>, Option<Dot>)>) {
        // an unbounded `lo` (`None`) first
        ranges.sort_by(|a, b| a.0.cmp(&b.0));
        let mut out: Vec<(Option<Dot>, Option<Dot>)> = Vec::with_capacity(ranges.len());
        for (lo, hi) in ranges {
            if let Some(l) = out.last_mut() {
                // overlapping or touching the last range (sorted: only the first `lo` is `None`)
                let touches = match (&l.1, &lo) {
                    (Some(h), Some(lo)) => lo <= h,
                    _ => true,
                };
                if touches {
                    l.1 = match (l.1.take(), hi) {
                        (Some(h), Some(x)) => Some(if x > h { x } else { h }),
                        _ => None,
                    };
                    continue;
                }
            }
            out.push((lo, hi));
        }
        self.with(|m| m.cover = out);
    }
    /// What was missed since the last call (cleared; the cover stays).
    pub(crate) fn take(&self) -> Missed {
        self.with(|m| {
            let keep = Missed { count: m.count, cover: std::mem::take(&mut m.cover), ..Missed::default() };
            std::mem::replace(m, keep)
        })
    }
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
    /// Rows held elsewhere (a node's store, `Partial`): how many; `rows` is empty until loaded.
    stub: Option<usize>,
}

impl Block {
    fn new(rows: Vec<Row>) -> Block {
        let mut b = Block { rows, shown: 0, min: 0, stub: None };
        b.recount();
        b
    }
    fn recount(&mut self) {
        if self.stub.is_some() {
            return;
        }
        self.shown = self.rows.iter().filter(|r| r.shown).count();
        self.min = self.rows.iter().map(|r| r.depth).min().unwrap_or(i64::MAX);
    }
    /// Rows in the block, loaded or not.
    fn n(&self) -> usize {
        self.stub.unwrap_or(self.rows.len())
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
    /// Set when blocks may be stubs (held in a node's store).
    part: Option<Arc<Partial>>,
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
        Placement { shift: vec![0; blocks.len()], blocks, free: Vec::new(), order, len, shown, cap, part: None }
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

    /// Block `b`'s rows; none (a miss noted) for a stub.
    fn block(&self, b: usize) -> &[Row] {
        if !self.held(b) {
            return &[];
        }
        self.blocks.get(b).map_or(&[], |x| &x.rows)
    }

    /// Rows in block `b`, loaded or not.
    fn n_of(&self, b: usize) -> usize {
        self.blocks.get(b).map_or(0, |x| x.n())
    }

    /// Whether block `b`'s rows are loaded; else notes a miss.
    fn held(&self, b: usize) -> bool {
        match self.blocks.get(b) {
            Some(x) if x.stub.is_some() => {
                if let Some(p) = &self.part {
                    p.block(b);
                }
                false
            }
            _ => true,
        }
    }

    fn shift_of(&self, b: usize) -> i64 {
        self.shift.get(b).copied().unwrap_or(0)
    }

    /// Placed nodes.
    pub(crate) fn len(&self) -> usize {
        self.len
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
            let n = self.n_of(*b);
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
            return (*b, self.n_of(*b));
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
                if !self.held(*b) {
                    return None;
                }
                return x.rows.iter().filter(|r| r.shown).nth(k);
            }
            k -= x.shown;
        }
        None
    }

    /// Visible nodes `r` (by visible index) in order: whole blocks before them skipped by count.
    pub(crate) fn vis_range(&self, r: Range<usize>) -> Vec<&Row> {
        let (mut skip, mut out, mut missing) = (r.start, Vec::with_capacity(r.len().min(self.shown)), 0);
        for b in &self.order {
            let Some(x) = self.blocks.get(*b) else { continue };
            if out.len() + missing >= r.len() {
                break;
            }
            if skip >= x.shown {
                skip -= x.shown;
                continue;
            }
            let want = (x.shown - skip).min(r.len() - out.len() - missing);
            if self.held(*b) {
                out.extend(x.rows.iter().filter(|r| r.shown).skip(skip).take(want));
            } else {
                missing += want;
            }
            skip = 0;
        }
        out
    }

    /// Visible nodes in order.
    pub(crate) fn vis(&self) -> impl Iterator<Item = &Row> + '_ {
        self.order.iter().filter(|b| self.blocks.get(**b).is_some_and(|x| x.shown > 0) && self.held(**b)).filter_map(|b| self.blocks.get(*b)).flat_map(|x| x.rows.iter().filter(|r| r.shown))
    }

    /// Visible nodes before position `i`.
    pub(crate) fn rank(&self, i: usize) -> usize {
        let (k, o) = self.locate(i).unwrap_or((self.order.len(), 0));
        let before: usize = self.order.get(..k).unwrap_or_default().iter().filter_map(|b| self.blocks.get(*b)).map(|x| x.shown).sum();
        let here = match self.order.get(k) {
            Some(b) if o > 0 => self.block(*b).iter().take(o).filter(|r| r.shown).count(),
            _ => 0,
        };
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
        let here = match self.order.get(k) {
            Some(b) if o > 0 => self.block(*b).get(..o).unwrap_or_default(),
            _ => &[],
        };
        here.iter().rev().find(|r| r.shown).or_else(|| {
            let before = self.order.get(..k).unwrap_or_default();
            let b = before.iter().rev().find(|b| self.blocks.get(**b).is_some_and(|x| x.shown > 0))?;
            self.block(*b).iter().rev().find(|r| r.shown)
        })
    }

    /// Position of the first row of block `b`.
    fn base(&self, b: usize) -> usize {
        self.order.iter().take_while(|x| **x != b).map(|x| self.n_of(*x)).sum()
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
            && c.o >= self.n_of(*b)
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
                // a stub's rows are needed: give up (the miss is noted)
                if !self.held(*b) {
                    return Cursor { k: self.order.len(), o: 0, at: self.len };
                }
                let from = if j == c.k { c.o + 1 } else { 0 };
                let found = x.rows.iter().skip(from).position(|r| r.depth + s <= d);
                *work += found.map_or(x.rows.len().saturating_sub(from), |q| q + 1);
                if let Some(q) = found {
                    return self.norm(Cursor { k: j, o: from + q, at: at + from + q });
                }
            }
            at += x.n();
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
        if !self.held(b) {
            return k;
        }
        let Some(x) = self.blocks.get_mut(b).map(Arc::make_mut) else { return self.order.len() };
        let tail = x.rows.split_off(o.min(x.rows.len()));
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
        // a stub stays as it is (block bounds do not change the order)
        let stub = |x: usize| self.blocks.get(x).is_some_and(|x| x.stub.is_some());
        if stub(a) || stub(b) || self.n_of(a) + self.n_of(b) > self.cap {
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
            let n = self.n_of(b);
            let (lo, hi) = (x.start.max(at), x.end.min(at + n));
            if lo == at && hi == at + n {
                if let Some(s) = self.shift.get_mut(b) {
                    *s += dd;
                }
            } else if lo < hi
                && self.held(b)
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
            if !self.held(b) {
                break;
            }
            let s = self.shift_of(b);
            let want = x.len() - out.len();
            let Some(blk) = self.blocks.get_mut(b).map(Arc::make_mut) else { break };
            let o = o.min(blk.rows.len());
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
            let x = self.blocks.get(*b).map_or((0, 0), |x| (x.n(), x.shown));
            self.len = self.len.saturating_sub(x.0);
            self.shown = self.shown.saturating_sub(x.1);
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
            let x = self.blocks.get(*b).map_or((0, 0), |x| (x.n(), x.shown));
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
        if !self.held(b) {
            return;
        }
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
/// it: a copy clones only the chunks it writes. A chunk's first dot (none for the first chunk)
/// never changes: an entry goes to the last chunk starting at or before it.
#[derive(Clone, Debug, Default)]
struct DotMap {
    chunks: Vec<MapChunk>,
    len: usize,
    /// Set when chunks may be stubs (held in a node's store).
    part: Option<Arc<Partial>>,
}

#[derive(Clone, Debug)]
struct MapChunk {
    /// The first entry's dot when the chunk was made (`None`: the first chunk).
    lo: Option<Dot>,
    /// The entries; `None` for a stub (held elsewhere, `Partial`).
    e: Option<Arc<Vec<(Dot, usize)>>>,
}

impl DotMap {
    fn sorted(v: Vec<(Dot, usize)>) -> DotMap {
        let len = v.len();
        let size = DotMap::size(len);
        let mut chunks = Vec::with_capacity(len / size + 1);
        let mut it = v.into_iter().peekable();
        while it.peek().is_some() {
            let c: Vec<(Dot, usize)> = it.by_ref().take(size).collect();
            let lo = if chunks.is_empty() { None } else { c.first().map(|x| x.0.clone()) };
            chunks.push(MapChunk { lo, e: Some(Arc::new(c)) });
        }
        // the first chunk is there even when empty: a placement loaded from its top has it
        if chunks.is_empty() {
            chunks.push(MapChunk { lo: None, e: Some(Arc::default()) });
        }
        DotMap { chunks, len, part: None }
    }
    fn size(len: usize) -> usize {
        len.isqrt().max(64)
    }
    /// The chunk holding `d` or where it would go.
    fn chunk(&self, d: &Dot) -> usize {
        self.chunks.partition_point(|c| c.lo.as_ref().is_none_or(|x| x <= d)).saturating_sub(1)
    }
    /// Chunk `k`'s entries; `None` (a miss noted) for a stub.
    fn held(&self, k: usize) -> Option<&Arc<Vec<(Dot, usize)>>> {
        let c = self.chunks.get(k)?;
        if c.e.is_none()
            && let Some(p) = &self.part
        {
            p.chunk(c.lo.as_ref());
        }
        c.e.as_ref()
    }
    /// The entry at or before `d`.
    fn at_or_before(&self, d: &Dot) -> Option<(&Dot, usize)> {
        let c = self.held(self.chunk(d))?;
        let i = c.partition_point(|x| x.0 <= *d).checked_sub(1)?;
        c.get(i).map(|x| (&x.0, x.1))
    }
    fn get(&self, d: &Dot) -> Option<usize> {
        self.at_or_before(d).filter(|x| x.0 == d).map(|x| x.1)
    }
    fn set(&mut self, d: Dot, b: usize) {
        if self.chunks.is_empty() {
            self.chunks.push(MapChunk { lo: None, e: Some(Arc::default()) });
        }
        let k = self.chunk(&d);
        if self.held(k).is_none() {
            return;
        }
        let Some(c) = self.chunks.get_mut(k).and_then(|c| c.e.as_mut()).map(Arc::make_mut) else { return };
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
                    let lo = tail.first().map(|x| x.0.clone());
                    self.chunks.insert(k + 1, MapChunk { lo, e: Some(Arc::new(tail)) });
                }
            }
        }
    }
    #[cfg(any(test, fuzzing))]
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
    /// Which whole pass or load this placement descends from (`Lin::build`, `Lin::from_top`):
    /// copies and follows keep it.
    origin: u64,
    /// Set while blocks or chunks may be stubs; shared with `p` and `at`.
    part: Option<Arc<Partial>>,
    /// At or above every position write's stamp (`None`: unknown): a run or move stamped above
    /// it and above the rest of its delta places right after its anchor without looking at the
    /// anchor's children's records (`slot`; a node's own commits, §2.2, §8).
    newest: Option<Stamp>,
}

/// The next `Lin::origin`.
static ORIGIN: AtomicU64 = AtomicU64::new(1);

fn next_origin() -> u64 {
    ORIGIN.fetch_add(1, Ordering::Relaxed)
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
    Held { span: u64, pos: Vec<PosW>, created: bool },
    /// A row starts at this element: a record split there (whether or not the record changed
    /// anything).
    Cut,
}

/// The element after `x` when both are inside record `(k, r)`: where a node splits once
/// something anchors at `x`.
fn inside(k: &Dot, span: u64, x: &Dot) -> Option<Dot> {
    (x.ctr - k.ctr + 1 < span).then(|| nth(x, 1))
}

/// A row's first element, whether it is visible and its visible char (`flip`).
type Flag = (Dot, bool, Option<char>);

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
        let newest = elems.values().flat_map(|e| e.pos.iter().map(|x| &x.0)).max().cloned();
        Lin { p, waiting: placed.waiting, cyc, at, origin: next_origin(), part: None, newest }
    }

    // ---- the stored form (`SeqPlace`): blocks by arena id, dot-map chunks by first dot

    /// Everything but the rows and the dot map's entries.
    pub(crate) fn top(&self) -> PlaceTop {
        let p = &self.p;
        let mut waiting: Vec<Dot> = self.waiting.iter().cloned().collect();
        waiting.sort();
        let mut cyc: Vec<Dot> = self.cyc.iter().cloned().collect();
        cyc.sort();
        let blocks = p.order.iter().filter_map(|b| p.blocks.get(*b).map(|x| PlaceBlock { id: *b, len: x.n(), shown: x.shown, min: x.min, shift: p.shift_of(*b) })).collect();
        let chunks = self.at.chunks.iter().skip(1).filter_map(|c| c.lo.clone()).collect();
        PlaceTop { cap: p.cap, map_len: self.at.len, waiting, cyc, blocks, chunks, newest: self.newest.clone() }
    }

    /// Block `id`'s rows (depths unshifted); `None` for a stub or no such block.
    pub(crate) fn rows_of(&self, id: usize) -> Option<Vec<PlaceRow>> {
        let x = self.p.blocks.get(id).filter(|x| x.stub.is_none() && self.p.order.contains(&id))?;
        Some(x.rows.iter().map(|r| PlaceRow { dot: r.dot.clone(), span: r.span, created: r.created, parent: r.parent.clone(), head: r.head, shown: r.shown, depth: r.depth }).collect())
    }

    /// The entries of the dot-map chunk starting at `lo` (`None`: the first); `None` for a stub.
    pub(crate) fn chunk_of(&self, lo: Option<&Dot>) -> Option<Vec<(Dot, usize)>> {
        let c = self.at.chunks.iter().find(|c| c.lo.as_ref() == lo)?;
        Some(c.e.as_ref()?.to_vec())
    }

    /// A placement whose blocks and chunks are all stubs, from its top; `None` if inconsistent.
    pub(crate) fn from_top(t: &PlaceTop) -> Option<Lin> {
        let n = t.blocks.len();
        // arena ids stay below the blocks a placement held at once
        let arena = t.blocks.iter().map(|b| b.id).max().map_or(0, |m| m + 1);
        if arena > 4 * n + 64 || t.blocks.iter().any(|b| b.shown > b.len) || t.chunks.windows(2).any(|w| matches!(w, [a, b] if a >= b)) || t.cap == 0 {
            return None;
        }
        let part = Arc::new(Partial::default());
        let mut blocks: Vec<Arc<Block>> = (0..arena).map(|_| Arc::new(Block::default())).collect();
        let mut shift = vec![0i64; arena];
        let mut used = vec![false; arena];
        for b in &t.blocks {
            if std::mem::replace(used.get_mut(b.id)?, true) {
                return None;
            }
            *blocks.get_mut(b.id)? = Arc::new(Block { rows: Vec::new(), shown: b.shown, min: b.min, stub: Some(b.len) });
            *shift.get_mut(b.id)? = b.shift;
        }
        let free = (0..arena).filter(|i| !used.get(*i).copied().unwrap_or(true)).collect();
        let order: Vec<usize> = t.blocks.iter().map(|b| b.id).collect();
        let len = t.blocks.iter().map(|b| b.len).fold(0usize, usize::saturating_add);
        let shown = t.blocks.iter().map(|b| b.shown).sum();
        let p = Placement { blocks, shift, free, order, len, shown, cap: t.cap.min(BLOCK), part: Some(part.clone()) };
        let chunks = std::iter::once(None).chain(t.chunks.iter().cloned().map(Some)).map(|lo| MapChunk { lo, e: None }).collect();
        let at = DotMap { chunks, len: t.map_len, part: Some(part.clone()) };
        Some(Lin { p, waiting: t.waiting.iter().cloned().collect(), cyc: t.cyc.iter().cloned().collect(), at, origin: next_origin(), part: Some(part), newest: t.newest.clone() })
    }

    /// Loads the rows of stub block `id`; `false` if they do not fit its counts.
    pub(crate) fn fill(&mut self, id: usize, rows: Vec<PlaceRow>) -> bool {
        let Some(x) = self.p.blocks.get(id).filter(|x| x.stub.is_some()) else { return false };
        let rows: Vec<Row> = rows.into_iter().map(|r| Row { dot: r.dot, span: r.span.max(1), created: r.created, parent: r.parent, head: r.head, shown: r.shown, ch: None, depth: r.depth }).collect();
        let b = Block::new(rows);
        if Some(b.rows.len()) != x.stub || b.shown != x.shown || b.min != x.min {
            return false;
        }
        if let Some(x) = self.p.blocks.get_mut(id) {
            *x = Arc::new(b);
        }
        true
    }

    /// Loads the entries of the stub chunk starting at `lo`; `false` if they do not fit its
    /// bounds or name no block.
    pub(crate) fn fill_chunk(&mut self, lo: Option<&Dot>, e: Vec<(Dot, usize)>) -> bool {
        let Some(k) = self.at.chunks.iter().position(|c| c.lo.as_ref() == lo && c.e.is_none()) else { return false };
        let hi = self.at.chunks.get(k + 1).and_then(|c| c.lo.clone());
        let fits = e.windows(2).all(|w| matches!(w, [a, b] if a.0 < b.0))
            && e.first().is_none_or(|x| lo.is_none_or(|lo| *lo <= x.0))
            && e.last().is_none_or(|x| hi.as_ref().is_none_or(|hi| x.0 < *hi))
            && e.iter().all(|x| x.1 < self.p.blocks.len());
        if !fits {
            return false;
        }
        if let Some(c) = self.at.chunks.get_mut(k) {
            c.e = Some(Arc::new(e));
        }
        true
    }

    /// The stub blocks (by id) and chunks (by first dot).
    pub(crate) fn stubs(&self) -> (Vec<usize>, Vec<Option<Dot>>) {
        let b = self.p.order.iter().copied().filter(|b| self.p.blocks.get(*b).is_some_and(|x| x.stub.is_some())).collect();
        let c = self.at.chunks.iter().filter(|c| c.e.is_none()).map(|c| c.lo.clone()).collect();
        (b, c)
    }

    /// Whether every block and chunk is loaded; then no longer partial.
    pub(crate) fn complete(&mut self) -> bool {
        let (b, c) = self.stubs();
        if !b.is_empty() || !c.is_empty() {
            return false;
        }
        self.part = None;
        self.p.part = None;
        self.at.part = None;
        true
    }

    /// The handle a partial placement notes its misses in.
    pub(crate) fn partial(&self) -> Option<&Arc<Partial>> {
        self.part.as_ref()
    }

    /// Sets the visible chars of a text's loaded rows from its records (the stored form keeps
    /// none).
    pub(crate) fn fill_chars(&mut self, elems: &Elems) {
        let want = |r: &Row| if r.shown { elems.get(&r.dot).and_then(SeqElem::char) } else { None };
        for b in self.p.order.clone() {
            if !self.p.blocks.get(b).is_some_and(|x| x.stub.is_none() && x.rows.iter().any(|r| r.ch != want(r))) {
                continue;
            }
            if let Some(x) = self.p.blocks.get_mut(b).map(Arc::make_mut) {
                for r in &mut x.rows {
                    r.ch = want(r);
                }
            }
        }
    }

    /// What changed from `old` (which this placement descends from: `None` if not): the loaded
    /// blocks to write, the blocks gone, the loaded chunks to write and whether the chunk list
    /// changed.
    pub(crate) fn diff(&self, old: &Lin) -> Option<PlaceDiff> {
        if self.origin != old.origin {
            return None;
        }
        let (p, q) = (&self.p, &old.p);
        let kept: HashSet<usize> = p.order.iter().copied().collect();
        let had: HashSet<usize> = q.order.iter().copied().collect();
        let blocks = p.order.iter().copied().filter(|b| p.blocks.get(*b).is_some_and(|x| x.stub.is_none()) && !(had.contains(b) && matches!((p.blocks.get(*b), q.blocks.get(*b)), (Some(x), Some(y)) if Arc::ptr_eq(x, y)))).collect();
        let gone = q.order.iter().copied().filter(|b| !kept.contains(b)).collect();
        let olds: HashMap<Option<&Dot>, &MapChunk> = old.at.chunks.iter().map(|c| (c.lo.as_ref(), c)).collect();
        let chunks = self
            .at
            .chunks
            .iter()
            .filter(|c| c.e.as_ref().is_some_and(|e| !olds.get(&c.lo.as_ref()).and_then(|o| o.e.as_ref()).is_some_and(|o| Arc::ptr_eq(e, o))))
            .map(|c| c.lo.clone())
            .collect();
        let dir = self.at.chunks.len() != old.at.chunks.len() || self.at.chunks.iter().zip(&old.at.chunks).any(|(a, b)| a.lo != b.lo);
        Some(PlaceDiff { blocks, gone, chunks, dir })
    }

    /// Whether `o` is the same placement (rows, depths, waiting anchors and broken cycles;
    /// chars aside), both loaded whole.
    #[cfg(any(test, fuzzing))]
    pub(crate) fn same(&self, o: &Lin) -> bool {
        let key = |(r, d): (&Row, i64)| (r.dot.clone(), r.span, r.created, r.parent.clone(), r.head, r.shown, d);
        self.p.len == o.p.len && self.p.shown == o.p.shown && self.p.iter_depth().map(key).eq(o.p.iter_depth().map(key)) && self.waiting == o.waiting && self.cyc == o.cyc
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
    #[cfg(any(test, fuzzing))]
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
        let same = |c: &MapChunk, x: &MapChunk| matches!((&c.e, &x.e), (Some(c), Some(x)) if Arc::ptr_eq(c, x));
        (a.chunks.iter().filter(|c| !b.chunks.iter().any(|x| same(c, x))).count(), a.chunks.len())
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
        // the state's record straddling its start, then those starting inside it: (record,
        // offset of the piece in it, length)
        let head = elems.find(dot).filter(|(k, _)| *k != dot).map(|(k, r)| {
            let off = dot.ctr - k.ctr;
            ((k, r), off, (r.span - off).min(de.span))
        });
        if head.is_some() {
            out.push((dot.clone(), Plan::Cut));
        }
        // a `Derived(S, c)` record between two `S` records is not part of it
        let inner = rs.into_iter().filter(|(k, _)| k.src == dot.src).map(|(k, r)| ((k, r), 0, r.span.min(last.ctr - k.ctr + 1)));
        // a delta piece with creation or position writes must not change the state piece's
        // creation, nor add position writes to a range
        let writes = de.created.is_some() || !de.pos.is_empty();
        let mut next = dot.ctr;
        for ((k, r), off, len) in head.into_iter().chain(inner) {
            if k.ctr + off != next {
                return false;
            }
            next = k.ctr.saturating_add(off).saturating_add(len);
            let (pd, pe) = if off == 0 { (k.clone(), Cow::Borrowed(r)) } else { let (d, e) = piece(k, r, off, len); (d, Cow::Owned(e)) };
            if writes {
                let (_, dp) = piece(dot, de, pd.ctr - dot.ctr, len);
                if dp.created.as_ref().is_some_and(|c| pe.created.as_ref() != Some(c)) || len != 1 && !dp.pos.iter().all(|p| pe.pos.iter().any(|q| q.0 == p.0)) {
                    return false;
                }
            }
            out.push((pd, Plan::Held { span: len, pos: pe.pos.clone(), created: pe.created.is_some() }));
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
                if stamp.dot != *dot || de.pos.len() != 1 || de.pos.first().is_none_or(|p| !is_creation(p, &(stamp.clone(), anchor.clone()))) || anchor == Anchor::Dot(dot.clone()) {
                    return None;
                }
                let (known, cut) = match &anchor {
                    Anchor::Head => (true, None),
                    // a placed anchor needs no record lookup (held in part: no page of its
                    // records); one not placed (an element of this delta, or none yet) does
                    Anchor::Dot(x) => match self.placed(x)? {
                        Some(cut) => (true, cut),
                        None => match elems.find(x) {
                            Some((k, r)) => (true, inside(k, r.span, x)),
                            // a virtual anchor on `END` (§6.1): it would split nodes of its source
                            None if x.src.is_derived() => return None,
                            None => (false, None),
                        },
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
    /// A placement held in part fails where it misses rows, chunks or records (`Partial`).
    pub(crate) fn follow(&mut self, elems: &dyn Recs, text: bool, plans: Vec<(Dot, Plan)>) -> bool {
        let mut work = 0;
        let before = self.part.as_ref().map(|p| p.count());
        let ok = self.follow_in(elems, text, plans, &mut work);
        if let Some(p) = &self.part {
            p.with(|m| m.work += work);
        }
        #[cfg(test)]
        PROBE.with(|p| p.set((p.get().0 + work, p.get().1)));
        ok && self.part.as_ref().map(|p| p.count()) == before
    }

    /// `follow`, charging the rows and blocks it looks at to `work`.
    fn follow_in(&mut self, elems: &dyn Recs, text: bool, plans: Vec<(Dot, Plan)>, work: &mut usize) -> bool {
        // runs of new elements by the existing node (`None`: HEAD) they follow, with the first
        // element's edge stamp
        let mut runs: Vec<(Option<Dot>, Stamp, Vec<Dot>)> = Vec::new();
        // the run holding each new element; `None`: hidden
        let mut new: HashMap<Dot, Option<usize>> = HashMap::new();
        // single elements whose visibility may change, with it
        let mut flags: Vec<Flag> = Vec::new();
        // elements whose chosen edge changed: (edge stamp, element, anchor, sibling key)
        let mut moves: Vec<(Stamp, Dot, Anchor, Stamp)> = Vec::new();
        // the sibling key each of those sits by until re-placed
        let mut sibs = Sibs { elems, sits: HashMap::new() };
        // elements a row must start at
        let mut cuts: Vec<Dot> = Vec::new();
        // the newest position write before this delta (`newest` takes the delta's too)
        let before = self.newest.clone();
        if before.is_some() {
            for (dot, plan) in &plans {
                if let (Plan::New { .. } | Plan::Held { .. }, Some(r)) = (plan, elems.get(dot)) {
                    self.newest = r.pos.iter().map(|x| &x.0).chain(self.newest.as_ref()).max().cloned();
                }
            }
        }
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
                    let c = (stamp.clone(), anchor.clone());
                    if r.span != 1 || r.created.as_ref() != Some(&c) || r.pos.len() != 1 || r.pos.first().is_none_or(|p| !is_creation(p, &c)) || self.waiting.contains(&dot) {
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
                            Some(Some(m)) => {
                                sibs.sits.extend(pos.first().map(|o| (dot.clone(), sib_key(o).clone())));
                                moves.push(m);
                            }
                            Some(None) => {}
                            None => return false,
                        }
                    }
                    // a range record has no content: never visible
                    if span == 1 {
                        let (shown, ch) = shows(r, text);
                        flags.push((dot, shown, ch));
                    }
                }
            }
        }
        // a bounded number of placements, each O(√n) plus the sibling subtrees it skips: past
        // about a whole pass's worth of rows and blocks looked at a rebuild is cheaper
        if runs.len() + moves.len() + cuts.len() > self.p.len.isqrt().max(64) {
            return false;
        }
        // the newest sibling key placed here, when above every edge before: that run or move goes
        // first among its anchor's children without looking at theirs (the rest of a run is its
        // chain; sibling keys are below their stamps, so `before` bounds them)
        let edges = || runs.iter().map(|r| &r.1).chain(moves.iter().map(|m| &m.3));
        let fresh = edges().max().filter(|f| before.as_ref().is_some_and(|b| *f > b) && edges().filter(|e| e == f).count() == 1).cloned();
        let each = self.p.order.len() + self.p.cap;
        for x in cuts {
            *work += each;
            if !self.cut_row(&x, work) || *work > self.p.len.max(1024) {
                return false;
            }
        }
        for (key, stamp, run) in runs {
            *work += each;
            let Some(slot) = self.slot(&sibs, &key, &stamp, fresh.as_ref(), usize::MAX..usize::MAX, work) else { return false };
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
        for (_, dot, anchor, key) in moves {
            *work += each;
            // onto a new element: its run's next element (a newer stamp) may be a sibling
            let fresh = fresh.as_ref().filter(|_| !matches!(&anchor, Anchor::Dot(x) if new.contains_key(x)));
            if !self.place_moved(&sibs, &dot, key, anchor, fresh, work) {
                return false;
            }
            sibs.sits.remove(&dot);
        }
        self.flip(flags);
        true
    }

    /// Sets the visibility and char of the rows starting at `flags` (hidden ones skipped), one
    /// walk of each block they touch.
    fn flip(&mut self, flags: Vec<Flag>) {
        let mut by: Vec<(usize, Flag)> = flags.into_iter().filter_map(|f| Some((self.at.get(&f.0)?, f))).collect();
        by.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.0.cmp(&b.1.0)));
        for group in by.chunk_by(|a, b| a.0 == b.0) {
            if group.first().is_some_and(|g| !self.p.held(g.0)) {
                continue;
            }
            let Some(x) = group.first().and_then(|g| self.p.blocks.get_mut(g.0)).map(Arc::make_mut) else { continue };
            for row in &mut x.rows {
                let Ok(i) = group.binary_search_by(|g| g.1.0.cmp(&row.dot)) else { continue };
                let Some((_, (_, now, ch))) = group.get(i) else { continue };
                let now = *now;
                row.ch = *ch;
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
        }
    }

    /// The edge change of single element `dot` whose position writes went from `old` to `now`:
    /// `Some(None)` if its chosen edge stays; `None`: rebuild. A write gained naming an element
    /// inside a range record cuts a row after it (`cuts`); rebuilds if a write gained or lost
    /// names an unknown element (an absent `Derived` one: a virtual anchor), a write lost names
    /// an element inside a range record (its node may join the next again), the element is on a
    /// broken cycle (§6.2: its demotion may change).
    fn moved(&self, elems: &dyn Recs, dot: &Dot, old: &[PosW], now: &[PosW], cuts: &mut Vec<Dot>) -> Option<Option<(Stamp, Dot, Anchor, Stamp)>> {
        if self.cyc.contains(dot) {
            return None;
        }
        let gained = now.iter().filter(|p| !old.contains(p)).map(|p| (true, p));
        let lost = old.iter().filter(|p| !now.contains(p)).map(|p| (false, p));
        for (gain, (_, a, _)) in gained.chain(lost) {
            let Anchor::Dot(x) = a else { continue };
            let (k, r) = elems.find(x)?;
            match inside(k, r.span, x) {
                Some(c) if gain => cuts.push(c),
                Some(_) => return None,
                None => {}
            }
        }
        let p = now.first()?;
        // (a copy of the edge with another anchor or key moves it too, §4.1 copy order)
        Some((old.first() != now.first()).then(|| (p.0.clone(), dot.clone(), p.1.clone(), sib_key(p).clone())))
    }

    /// Whether element `x` is placed: `Some(Some(cut))`, with the element after it when both
    /// are in its row (where the row splits once something anchors at `x`), `Some(None)` if
    /// not placed; `None` if a row or chunk looked at is not loaded (a miss noted).
    fn placed(&self, x: &Dot) -> Option<Option<Option<Dot>>> {
        let before = self.part.as_ref().map(|p| p.count());
        let Some((b, o)) = self.holder(x) else {
            return (self.part.as_ref().map(|p| p.count()) == before).then_some(None);
        };
        let r = self.p.block(b).get(o)?;
        Some(Some(inside(&r.dot, r.span, x)))
    }

    /// Block and offset of the row holding element `x`.
    fn holder(&self, x: &Dot) -> Option<(usize, usize)> {
        let (k, b) = self.at.at_or_before(x)?;
        let o = self.p.block(b).iter().position(|r| r.dot == *k)?;
        let r = self.p.block(b).get(o)?;
        crate::seq_span::holds(&r.dot, r.span, x).then_some((b, o))
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

    /// Moves the subtree of `dot` below `anchor` with sibling key `stamp`; `false`: rebuild (the
    /// element or the anchor is not placed, or the anchor is in the subtree: a cycle).
    fn place_moved(&mut self, sibs: &Sibs, dot: &Dot, stamp: Stamp, anchor: Anchor, fresh: Option<&Stamp>, work: &mut usize) -> bool {
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
        let (Some(Some(q)), Some(nd)) = (self.slot(sibs, &key, &stamp, fresh, i..e, work), self.depth_below(&key)) else { return false };
        self.p.relocate(i..e, q, nd - d, Some(&mut self.at));
        let Some((b, o)) = self.loc(dot) else { return false };
        let Some(row) = self.p.blocks.get_mut(b).map(Arc::make_mut).and_then(|x| x.rows.get_mut(o)) else { return false };
        row.head = key.is_none();
        row.parent = key;
        true
    }

    /// Where a node whose edge (sibling key `stamp`) names `key` (`None`: HEAD) goes: after the
    /// anchor and its children with greater sibling keys, with their subtrees (§6.1), and
    /// at HEAD before the `END` nodes, as if the rows `skip` (the node's own subtree) were out;
    /// `None`: rebuild. `stamp` equal to `fresh` (above every other edge) goes before the
    /// anchor's first child.
    fn slot(&self, sibs: &Sibs, key: &Option<Dot>, stamp: &Stamp, fresh: Option<&Stamp>, skip: Range<usize>, work: &mut usize) -> Option<Slot> {
        let first = fresh == Some(stamp);
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
            if rd <= d || key.is_none() && !r.head || first {
                return Some(Some(c.at));
            }
            match sibs.key(r, &want)?.cmp(stamp) {
                std::cmp::Ordering::Less => return Some(Some(c.at)),
                // one key on two edges: ties go by dot, rebuild
                std::cmp::Ordering::Equal => return None,
                std::cmp::Ordering::Greater => {}
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

/// The records a follow reads sibling keys from, and the sibling key each node the delta moves
/// sits by until re-placed: its old chosen write's, which the join may have replaced (a copy,
/// §4.1) or put below another write at that anchor (an undo's restoring write, a lower key).
struct Sibs<'a> {
    elems: &'a dyn Recs,
    sits: HashMap<Dot, Stamp>,
}

impl Sibs<'_> {
    /// The sibling key of node `row` towards `want`: that of its greatest position write naming
    /// it (a demoted edge is the `prev` one, §6.2), or its `sits` one.
    fn key(&self, row: &Row, want: &Anchor) -> Option<Stamp> {
        if let Some(k) = self.sits.get(&row.dot) {
            return Some(k.clone());
        }
        let e = self.elems.elem(&row.dot)?;
        e.pos.iter().find(|p| p.1 == *want).map(|p| sib_key(p).clone())
    }
}
