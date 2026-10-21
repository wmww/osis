//! The cached placement of a sequence (spec/crdt.md §6): built by one whole pass
//! (`linearize::place_idx`), then followed through joins that add elements or change flags and
//! content; any other change drops it and the next use rebuilds it.
//!
//! Rows sit in blocks of a few hundred with their visible counts, so finding a row by dot (a map
//! to its block, built on first use), by position or by visible index, and splicing a run in,
//! cost O(√n) instead of a scan and a shift of the whole order.
//!
//! A new element anchored at HEAD or at a single-element record goes right after its anchor,
//! past the anchor's children whose edge stamps beat its own (with their subtrees, found by a
//! bounded scan). It closes no cycle (nothing anchors at it unless a write waits for its dot,
//! which falls back), so no demotion changes. A flag or content write moves nothing; only
//! visibility changes. Everything else (moves, resets, range splits, `Derived` dots, an older
//! insert at HEAD) falls back to a whole pass.

use crate::linearize::{Placed, place_idx};
use crate::seq::{Anchor, SeqContent, SeqElem, is_visible};
use crate::seq_span::{Elems, elem, find, nth};
use crate::stamp::{Dot, Stamp};
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, OnceLock};

/// Rows per block when built: about √n, at most this; a block splits in two above twice its
/// build size.
const BLOCK: usize = 256;
/// Rows scanned past an anchor for the end of its newer children's subtrees; more rebuild.
const SCAN: usize = 4096;

/// One placed node.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Row {
    /// First element. A visible element is a node of its own.
    pub dot: Dot,
    /// Last element (where children anchor).
    pub last: Dot,
    /// Elements in the node.
    pub span: u64,
    /// Whether the node is created (a chain); else its elements are bare anchors or flag-only,
    /// each placed on its own.
    pub created: bool,
    /// Chosen parent node (by first element): `None` for HEAD and `END`.
    pub parent: Option<Dot>,
    /// Whether the node is visible (§5.7 Read).
    pub shown: bool,
    /// A visible text element's char.
    pub ch: Option<char>,
}

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
}

/// The placement of every placed node (deleted, content-less and bare anchors included) in
/// order; hidden ones (unknown anchor, §6.1) are absent. Blocks live in an arena (stable ids,
/// so the dot map survives splits) and `order` lists them in order; there is always one. A copy
/// shares the blocks until it changes one.
#[derive(Clone, Debug)]
pub(crate) struct Placement {
    blocks: Vec<Arc<Block>>,
    order: Vec<usize>,
    len: usize,
    shown: usize,
    /// Rows per block when built.
    cap: usize,
}

impl PartialEq for Placement {
    fn eq(&self, o: &Placement) -> bool {
        self.len == o.len && self.shown == o.shown && self.iter().eq(o.iter())
    }
}
impl Eq for Placement {}

impl Placement {
    fn from_rows(rows: Vec<Row>) -> Placement {
        let (len, shown) = (rows.len(), rows.iter().filter(|r| r.shown).count());
        let cap = len.isqrt().clamp(4, BLOCK);
        let mut blocks: Vec<Arc<Block>> = Vec::with_capacity(len / cap + 1);
        let mut it = rows.into_iter().peekable();
        while it.peek().is_some() || blocks.is_empty() {
            let rows: Vec<Row> = it.by_ref().take(cap).collect();
            let shown = rows.iter().filter(|r| r.shown).count();
            blocks.push(Arc::new(Block { rows, shown }));
        }
        let order = (0..blocks.len()).collect();
        Placement { blocks, order, len, shown, cap }
    }

    /// By dot, from a placement by index.
    pub(crate) fn of(p: &Placed, text: bool) -> Placement {
        let first = |i: usize| p.nodes.get(i).map(|n| n.dot.clone().into_owned());
        let rows = p
            .order
            .iter()
            .filter_map(|i| {
                let n = p.nodes.get(*i)?;
                let (shown, ch) = shows(&n.elem, text);
                Some(Row {
                    dot: n.dot.clone().into_owned(),
                    last: nth(&n.dot, n.elem.span - 1),
                    span: n.elem.span,
                    created: n.elem.created.is_some(),
                    parent: p.parent.get(*i).copied().flatten().filter(|j| *j < p.nodes.len()).and_then(first),
                    shown,
                    ch,
                })
            })
            .collect();
        Placement::from_rows(rows)
    }

    fn block(&self, b: usize) -> &[Row] {
        self.blocks.get(b).map_or(&[], |x| &x.rows)
    }

    /// Visible nodes.
    pub(crate) fn shown(&self) -> usize {
        self.shown
    }

    /// Every node in order.
    pub(crate) fn iter(&self) -> impl Iterator<Item = &Row> + '_ {
        self.order.iter().flat_map(|b| self.block(*b))
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

    /// The rows from offset `o` of block `b` on, with their block and offset.
    fn rows_from(&self, b: usize, o: usize) -> impl Iterator<Item = (usize, usize, &Row)> + '_ {
        let k = self.order.iter().position(|x| *x == b).unwrap_or(self.order.len());
        self.order.get(k..).unwrap_or_default().iter().enumerate().flat_map(move |(j, x)| {
            let from = if j == 0 { o } else { 0 };
            self.block(*x).iter().enumerate().skip(from).map(move |(i, r)| (*x, i, r))
        })
    }

    /// Splices `rows` in before offset `o` of block `b`, splitting it when it grows too big;
    /// `at` (dot to block) follows.
    fn insert(&mut self, b: usize, o: usize, rows: Vec<Row>, at: Option<&mut DotMap>) {
        let n = rows.len();
        let shown = rows.iter().filter(|r| r.shown).count();
        let mut at = at;
        if let Some(m) = at.as_deref_mut() {
            for r in &rows {
                m.set(r.dot.clone(), b);
            }
        }
        let Some(x) = self.blocks.get_mut(b).map(Arc::make_mut) else { return };
        let o = o.min(x.rows.len());
        x.rows.splice(o..o, rows);
        x.shown += shown;
        self.len += n;
        self.shown += shown;
        if x.rows.len() <= 2 * self.cap {
            return;
        }
        let tail = x.rows.split_off(x.rows.len() / 2);
        let moved = tail.iter().filter(|r| r.shown).count();
        x.shown -= moved;
        let id = self.blocks.len();
        if let Some(m) = at {
            for r in &tail {
                m.set(r.dot.clone(), id);
            }
        }
        self.blocks.push(Arc::new(Block { rows: tail, shown: moved }));
        let k = self.order.iter().position(|y| *y == b).map_or(self.order.len(), |k| k + 1);
        self.order.insert(k, id);
    }
}

/// Dot to block, cheap to copy: a shared base plus the entries set since, folded in once they
/// reach a quarter of it.
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
        if self.new.len() > 1024 && self.new.len() * 4 > self.base.len() {
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
    /// The block of each row's first dot, built on first lookup.
    at: OnceLock<DotMap>,
}

impl PartialEq for Lin {
    fn eq(&self, o: &Lin) -> bool {
        self.p == o.p && self.waiting == o.waiting
    }
}
impl Eq for Lin {}

/// How the cache follows one record of a delta, decided against the state before it joins.
pub(crate) enum Plan {
    /// A new element created at `anchor`; whether the anchor's element is held.
    New { stamp: Stamp, anchor: Anchor, known: bool },
    /// Flag or content writes to the record of this span, whose position writes and creation
    /// stay as they were.
    Flags { span: u64, pos: Vec<(Stamp, Anchor)>, created: bool },
}

/// Where a run goes: before offset `.1` of block `.0`; `None` below a hidden node.
type Slot = Option<(usize, usize)>;

impl Lin {
    pub(crate) fn build(elems: &Elems, text: bool) -> Lin {
        let placed = place_idx(elems);
        let p = Placement::of(&placed, text);
        Lin { p, waiting: placed.waiting, at: OnceLock::new() }
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
        let counts = p.order.iter().all(|b| p.blocks.get(*b).is_some_and(|x| x.shown == x.rows.iter().filter(|r| r.shown).count()));
        let map = self.at.get().is_none_or(|m| m.len() == p.len && p.order.iter().all(|b| p.block(*b).iter().all(|r| m.get(&r.dot) == Some(*b))));
        counts && map && p.len == p.iter().count() && p.shown == p.vis().count()
    }

    /// Position of the node starting at `d`.
    pub(crate) fn index(&self, d: &Dot) -> Option<usize> {
        let (b, o) = self.loc(d)?;
        Some(self.p.base(b) + o)
    }

    /// The plan for joining record `(dot, de)` into `elems`; `None`: rebuild.
    pub(crate) fn plan(&self, elems: &Elems, dot: &Dot, de: &SeqElem) -> Option<Plan> {
        match find(elems, dot) {
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
                    Anchor::Dot(x) => match find(elems, x) {
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
                if !de.pos.iter().all(|p| r.pos.iter().any(|q| q.0 == p.0)) {
                    return None;
                }
                Some(Plan::Flags { span: r.span, pos: r.pos.clone(), created: r.created.is_some() })
            }
        }
    }

    /// Follows a joined delta by its records' plans, in dot order; `false`: rebuild. New
    /// elements are spliced in as runs where they place, flag and content writes flip
    /// visibility.
    pub(crate) fn follow(&mut self, elems: &Elems, text: bool, plans: Vec<(Dot, Plan)>) -> bool {
        // runs of new elements by the existing node (`None`: HEAD) they follow, with the first
        // element's edge stamp
        let mut runs: Vec<(Option<Dot>, Stamp, Vec<Dot>)> = Vec::new();
        let mut keys: HashSet<Option<Dot>> = HashSet::new();
        // the run holding each new element; `None`: hidden
        let mut new: HashMap<Dot, Option<usize>> = HashMap::new();
        let mut flags: Vec<Dot> = Vec::new();
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
                            if !keys.insert(key.clone()) {
                                return false;
                            }
                            runs.push((key, stamp, vec![dot.clone()]));
                            Some(runs.len() - 1)
                        }
                    };
                    new.insert(dot, run);
                }
                Plan::Flags { span, pos, created } => {
                    if r.span != span || r.pos != pos || r.created.is_some() != created {
                        return false;
                    }
                    // a range record has no content: never visible
                    if span == 1 {
                        flags.push(dot);
                    }
                }
            }
        }
        for (key, stamp, run) in runs {
            let Some(slot) = self.slot(elems, &key, &stamp) else { return false };
            // below a hidden node: hidden too
            let Some((b, o)) = slot else { continue };
            let mut parent = key;
            let rows: Vec<Row> = run
                .into_iter()
                .map(|d| {
                    let (shown, ch) = elems.get(&d).map_or((false, None), |e| shows(e, text));
                    let row = Row { dot: d.clone(), last: d.clone(), span: 1, created: true, parent: parent.take(), shown, ch };
                    parent = Some(d);
                    row
                })
                .collect();
            self.p.insert(b, o, rows, self.at.get_mut());
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

    /// Where a new run whose first edge (stamp `stamp`) names `key` (`None`: HEAD) goes: after
    /// the anchor and its children with greater edge stamps, with their subtrees (§6.1 sibling
    /// order); `None`: rebuild.
    fn slot(&self, elems: &Elems, key: &Option<Dot>, stamp: &Stamp) -> Option<Slot> {
        let Some(x) = key else {
            // HEAD: first, unless a HEAD child with a greater stamp is there (rebuild)
            let b = *self.p.order.first()?;
            if self.p.block(b).first().and_then(|r| child_stamp(elems, r, &Anchor::Head)).is_some_and(|c| c >= *stamp) {
                return None;
            }
            return Some(Some((b, 0)));
        };
        let Some((b, o)) = self.loc(x) else { return Some(None) };
        let want = Anchor::Dot(x.clone());
        // rows in the anchor's subtree so far (preorder: a parent comes before its children)
        let mut sub: HashSet<&Dot> = HashSet::from([x]);
        let mut end = (b, o + 1);
        for (n, (bb, oo, r)) in self.p.rows_from(b, o + 1).enumerate() {
            if n >= SCAN {
                return None;
            }
            match &r.parent {
                Some(p) if sub.contains(p) => {
                    if p == x && child_stamp(elems, r, &want)? < *stamp {
                        return Some(Some((bb, oo)));
                    }
                    sub.insert(&r.dot);
                }
                _ => return Some(Some((bb, oo))),
            }
            end = (bb, oo + 1);
        }
        Some(Some(end))
    }
}

/// The edge stamp of node `row` towards `want`: its greatest position write naming it (a
/// demoted edge is the `prev` one, §6.2).
fn child_stamp(elems: &Elems, row: &Row, want: &Anchor) -> Option<Stamp> {
    let e = elem(elems, &row.dot)?;
    e.pos.iter().find(|(_, a)| a == want).map(|(s, _)| s.clone())
}
