//! Trust sets and disputes (spec/permissions.md §5.1, Trust; notes/owner-removal-plan.md step
//! 3, notes/owners.md): a node's side in a fight between admins is one more input to the walk.
//! Private to osis-perm and the API layer (the coherence rule of notes/owner-removal-plan.md):
//! nothing else names a side or asks whether a dispute is open.
//!
//! - A **trusted op** R is a held edge write with a frontier by A on another holder M's edge
//!   (`Input::trustable`). Its **seeds** (`Input::seeds`): the writes ordered before R, not
//!   listed in R's frontier, by M or any node that ever reaches M by admin edges (A excepted),
//!   on R's target or anything it ever reaches, but a node's writes lowering its own edge
//!   (`lowers_own`: a self-removal never contests R; a self-grant does). The walk starts with
//!   D at the seeds of the active trusted ops; one the settled walk leaves unapplied is void:
//!   every void op loses its seeds at once and the walk is redone from scratch
//!   (`Timeline::evaluate_with`).
//! - A **dispute** (`Timeline::disputes`): a trustable op R the settled walk did not apply and
//!   no seed dropped, that applies as an explicit write lowering M's edge below its value just
//!   before it (`demoting`) in the walk with R's seeds added to D. Keyed (R, M).
//! - Every answer is a pure function of (held set, trust set): a timeline under a trust set is
//!   only ever evaluated from scratch (`Timeline::extend`, `append` and `add_leaves` decline
//!   it; `Timelines` never saves or restores one).

use crate::graph::{Owners, RECORD_EDGE};
use crate::types::{lowers, Edge, EdgeOp, Point, RoleCommit, WriteId};
use crate::walk::{Input, Walked};
use osis_base::Tid;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

/// The explicit demotions a node sides with (the trust set).
#[derive(Clone, Default, PartialEq, Eq, Debug)]
pub struct Trust {
    pub ops: BTreeSet<WriteId>,
}

impl Trust {
    pub fn is_empty(&self) -> bool {
        self.ops.is_empty()
    }
    /// Whether one of the ops is of commit `id`.
    pub fn names(&self, id: &osis_base::CommitId) -> bool {
        self.ops.range(WriteId(*id, 0)..=WriteId(*id, u32::MAX)).next().is_some()
    }
}

/// An open dispute: `op` (R) lowers `holder`'s edge, is unapplied, and applies once its seeds
/// are in D.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct Dispute {
    pub op: WriteId,
    pub holder: Tid,
}

/// A dispute an update detected (`Timelines::take_detected`), with what a default side reads.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Detected {
    pub dispute: Dispute,
    pub author: Tid,
    pub target: Tid,
    /// R applied in this node's walk before the update (it stood here, then stopped applying),
    /// as against arriving unapplied.
    pub stood: bool,
    /// Whether the node (`Timelines::detect`) holds a role on something the target reaches: on
    /// the walk's side, and with R trusted.
    pub standing: (bool, bool),
}

/// Candidates walked per update by dispute detection (`Timelines::detect`): a resource bound
/// against a hostile author, whose every contestable write costs a walk once, when it arrives
/// or stops applying. Past it candidates wait for the scan (`Timeline::disputes`), reported
/// as unexamined, with no default side. At 0 detection records no default (the walk's side
/// everywhere, as before step 4); at infinity a batch of k hostile writes costs k walks.
pub const DETECT_MAX: usize = 16;

/// A held write on an edge: (point, op, value).
type EdgeWrite = (Point, u32, Option<Edge>);

/// Indexes of the held commits that seeds read, built once per evaluation.
pub(crate) struct TrustIndex {
    by_author: BTreeMap<Tid, Vec<Arc<RoleCommit>>>,
    /// Per edge, its held writes in order.
    by_edge: BTreeMap<(Tid, Tid), Vec<EdgeWrite>>,
}

impl TrustIndex {
    pub(crate) fn new(input: &Input) -> TrustIndex {
        let mut ix = TrustIndex { by_author: BTreeMap::new(), by_edge: BTreeMap::new() };
        for c in input.commits.values() {
            ix.by_author.entry(c.author).or_default().push(c.clone());
            for (k, o) in c.ops.iter().enumerate() {
                let Ok(k) = u32::try_from(k) else { continue };
                ix.by_edge.entry((o.holder, o.target)).or_default().push((c.point(), k, o.edge));
            }
        }
        for v in ix.by_edge.values_mut() {
            v.sort_unstable_by_key(|e| (e.0, e.1));
        }
        ix
    }
}

impl Input {
    /// R as a trusted op, if it may be one: a held op with a frontier on the edge of a holder
    /// other than its author (and its target).
    pub(crate) fn trustable(&self, w: &WriteId) -> Option<(&Arc<RoleCommit>, &EdgeOp)> {
        let c = self.commits.get(&w.0)?;
        let op = c.ops.get(usize::try_from(w.1).ok()?)?;
        (c.frontier.is_some() && op.holder != c.author && op.holder != op.target).then_some((c, op))
    }

    /// The value edge (`holder`, `target`) had before op `k` at `point` as held writes set it:
    /// the last held op on it ordered before, else its record value.
    fn preceding(&self, ix: &TrustIndex, holder: Tid, target: Tid, point: Point, k: u32) -> Option<Edge> {
        let ops = ix.by_edge.get(&(holder, target)).map(Vec::as_slice).unwrap_or_default();
        let i = ops.partition_point(|e| (e.0, e.1) < (point, k));
        match i.checked_sub(1).and_then(|i| ops.get(i)) {
            Some(e) => e.2,
            None => (self.owners.first_admin(&target) == Some(holder)).then_some(RECORD_EDGE),
        }
    }

    /// Whether op `k` of `c` lowers its author's own edge: strictly below (`lowers`, not equal)
    /// the value it had before (`preceding`).
    fn lowers_own(&self, ix: &TrustIndex, c: &RoleCommit, k: u32, op: &EdgeOp) -> bool {
        if op.holder != c.author {
            return false;
        }
        let old = self.preceding(ix, op.holder, op.target, c.point(), k);
        lowers(op.edge.as_ref(), old.as_ref()) && op.edge != old
    }

    /// The seeds of trusted op `w` (module doc), each with R's point as the point of its drop.
    /// Empty when `w` is not trustable.
    pub(crate) fn seeds(&self, ix: &TrustIndex, w: &WriteId) -> BTreeMap<WriteId, Point> {
        let Some((r, op)) = self.trustable(w) else { return BTreeMap::new() };
        let point = r.point();
        let below = self.ever_forward([op.target]);
        let mut out = BTreeMap::new();
        for x in self.victims(op.holder, r.author) {
            for c in ix.by_author.get(&x).into_iter().flatten() {
                if c.id == r.id || c.point() >= point || r.frontier.as_ref().is_some_and(|f| f.covers(&c.id)) {
                    continue;
                }
                for (k, o) in c.ops.iter().enumerate() {
                    let Ok(k) = u32::try_from(k) else { continue };
                    if (below.contains(&o.target) || below.contains(&o.holder)) && !self.lowers_own(ix, c, k, o) {
                        out.insert(WriteId(c.id, k), point);
                    }
                }
            }
        }
        out
    }

    /// Who a demotion of `holder`'s edge by `author` demotes (the static over-approximation,
    /// notes/owners.md Model results): the nodes that ever reach `holder` by admin edges
    /// (record edges included), `holder` itself when a node, `author` excepted.
    fn victims(&self, holder: Tid, author: Tid) -> BTreeSet<Tid> {
        let mut seen: BTreeSet<Tid> = BTreeSet::from([holder]);
        let mut stack = vec![holder];
        while let Some(e) = stack.pop() {
            let next: Vec<Tid> = self.owners.first_admin(&e).into_iter().chain(self.ever.admin_holders.get(&e).into_iter().flatten().copied()).collect();
            for y in next {
                if seen.insert(y) {
                    stack.push(y);
                }
            }
        }
        seen.into_iter().filter(|x| self.nodes.contains(x) && *x != author).collect()
    }
}

/// The seeds of every op in `active`; a write seeded by several keeps the earliest point.
pub(crate) fn seeds_of(input: &Input, ix: &TrustIndex, active: &BTreeSet<WriteId>) -> BTreeMap<WriteId, Point> {
    let mut d0: BTreeMap<WriteId, Point> = BTreeMap::new();
    for r in active {
        for (w, p) in input.seeds(ix, r) {
            d0.entry(w).and_modify(|q| *q = (*q).min(p)).or_insert(p);
        }
    }
    d0
}

/// Whether the walk `w` applied op `k` of `c` as an explicit write lowering the edge below its
/// value just before it (the last history change on that edge before, else its record value).
pub(crate) fn demoting(w: &Walked, owners: &Owners, c: &RoleCommit, k: usize) -> bool {
    let Some(op) = c.ops.get(k) else { return false };
    let point = c.point();
    let i = w.history.iter().position(|h| h.point == point && (h.holder, h.target) == (op.holder, op.target) && h.explicit.is_some());
    let Some(i) = i else { return false };
    let before = w.history.iter().take(i).rev().find(|h| (h.holder, h.target) == (op.holder, op.target));
    let old = match before {
        Some(h) => h.edge,
        None => (owners.first_admin(&op.target) == Some(op.holder)).then_some(RECORD_EDGE),
    };
    lowers(op.edge.as_ref(), old.as_ref()) && op.edge != old
}
