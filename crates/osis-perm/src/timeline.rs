//! The membership timeline (spec/permissions.md §5.1) and its queries: roster, effective role,
//! effective invite and authority class at a point, the applied and dropped edge writes.

use crate::graph::{Class, Edges, Owners, Standing, View};
use crate::held::HeldSet;
use crate::types::{Edge, MembershipCommit, Point, RosterSnapshot, WriteId};
use crate::walk::{self, Applied, Demotion, Input};
use osis_core::{CommitId, Role, Tid, Ts};
use std::borrow::Cow;
use std::collections::BTreeMap;
use std::sync::Arc;

/// When a query is evaluated: the edge state just before `point` (`None`: after every held
/// write) with edges alive at `ts` (`None`: the end of time, where every `until` has passed).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct At {
    pub point: Option<Point>,
    pub ts: Option<Ts>,
}

impl At {
    /// Just before the write at `p`, as its author's authority is judged.
    pub fn before(p: Point) -> At {
        At { point: Some(p), ts: Some(p.ts) }
    }
    /// The current state, edges alive at `ts`.
    pub fn now(ts: Ts) -> At {
        At { point: None, ts: Some(ts) }
    }
    /// The current state at the end of time: only edges without `until` count. Re-grant
    /// (§5.2) is judged here.
    pub const END: At = At { point: None, ts: None };
}

/// Layer 1 evaluated over a held set.
pub struct Timeline {
    pub(crate) owners: Owners,
    pub(crate) commits: BTreeMap<CommitId, Arc<MembershipCommit>>,
    pub(crate) snaps: BTreeMap<CommitId, Arc<RosterSnapshot>>,
    pub(crate) walked: walk::Walked,
    dropped: BTreeMap<WriteId, Point>,
    epoch_starts: BTreeMap<Tid, CommitId>,
    passes: usize,
    converged: bool,
}

impl Timeline {
    /// Evaluates from scratch (D rebuilt, §5.1 step 5).
    pub fn evaluate(held: &dyn HeldSet) -> Timeline {
        let input = Input::gather(held);
        let out = walk::run(&input);
        Timeline {
            owners: input.owners,
            commits: input.commits,
            snaps: input.snaps,
            walked: out.walked,
            dropped: out.dropped,
            epoch_starts: out.epoch_starts,
            passes: out.passes,
            converged: out.converged,
        }
    }
    /// Walks evaluated (1 when nothing was dropped and no epoch start applied).
    pub fn passes(&self) -> usize {
        self.passes
    }
    /// False only if the pass bound was hit (never observed; the result is then the last walk).
    pub fn converged(&self) -> bool {
        self.converged
    }
    pub fn owners(&self) -> &Owners {
        &self.owners
    }
    /// The drop set D, each with the point of the demotion whose audit dropped it.
    pub fn dropped(&self) -> &BTreeMap<WriteId, Point> {
        &self.dropped
    }
    /// Edge writes applied by the timeline, with their attribution.
    pub fn applied(&self) -> &BTreeMap<WriteId, Applied> {
        &self.walked.applied
    }
    pub fn is_applied(&self, w: &WriteId) -> bool {
        self.walked.applied.contains_key(w)
    }
    /// The epoch start of `thing` (§6), if one applies.
    pub fn epoch_start(&self, thing: &Tid) -> Option<CommitId> {
        self.epoch_starts.get(thing).copied()
    }
    pub fn epoch_starts(&self) -> &BTreeMap<Tid, CommitId> {
        &self.epoch_starts
    }
    /// Explicit demotions of `node` on `thing` in timeline order (§5.2 input).
    pub fn demotions(&self, node: &Tid, thing: &Tid) -> &[Demotion] {
        self.walked.demotions.get(&(*node, *thing)).map_or(&[], |v| v.as_slice())
    }
    pub fn membership_commit(&self, id: &CommitId) -> Option<&Arc<MembershipCommit>> {
        self.commits.get(id)
    }
    pub fn roster_snapshot(&self, id: &CommitId) -> Option<&Arc<RosterSnapshot>> {
        self.snaps.get(id)
    }

    /// The edge state just before `point` (`None`: the current state).
    pub fn edges_at(&self, point: Option<Point>) -> Cow<'_, Edges> {
        let Some(p) = point else { return Cow::Borrowed(&self.walked.edges) };
        let mut e = self.walked.initial.clone();
        for c in self.walked.history.iter().take_while(|c| c.point < p) {
            e.set(c.member, c.target, c.edge);
        }
        Cow::Owned(e)
    }

    /// The roster of `thing` (§5.1): its edges alive at `at`.
    pub fn roster(&self, thing: &Tid, at: At) -> BTreeMap<Tid, Edge> {
        let edges = self.edges_at(at.point);
        edges.members(thing).filter(|(_, e)| e.alive_at(at.ts)).map(|(m, e)| (*m, *e)).collect()
    }

    /// Standing (class and effective role) of `node` on `thing`.
    pub fn standing(&self, node: &Tid, thing: &Tid, at: At) -> Standing {
        let edges = self.edges_at(at.point);
        let view = View { owners: &self.owners, edges: &edges, ts: at.ts };
        let best = view.roles_from(node);
        view.standing(node, &best, thing)
    }

    /// Effective role (§1).
    pub fn role(&self, node: &Tid, thing: &Tid, at: At) -> Option<Role> {
        self.standing(node, thing, at).role
    }

    /// Authority class (§5.1 step 3).
    pub fn class(&self, node: &Tid, thing: &Tid, at: At) -> Class {
        self.standing(node, thing, at).class
    }

    /// Effective invite (§2).
    pub fn invite(&self, node: &Tid, thing: &Tid, at: At) -> Option<Role> {
        let edges = self.edges_at(at.point);
        let view = View { owners: &self.owners, edges: &edges, ts: at.ts };
        let best = view.roles_from(node);
        view.invite(&best, thing)
    }

    /// Effective roles of `node` on every thing it reaches.
    pub fn roles_of(&self, node: &Tid, at: At) -> BTreeMap<Tid, Role> {
        let edges = self.edges_at(at.point);
        View { owners: &self.owners, edges: &edges, ts: at.ts }.roles_from(node)
    }
}
