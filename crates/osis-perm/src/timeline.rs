//! The membership timeline (spec/permissions.md §5.1) and its queries: roster, effective role,
//! effective invite and authority class at a point, the applied and dropped edge writes.

use crate::graph::{Class, Edges, Owners, Standing, View};
use crate::held::HeldSet;
use crate::types::{Edge, MembershipCommit, Point, RosterSnapshot, WriteId};
use crate::walk::{self, Applied, Demotion, Input};
use osis_core::{CommitId, Role, Tid, Ts};
use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};

/// History changes between two kept edge states (`edges_at` replays at most this many).
const CHECKPOINT: usize = 256;

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
    /// Inputs `extend` must find unchanged.
    nodes: BTreeSet<Tid>,
    epoch_changed: bool,
    /// The furthest point a walk under the final epoch starts other than the final one reached.
    reach: Option<Point>,
    /// The edge state before history change `i * CHECKPOINT`, for `edges_at`.
    checkpoints: Vec<Edges>,
    /// Answers of layer-2 queries, valid as long as this timeline (the held set of its
    /// component) is.
    pub(crate) memo: Memo,
}

/// `first_held` by (node, thing, role).
type FirstHeld = BTreeMap<(Tid, Tid, Role), Option<Option<Point>>>;
/// `delta_valid` by its arguments.
type Valid = BTreeMap<(Point, Tid, String, crate::types::Dots, Role), crate::content::Validity>;

/// Memoized layer-2 answers.
#[derive(Default)]
pub(crate) struct Memo {
    pub first_held: Mutex<FirstHeld>,
    pub valid: Mutex<Valid>,
    /// `roles_of` at `At::END`, per node.
    pub roles_end: Mutex<BTreeMap<Tid, Arc<BTreeMap<Tid, Role>>>>,
    /// Held records by the edges and things they write, for certificates.
    pub certs: std::sync::OnceLock<crate::cert::CertIndex>,
}

fn checkpoints(w: &walk::Walked) -> Vec<Edges> {
    let mut out = Vec::with_capacity(w.history.len() / CHECKPOINT + 1);
    let mut e = w.initial.clone();
    for (i, c) in w.history.iter().enumerate() {
        if i % CHECKPOINT == 0 {
            out.push(e.clone());
        }
        e.set(c.member, c.target, c.edge);
    }
    out
}

impl Timeline {
    /// Evaluates from scratch (D rebuilt, §5.1 step 5).
    pub fn evaluate(held: &dyn HeldSet) -> Timeline {
        let input = Input::gather(held);
        let out = walk::run(&input);
        Timeline::from_outcome(input, out)
    }

    fn from_outcome(input: Input, out: walk::Outcome) -> Timeline {
        let checkpoints = checkpoints(&out.walked);
        Timeline {
            owners: input.owners,
            commits: input.commits,
            snaps: input.snaps,
            walked: out.walked,
            dropped: out.dropped,
            epoch_starts: out.epoch_starts,
            passes: out.passes,
            converged: out.converged,
            nodes: input.nodes,
            epoch_changed: out.epoch_changed,
            reach: out.reach,
            checkpoints,
            memo: Memo::default(),
        }
    }

    /// This timeline for `held`, which holds the same things, `/created` records and roster
    /// snapshots plus more membership commits: the final walk is rolled back to the earliest
    /// new commit and goes on from there instead of starting over (equal to `evaluate`).
    /// `None` when that does not hold (another walk reached that point, or the inputs differ
    /// otherwise): evaluate. With no new commit the inputs may add only leaves (`/created` of
    /// things nothing held names, `Timelines`): the walk is kept as it is.
    pub fn extend(self, held: &dyn HeldSet) -> Option<Timeline> {
        if !self.converged {
            return None;
        }
        let input = Input::gather(held);
        // a new author or member could have changed how earlier writes were walked; after epoch
        // changes, going on from the old starts finds the same ones only when they have a
        // unique fixed point (walk::drive)
        if !input.snaps.keys().eq(self.snaps.keys()) || input.nodes != self.nodes || (self.epoch_changed && input.cyclic()) {
            return None;
        }
        if !self.commits.keys().all(|k| input.commits.contains_key(k)) {
            return None;
        }
        let Some(from) = input.commits.iter().filter(|(k, _)| !self.commits.contains_key(*k)).map(|(_, c)| c.point()).min() else {
            let Timeline { walked, dropped, epoch_starts, passes, epoch_changed, reach, .. } = self;
            let out = walk::Outcome { walked, dropped, epoch_starts, passes, converged: true, epoch_changed, reach };
            return Some(Timeline::from_outcome(input, out));
        };
        if self.reach.is_some_and(|r| r >= from) {
            return None;
        }
        let Timeline { walked, dropped, epoch_starts, passes, epoch_changed, reach, .. } = self;
        let out = walk::resume(&input, walk::Resume { walked, dropped, epoch_starts, passes, epoch_changed, reach, from });
        Some(Timeline::from_outcome(input, out))
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
        // from the newest kept state before `p`: O(edges + CHECKPOINT), not O(history)
        let n = self.walked.history.partition_point(|c| c.point < p);
        let k = (n / CHECKPOINT).min(self.checkpoints.len().saturating_sub(1));
        let mut e = self.checkpoints.get(k).cloned().unwrap_or_else(|| self.walked.initial.clone());
        for c in self.walked.history.iter().take(n).skip(k * CHECKPOINT) {
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
        let view = View::new(&self.owners, &edges, at.ts);
        let best = view.roles_from(node);
        view.standing(node, &best, thing)
    }

    /// Effective role (§1).
    pub fn role(&self, node: &Tid, thing: &Tid, at: At) -> Option<Role> {
        if at != At::END {
            return self.roles_of(node, at).get(thing).copied();
        }
        if let Some(r) = self.memo.roles_end.lock().ok().and_then(|m| m.get(node).cloned()) {
            return r.get(thing).copied();
        }
        let r = Arc::new(self.roles_of(node, at));
        let out = r.get(thing).copied();
        if let Ok(mut m) = self.memo.roles_end.lock() {
            m.insert(*node, r);
        }
        out
    }

    /// Authority class (§5.1 step 3).
    pub fn class(&self, node: &Tid, thing: &Tid, at: At) -> Class {
        self.standing(node, thing, at).class
    }

    /// Effective invite (§2).
    pub fn invite(&self, node: &Tid, thing: &Tid, at: At) -> Option<Role> {
        let edges = self.edges_at(at.point);
        let view = View::new(&self.owners, &edges, at.ts);
        let best = view.roles_from(node);
        view.invite(&best, thing)
    }

    /// Effective roles of `node` on every thing it reaches.
    pub fn roles_of(&self, node: &Tid, at: At) -> BTreeMap<Tid, Role> {
        let edges = self.edges_at(at.point);
        View::new(&self.owners, &edges, at.ts).roles_from(node)
    }
}
