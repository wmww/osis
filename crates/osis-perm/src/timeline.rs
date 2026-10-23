//! The membership timeline (spec/permissions.md §5.1) and its queries: roster, effective role,
//! effective invite and authority class at a point, the applied and dropped edge writes.

use crate::graph::{Class, Edges, EdgesAt, Owners, Standing, View};
use crate::held::HeldSet;
use crate::types::{Edge, MembershipCommit, Point, RosterSnapshot, WriteId};
use crate::walk::{self, Applied, Demotion, Input};
use osis_core::{CommitId, Role, Tid, Ts};
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
    /// Inputs `extend` must find unchanged.
    nodes: BTreeSet<Tid>,
    pub(crate) epoch_changed: bool,
    /// The furthest point a walk under the final epoch starts other than the final one reached.
    pub(crate) reach: Option<Point>,
    /// The edge state before history change `i * CHECKPOINT`, for `edges_at` (shared with
    /// the timeline `extend` made this from).
    checkpoints: Vec<Arc<Edges>>,
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

/// The kept edge states of `w`'s history, going on from those in `out` (still valid for it).
fn checkpoints(w: &walk::Walked, mut out: Vec<Arc<Edges>>) -> Vec<Arc<Edges>> {
    out.truncate(w.history.len().div_ceil(CHECKPOINT));
    let start = out.len().saturating_sub(1) * CHECKPOINT;
    let mut e = out.last().map_or_else(|| w.initial.clone(), |c| (**c).clone());
    for (i, c) in w.history.iter().enumerate().skip(start) {
        if i % CHECKPOINT == 0 && i / CHECKPOINT == out.len() {
            out.push(Arc::new(e.clone()));
        }
        e.set(c.member, c.target, c.edge);
    }
    out
}

/// What a timeline hands the one `extend` makes from it: what stays true over the history
/// both share (the same initial state and changes up to the first that differs).
pub(crate) struct Kept {
    history: Vec<(Point, Tid, Tid, Option<Edge>)>,
    checkpoints: Vec<Arc<Edges>>,
    first_held: FirstHeld,
}

impl Kept {
    fn of(tl: &mut Timeline) -> Kept {
        let history = tl.walked.history.iter().map(|c| (c.point, c.member, c.target, c.edge)).collect();
        let first_held = std::mem::take(&mut *tl.memo.first_held.lock().unwrap_or_else(|e| e.into_inner()));
        Kept { history, checkpoints: std::mem::take(&mut tl.checkpoints), first_held }
    }

    /// The kept states and `first_held` answers still valid for `w`.
    fn carry(self, w: &walk::Walked) -> (Vec<Arc<Edges>>, FirstHeld) {
        let same = self.checkpoints.first().is_some_and(|e| **e == w.initial);
        let n = if same { self.history.iter().zip(&w.history).take_while(|(a, c)| **a == (c.point, c.member, c.target, c.edge)).count() } else { 0 };
        let mut cps = self.checkpoints;
        cps.truncate(if same { n / CHECKPOINT + 1 } else { 0 });
        // an answer found at a change before the first that differs stands
        let bound = self.history.get(n).map(|h| h.0);
        let mut fh = self.first_held;
        fh.retain(|_, v| same && v.is_some_and(|p| p.is_none_or(|p| bound.is_none_or(|b| p < b))));
        (checkpoints(w, cps), fh)
    }
}

impl Timeline {
    /// Evaluates from scratch (D rebuilt, §5.1 step 5).
    pub fn evaluate(held: &dyn HeldSet) -> Timeline {
        let input = Input::gather(held);
        let out = walk::run(&input);
        Timeline::from_outcome(input, out)
    }

    pub(crate) fn from_outcome(input: Input, out: walk::Outcome) -> Timeline {
        Timeline::from_kept(input, out, None)
    }

    fn from_kept(input: Input, out: walk::Outcome, kept: Option<Kept>) -> Timeline {
        let (checkpoints, first_held) = match kept {
            Some(k) => k.carry(&out.walked),
            None => (checkpoints(&out.walked, Vec::new()), FirstHeld::new()),
        };
        Timeline {
            owners: input.owners,
            commits: input.commits,
            snaps: input.snaps,
            walked: out.walked,
            dropped: out.dropped,
            epoch_starts: out.epoch_starts,
            passes: out.passes,
            nodes: input.nodes,
            epoch_changed: out.epoch_changed,
            reach: out.reach,
            checkpoints,
            memo: Memo { first_held: Mutex::new(first_held), ..Memo::default() },
        }
    }

    /// This timeline for `held`, which holds the same things, `/created` records and roster
    /// snapshots plus more membership commits and new leaves (things only their `/created`
    /// names among the held commits and snapshots): the leaves first take their owner's
    /// demotions (`Walked::alias_leaves`), then the final walk is rolled back to the earliest
    /// new commit and goes on from there instead of starting over (equal to `evaluate`).
    /// `None` when that does not hold (another walk reached that point, a new thing an earlier
    /// write names, or the inputs differ otherwise): evaluate.
    pub fn extend(mut self, held: &dyn HeldSet) -> Option<Timeline> {
        let input = Input::gather(held);
        // a new author or member could have changed how earlier writes were walked
        if !input.snaps.keys().eq(self.snaps.keys()) || input.nodes != self.nodes {
            return None;
        }
        if !self.commits.keys().all(|k| input.commits.contains_key(k)) {
            return None;
        }
        let leaves = self.leaves(&input)?;
        let added = input.commits.iter().filter(|(k, _)| !self.commits.contains_key(*k)).map(|(_, c)| c.point()).min();
        let kept = Kept::of(&mut self);
        let Timeline { mut walked, dropped, epoch_starts, passes, epoch_changed, reach, .. } = self;
        walked.alias_leaves(&leaves, &input.nodes)?;
        let Some(from) = added else {
            let out = walk::Outcome { walked, dropped, epoch_starts, passes, epoch_changed, reach };
            return Some(Timeline::from_kept(input, out, Some(kept)));
        };
        // after epoch changes, going on from the old starts finds the same ones only when they
        // have a unique fixed point (walk::drive)
        if reach.is_some_and(|r| r >= from) || (epoch_changed && input.cyclic()) {
            return None;
        }
        let out = walk::resume(&input, walk::Resume { walked, dropped, epoch_starts, epoch_changed, reach, from });
        Some(Timeline::from_kept(input, out, Some(kept)))
    }

    /// The things `input` adds by their `/created`, with their owners: leaves the walk never
    /// met, so before any new commit naming one, every node's role on it is its role on its
    /// owner. `None` when one is not a leaf of the walk (a key actor, or named by a walked
    /// commit or snapshot).
    fn leaves(&self, input: &Input) -> Option<Vec<(Tid, Tid)>> {
        let mut out = Vec::new();
        for (t, _) in input.owners.links().filter(|(t, _)| self.owners.owner(t).is_none()) {
            out.push((*t, input.owners.owner_actor(t)?));
        }
        if out.is_empty() {
            return Some(out);
        }
        let new: BTreeSet<Tid> = out.iter().map(|l| l.0).collect();
        let named = self.commits.values().flat_map(|c| c.ops.iter().flat_map(|o| [o.member, o.target]))
            .chain(self.snaps.values().flat_map(|s| std::iter::once(s.thing).chain(s.roster.keys().copied()).chain(s.ledger.iter().map(|x| x.member))));
        for t in named {
            if new.contains(&t) {
                return None;
            }
        }
        Some(out)
    }

    /// Walks the last evaluation or `extend` made (1 when nothing was dropped and no epoch
    /// start applied).
    pub fn passes(&self) -> usize {
        self.passes
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
    /// Class falls of `node` on `thing` in the settled walk (§5.1 step 4), in timeline order,
    /// where `node` has an earlier held write on `thing`.
    pub fn falls(&self, node: &Tid, thing: &Tid) -> &[crate::walk::Fall] {
        self.walked.falls.get(&(*node, *thing)).map_or(&[], |v| v.as_slice())
    }
    pub fn membership_commit(&self, id: &CommitId) -> Option<&Arc<MembershipCommit>> {
        self.commits.get(id)
    }
    pub fn roster_snapshot(&self, id: &CommitId) -> Option<&Arc<RosterSnapshot>> {
        self.snaps.get(id)
    }

    /// The edge state just before `point` (`None`: the current state).
    pub fn edges_at(&self, point: Option<Point>) -> EdgesAt<'_> {
        let Some(p) = point else { return EdgesAt::new(&self.walked.edges) };
        let mut e = EdgesAt::new(&self.walked.initial);
        self.advance(&mut e, 0, self.walked.history.partition_point(|c| c.point < p));
        e
    }

    /// Brings `e`, the state after the first `pos` history changes, to after the first `n`
    /// (`n >= pos`): from the newest kept state when that is past `pos`, the changes since as
    /// an overlay. O(CHECKPOINT), no copy.
    pub(crate) fn advance<'a>(&'a self, e: &mut EdgesAt<'a>, mut pos: usize, n: usize) {
        let k = (n / CHECKPOINT).min(self.checkpoints.len().saturating_sub(1));
        if k * CHECKPOINT > pos
            && let Some(base) = self.checkpoints.get(k)
        {
            *e = EdgesAt::new(base);
            pos = k * CHECKPOINT;
        }
        for c in self.walked.history.iter().take(n).skip(pos) {
            e.set(c.member, c.target, c.edge);
        }
    }

    /// The roster of `thing` (§5.1): its edges alive at `at`.
    pub fn roster(&self, thing: &Tid, at: At) -> BTreeMap<Tid, Edge> {
        let edges = self.edges_at(at.point);
        edges.members(thing).filter(|(_, e)| e.alive_at(at.ts)).map(|(m, e)| (*m, *e)).collect()
    }

    /// Standing (class and effective role) of `node` on `thing`.
    pub fn standing(&self, node: &Tid, thing: &Tid, at: At) -> Standing {
        let edges = self.edges_at(at.point);
        let view = View::at(&self.owners, &edges, at.ts);
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
        let view = View::at(&self.owners, &edges, at.ts);
        let best = view.roles_from(node);
        view.invite(&best, thing)
    }

    /// Effective roles of `node` on every thing it reaches.
    pub fn roles_of(&self, node: &Tid, at: At) -> BTreeMap<Tid, Role> {
        let edges = self.edges_at(at.point);
        View::at(&self.owners, &edges, at.ts).roles_from(node)
    }
}
