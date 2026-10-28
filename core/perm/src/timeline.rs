//! The membership timeline (spec/permissions.md §5.1) and its queries: roster, effective role,
//! effective invite and authority class at a point, the applied and dropped edge writes.

use crate::graph::{Class, Edges, EdgesAt, Owners, Standing, View};
use crate::held::HeldSet;
use crate::types::{Edge, MembershipCommit, Point, RosterSnapshot, WriteId};
use crate::walk::{self, Applied, Demotion, Input};
use osis_base::{CommitId, CreationRecord, Role, Tid, Ts};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};

/// History changes between two kept edge states (`edges_at` replays at most this many as an
/// overlay; a kept state shares its unchanged per-thing maps, `Edges`).
const CHECKPOINT: usize = 32;

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
    /// The inputs walked (`append` adds to them).
    pub(crate) input: Input,
    /// The final walk's items over `input`.
    items: walk::Items,
    pub(crate) walked: walk::Walked,
    dropped: BTreeMap<WriteId, Point>,
    epoch_starts: BTreeMap<Tid, CommitId>,
    passes: usize,
    pub(crate) epoch_changed: bool,
    /// The furthest point a walk under the final epoch starts other than the final one reached
    /// (the latest point of a drop in D; kept for the walk cache).
    pub(crate) reach: Option<Point>,
    /// Kept edge states `(i, state before history change i)`, `i` increasing from 0, about
    /// `CHECKPOINT` apart, for `edges_at` (shared with the timeline `extend` made this from).
    checkpoints: Checkpoints,
    /// Answers of layer-2 queries, valid as long as this timeline (the held set of its
    /// component) is.
    pub(crate) memo: Memo,
    /// Commits the last `append` placed without walking again.
    pub(crate) placed: usize,
}

/// `first_held` by (node, thing, role).
type FirstHeld = BTreeMap<(Tid, Tid, Role), Option<Option<Point>>>;
/// `delta_valid` by its arguments.
type Valid = BTreeMap<(Point, Tid, String, crate::types::Dots, Role), crate::content::Validity>;

/// Memoized layer-2 answers.
#[derive(Default)]
pub(crate) struct Memo {
    pub first_held: Mutex<FirstHeld>,
    /// `first_held`'s replays by (node, role), to go on with.
    pub replays: Mutex<BTreeMap<(Tid, Role), crate::content::Replay>>,
    pub valid: Mutex<Valid>,
    /// `roles_of` at `At::END`, per node.
    pub roles_end: Mutex<BTreeMap<Tid, Arc<BTreeMap<Tid, Role>>>>,
    /// Held records by the edges and things they write, for certificates.
    pub certs: std::sync::OnceLock<crate::cert::CertIndex>,
}

/// Kept edge states (`Timeline::checkpoints`).
type Checkpoints = Vec<(usize, Arc<Edges>)>;

/// The kept edge states of `w`'s history, going on from those in `out` (still valid for it).
fn checkpoints(w: &walk::Walked, mut out: Checkpoints) -> Checkpoints {
    let len = w.history.len();
    out.retain(|c| c.0 < len);
    let (start, mut e) = match out.last() {
        Some((i, c)) => (*i, (**c).clone()),
        None => (0, w.initial.clone()),
    };
    let mut next = if out.is_empty() { 0 } else { start + CHECKPOINT };
    for (i, c) in w.history.iter().enumerate().skip(start) {
        if i == next {
            out.push((i, Arc::new(e.clone())));
            next += CHECKPOINT;
        }
        e.set(c.member, c.target, c.edge);
    }
    out
}

/// What a timeline hands the one `extend` or `append` makes from it: what stays true over
/// the history both share (the same initial state and changes up to the first that differs,
/// `Outcome::common`).
pub(crate) struct Kept {
    checkpoints: Checkpoints,
    first_held: FirstHeld,
}

impl Kept {
    fn of(tl: &mut Timeline) -> Kept {
        let first_held = std::mem::take(&mut *tl.memo.first_held.lock().unwrap_or_else(|e| e.into_inner()));
        Kept { checkpoints: std::mem::take(&mut tl.checkpoints), first_held }
    }

    /// The kept states and `first_held` answers still valid for `w`.
    fn carry(self, w: &walk::Walked, common: Option<(usize, Option<Point>)>) -> (Checkpoints, FirstHeld) {
        let mut cps = self.checkpoints;
        let mut fh = self.first_held;
        match common {
            // an answer found at a change before the first that differs stands
            Some((n, bound)) => {
                cps.retain(|c| c.0 <= n);
                fh.retain(|_, v| v.is_some_and(|p| p.is_none_or(|p| bound.is_none_or(|b| p < b))));
            }
            None => {
                cps.clear();
                fh.clear();
            }
        }
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
            Some(k) => k.carry(&out.walked, out.common),
            None => (checkpoints(&out.walked, Vec::new()), FirstHeld::new()),
        };
        let items = out.items.unwrap_or_else(|| walk::items(&input, &out.epoch_starts));
        Timeline {
            input,
            items,
            walked: out.walked,
            dropped: out.dropped,
            epoch_starts: out.epoch_starts,
            passes: out.passes,
            epoch_changed: out.epoch_changed,
            reach: out.reach,
            checkpoints,
            memo: Memo { first_held: Mutex::new(first_held), ..Memo::default() },
            placed: 0,
        }
    }

    /// This timeline for `held`, which holds the same roster snapshots, every membership commit
    /// walked here, maybe more, and maybe new things, `/created` records and nodes (equal to
    /// `evaluate`). Before the first point `p` where the walk meets anything new (a new commit,
    /// or an item naming a thing whose owner link is new, one below it, or a new node), the
    /// walk is the same but for the demotions on those things: they have no edges there, so a
    /// node's role on one is its role on its owner (`Walked::alias_leaves`); a new node reaches
    /// nothing walked there (it owns only such things). So the final walk takes those, is
    /// rolled back to `p` (or to the first write a drop found after it dropped, D keeping what
    /// was found before) and goes on from there instead of starting over. `None` when that
    /// does not hold (other snapshots, a node gone that is not now owned, a new node owning a
    /// thing walked before, a membership cycle after epoch starts changed, a record changed
    /// under its ID): evaluate.
    pub fn extend(mut self, held: &dyn HeldSet) -> Option<Timeline> {
        let input = Input::gather(held);
        if !input.snaps.keys().eq(self.input.snaps.keys()) {
            return None;
        }
        if !self.input.commits.keys().all(|k| input.commits.contains_key(k)) || !self.input.kept_in(&input) {
            return None;
        }
        let added = input.commits.iter().filter(|(k, _)| !self.input.commits.contains_key(*k)).map(|(_, c)| c.point()).min();
        let (below, from) = self.joined(&input, added)?;
        let cut = match from {
            Some(f) => self.walked.rest.marks.get(self.items.list_before(f)).map_or(self.walked.rest.log.len(), |m| m.0),
            None => self.walked.rest.log.len(),
        };
        let leaves: Vec<(Tid, Tid)> = below.iter().filter_map(|t| input.owners.owner_actor(t).map(|o| (*t, o))).collect();
        let joins = !below.is_empty() || input.nodes != self.input.nodes;
        let mut kept = Kept::of(&mut self);
        // a role through a new owner link may differ from where the walk meets it on, its
        // history changed there or not; on one of them, from the start
        if !below.is_empty() {
            kept.first_held.retain(|(_, t, _), v| !below.contains(t) && v.is_some_and(|q| q.is_none_or(|q| from.is_none_or(|f| q < f))));
        }
        let Timeline { mut walked, dropped, epoch_starts, passes, epoch_changed, reach, .. } = self;
        walked.alias_leaves(&leaves, &input.nodes, cut)?;
        let Some(from) = from else {
            let common = Some((walked.history.len(), None));
            let out = walk::Outcome { walked, dropped, epoch_starts, passes, epoch_changed, reach, items: None, common };
            return Some(Timeline::from_kept(input, out, Some(kept)));
        };
        // after epoch changes, going on from the old starts finds the same ones only when they
        // have a unique fixed point (walk::drive)
        if epoch_changed && input.cyclic() {
            return None;
        }
        let out = walk::resume(&input, walk::Resume { walked, dropped, epoch_starts, epoch_changed, from, items: None });
        let tl = Timeline::from_kept(input, out, Some(kept));
        #[cfg(debug_assertions)]
        if joins {
            tl.walked.check_scratch(&tl.input, &tl.dropped);
        }
        Some(tl)
    }

    /// What `input` (this timeline's, grown) adds that the walk may meet before its new commits
    /// (from `added`): the things whose owner link is new and every thing below them, and the
    /// first point where an item walked here names one of them or a new node (`None`: none
    /// does, and no commit is new). `None` when an owner link is gone, a node is gone that is
    /// not now owned, or a new node owns a thing not among them.
    fn joined(&self, input: &Input, added: Option<Point>) -> Option<(BTreeSet<Tid>, Option<Point>)> {
        if !self.input.owners.links().all(|(t, o)| input.owners.owner(t) == Some(*o)) {
            return None;
        }
        let mut below: BTreeSet<Tid> = input.owners.links().filter(|(t, _)| self.input.owners.owner(t).is_none()).map(|(t, _)| *t).collect();
        let mut stack: Vec<Tid> = below.iter().copied().collect();
        while let Some(t) = stack.pop() {
            for y in input.owners.owned(&t) {
                if below.insert(*y) {
                    stack.push(*y);
                }
            }
        }
        if self.input.nodes.difference(&input.nodes).any(|n| !below.contains(n)) {
            return None;
        }
        let came: Vec<Tid> = input.nodes.difference(&self.input.nodes).filter(|n| !below.contains(n)).copied().collect();
        if came.iter().any(|n| input.owners.owned(n).iter().any(|y| !below.contains(y))) {
            return None;
        }
        let mut named = below.clone();
        named.extend(came);
        if named.is_empty() {
            return Some((below, added));
        }
        // (named by an epoch start's roster: from the start)
        if self.items.initial_names(&named) {
            return None;
        }
        let first = self.items.first_naming(&named, added);
        Some((below, match (first, added) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        }))
    }

    /// This timeline with membership commits `new` added (not held here, on things of this
    /// timeline, by and for its nodes or nodes that reach nothing here) and the `/created` of
    /// key actors `keys` new here (nodes `new` names, nothing else held of them): `extend`
    /// without gathering the held set again. Each commit, in timeline order, is placed in the walk
    /// without walking again where that is exact (`Walked::insert`: it applies nothing, or no
    /// later item reads what it changes); from the first that is not, the walk goes on from
    /// it. `Err(self)`, unchanged, when `extend` would not hold or the inputs would change
    /// otherwise (`Input::can_append`).
    pub fn append(mut self, new: &[Arc<MembershipCommit>], keys: &[(Tid, CreationRecord)]) -> Result<Timeline, Box<Timeline>> {
        if new.is_empty() {
            return Ok(self);
        }
        if !self.input.can_append(new, self.epoch_changed) || keys.iter().any(|(t, r)| self.input.owners.owner(t).is_some() || r.tid() != *t || !matches!(r, CreationRecord::KeyActor { .. })) {
            return Err(Box::new(self));
        }
        for (t, r) in keys {
            self.input.owners.insert(*t, r);
        }
        let mut new = new.to_vec();
        new.sort_by_key(|c| c.point());
        // chain certificates list held writes
        self.memo.certs = std::sync::OnceLock::new();
        self.placed = 0;
        for (j, c) in new.iter().enumerate() {
            let p = c.point();
            let first: BTreeMap<Tid, Option<Point>> = c.ops.iter().map(|o| (o.target, self.input.first_write.get(&(c.author, o.target)).copied())).collect();
            let mut fresh: BTreeSet<Tid> = c.ops.iter().map(|o| o.member).filter(|m| self.input.owners.owner_actor(m).is_none()).collect();
            fresh.extend(c.ops.iter().map(|o| o.target).filter(|t| self.input.owners.is_key(t)));
            fresh.insert(c.author);
            fresh.retain(|t| !self.input.nodes.contains(t));
            self.input.append(std::slice::from_ref(c));
            let n0 = self.walked.history.len();
            let h = self.walked.rest.marks.get(self.items.place(c)).map_or(n0, |m| m.1);
            let (base, pos) = self.kept_before(h);
            let mut before = (*base).clone();
            drop(base);
            for x in self.walked.history.iter().take(h).skip(pos) {
                before.set(x.member, x.target, x.edge);
            }
            let pl = self.walked.insert(&self.input, &self.items, &self.dropped, &self.epoch_starts, c, before, &first, &fresh);
            match pl {
                walk::Placement::Idle => {
                    self.items.add(std::slice::from_ref(c));
                    self.placed += 1;
                }
                walk::Placement::Inserted(h) => {
                    self.items.add(std::slice::from_ref(c));
                    self.inserted(h, self.walked.history.len() - n0, p);
                    self.placed += 1;
                }
                walk::Placement::Declined | walk::Placement::From(..) => {
                    // placed up to a later item: the walk goes on from there (or from a later
                    // commit of this batch before it)
                    let (rest, joined, from) = match pl {
                        walk::Placement::From(h, q) => {
                            self.items.add(std::slice::from_ref(c));
                            self.inserted(h, self.walked.history.len() - n0, p);
                            let rest = new.get(j + 1..).unwrap_or_default();
                            (rest, rest, rest.first().map_or(q, |r| r.point().min(q)))
                        }
                        _ => {
                            let rest = new.get(j..).unwrap_or_default();
                            (rest, rest.get(1..).unwrap_or_default(), p)
                        }
                    };
                    self.input.append(joined);
                    self.items.add(rest);
                    let kept = Kept::of(&mut self);
                    let Timeline { input, items, walked, dropped, epoch_starts, epoch_changed, placed, .. } = self;
                    let out = walk::resume(&input, walk::Resume { walked, dropped, epoch_starts, epoch_changed, from, items: Some(items) });
                    let tl = Timeline { placed, ..Timeline::from_kept(input, out, Some(kept)) };
                    #[cfg(debug_assertions)]
                    if matches!(pl, walk::Placement::From(..)) {
                        tl.walked.check_scratch(&tl.input, &tl.dropped);
                    }
                    return Ok(tl);
                }
            }
        }
        Ok(self)
    }

    /// Whether the commits and snapshots `held` holds on `things` are the ones walked here,
    /// with the same content (a record can grow under its ID: a part that arrives late).
    pub(crate) fn holds_same(&self, held: &dyn HeldSet, things: &BTreeSet<Tid>) -> bool {
        things.iter().all(|t| {
            held.edge_commits(t).iter().all(|c| self.input.holds_commit(c)) && held.roster_snapshots(t).iter().filter(|s| s.thing == *t).all(|s| self.input.holds_snapshot(s))
        })
    }

    /// The newest kept edge state at or before history change `h`, and its change index.
    fn kept_before(&self, h: usize) -> (Arc<Edges>, usize) {
        let k = self.checkpoints.partition_point(|c| c.0 <= h);
        match k.checked_sub(1).and_then(|k| self.checkpoints.get(k)) {
            Some((i, e)) => (e.clone(), *i),
            None => (Arc::new(self.walked.initial.clone()), 0),
        }
    }

    /// `n` changes were inserted into the history at change `h` (point `p`) by
    /// `Walked::insert`, which no later change touches the edges of: each later kept state
    /// moves by `n` and takes them; answers past `p` go.
    fn inserted(&mut self, h: usize, n: usize, p: Point) {
        let changes: Vec<(Tid, Tid, Option<Edge>)> = self.walked.history.iter().skip(h).take(n).map(|c| (c.member, c.target, c.edge)).collect();
        // a history that was empty kept no state: the initial one, so later gaps get split
        if self.checkpoints.is_empty() {
            self.checkpoints.push((0, Arc::new(self.walked.initial.clone())));
        }
        let k = self.checkpoints.partition_point(|c| c.0 <= h);
        let later = self.checkpoints.get_mut(k..).unwrap_or_default();
        for c in later.iter_mut() {
            c.0 += n;
        }
        Edges::set_all(later.iter_mut().map(|c| &mut c.1), &changes);
        // keep the gap the insert widened within twice the interval
        let end = self.checkpoints.get(k).map_or(self.walked.history.len(), |c| c.0);
        if let Some((i, base)) = k.checked_sub(1).and_then(|k| self.checkpoints.get(k)).cloned()
            && end - i > 2 * CHECKPOINT
        {
            let mut e = (*base).clone();
            for c in self.walked.history.iter().skip(i).take(CHECKPOINT) {
                e.set(c.member, c.target, c.edge);
            }
            self.checkpoints.insert(k, (i + CHECKPOINT, Arc::new(e)));
        }
        #[cfg(debug_assertions)]
        {
            let mut e = self.walked.initial.clone();
            let mut cps = self.checkpoints.iter().peekable();
            for (i, c) in self.walked.history.iter().enumerate() {
                while let Some((j, s)) = cps.next_if(|x| x.0 == i) {
                    debug_assert!(**s == e, "kept state {j} after an insert at {h}");
                }
                e.set(c.member, c.target, c.edge);
            }
            debug_assert!(cps.next().is_none(), "kept states past the history");
        }
        let fh = std::mem::take(&mut *self.memo.first_held.lock().unwrap_or_else(|e| e.into_inner()));
        let mut fh = fh;
        fh.retain(|_, v| v.is_some_and(|q| q.is_none_or(|q| q < p)));
        self.memo = Memo { first_held: Mutex::new(fh), ..Memo::default() };
    }

    /// Walks the last evaluation or `extend` made (1 when nothing was dropped and no epoch
    /// start applied).
    pub fn passes(&self) -> usize {
        self.passes
    }
    pub fn owners(&self) -> &Owners {
        &self.input.owners
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
        self.input.commits.get(id)
    }
    pub fn roster_snapshot(&self, id: &CommitId) -> Option<&Arc<RosterSnapshot>> {
        self.input.snaps.get(id)
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
        let k = self.checkpoints.partition_point(|c| c.0 <= n);
        if let Some((i, base)) = k.checked_sub(1).and_then(|k| self.checkpoints.get(k))
            && *i > pos
        {
            *e = EdgesAt::new(base);
            pos = *i;
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
        let view = View::at(&self.input.owners, &edges, at.ts);
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
        let view = View::at(&self.input.owners, &edges, at.ts);
        let best = view.roles_from(node);
        view.invite(&best, thing)
    }

    /// Effective roles of `node` on every thing it reaches.
    pub fn roles_of(&self, node: &Tid, at: At) -> BTreeMap<Tid, Role> {
        let edges = self.edges_at(at.point);
        View::at(&self.input.owners, &edges, at.ts).roles_from(node)
    }
}
