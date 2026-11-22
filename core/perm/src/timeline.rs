//! The role timeline (spec/permissions.md §5.1): the settled walk along stated paths
//! (`paths::Paths`) over what a node holds, read per holder. The walk answers per edge (its
//! applied writes, its value before a key); this layer keeps the edge state those histories
//! end in and answers what is asked across edges: effective roles (§1), rosters, standing,
//! the default path, at the end or just before a key.
//!
//! The node gives it the held commits as the walk's input (`HeldSet`), naming what moved since
//! the last update; any order of updates reads as the walk from scratch over what is held.

use crate::graph::{Class, Edges, EdgesAt, Need, Records, Standing, View, RECORD_EDGE};
use crate::paths::{self, Key, MemStore, Paths, Status, Store, Way};
use crate::types::{Edge, EdgeOp, Point, RoleCommit, WriteId};
use osis_base::format::{PathMarks, MAX_CHAIN_DEPTH};
use osis_base::{CommitId, CreationRecord, RecordLink, Role, Tid, Ts, WallMs};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

/// A held commit as the walk reads it.
#[derive(Clone, Debug, PartialEq)]
pub struct Held {
    pub id: CommitId,
    pub ts: Ts,
    pub signer: Tid,
    /// Its parts but its edge writes, in the node's numbering (`WriteId(id, index)`): a delta, or
    /// `PartKind::None` where nothing is read.
    pub parts: Vec<paths::Part>,
    /// Its edge writes, where it has any that count: op k is `WriteId(id, k)` in this layer's
    /// queries, along the path the commit states for its target, the frontier naming commits
    /// whole.
    pub role: Option<Arc<RoleCommit>>,
}

/// What the node holds that the walk reads. Applied, verified commits only (pending ones are
/// not held, spec/commits.md §4).
pub trait HeldSet {
    /// The `created.0` record of `thing`, if held.
    fn created(&self, thing: &Tid) -> Option<CreationRecord>;
    /// Held commit `id` as the walk reads it; `None` where it is not held or nothing of it is
    /// read.
    fn commit(&self, id: &CommitId) -> Option<Held>;
}

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
    /// The current state at the end of time: only edges without `until` count.
    pub const END: At = At { point: None, ts: None };
    /// The current state as keys see it (spec/crypto.md §4): every `until` disregarded, a
    /// removal's retain value (`until` 0, §2) counting as no edge.
    pub const KEYS: At = At { point: None, ts: Some(Ts::ZERO) };
}

/// The key just before every part of the commit at `p`.
pub fn key_of(p: Point) -> Key {
    Key { ts: p.ts, signer: p.node, commit: p.commit, part: 0 }
}

/// The point of the commit holding the part at `k`.
pub fn point_of(k: Key) -> Point {
    Point { ts: k.ts, node: k.signer, commit: k.commit }
}

/// What an update changed.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Changed {
    /// What the walk reports (`paths::Changed`).
    pub walk: paths::Changed,
    /// Things whose record came or went: their record edge with it.
    pub created: BTreeSet<Tid>,
    /// The held deltas whose verdict may have moved (`Paths::reached`).
    pub reached: BTreeSet<WriteId>,
    /// The edge writes (commit, op) that are new or whose status changed.
    pub ops: BTreeSet<WriteId>,
}

impl Changed {
    /// The edges (holder, target) whose value at some key changed, a record edge that came or
    /// went aside (`created`).
    pub fn edges(&self) -> impl Iterator<Item = &(Tid, Tid)> {
        self.walk.edges.keys()
    }
    pub fn is_empty(&self) -> bool {
        *self == Changed::default()
    }
}

/// The timeline over a held set.
#[derive(Clone)]
pub struct Timeline<S: Store = MemStore> {
    paths: Paths<S>,
    records: Records,
    /// The edge state after every applied write.
    now: Edges,
    /// The applied writes in key order, each with its edge (holder, target).
    log: BTreeMap<Key, (Tid, Tid)>,
    /// Per target, the holders whose edge on it a held edge write sets, applied or not.
    into: BTreeMap<Tid, BTreeSet<Tid>>,
    /// Per thing whose record is not held, the held commits with a path member whose record
    /// chain stops at it: given again when the record comes (their hops read the chain).
    waiting: BTreeMap<Tid, BTreeSet<CommitId>>,
    /// The held commits with edge writes, as given: each with its other parts, which its ops
    /// are numbered after in the walk.
    roles: BTreeMap<CommitId, (Arc<RoleCommit>, Vec<paths::Part>)>,
    /// Per target, the held commits with an edge write on it.
    on: BTreeMap<Tid, BTreeSet<CommitId>>,
}

impl Default for Timeline<MemStore> {
    fn default() -> Self {
        Timeline::new(BTreeSet::new())
    }
}

impl Timeline<MemStore> {
    /// Nothing held, under `trust`.
    pub fn new(trust: BTreeSet<WriteId>) -> Timeline {
        Timeline::with_store(trust, MemStore::default())
    }
}

impl<S: Store> Timeline<S> {
    pub fn with_store(trust: BTreeSet<WriteId>, store: S) -> Timeline<S> {
        Timeline { paths: Paths::with_store(&BTreeMap::new(), trust, store), records: Records::default(), now: Edges::default(), log: BTreeMap::new(), into: BTreeMap::new(), waiting: BTreeMap::new(), roles: BTreeMap::new(), on: BTreeMap::new() }
    }

    /// The walk.
    pub fn paths(&self) -> &Paths<S> {
        &self.paths
    }

    pub fn records(&self) -> &Records {
        &self.records
    }

    /// Brings the timeline up to what `held` holds: `commits` names every commit whose reading
    /// (`HeldSet::commit`) may have changed since the last update, held or not, `things` every
    /// thing whose record came or went. A commit with edge writes given as it was is not taken
    /// again (its component would be walked again from its key).
    pub fn update(&mut self, held: &dyn HeldSet, commits: &BTreeSet<CommitId>, things: &BTreeSet<Tid>) -> Changed {
        let mut out = Changed::default();
        let (mut came, mut went) = (Vec::new(), Vec::new());
        let mut again: BTreeSet<CommitId> = commits.clone();
        for t in things {
            match (held.created(t).filter(|r| r.tid() == *t), self.records.link(t)) {
                (Some(rec), None) => {
                    self.records.insert(*t, &rec);
                    out.created.insert(*t);
                    if let RecordLink::Admin(a) = rec.record_link() {
                        came.push((*t, a));
                    }
                    again.extend(self.waiting.remove(t).unwrap_or_default());
                }
                (None, Some(l)) => {
                    // a part whose hops read the record edge loses it: given again
                    if let RecordLink::Admin(a) = l {
                        again.extend(self.paths.through(&a, t));
                        went.push((*t, a));
                    }
                    self.records.remove(t);
                    out.created.insert(*t);
                }
                _ => {}
            }
        }
        let mut gone = Vec::new();
        let mut given = Vec::new();
        for id in &again {
            let now = held.commit(id);
            let was = self.roles.get(id);
            if let (Some(h), Some((role, parts))) = (&now, was)
                && h.role.as_ref().is_some_and(|r| Arc::ptr_eq(r, role) || r == role)
                && h.parts == *parts
                && commits.contains(id)
            {
                continue;
            }
            if let Some((role, _)) = self.roles.remove(id) {
                for o in &role.ops {
                    if let Some(s) = self.on.get_mut(&o.target) {
                        s.remove(id);
                        if s.is_empty() {
                            self.on.remove(&o.target);
                        }
                    }
                }
            }
            match now {
                Some(h) => {
                    let c = commit_of(&h);
                    self.await_records(&c);
                    if let Some(role) = h.role {
                        for o in &role.ops {
                            self.on.entry(o.target).or_default().insert(h.id);
                            self.into.entry(o.target).or_default().insert(o.holder);
                        }
                        self.roles.insert(h.id, (role, h.parts));
                    }
                    given.push(c);
                }
                None => gone.push(*id),
            }
        }
        if came.is_empty() && went.is_empty() && gone.is_empty() && given.is_empty() {
            return out;
        }
        let went_things: Vec<Tid> = went.iter().map(|x| x.0).collect();
        out.walk = self.paths.sync(&came, &went_things, &gone, &given);
        // a record edge that came or went does so from the start
        for (t, a) in came.iter().chain(&went) {
            let last = self.paths.last(a, t).map(|(_, w)| w.value);
            self.now.set(&self.records, *a, *t, last.unwrap_or(self.records.is_record_edge(a, t).then_some(RECORD_EDGE)));
        }
        self.follow(&mut out);
        out
    }

    /// Replaces the trust set (spec/permissions.md §5.1 Trust set): edge writes (commit, op).
    pub fn set_trust(&mut self, trust: &BTreeSet<WriteId>) -> Changed {
        let trust = trust.iter().filter_map(|w| self.part_of(w)).collect();
        let mut out = Changed { walk: self.paths.set_trust(trust), ..Changed::default() };
        self.follow(&mut out);
        out
    }

    /// The held trusted edge writes.
    pub fn trust(&self) -> BTreeSet<WriteId> {
        self.paths.trust().iter().filter_map(|w| self.op_of(w)).collect()
    }

    /// The held lowerings whose trust would change the reading (`Paths::disputes`).
    pub fn disputes(&mut self) -> BTreeSet<WriteId> {
        self.paths.disputes().iter().filter_map(|w| self.op_of(w)).collect()
    }

    /// The trusted edge writes the walk does not apply.
    pub fn void_trusted(&self) -> BTreeSet<WriteId> {
        self.paths.void_trusted().iter().filter_map(|w| self.op_of(w)).collect()
    }

    /// Notes under the first thing with no held record up each member's chain that `c` is to be
    /// given again when it comes.
    fn await_records(&mut self, c: &paths::Commit) {
        for p in &c.parts {
            if matches!(p.kind, paths::PartKind::None) {
                continue;
            }
            for m in p.path.iter().chain([&p.on]) {
                let mut t = *m;
                for _ in 0..=MAX_CHAIN_DEPTH {
                    match self.records.link(&t) {
                        Some(RecordLink::Admin(a)) => t = a,
                        Some(RecordLink::Key) => break,
                        None => {
                            self.waiting.entry(t).or_default().insert(c.id);
                            break;
                        }
                    }
                }
            }
        }
    }

    /// Brings the edge state and the log to the walk after an update reporting `out.walk`, and
    /// fills what it reaches.
    fn follow(&mut self, out: &mut Changed) {
        for ((h, t), k) in &out.walk.edges {
            let stale: Vec<Key> = self.log.range(*k..).filter(|(_, e)| **e == (*h, *t)).map(|(k, _)| *k).collect();
            for k in stale {
                self.log.remove(&k);
            }
            for (key, _) in self.paths.history(h, t).into_iter().filter(|(key, _)| key >= k) {
                self.log.insert(key, (*h, *t));
            }
            let last = self.paths.last(h, t).map(|(_, w)| w.value);
            let value = last.unwrap_or(self.records.is_record_edge(h, t).then_some(RECORD_EDGE));
            self.now.set(&self.records, *h, *t, value);
        }
        out.reached = self.paths.reached(&out.walk);
        out.ops = out.walk.parts.iter().filter_map(|w| self.op_of(w)).collect();
    }

    /// The walk's ID of edge write `w` (commit, op).
    fn part_of(&self, w: &WriteId) -> Option<WriteId> {
        let (_, parts) = self.roles.get(&w.0)?;
        Some(WriteId(w.0, u32::try_from(parts.len()).ok()?.checked_add(w.1)?))
    }

    /// The edge write (commit, op) the walk's part `w` is, if one.
    fn op_of(&self, w: &WriteId) -> Option<WriteId> {
        let (_, parts) = self.roles.get(&w.0)?;
        Some(WriteId(w.0, w.1.checked_sub(u32::try_from(parts.len()).ok()?)?))
    }

    // ---- edge writes, each (commit, op) ----

    /// The held commit `id` with edge writes.
    pub fn role_commit(&self, id: &CommitId) -> Option<&Arc<RoleCommit>> {
        self.roles.get(id).map(|x| &x.0)
    }

    /// An edge write held here: its signer, holder and target.
    pub fn edge_op(&self, w: &WriteId) -> Option<(Tid, Tid, Tid)> {
        let c = self.role_commit(&w.0)?;
        let op = c.ops.get(usize::try_from(w.1).ok()?)?;
        Some((c.signer, op.holder, op.target))
    }

    /// The edge writes held on `t`, applied or not, each with its ID, commit and op.
    pub fn held_on<'t>(&'t self, t: &'t Tid) -> impl Iterator<Item = (WriteId, &'t RoleCommit, &'t EdgeOp)> + 't {
        self.on.get(t).into_iter().flatten().filter_map(|id| self.roles.get(id)).flat_map(move |(c, _)| (0u32..).zip(&c.ops).filter(move |(_, o)| o.target == *t).map(move |(k, o)| (WriteId(c.id, k), &**c, o)))
    }

    /// The edge writes applied on `t`, each with its commit and op.
    pub fn applied_on<'t>(&'t self, t: &'t Tid) -> impl Iterator<Item = (&'t RoleCommit, &'t EdgeOp)> + 't {
        self.held_on(t).filter(|(w, _, _)| self.is_applied(w)).map(|(_, c, o)| (c, o))
    }

    /// What the settled walk did with held edge write `w`.
    pub fn status(&self, w: &WriteId) -> Option<Status> {
        self.paths.status(&self.part_of(w)?)
    }

    /// Whether the settled walk applies `w`.
    pub fn is_applied(&self, w: &WriteId) -> bool {
        matches!(self.status(w), Some(Status::Applied | Status::MayGrant))
    }

    /// How the settled walk applies `w`.
    pub fn way(&self, w: &WriteId) -> Option<Way> {
        self.paths.way(&self.part_of(w)?)
    }

    /// Applied edge write `w`: what it found on its edge.
    pub fn applied(&self, w: &WriteId) -> Option<paths::Applied> {
        self.paths.applied(&self.part_of(w)?).map(|x| x.1)
    }

    /// Whether `w` is chained (spec/permissions.md §4 Chained writes).
    pub fn is_chained(&self, w: &WriteId) -> bool {
        self.part_of(w).and_then(|p| self.paths.is_chained(&p)) == Some(true)
    }

    /// The commit of the edge write in force on (`holder`, `target`): the last applied one, when
    /// it set a value (spec/permissions.md §2: the next edge write resets the entry it created).
    pub fn in_force(&self, holder: &Tid, target: &Tid) -> Option<CommitId> {
        self.paths.last(holder, target).filter(|(_, a)| a.value.is_some()).map(|(w, _)| w.0)
    }

    /// A held delta's verdict (`Paths::content`), by (commit, part).
    pub fn content(&self, id: &WriteId) -> Option<paths::Content> {
        self.paths.content(id)
    }

    /// Whether a thing's record or an edge write on it is held.
    pub fn knows(&self, t: &Tid) -> bool {
        self.records.link(t).is_some() || self.on.contains_key(t)
    }

    /// Every thing with a held record or edge write on it.
    pub fn things(&self) -> impl Iterator<Item = &Tid> {
        let extra = self.on.keys().filter(|t| self.records.link(t).is_none());
        self.records.links().map(|(t, _)| t).chain(extra)
    }

    /// Whether (`holder`, `target`) as restored (§5.1) gives or lets grant more than its value
    /// now: a self-removal, a finalize or a may-grant grant lowered it with no explicit write
    /// since. An expiry by `until` is read from the edge itself.
    pub fn lowered_unaudited(&self, holder: &Tid, target: &Tid) -> bool {
        let v = self.now.get(&self.records, holder, target);
        let (role, grant) = (v.map(|v| v.role), v.filter(|v| v.role == Role::Admin || v.may_grant).map(|v| v.role));
        let (r, g) = self.paths.restored(holder, target);
        r > role || g > grant
    }

    /// Whether an explicit write of `new` on (`holder`, `target`) at `ts`, after every held
    /// write, takes the edge down (§5.1): the edge as restored gives or lets grant more.
    pub fn audits(&self, holder: &Tid, target: &Tid, new: Option<Edge>, ts: Ts) -> bool {
        let role = new.filter(|v| v.alive_at(Some(ts))).map(|v| v.role);
        let grant = role.filter(|r| *r == Role::Admin || new.is_some_and(|v| v.may_grant));
        let (r, g) = self.paths.restored(holder, target);
        role < r || grant < g
    }

    // ---- the edge state ----

    /// The edge state just before `point` (`None`: after every applied write).
    pub fn edges_at(&self, point: Option<Point>) -> EdgesAt<'_> {
        let mut e = EdgesAt::new(&self.records, &self.now);
        let Some(p) = point else { return e };
        let k = key_of(p);
        let mut seen = BTreeSet::new();
        for (_, (h, t)) in self.log.range(k..) {
            if seen.insert((*h, *t)) {
                e.set(*h, *t, self.paths.value_before(h, t, &k));
            }
        }
        e
    }

    /// The edges at the end, each edge whose last write is a finalize (§2) as it stood just
    /// before it: what an `until` passing alone ended (§3, Lost access).
    pub fn edges_unfinalized(&self) -> EdgesAt<'_> {
        let mut e = self.edges_at(None);
        for (t, hs) in &self.into {
            for h in hs {
                if let Some((w, a)) = self.paths.last(h, t)
                    && self.paths.way(&w) == Some(Way::Finalize)
                {
                    e.set(*h, *t, a.before);
                }
            }
        }
        e
    }

    /// The applied writes on the edges into `thing`, in key order: (key, holder, value).
    fn writes_on(&self, thing: &Tid) -> Vec<(Key, Tid, Option<Edge>)> {
        let mut out: Vec<(Key, Tid, Option<Edge>)> = self.into.get(thing).into_iter().flatten().flat_map(|h| self.paths.history(h, thing).into_iter().map(|(k, v)| (k, *h, v))).collect();
        out.sort_by_key(|x| x.0);
        out
    }

    /// The roster of `thing` (§5.1): its edges alive at `at`.
    pub fn roster(&self, thing: &Tid, at: At) -> BTreeMap<Tid, Edge> {
        let edges = self.edges_at(at.point);
        edges.holders(thing).filter(|(_, e)| e.alive_at(at.ts)).map(|(m, e)| (*m, *e)).collect()
    }

    /// Each holder of `thing` whose current edge does not say retain (§2), with the point of the
    /// write since which it has held such an edge without a break (`None`: since before every
    /// write: its record edge).
    pub fn standing_since(&self, thing: &Tid) -> BTreeMap<Tid, Option<Point>> {
        let mut out: BTreeMap<Tid, Option<Point>> = self.records.mint_admin(thing).map(|a| (a, None)).into_iter().collect();
        for (k, h, v) in self.writes_on(thing) {
            if v.is_some_and(|e| !e.says_retain()) {
                out.entry(h).or_insert(Some(point_of(k)));
            } else {
                out.remove(&h);
            }
        }
        out
    }

    /// `standing_since` of every thing with a holder, over the writes before `before` (`None`:
    /// all of them). O(the applied writes and the records).
    pub fn standing_since_all(&self, before: Option<Point>) -> BTreeMap<Tid, BTreeMap<Tid, Option<Point>>> {
        let mut out: BTreeMap<Tid, BTreeMap<Tid, Option<Point>>> = BTreeMap::new();
        for (t, l) in self.records.links() {
            if let RecordLink::Admin(a) = l {
                out.entry(*t).or_default().insert(*a, None);
            }
        }
        let end = before.map(key_of);
        for (k, (h, t)) in self.log.iter().take_while(|(k, _)| end.is_none_or(|e| **k < e)) {
            let v = self.paths.last_before(h, t, &Key { part: k.part.saturating_add(1), ..*k }).and_then(|(_, a)| a.value);
            let on = out.entry(*t).or_default();
            if v.is_some_and(|e| !e.says_retain()) {
                on.entry(*h).or_insert(Some(point_of(*k)));
            } else {
                on.remove(h);
            }
        }
        out.retain(|_, hs| !hs.is_empty());
        out
    }

    /// The holders whose edge on `thing`, alive at `ts`, gives a role below one an earlier write
    /// of it (or its record edge) gave: lowered, not ended (`ended`).
    pub fn lowered(&self, thing: &Tid, ts: Ts) -> BTreeSet<Tid> {
        let mut top: BTreeMap<Tid, Role> = self.records.mint_admin(thing).map(|a| (a, RECORD_EDGE.role)).into_iter().collect();
        for (_, h, v) in self.writes_on(thing) {
            if let Some(e) = v {
                let r = top.entry(h).or_insert(e.role);
                *r = (*r).max(e.role);
            }
        }
        top.into_iter().filter(|(m, r)| self.now.get(&self.records, m, thing).is_some_and(|e| e.alive_at(Some(ts)) && e.role < *r)).map(|(m, _)| m).collect()
    }

    /// The holders with no edge alive on `thing` at `ts` that the walk saw one of: whether each
    /// one's edge ended saying retain (`Edge::ends_retaining`), the point of its last write
    /// (`None`: its record edge, never written) and the role the edge last gave (a removal's
    /// value saying retain gives none: the role before it).
    pub fn ended(&self, thing: &Tid, ts: Ts) -> BTreeMap<Tid, (bool, Option<Point>, Role)> {
        let mut out: BTreeMap<Tid, (bool, Option<Point>, Role)> = self.records.mint_admin(thing).map(|a| (a, (RECORD_EDGE.ends_retaining(), None, RECORD_EDGE.role))).into_iter().collect();
        for (k, h, v) in self.writes_on(thing) {
            match (v, out.get_mut(&h)) {
                (Some(e), x) => {
                    let role = x.filter(|_| e.says_retain()).map_or(e.role, |x| x.2);
                    out.insert(h, (e.ends_retaining(), Some(point_of(k)), role));
                }
                (None, Some(x)) => (x.0, x.1) = (false, Some(point_of(k))),
                (None, None) => {}
            }
        }
        out.retain(|m, _| !self.now.get(&self.records, m, thing).is_some_and(|e| e.alive_at(Some(ts))));
        out
    }

    // ---- roles ----

    fn with_roles<R>(&self, node: &Tid, at: At, f: impl FnOnce(&View<'_>, &BTreeMap<Tid, Role>) -> R) -> R {
        let edges = self.edges_at(at.point);
        let view = View::at(&edges, at.ts);
        f(&view, &view.roles_from(node))
    }

    /// Standing (what it may write of grants, and its effective role) of `node` on `thing`.
    pub fn standing(&self, node: &Tid, thing: &Tid, at: At) -> Standing {
        self.with_roles(node, at, |view, best| view.standing(best, thing))
    }

    pub fn class(&self, node: &Tid, thing: &Tid, at: At) -> Class {
        self.standing(node, thing, at).class
    }

    /// The highest role at which a path from `node` gives may-grant on `thing` (§2).
    pub fn may_grant(&self, node: &Tid, thing: &Tid, at: At) -> Option<Role> {
        self.with_roles(node, at, |view, best| view.may_grant(best, thing))
    }

    /// Effective role (§1), read backward from `thing`.
    pub fn role(&self, node: &Tid, thing: &Tid, at: At) -> Option<Role> {
        self.roles_on(thing, at).get(node).copied()
    }

    /// Every thing's effective role on `thing` at `at`, by the widest paths into it.
    pub fn roles_on(&self, thing: &Tid, at: At) -> Arc<BTreeMap<Tid, Role>> {
        Arc::new(self.roles_on_without(thing, at, &BTreeSet::new()))
    }

    /// `roles_on` on the current edges at `ts`, and the earliest `until` the walk followed: the
    /// answer holds at any later ts before it.
    pub fn roles_on_now(&self, thing: &Tid, ts: Ts) -> (Arc<BTreeMap<Tid, Role>>, Option<WallMs>) {
        let (r, u) = self.roles_on_now_without(thing, ts, &BTreeSet::new());
        (Arc::new(r), u)
    }

    /// `roles_on_now` over the edges not in `skip`, each named (target, holder).
    pub fn roles_on_now_without(&self, thing: &Tid, ts: Ts, skip: &BTreeSet<(Tid, Tid)>) -> (BTreeMap<Tid, Role>, Option<WallMs>) {
        let edges = self.edges_at(None);
        View::at(&edges, Some(ts)).roles_to_expiring(thing, skip)
    }

    /// `roles_on` over the edges not in `skip`, each named (target, holder).
    pub fn roles_on_without(&self, thing: &Tid, at: At, skip: &BTreeSet<(Tid, Tid)>) -> BTreeMap<Tid, Role> {
        let edges = self.edges_at(at.point);
        View::at(&edges, at.ts).roles_to_expiring(thing, skip).0
    }

    /// `node`'s effective role on `thing` at `ts` over `edges_unfinalized`, the edges in `skip`
    /// (each named (target, holder)) left out.
    pub fn role_unfinalized(&self, node: &Tid, thing: &Tid, ts: Ts, skip: &BTreeSet<(Tid, Tid)>) -> Option<Role> {
        let edges = self.edges_unfinalized();
        View::at(&edges, Some(ts)).roles_to_expiring(thing, skip).0.get(node).copied()
    }

    /// The path from `node` into `thing` giving `need` on the current edges at `ts`
    /// (`graph::Ways::path`): the things listed, the hops marked direct and whether the last hop
    /// is a record edge.
    pub fn path_now(&self, node: &Tid, thing: &Tid, need: Need, ts: Ts) -> Option<(Vec<Tid>, PathMarks, bool)> {
        let edges = self.edges_at(None);
        View::at(&edges, Some(ts)).ways_to(thing, need).0.path(&self.records, node)
    }

    /// `node`'s roles over every grant the walk applied, the ended ones included: what it
    /// reached by the paths the held writes show (spec/crypto.md §4 Holders for keys: removals,
    /// finalizes and a retain value end a path; `until` is disregarded). A path may join edges
    /// that never stood at once. O(the applied writes).
    pub fn roles_ever(&self, node: &Tid) -> BTreeMap<Tid, Role> {
        let mut ever = Edges::default();
        for (t, hs) in &self.into {
            for h in hs {
                let best = self.paths.history(h, t).into_iter().filter_map(|(_, v)| v.filter(|e| !e.says_retain())).max_by_key(|e| e.role);
                if let Some(e) = best {
                    ever.set(&self.records, *h, *t, Some(Edge { until: None, ..e }));
                }
            }
        }
        View::new(&self.records, &ever, Some(Ts::ZERO)).roles_from(node)
    }

    /// Effective roles of `node` on every thing it reaches.
    pub fn roles_of(&self, node: &Tid, at: At) -> BTreeMap<Tid, Role> {
        let edges = self.edges_at(at.point);
        View::at(&edges, at.ts).roles_from(node)
    }

    /// `roles_of` over the edges not in `skip`, each named (target, holder).
    pub fn roles_without(&self, node: &Tid, at: At, skip: &BTreeSet<(Tid, Tid)>) -> BTreeMap<Tid, Role> {
        let edges = self.edges_at(at.point);
        View::at(&edges, at.ts).roles_from_without(node, skip)
    }
}

/// The walk's input for `h`: its parts, then its edge writes.
fn commit_of(h: &Held) -> paths::Commit {
    let mut parts = h.parts.clone();
    if let Some(r) = &h.role {
        let list = r.frontier.as_ref().map(|f| Arc::new(paths::List::whole((**f).clone())));
        parts.extend(r.ops.iter().map(|o| paths::Part { on: o.target, path: r.path_to(&o.target).to_vec(), direct: r.direct, kind: paths::PartKind::Edge(paths::EdgeWrite { holder: o.holder, value: o.edge, frontier: list.clone() }) }));
    }
    paths::Commit { id: h.id, ts: h.ts, signer: h.signer, parts }
}
