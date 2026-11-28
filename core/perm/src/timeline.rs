//! The role timeline (spec/permissions.md §5.1): the settled walk along stated paths
//! (`paths::Paths`) over what a node holds, read per holder. The walk answers per edge (its
//! applied writes, its value before a key); this layer keeps the edge state those histories
//! end in and answers what is asked across edges: effective roles (§1), rosters, standing,
//! the default path, at the end or just before a key.
//!
//! The node gives it the held commits as the walk's input (`HeldSet`), naming what moved since
//! the last update; any order of updates reads as the walk from scratch over what is held.

use crate::graph::{Edges, EdgesAt, Need, Records, View, RECORD_EDGE};
use crate::paths::{self, Key, MemStore, Paths, Status, Store, Way};
use crate::types::{Grant, GrantOp, Point, RoleCommit, WriteId};
use osis_base::format::MAX_CHAIN_DEPTH;
use osis_base::{CommitId, CreationRecord, Holder, RecordLink, Role, SignKey, Tid, Ts, Time};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

/// A held commit as the walk reads it.
#[derive(Clone, Debug, PartialEq)]
pub struct Held {
    pub id: CommitId,
    pub ts: Ts,
    /// The thing it is signed as, and the key that signed it.
    pub signer: Tid,
    pub key: SignKey,
    /// Its parts but its grant writes, in the node's numbering (`WriteId(id, index)`): a delta, or
    /// `PartKind::None` where nothing is read.
    pub parts: Vec<paths::Part>,
    /// Its grant writes, where it has any that count: op k is `WriteId(id, k)` in this layer's
    /// queries, along the path the commit states for its target, the frontier naming commits
    /// whole.
    pub role: Option<Arc<RoleCommit>>,
    /// The held snapshots' deltas carrying copies of its writes (spec/permissions.md §5.2
    /// Copies). A snapshot's own part lists the commits it carries among those held
    /// (`DeltaClass::Snapshot`): the two say the same of every pair held.
    pub carriers: Vec<WriteId>,
}

impl Held {
    /// Its parts but its grant writes, as the walk's input.
    pub fn deltas(self) -> paths::Commit {
        paths::Commit { id: self.id, ts: self.ts, signer: self.signer, key: self.key, parts: self.parts }
    }

    /// Its parts and its grant writes as the walk's input: op k is part `parts.len() + k`, along
    /// the path the commit states for its target, the frontier naming commits whole.
    pub fn commit(&self) -> paths::Commit {
        let mut parts = self.parts.clone();
        if let Some(r) = &self.role {
            let list = r.frontier.as_ref().map(|f| Arc::new(paths::List::whole((**f).clone())));
            parts.extend(r.ops.iter().map(|o| paths::Part { on: o.target, path: r.path_to(&o.target).to_vec(), direct: r.direct, kind: paths::PartKind::Grant(paths::GrantWrite { holder: o.holder, value: o.edge, frontier: list.clone() }) }));
        }
        paths::Commit { id: self.id, ts: self.ts, signer: self.signer, key: self.key, parts }
    }
}

/// What the node holds that the walk reads. Applied, verified commits only (pending ones are
/// not held, spec/commits.md §4).
pub trait HeldSet {
    /// The `created.0` record of `thing`, if held.
    fn created(&self, thing: &Tid) -> Option<CreationRecord>;
    /// The held commits signed as `signer`: asked when its record goes.
    fn signed_as(&self, signer: &Tid) -> Vec<CommitId>;
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
    /// Things whose record came or went: their record grant with it.
    pub created: BTreeSet<Tid>,
    /// The held deltas whose verdict may have moved (`Paths::reached`).
    pub reached: BTreeSet<WriteId>,
    /// The grant writes (commit, op) that are new or whose status changed.
    pub ops: BTreeSet<WriteId>,
    /// Of `ops`, those the walk applied before the update.
    pub was_applied: BTreeSet<WriteId>,
    /// The commits given that were not held before.
    pub fresh: BTreeSet<CommitId>,
    /// The things whose held grant writes (`Timeline::held_on`) changed.
    pub held: BTreeSet<Tid>,
    /// The things the timeline came to know or know no more (`Timeline::knows`).
    pub known: BTreeSet<Tid>,
}

impl Changed {
    /// The grants of things (holder, target) whose value at some key changed, a record grant
    /// that came or went aside (`created`). Key grants are no part of a role (spec/permissions.md
    /// §1 Effective role): what they change is the validity `reached` names.
    pub fn edges(&self) -> impl Iterator<Item = (Tid, Tid)> + '_ {
        self.walk.edges.keys().filter_map(|(h, t)| h.thing().map(|h| (h, *t)))
    }
}

/// The timeline over a held set.
#[derive(Clone)]
pub struct Timeline<S: Store = MemStore> {
    paths: Paths<S>,
    records: Records,
    /// The grants of things after every applied write (key grants are the walk's alone).
    now: Edges,
    /// The applied writes on grants of things in key order, each with its edge (holder, target).
    log: BTreeMap<Key, (Tid, Tid)>,
    /// Per target, the things whose grant on it a held grant write sets, applied or not.
    into: BTreeMap<Tid, BTreeSet<Tid>>,
    /// Per target, the keys whose grant on it a held grant write sets, applied or not (never
    /// taken out).
    keys_into: BTreeMap<Tid, BTreeSet<SignKey>>,
    /// Per thing whose record is not held, the held commits with a path member whose record
    /// chain stops at it: given again when the record comes (their hops read the chain).
    waiting: BTreeMap<Tid, BTreeSet<CommitId>>,
    /// The held commits with grant writes, as given: each with its other parts, which its ops
    /// are numbered after in the walk.
    roles: BTreeMap<CommitId, (Arc<RoleCommit>, Vec<paths::Part>)>,
    /// Per target, the held commits with a grant write on it.
    on: BTreeMap<Tid, BTreeSet<CommitId>>,
    /// The trust set as given (`set_trust`): grant writes (commit, op), held or not yet.
    trusted: BTreeSet<WriteId>,
    /// The things a grant write held at some point named as its holder (never taken out: a
    /// superset of those held now).
    holders: BTreeSet<Tid>,
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
        Timeline { paths: Paths::with_store(&BTreeMap::new(), BTreeSet::new(), store), records: Records::default(), now: Edges::default(), log: BTreeMap::new(), into: BTreeMap::new(), keys_into: BTreeMap::new(), waiting: BTreeMap::new(), roles: BTreeMap::new(), on: BTreeMap::new(), trusted: trust.clone(), holders: BTreeSet::new() }
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
    /// thing whose record came or went. A commit read as it was is not taken again (one with
    /// grant writes would have its component walked again from its key), so the update reports
    /// what moved, never what was touched.
    pub fn update(&mut self, held: &dyn HeldSet, commits: &BTreeSet<CommitId>, things: &BTreeSet<Tid>) -> Changed {
        let mut out = Changed::default();
        let (mut came, mut went) = (Vec::new(), Vec::new());
        let was: BTreeMap<Tid, bool> = things.iter().map(|t| (*t, self.knows(t))).collect();
        let mut again: BTreeSet<CommitId> = commits.clone();
        // given again whatever their reading: a record their shape reads moved
        let mut forced: BTreeSet<CommitId> = BTreeSet::new();
        for t in things {
            match (held.created(t).filter(|r| r.tid() == *t), self.records.link(t)) {
                (Some(rec), None) => {
                    self.records.insert(*t, &rec);
                    out.created.insert(*t);
                    came.push((*t, rec.holder()));
                    forced.extend(self.waiting.remove(t).unwrap_or_default());
                }
                (None, Some(_)) => {
                    // a part whose hops read the record grant (a mint admin's, or the record's
                    // key's) loses it: given again
                    if let Some(h) = self.records.holder(t) {
                        forced.extend(self.paths.through(&h, t));
                        went.push((*t, h));
                    }
                    // a commit signed as a thing whose record is not held gives nothing
                    forced.extend(held.signed_as(t));
                    self.records.remove(t);
                    out.created.insert(*t);
                }
                _ => {}
            }
        }
        again.extend(forced.iter().copied());
        let held_on_before: BTreeSet<Tid> = again.iter().filter_map(|c| self.roles.get(c)).flat_map(|(r, _)| r.ops.iter().map(|o| o.target)).collect();
        let mut gone = Vec::new();
        let mut given = Vec::new();
        // per commit read again or gone, the held snapshots carrying it now
        let mut carriers: BTreeMap<CommitId, Vec<WriteId>> = BTreeMap::new();
        let held_before: BTreeSet<CommitId> = again.iter().filter(|c| self.paths.holds(c)).copied().collect();
        for id in &again {
            let now = held.commit(id);
            let was = self.roles.get(id);
            if let (Some(h), Some((role, parts))) = (&now, was)
                && h.role.as_ref().is_some_and(|r| Arc::ptr_eq(r, role) || r == role)
                && h.parts == *parts
                && !forced.contains(id)
            {
                continue;
            }
            if let Some((role, _)) = self.roles.remove(id) {
                for o in &role.ops {
                    out.held.insert(o.target);
                    if let Some(s) = self.on.get_mut(&o.target) {
                        s.remove(id);
                        if s.is_empty() {
                            self.on.remove(&o.target);
                        }
                    }
                }
            }
            match now {
                // signed as a thing whose record is not held: nothing of it is read until that
                // record comes
                Some(h) if self.records.link(&h.signer).is_none() => {
                    self.waiting.entry(h.signer).or_default().insert(*id);
                    carriers.insert(*id, Vec::new());
                    gone.push(*id);
                }
                Some(h) => {
                    if !held_before.contains(id) {
                        out.fresh.insert(*id);
                    }
                    let c = h.commit();
                    // read as it was (a touch that moved nothing the walk reads): not taken again
                    if h.role.is_none() && !forced.contains(id) && self.paths.reads(&c, &h.carriers) {
                        continue;
                    }
                    carriers.insert(*id, h.carriers.clone());
                    self.await_records(&c);
                    if let Some(role) = h.role {
                        for o in &role.ops {
                            out.held.insert(o.target);
                            self.on.entry(o.target).or_default().insert(h.id);
                            match o.holder {
                                Holder::Thing(holder) => {
                                    self.into.entry(o.target).or_default().insert(holder);
                                    self.holders.insert(holder);
                                }
                                Holder::Key(k) => {
                                    self.keys_into.entry(o.target).or_default().insert(k);
                                }
                            }
                        }
                        self.roles.insert(h.id, (role, h.parts));
                    }
                    given.push(c);
                }
                None => {
                    carriers.insert(*id, Vec::new());
                    gone.push(*id);
                }
            }
        }
        // known by a record or a held grant write: a thing whose grant writes changed was known
        // before by those or by its record, which only `things` move
        out.known = was.iter().filter(|(t, w)| self.knows(t) != **w).map(|(t, _)| *t).collect();
        for t in &out.held {
            if !was.contains_key(t) && self.records.link(t).is_none() && self.on.contains_key(t) != held_on_before.contains(t) {
                out.known.insert(*t);
            }
        }
        if came.is_empty() && went.is_empty() && gone.is_empty() && given.is_empty() {
            return out;
        }
        let went_things: Vec<Tid> = went.iter().map(|x| x.0).collect();
        osis_base::costs::count("timeline: commits given", given.len() as u64);
        out.walk = self.paths.sync(&came, &went_things, &gone, &given, &carriers);
        // a trusted write that came or went: the walk's trust set names it by its part
        let named = |c: &CommitId| self.trusted.range(WriteId(*c, 0)..=WriteId(*c, u32::MAX)).next().is_some();
        if given.iter().map(|c| &c.id).chain(&gone).any(named) {
            let trust: BTreeSet<WriteId> = self.trusted.iter().filter_map(|w| self.part_of(w)).collect();
            if trust != *self.paths.trust() {
                let more = self.paths.set_trust(trust);
                merge(&mut out.walk, more);
            }
        }
        // a record grant that came or went does so from the start
        for (t, h) in came.iter().chain(&went) {
            let Holder::Thing(a) = h else { continue };
            let last = self.paths.last(h, t).map(|(_, w)| w.value);
            self.now.set(&self.records, *a, *t, last.unwrap_or(self.records.is_record_edge(a, t).then_some(RECORD_EDGE)));
        }
        self.follow(&mut out);
        out
    }

    /// Whether the timeline holds commit `id` as `held` reads it now: an update naming it would
    /// take nothing (checks that no input of a reading moved unnamed).
    pub fn reads_now(&self, held: &dyn HeldSet, id: &CommitId) -> bool {
        match held.commit(id) {
            None => !self.paths.holds(id) && !self.roles.contains_key(id),
            Some(h) if self.records.link(&h.signer).is_none() => self.waiting.get(&h.signer).is_some_and(|s| s.contains(id)),
            Some(h) => match self.roles.get(id) {
                Some((role, parts)) => h.role.as_ref().is_some_and(|r| r == role) && h.parts == *parts,
                None => h.role.is_none() && self.paths.reads(&h.commit(), &h.carriers),
            },
        }
    }

    /// Replaces the trust set (spec/permissions.md §5.1 Trust set): grant writes (commit, op).
    pub fn set_trust(&mut self, trust: &BTreeSet<WriteId>) -> Changed {
        self.trusted = trust.clone();
        let trust = trust.iter().filter_map(|w| self.part_of(w)).collect();
        let mut out = Changed { walk: self.paths.set_trust(trust), ..Changed::default() };
        self.follow(&mut out);
        out
    }

    /// A timeline holding nothing under this one's trust set (tests: a from-scratch evaluation).
    pub fn emptied(&self) -> Timeline {
        Timeline::new(self.trusted.clone())
    }

    /// The held trusted grant writes.
    pub fn trust(&self) -> BTreeSet<WriteId> {
        self.paths.trust().iter().filter_map(|w| self.op_of(w)).collect()
    }

    /// The held lowerings whose trust would change the reading (`Paths::disputes`).
    pub fn disputes(&mut self) -> BTreeSet<WriteId> {
        self.paths.disputes().iter().filter_map(|w| self.op_of(w)).collect()
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
            let Holder::Thing(h) = h else { continue };
            let stale: Vec<Key> = self.log.range(*k..).filter(|(_, e)| **e == (*h, *t)).map(|(k, _)| *k).collect();
            for k in stale {
                self.log.remove(&k);
            }
            for (key, _) in self.paths.history(&Holder::Thing(*h), t).into_iter().filter(|(key, _)| key >= k) {
                self.log.insert(key, (*h, *t));
            }
            let last = self.paths.last(&Holder::Thing(*h), t).map(|(_, w)| w.value);
            let value = last.unwrap_or(self.records.is_record_edge(h, t).then_some(RECORD_EDGE));
            self.now.set(&self.records, *h, *t, value);
        }
        out.reached = self.paths.reached(&out.walk);
        out.ops = out.walk.parts.iter().filter_map(|w| self.op_of(w)).collect();
        out.was_applied = out.walk.was_applied.iter().filter_map(|w| self.op_of(w)).collect();
    }

    /// The walk's ID of grant write `w` (commit, op).
    fn part_of(&self, w: &WriteId) -> Option<WriteId> {
        let (_, parts) = self.roles.get(&w.0)?;
        Some(WriteId(w.0, u32::try_from(parts.len()).ok()?.checked_add(w.1)?))
    }

    /// The grant write (commit, op) the walk's part `w` is, if one.
    fn op_of(&self, w: &WriteId) -> Option<WriteId> {
        let (_, parts) = self.roles.get(&w.0)?;
        Some(WriteId(w.0, w.1.checked_sub(u32::try_from(parts.len()).ok()?)?))
    }

    // ---- grant writes, each (commit, op) ----

    /// The held commit `id` with grant writes.
    pub fn role_commit(&self, id: &CommitId) -> Option<&Arc<RoleCommit>> {
        self.roles.get(id).map(|x| &x.0)
    }

    /// A grant write held here: its signer, holder and target.
    pub fn edge_op(&self, w: &WriteId) -> Option<(Tid, Holder, Tid)> {
        let c = self.role_commit(&w.0)?;
        let op = c.ops.get(usize::try_from(w.1).ok()?)?;
        Some((c.signer, op.holder, op.target))
    }

    /// The grant writes held on `t`, applied or not, each with its ID, commit and op.
    pub fn held_on<'t>(&'t self, t: &'t Tid) -> impl Iterator<Item = (WriteId, &'t RoleCommit, &'t GrantOp)> + 't {
        self.on.get(t).into_iter().flatten().filter_map(|id| self.roles.get(id)).flat_map(move |(c, _)| (0u32..).zip(&c.ops).filter(move |(_, o)| o.target == *t).map(move |(k, o)| (WriteId(c.id, k), &**c, o)))
    }

    /// `held_on` of `t` by value.
    pub fn held_on_owned(&self, t: Tid) -> impl Iterator<Item = (WriteId, &RoleCommit, &GrantOp)> + '_ {
        self.on.get(&t).into_iter().flatten().filter_map(|id| self.roles.get(id)).flat_map(move |(c, _)| (0u32..).zip(&c.ops).filter(move |(_, o)| o.target == t).map(move |(k, o)| (WriteId(c.id, k), &**c, o)))
    }

    /// The grant writes applied on `t`, each with its commit and op.
    pub fn applied_on<'t>(&'t self, t: &'t Tid) -> impl Iterator<Item = (&'t RoleCommit, &'t GrantOp)> + 't {
        self.held_on(t).filter(|(w, _, _)| self.is_applied(w)).map(|(_, c, o)| (c, o))
    }

    /// What the settled walk did with held grant write `w`.
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

    /// The commits holding the seeds held grant write `w` would have were it trusted
    /// (spec/permissions.md §5.1 Seeds): what Sides' held first reads.
    pub fn seed_commits(&mut self, w: &WriteId) -> BTreeSet<CommitId> {
        match self.part_of(w) {
            Some(p) => self.paths.seed_commits(&p),
            None => BTreeSet::new(),
        }
    }

    /// Whether held grant write `w` would apply at its key were its holder's edge `old` there, the
    /// rest as the walk has it: its verdict over another state of its own edge, such as a second
    /// removal of a holder another write removed first (spec/crypto.md §4, Covers).
    pub fn applies_over(&self, w: &WriteId, old: Option<Grant>) -> bool {
        self.part_of(w).is_some_and(|p| self.paths.would_apply(&p, old))
    }

    /// Applied grant write `w`: what it found on its edge.
    pub fn applied(&self, w: &WriteId) -> Option<paths::Applied> {
        self.paths.applied(&self.part_of(w)?).map(|x| x.1)
    }

    /// Every held grant write the settled walk applies, with its commit's point.
    pub fn applied_writes(&self) -> BTreeMap<WriteId, Point> {
        self.ops().filter(|(w, _)| self.is_applied(w)).collect()
    }

    /// Every held grant write in the drop set, with the point of the lowering whose drops hold it
    /// (a trusted write's seed: its own point).
    pub fn dropped_writes(&self) -> BTreeMap<WriteId, Point> {
        let by = |w: &WriteId| self.part_of(w).and_then(|p| self.paths.dropped_by(&p)).and_then(|d| self.paths.key(&d)).map(point_of);
        self.ops().filter(|(w, _)| self.status(w) == Some(Status::Dropped)).map(|(w, p)| (w, by(&w).unwrap_or(p))).collect()
    }

    /// Every held grant write with its commit's point.
    fn ops(&self) -> impl Iterator<Item = (WriteId, Point)> + '_ {
        self.roles.values().flat_map(|(c, _)| (0u32..).zip(&c.ops).map(move |(k, _)| (WriteId(c.id, k), c.point())))
    }

    /// The commit of the grant write in force on (`holder`, `target`): the last applied one, when
    /// it set a value (spec/permissions.md §2: the next grant write resets the entry it created).
    pub fn in_force(&self, holder: &Holder, target: &Tid) -> Option<CommitId> {
        self.paths.last(holder, target).filter(|(_, a)| a.value.is_some()).map(|(w, _)| w.0)
    }

    /// The verdict part `ix` of `h` (`Held::deltas`) has over what is held, whether `h` is held
    /// or not (`Paths::judge`).
    pub fn judge(&self, h: &paths::Commit, ix: u32) -> Option<paths::Content> {
        self.paths.judge(h, ix)
    }

    /// The grant `key` holds on `thing` after every applied write (§1 Key grant): its last applied
    /// write's value, else the record's key's admin from the start. `until` is not judged here.
    pub fn key_grant(&self, key: &SignKey, thing: &Tid) -> Option<Grant> {
        match self.paths.last(&Holder::Key(*key), thing) {
            Some((_, a)) => a.value,
            None => (self.records.holder(thing) == Some(Holder::Key(*key))).then_some(RECORD_EDGE),
        }
    }

    /// The keys holding a grant on `thing` alive at `ts` (`None`: whatever its `until`), with it
    /// (`key_grant`).
    pub fn key_grants(&self, thing: &Tid, ts: Option<Ts>) -> BTreeMap<SignKey, Grant> {
        let record = self.records.holder(thing).and_then(|h| match h {
            Holder::Key(k) => Some(k),
            Holder::Thing(_) => None,
        });
        let keys = self.keys_into.get(thing).into_iter().flatten().copied().chain(record);
        keys.filter_map(|k| Some((k, self.key_grant(&k, thing).filter(|e| ts.is_none() || e.alive_at(ts))?))).collect()
    }

    /// Whether a held grant write names `t` as its holder.
    pub fn holds_edge(&self, t: &Tid) -> bool {
        self.holders.contains(t)
    }

    /// Whether a thing's record or a grant write on it is held.
    pub fn knows(&self, t: &Tid) -> bool {
        self.records.link(t).is_some() || self.on.contains_key(t)
    }

    /// Every thing with a held record or grant write on it, in tid order.
    pub fn things(&self) -> BTreeSet<Tid> {
        self.records.links().map(|(t, _)| *t).chain(self.on.keys().copied()).collect()
    }

    /// Whether (`holder`, `target`) as restored (§5.1) gives or lets grant more than its value
    /// now: a self-removal, a finalize or a may-grant grant lowered it with no explicit write
    /// since. An expiry by `until` is read from the edge itself.
    pub fn lowered_unaudited(&self, holder: &Tid, target: &Tid) -> bool {
        let v = self.now.get(&self.records, holder, target);
        let (role, grant) = (v.map(|v| v.role), v.filter(|v| v.role == Role::Admin || v.may_grant).map(|v| v.role));
        let (r, g) = self.paths.restored(&Holder::Thing(*holder), target);
        r > role || g > grant
    }

    /// Whether an explicit write of `new` on (`holder`, `target`) at `ts`, after every held
    /// write, takes the edge down (§5.1): the grant as restored gives or lets grant more.
    pub fn audits(&self, holder: &Holder, target: &Tid, new: Option<Grant>, ts: Ts) -> bool {
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
                e.set(*h, *t, self.paths.value_before(&Holder::Thing(*h), t, &k));
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
                if let Some((w, a)) = self.paths.last(&Holder::Thing(*h), t)
                    && self.paths.way(&w) == Some(Way::Finalize)
                {
                    e.set(*h, *t, a.before);
                }
            }
        }
        e
    }

    /// The applied writes on the edges into `thing`, in key order: (key, holder, value).
    fn writes_on(&self, thing: &Tid) -> Vec<(Key, Tid, Option<Grant>)> {
        let mut out: Vec<(Key, Tid, Option<Grant>)> = self.into.get(thing).into_iter().flatten().flat_map(|h| self.paths.history(&Holder::Thing(*h), thing).into_iter().map(|(k, v)| (k, *h, v))).collect();
        out.sort_by_key(|x| x.0);
        out
    }

    /// The roster of `thing` (§5.1): its edges alive at `at`.
    pub fn roster(&self, thing: &Tid, at: At) -> BTreeMap<Tid, Grant> {
        let edges = self.edges_at(at.point);
        edges.holders(thing).filter(|(_, e)| e.alive_at(at.ts)).map(|(m, e)| (*m, *e)).collect()
    }

    /// Each holder of `thing` whose current edge does not say retain (§2), with the point of the
    /// write since which it has held such an edge without a break (`None`: since before every
    /// write: its record grant).
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
            let v = self.paths.last_before(&Holder::Thing(*h), t, &Key { part: k.part.saturating_add(1), ..*k }).and_then(|(_, a)| a.value);
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
    /// of it (or its record grant) gave: lowered, not ended (`ended`).
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
    /// one's edge ended saying retain (`Grant::ends_retaining`), the point of its last write
    /// (`None`: its record grant, never written) and the role the edge last gave (a removal's
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
    pub fn roles_on_now(&self, thing: &Tid, ts: Ts) -> (Arc<BTreeMap<Tid, Role>>, Option<Time>) {
        let edges = self.edges_at(None);
        let (r, u) = View::at(&edges, Some(ts)).roles_to(thing, &BTreeSet::new());
        (Arc::new(r), u)
    }

    /// `roles_on` over the edges not in `skip`, each named (target, holder).
    pub fn roles_on_without(&self, thing: &Tid, at: At, skip: &BTreeSet<(Tid, Tid)>) -> BTreeMap<Tid, Role> {
        let edges = self.edges_at(at.point);
        View::at(&edges, at.ts).roles_to(thing, skip).0
    }

    /// `node`'s effective role on `thing` at `ts` over `edges_unfinalized`.
    pub fn role_unfinalized(&self, node: &Tid, thing: &Tid, ts: Ts) -> Option<Role> {
        let edges = self.edges_unfinalized();
        View::at(&edges, Some(ts)).roles_to(thing, &BTreeSet::new()).0.get(node).copied()
    }

    /// Every thing's way into `thing` giving `need` on the current edges at `ts`
    /// (`graph::Ways`), and the earliest `until` the search followed: the answer holds at any
    /// later ts before it, while no edge changes.
    pub fn ways_now(&self, thing: &Tid, need: Need, ts: Ts) -> (crate::graph::Ways, Option<Time>) {
        let edges = self.edges_at(None);
        View::at(&edges, Some(ts)).ways_to(thing, need)
    }

    /// `node`'s roles over every grant the walk applied, the ended ones included: what it
    /// reached by the paths the held writes show (spec/crypto.md §4 Holders for keys: removals,
    /// finalizes and a retain value end a path; `until` is disregarded). A path may join edges
    /// that never stood at once. O(the applied writes).
    pub fn roles_ever(&self, node: &Tid) -> BTreeMap<Tid, Role> {
        let mut ever = Edges::default();
        for (t, hs) in &self.into {
            for h in hs {
                let best = self.paths.history(&Holder::Thing(*h), t).into_iter().filter_map(|(_, v)| v.filter(|e| !e.says_retain())).max_by_key(|e| e.role);
                if let Some(e) = best {
                    ever.set(&self.records, *h, *t, Some(Grant { until: None, ..e }));
                }
            }
        }
        View::new(&self.records, &ever, Some(Ts::ZERO)).roles_from(node)
    }

    /// `roles_of` over the edges not in `skip`, each named (target, holder).
    pub fn roles_without(&self, node: &Tid, at: At, skip: &BTreeSet<(Tid, Tid)>) -> BTreeMap<Tid, Role> {
        let edges = self.edges_at(at.point);
        View::at(&edges, at.ts).roles_from_without(node, skip)
    }
}

/// Adds what a second update of one reading changed to the first's.
fn merge(w: &mut paths::Changed, o: paths::Changed) {
    let had = w.parts.clone();
    w.parts.extend(o.parts);
    for (e, k) in o.edges {
        let at = w.edges.entry(e).or_insert(k);
        *at = (*at).min(k);
    }
    for (e, k) in o.cuts {
        let at = w.cuts.entry(e).or_insert(k);
        *at = (*at).max(k);
    }
    w.regrant.extend(o.regrant);
    w.named.extend(o.named);
    w.carried.extend(o.carried);
    w.carried.retain(|c| !w.named.contains(c));
    w.purges.extend(o.purges);
    // applied before the first update: the second's reading before is the first's after
    w.was_applied.extend(o.was_applied.into_iter().filter(|p| !had.contains(p)));
}
