//! Writes (notes/api.md Writes): a `Write` batch becomes one atomic commit over every touched
//! thing, of any size. `set` makes a value equal (structural diff, spec/crdt.md §9), `edit`
//! writes only what changed between what the app showed and what the user produced, `replace`
//! resets then writes, path ops change one position. Rights are checked locally before signing.
//!
//! A batch records its API ops in wire-ready form (`WriteOp`, notes/client-port.md §1), checking
//! each as it is recorded; `commit` builds the engine `Mutation` from them under the lock.

use crate::error::{Error, Result};
use crate::handle::Osis;
use crate::sources::Source;
use crate::keys::Key;
use crate::read::{Reader, ak_of};
use osis_base::{Ak, CreationRecord, Role, Tid, Ts, Value, WallMs};
use osis_commit::PurgeItem;
use osis_crdt::{AnyView, Op, PathOp, PathSeg, diff_values};
use osis_node::{ChangeId, Mutation};
use osis_schema::core_types::{GROUP, PLACED, is_role_class};
use osis_schema::{AspectKey, CaseId, Codec, Path, PathError, Retention, Schema, Step, type_at, validate_write};
use std::collections::BTreeMap;
use std::ops::Range;
use std::time::Duration;

/// A written batch: its commit, or its ephemeral batch when it had no durable half
/// (notes/ephemeral.md).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Committed {
    pub id: ChangeId,
    pub ts: Ts,
}

/// One API op of a batch in wire-ready form: tids resolved, aspects by index into the batch's
/// key table (`Write::keys`), values untyped and validated, expiry as wall time.
#[derive(Clone, Debug)]
pub(crate) enum WriteOp {
    /// A new thing; its record fixes its tid.
    Create(CreationRecord),
    /// An empty `group.0` (the thing was no group when recorded).
    MakeGroup(Tid),
    /// Adds (removes) `member` to the items, or the subgroups, of `g`.
    Group { g: Tid, member: Tid, items: bool, add: bool },
    /// An op at a path of an aspect (whole-value ops at the root).
    Path { tid: Tid, key: u32, op: PathOp },
    /// The aspect's delta in this batch expires at `at`.
    Expires { tid: Tid, key: u32, at: WallMs },
    /// The aspect's delta in this batch has retention `r`.
    Retention { tid: Tid, key: u32, r: Retention },
    /// Purges the aspect's history (after its removal, recorded before).
    Purge { tid: Tid, key: u32 },
    /// Removes the thing's aspects and the placements this node may remove, as held at commit.
    Delete(Tid),
}

impl WriteOp {
    /// The thing it names; `None` for a create (it goes where its batch goes).
    fn tid(&self) -> Option<Tid> {
        match self {
            WriteOp::Create(_) => None,
            WriteOp::MakeGroup(t) | WriteOp::Delete(t) | WriteOp::Group { g: t, .. } => Some(*t),
            WriteOp::Path { tid, .. } | WriteOp::Expires { tid, .. } | WriteOp::Retention { tid, .. } | WriteOp::Purge { tid, .. } => Some(*tid),
        }
    }
}

/// A batch of writes: its durable ops become one commit, its ephemeral ops (keys declared
/// `ephemeral` or `signal`) apply in memory, all or nothing. Reads see written state only.
#[must_use = "a Write does nothing until commit()"]
pub struct Write<'d> {
    db: &'d Osis,
    ops: Vec<WriteOp>,
    /// The aspect keys the ops name, each once per (AK, schema).
    keys: Vec<Key>,
    /// `keys` by AK and the address of the writer's schema (0: untyped).
    key_ix: BTreeMap<(Ak, usize), u32>,
    actor: Tid,
    created: Vec<Tid>,
    /// Per group whose `group.0` this batch writes through the group calls: the expiry those
    /// writes asked for. Expiry is per aspect write, so one batch cannot mix them.
    group_exp: BTreeMap<Tid, Option<Duration>>,
    /// A thing that must still be known (`Osis::knows`) when the batch commits, checked under
    /// the commit's lock: a text session never recreates a thing deleted since it knew it.
    pub(crate) alive: Option<Tid>,
}

impl Osis {
    /// A new write batch acting as `me()`.
    pub fn write(&self) -> Write<'_> {
        Write { db: self, ops: Vec::new(), keys: Vec::new(), key_ix: BTreeMap::new(), actor: self.me(), created: Vec::new(), group_exp: BTreeMap::new(), alive: None }
    }

    /// Runs `f` on a new batch and commits it if `f` succeeds; returns what `f` returned (the
    /// commit itself: `write()` and `commit()`).
    pub fn write_with<R>(&self, f: impl FnOnce(&mut Write<'_>) -> Result<R>) -> Result<R> {
        let mut w = self.write();
        let r = f(&mut w)?;
        w.commit()?;
        Ok(r)
    }
}

/// Synthetic aspects and `created.0`: never written by ops.
fn read_only(ak: &str) -> bool {
    matches!(ak, "tid.0" | "aspects.0" | "groups.0" | "created.0")
}

pub(crate) fn segs(p: &Path) -> Result<Vec<PathSeg>> {
    p.0.iter()
        .map(|s| match s {
            Step::Field(id) => Ok(PathSeg::Field(*id)),
            Step::Case(id) => Ok(PathSeg::Case(*id)),
            Step::Key(k) => Ok(PathSeg::Key(k.clone())),
            Step::Index(i) => Ok(PathSeg::Index(*i)),
            Step::Elem(_) => Err(Error::Invalid("a set element is atomic: no path into it".into())),
        })
        .collect()
}

pub(crate) fn group_op(items: bool, member: Tid, add: bool) -> PathOp {
    let v = Value::Tid(member);
    let f = if items { crate::core::group::ITEMS } else { crate::core::group::SUBGROUPS };
    PathOp { path: vec![PathSeg::Field(f.0)], op: if add { Op::Add(v) } else { Op::Remove(v) } }
}

/// The wall time `d` from now; `Invalid` for a zero duration (an expiry must be in the future).
fn expiry_in(db: &Osis, d: Duration) -> Result<WallMs> {
    let ms = u64::try_from(d.as_millis()).unwrap_or(u64::MAX);
    if ms == 0 {
        return Err(Error::Invalid("expiry 0 ms is not in the future".into()));
    }
    Ok(WallMs(db.now().0.saturating_add(ms)))
}

/// `group.0` as a key of the shared core schema.
fn group_key() -> Key {
    Key { ak: Ak::new(GROUP.ak()).unwrap_or_else(|_| unreachable!("a core AK")), schema: Some(crate::keys::core_schema()) }
}

/// Records that a batch writes `g`'s `group.0` with expiry `d`; `Invalid` when another write
/// of it in the batch asked for a different one. `true` when this is its first.
fn note_expiry(exp: &mut BTreeMap<Tid, Option<Duration>>, g: Tid, d: Option<Duration>) -> Result<bool> {
    match exp.get(&g) {
        Some(x) if *x == d => Ok(false),
        Some(_) => Err(Error::Invalid(format!("this batch writes the groups of {g} with different expiries (expiry is per aspect write): use one batch each"))),
        None => {
            exp.insert(g, d);
            Ok(true)
        }
    }
}

impl<'d> Write<'d> {
    /// Acts for `actor` instead of `me()` (header actor; this node needs its rights).
    pub fn act_as(&mut self, actor: Tid) -> &mut Self {
        self.actor = actor;
        self
    }

    /// `t` after moves; recorded as given when the batch goes to a remote node, which
    /// resolves it as it replays the batch (`Osis::replay`).
    fn resolve(&self, t: Tid) -> Tid {
        if self.created.contains(&t) || !self.db.is_local(t) { t } else { self.db.read_local(|r| r.resolve(t)) }
    }

    /// `t` resolved, failing `UnknownThing` when it is not held; a remote node checks at replay.
    fn known(&self, t: Tid) -> Result<Tid> {
        let t = self.resolve(t);
        if self.created.contains(&t) || !self.db.is_local(t) || self.db.holds(t) { Ok(t) } else { Err(Error::UnknownThing { tid: t }) }
    }

    /// The index of `key` (AK `ak`) in the key table: one entry, and one copy of its schema,
    /// per (AK, schema) of the batch. A schema is told apart by address: keys borrow theirs
    /// from a static or an `Arc` the table shares, so the address is not reused meanwhile.
    fn intern<K: AspectKey>(&mut self, ak: Ak, key: &K) -> u32 {
        let at = key.schema().map_or(0, |s: &Schema| std::ptr::from_ref(s).addr());
        let id = (ak, at);
        if let Some(i) = self.key_ix.get(&id) {
            return *i;
        }
        let i = u32::try_from(self.keys.len()).unwrap_or(u32::MAX);
        self.keys.push(Key { ak: id.0.clone(), schema: key.shared_schema() });
        self.key_ix.insert(id, i);
        i
    }

    /// A new thing owned by `owner` (fixed forever; needs write on it). It is ephemeral (in
    /// memory, gone at restart) until its first durable write, which persists it with its owner
    /// chain and its placements, keeping its tid. Group ops in the same batch place it
    /// atomically; placing an ephemeral thing is an ephemeral write of the group.
    pub fn create(&mut self, owner: Tid) -> Result<Tid> {
        let owner = self.known(owner)?;
        let rec = self.db.engine(|e| e.thing_record(owner));
        let t = rec.tid();
        self.ops.push(WriteOp::Create(rec));
        self.created.push(t);
        Ok(t)
    }

    /// Gives `tid` an empty `group.0` if it is no group yet (neither `group.0` nor ephemeral
    /// placements, `placed.0~`).
    pub fn make_group(&mut self, tid: Tid) -> Result<()> {
        let t = self.known(tid)?;
        if !self.created.contains(&t) && (self.db.get(t, GROUP)?.is_some() || self.db.get(t, PLACED)?.is_some()) {
            return Ok(());
        }
        self.group_expiry(t, None)?;
        self.ops.push(WriteOp::MakeGroup(t));
        Ok(())
    }

    /// Records that this batch writes `g`'s `group.0` with expiry `d`; `Invalid` when another
    /// write of it in this batch asked for a different one.
    fn group_expiry(&mut self, g: Tid, d: Option<Duration>) -> Result<()> {
        if !note_expiry(&mut self.group_exp, g, d)? {
            return Ok(());
        }
        if let Some(d) = d {
            let at = expiry_in(self.db, d)?;
            let key = self.intern(group_key().ak, &group_key());
            self.ops.push(WriteOp::Expires { tid: g, key, at });
        }
        Ok(())
    }

    fn group(&mut self, g: Tid, items: bool, member: Tid, add: bool, exp: Option<Duration>) -> Result<()> {
        let g = self.known(g)?;
        let member = self.resolve(member);
        self.group_expiry(g, exp)?;
        // an ephemeral item's placement is an ephemeral write (notes/ephemeral.md Ephemeral
        // placements): `Engine::write` splits the group ops by what persists
        self.ops.push(WriteOp::Group { g, member, items, add });
        Ok(())
    }

    /// Adds `tid` to the items of group `g`: an ephemeral write while `tid` stays ephemeral
    /// (made durable when it persists), else a durable one (persisting `g`). A group's items
    /// sync only through groups listing it as a subgroup (its members are its items and its
    /// subgroups' members, not its items' items). So when `tid` is durable after the commit and
    /// reaches no synced group while `g`'s own aspects sync (`g` is an item of a synced group,
    /// not a subgroup of one), the commit fails `Invalid` before anything applies: add `g` as a
    /// subgroup too. A placement only in groups that do not sync at all (device-local data) is
    /// allowed and reported by a `NotSynced` diagnostic.
    pub fn place(&mut self, tid: Tid, g: Tid) -> Result<()> {
        self.place_expiring(tid, g, None)
    }
    /// `place` whose placement expires after `expires` (`None`: never). Expiry is per aspect
    /// write, so every group call on `g` in this batch must ask for the same expiry (else
    /// `Invalid`).
    pub fn place_expiring(&mut self, tid: Tid, g: Tid, expires: Option<Duration>) -> Result<()> {
        self.group(g, true, tid, true, expires)
    }
    /// Removes `tid` from the items of `g`. A tied edge of `g` on `tid` (`Osis::share_into`)
    /// goes in a commit right after when this node may remove it as a self-removal (admin on `g`
    /// only); otherwise a node that may remove it does so later (spec/permissions.md §2).
    pub fn unplace(&mut self, tid: Tid, g: Tid) -> Result<()> {
        self.group(g, true, tid, false, None)
    }
    pub fn add_subgroup(&mut self, g: Tid, sub: Tid) -> Result<()> {
        self.group(g, false, sub, true, None)
    }
    /// Removes `sub` from the subgroups of `g`; its tied edge as `unplace`'s.
    pub fn remove_subgroup(&mut self, g: Tid, sub: Tid) -> Result<()> {
        self.group(g, false, sub, false, None)
    }

    /// Removes every aspect the node knows of `tid` and its placements and subgroup edges in
    /// every group this node may write (one it may not keeps listing it; it reads deleted
    /// there), as held when the batch commits. Afterwards `knows(tid)` is `false`; the tid stays
    /// valid and a later write recreates the thing.
    pub fn delete(&mut self, tid: Tid) -> Result<()> {
        let t = self.known(tid)?;
        self.ops.push(WriteOp::Delete(t));
        Ok(())
    }

    /// A raw path op through `key` (text sessions).
    pub(crate) fn raw_op(&mut self, tid: Tid, key: &Key, op: PathOp) -> Result<()> {
        let t = self.known(tid)?;
        let key = self.intern(key.ak.clone(), key);
        self.ops.push(WriteOp::Path { tid: t, key, op });
        Ok(())
    }

    /// One aspect of a thing, for whole-value and path ops.
    pub fn at<K: AspectKey>(&mut self, tid: Tid, key: K) -> AspectWrite<'_, 'd, K> {
        let ix = match ak_of(&key) {
            Err(e) => Err(e),
            Ok(ak) if read_only(ak.as_str()) || is_role_class(ak.as_str()) => Err(Error::Invalid(format!("{ak} is written only by the engine or the sharing calls"))),
            Ok(ak) => Ok(self.intern(ak, &key)),
        };
        let tid = self.resolve(tid);
        AspectWrite { w: self, tid, key, ix }
    }

    /// The things that decide the batch's source: those it names but does not create; creates
    /// only: their owners.
    fn deciders(&self) -> Vec<Tid> {
        let named: Vec<Tid> = self.ops.iter().filter_map(WriteOp::tid).filter(|t| !self.created.contains(t)).collect();
        if !named.is_empty() {
            return named;
        }
        self.ops.iter().filter_map(|o| if let WriteOp::Create(CreationRecord::Thing { owner, .. }) = o { Some(*owner) } else { None }).filter(|t| !self.created.contains(t)).collect()
    }

    /// Writes every op: the durable ones as one atomic commit, the ephemeral ones in memory;
    /// `None` when nothing changes. Fails before anything applies with `Permission`,
    /// `UnknownThing` or `Invalid`; `OutcomeUnknown`, only through another node, may have applied:
    /// read before repeating it (crate::port::client).
    pub fn commit(self) -> Result<Option<Committed>> {
        let deciders = self.deciders();
        if let Source::Remote(r) = self.db.route_write_all(&deciders)? {
            let db = self.db;
            if self.alive.is_some() {
                return Err(Error::Unsupported("text sessions through a remote node".into()));
            }
            return db.remote_write(&r, self.wire(&r)?);
        }
        let db = self.db;
        db.after_route();
        let limit = db.inner.limit;
        let (r, unplaced) = db.locked(|l| {
            // the routing invariant's second half: under the lock this commit takes, every thing it
            // writes is still this engine's. A write decided Local before a move fails here, never
            // lands in a group that no longer syncs (crate::sources)
            db.guard_local(l, &deciders)?;
            let e = l.engine();
            if let Some(t) = self.alive
                && !crate::read::knows_in(e, t)
            {
                return Err(Error::UnknownThing { tid: t });
            }
            let actor = db.acting;
            let Built { mut m, placed, unplaced } = self.build(&mut Reader { e, limit, actor })?;
            // whatever actor the batch names, an acting handle's write is that actor's alone
            if let Some(a) = actor {
                m.confine(a);
            }
            let r = match e.write(m)? {
                Some(w) => {
                    if w.id.commit().is_some() {
                        not_synced(e, &placed);
                    }
                    Some(Committed { id: w.id, ts: w.ts })
                }
                None => None,
            };
            Ok((r, unplaced))
        })?;
        db.untie_now(&unplaced);
        Ok(r)
    }

    /// The batch in its wire form (notes/client-port.md §2): `[actor, [ak*], [op*]]`.
    fn wire(&self, there: &crate::port::client::Remote) -> Result<Vec<Value>> {
        use crate::port::codec::{op_v, retention_v, u};
        if self.ops.len() > crate::port::MAX_BATCH_OPS {
            return Err(Error::Invalid(format!("a batch to a remote node holds at most {} ops", crate::port::MAX_BATCH_OPS)));
        }
        let t = Value::Tid;
        let ops = self
            .ops
            .iter()
            .map(|o| {
                Ok(Value::List(match o {
                    WriteOp::Create(rec) => vec![u(0), rec.to_value()],
                    WriteOp::MakeGroup(g) => vec![u(1), t(*g)],
                    WriteOp::Group { g, member, items, add } => vec![u(2), t(*g), t(*member), Value::Bool(*items), Value::Bool(*add)],
                    WriteOp::Path { tid, key, op } => vec![u(3), t(*tid), u(u64::from(*key)), op_v(op)?],
                    WriteOp::Expires { tid, key, at } => vec![u(4), t(*tid), u(u64::from(*key)), u(at.0)],
                    WriteOp::Retention { tid, key, r } => vec![u(5), t(*tid), u(u64::from(*key)), retention_v(r)],
                    WriteOp::Purge { tid, key } => vec![u(6), t(*tid), u(u64::from(*key))],
                    WriteOp::Delete(x) => vec![u(7), t(*x)],
                }))
            })
            .collect::<Result<Vec<Value>>>()?;
        // not named by `act_as`: whoever this process is at that node
        let actor = if self.actor == self.db.me() { there.acts_as().unwrap_or(self.actor) } else { self.actor };
        Ok(vec![t(actor), Value::List(self.keys.iter().map(|k| crate::port::codec::ak_v(&k.ak)).collect()), Value::List(ops)])
    }

    /// The engine mutation of the recorded ops, against the state `r` holds (`delete`).
    fn build(self, r: &mut Reader<'_>) -> Result<Built> {
        let acting = self.db.acting;
        let Write { ops, keys, actor, created, mut group_exp, .. } = self;
        let gk = std::cell::LazyCell::new(group_key);
        let mut b = Built { m: Mutation::new(), placed: Vec::new(), unplaced: Vec::new() };
        let key = |i: u32| keys.get(i as usize).ok_or_else(|| Error::Invalid("op names no key of its batch".into()));
        for op in ops {
            match op {
                WriteOp::Create(rec) => {
                    // the account's devices administer what a client makes through the groups;
                    // the client's actor goes away with the client (notes/client-port.md §3)
                    if let (Some(a), CreationRecord::Thing { owner, .. }) = (acting, &rec)
                        && *owner == a
                    {
                        return Err(Error::Invalid("an acting actor owns nothing: a thing it creates has another owner".into()));
                    }
                    b.m.create(rec);
                }
                WriteOp::MakeGroup(t) => {
                    b.m.op(t, &*gk, PathOp { path: Vec::new(), op: Op::Set(osis_schema::core_types::Group::default().to_value()) })?;
                }
                WriteOp::Group { g, member, items, add } => b.group(&gk, g, member, items, add)?,
                WriteOp::Path { tid, key: k, op } => {
                    b.m.op(tid, key(k)?, op)?;
                }
                WriteOp::Expires { tid, key: k, at } => {
                    b.m.expires(tid, key(k)?, at)?;
                }
                WriteOp::Retention { tid, key: k, r } => {
                    b.m.retention(tid, key(k)?, r)?;
                }
                WriteOp::Purge { tid, key: k } => {
                    b.m.purge(PurgeItem::Aspect { tid, ak: key(k)?.ak.clone() });
                }
                WriteOp::Delete(t) => {
                    for ak in r.aspects(t)?.iter().filter(|a| !read_only(a.as_str()) && !is_role_class(a.as_str())) {
                        // the key decides the side that holds it
                        b.m.remove_aspect(t, ak)?;
                    }
                    let gs = r.groups_of(t);
                    let writable = |r: &Reader<'_>, g: &Tid| matches!(r.role_on(*g), Some(Role::Write | Role::Admin));
                    let items: Vec<Tid> = gs.item_of.into_iter().filter(|g| *g != t && writable(r, g)).collect();
                    let subs: Vec<Tid> = gs.subgroup_of.into_iter().filter(|g| *g != t && writable(r, g)).collect();
                    for (g, items) in items.into_iter().map(|g| (g, true)).chain(subs.into_iter().map(|g| (g, false))) {
                        // as `unplace` / `remove_subgroup` would record it
                        let g = if created.contains(&g) { g } else { r.resolve(g) };
                        if !created.contains(&g) && !r.holds(g) {
                            return Err(Error::UnknownThing { tid: g });
                        }
                        let member = if created.contains(&t) { t } else { r.resolve(t) };
                        note_expiry(&mut group_exp, g, None)?;
                        b.group(&gk, g, member, items, false)?;
                    }
                    b.m.free(t);
                }
            }
        }
        b.m.act_as(actor);
        Ok(b)
    }
}

impl Osis {
    /// Commits a batch received in wire form (`Write::wire`) as this node's own: tids resolved
    /// and checked as the recorder checks them locally, keys typed by this node's schemas, a
    /// `make_group` of what already is a group dropped.
    pub(crate) fn replay(&self, args: Vec<Value>) -> Result<Option<Committed>> {
        use crate::port::codec::{Args, bad, op, retention};
        let mut a = Args::of(args);
        let actor = a.tid()?;
        if self.acting.is_some_and(|x| x != actor) {
            return Err(Error::Invalid("a client writes only as its own actor".into()));
        }
        let keys: Vec<Key> = a.list()?.iter().map(|v| crate::port::codec::ak(v).and_then(|ak| self.key(ak.as_str()))).collect::<Result<_>>()?;
        if let Some(k) = keys.iter().find(|k| read_only(k.ak.as_str()) || is_role_class(k.ak.as_str())) {
            return Err(Error::Invalid(format!("{} is written only by the engine or the sharing calls", k.ak)));
        }
        let raw = a.list()?;
        a.end()?;
        if raw.len() > crate::port::MAX_BATCH_OPS {
            return Err(bad("batch (too many ops)"));
        }
        let mut w = self.write();
        w.act_as(actor);
        w.keys = keys;
        let nkeys = w.keys.len();
        let key = |k: u64| u32::try_from(k).ok().filter(|k| (*k as usize) < nkeys).ok_or_else(|| bad("key index"));
        let mut expiring = Vec::new();
        for o in raw {
            let mut o = Args::new(o)?;
            let op = match o.uint()? {
                0 => {
                    let rec = CreationRecord::from_value(&o.next()?).ok_or_else(|| bad("creation record"))?;
                    if !matches!(rec, CreationRecord::Thing { creator: None, .. }) {
                        return Err(bad("creation record"));
                    }
                    w.created.push(rec.tid());
                    WriteOp::Create(rec)
                }
                1 => {
                    let g = w.known(o.tid()?)?;
                    if !w.created.contains(&g) && (self.get(g, GROUP)?.is_some() || self.get(g, PLACED)?.is_some()) {
                        continue;
                    }
                    WriteOp::MakeGroup(g)
                }
                2 => WriteOp::Group { g: w.known(o.tid()?)?, member: w.resolve(o.tid()?), items: o.bool()?, add: o.bool()? },
                3 => {
                    let (tid, k, p) = (w.resolve(o.tid()?), key(o.uint()?)?, op(o.next()?)?);
                    // a link is the node's: this one would name a blob of something it may not
                    // read, or none at all, for every reader of the aspect
                    if self.acting.is_some() && op_links(&p) {
                        return Err(Error::Invalid("a client writes values, not links".into()));
                    }
                    WriteOp::Path { tid, key: k, op: p }
                }
                4 => {
                    let (tid, k, at) = (w.resolve(o.tid()?), key(o.uint()?)?, WallMs(o.uint()?));
                    expiring.push(tid);
                    WriteOp::Expires { tid, key: k, at }
                }
                5 => WriteOp::Retention { tid: w.resolve(o.tid()?), key: key(o.uint()?)?, r: retention(o.next()?)? },
                6 => WriteOp::Purge { tid: w.resolve(o.tid()?), key: key(o.uint()?)? },
                7 => WriteOp::Delete(w.known(o.tid()?)?),
                _ => return Err(bad("op kind")),
            };
            o.end()?;
            // a group written with an expiry: a `delete` of the batch removing a placement there
            // fails as it would locally (`note_expiry`)
            if let WriteOp::Group { g, .. } | WriteOp::MakeGroup(g) = &op {
                w.group_exp.entry(*g).or_insert(None);
            }
            w.ops.push(op);
        }
        for g in expiring {
            if let Some(e) = w.group_exp.get_mut(&g) {
                *e = Some(Duration::MAX);
            }
        }
        for t in w.ops.iter().filter_map(WriteOp::tid).collect::<Vec<_>>() {
            w.known(t)?;
        }
        w.commit()
    }
}

/// Whether `p` holds a link, in its path or its values.
fn op_links(p: &PathOp) -> bool {
    fn link(v: &Value) -> bool {
        match v {
            Value::Link(_) => true,
            Value::List(l) => l.iter().any(link),
            Value::Set(s) => s.iter().any(link),
            Value::Map(m) => m.iter().any(|(k, x)| link(k) || link(x)),
            Value::Enum(_, Some(x)) => link(x),
            _ => false,
        }
    }
    p.path.iter().any(|s| matches!(s, PathSeg::Key(k) if link(k)))
        || match &p.op {
            Op::Set(v) | Op::Replace(v) | Op::Put(v) | Op::Add(v) | Op::Remove(v) | Op::Inc(v) => link(v),
            Op::Insert { items, .. } | Op::InsertAfter { items, .. } => items.iter().any(link),
            Op::Edit { base, new } => link(base) || link(new),
            Op::RemoveAspect | Op::Delete { .. } | Op::DeleteDots { .. } | Op::Move { .. } | Op::Paste { .. } => false,
        }
}

/// A batch's engine mutation and the placements its commit acts on.
struct Built {
    m: Mutation,
    /// Things placed into groups (the `NotSynced` check).
    placed: Vec<Tid>,
    /// (thing, group) placements and subgroup edges removed: their tied edges go after the
    /// commit where that is a self-removal (`Osis::untie_now`).
    unplaced: Vec<(Tid, Tid)>,
}

impl Built {
    fn group(&mut self, gk: &Key, g: Tid, member: Tid, items: bool, add: bool) -> Result<()> {
        self.m.op(g, gk, group_op(items, member, add))?;
        if items && add {
            self.m.require_synced(member, g);
            self.placed.push(member);
        }
        if !add {
            self.unplaced.push((member, g));
        }
        Ok(())
    }
}

/// Reports things placed only where no synced group holds them (spec/requirements.md, Offline
/// and network): durable closures only, what sync carries.
fn not_synced(e: &mut osis_node::Engine, placed: &[Tid]) {
    if placed.is_empty() {
        return;
    }
    let labeled = e.labeled_groups();
    for t in placed {
        if e.ephemeral_thing(t).is_some() || labeled.contains(t) || e.durable_groups_of(t).iter().any(|g| labeled.contains(g)) {
            continue;
        }
        e.report(osis_node::Diagnostic { kind: osis_node::DiagnosticKind::NotSynced, tids: vec![*t], commit: None, peer: None, detail: "placed only in groups no synced group holds: it stays on this device".into() });
    }
}

/// Ops on one aspect inside a `Write`.
pub struct AspectWrite<'w, 'd, K> {
    w: &'w mut Write<'d>,
    tid: Tid,
    key: K,
    /// The key's index in the batch's key table, or why no op on it may be recorded.
    ix: Result<u32>,
}

impl<'w, 'd, K: AspectKey> AspectWrite<'w, 'd, K> {
    fn ok(&self) -> Result<u32> {
        self.ix.clone()
    }

    fn push(&mut self, op: WriteOp) {
        self.w.ops.push(op);
    }

    fn op(&mut self, op: PathOp) -> Result<()> {
        let key = self.ok()?;
        self.push(WriteOp::Path { tid: self.tid, key, op });
        Ok(())
    }

    /// A whole-value op of `v`, validated against the writer's schema.
    fn whole(&mut self, v: &K::T, op: fn(Value) -> Op) -> Result<()> {
        self.ok()?;
        let v = self.key.encode(v);
        self.key.validate(&v)?;
        self.op(PathOp { path: Vec::new(), op: op(v) })
    }

    /// Makes the aspect read `v` (structural diff against the current state: a concurrent
    /// edit inside the value survives, but a field the app did not touch is written back if
    /// it differs from the current state). For "must be exactly this"; interactive edits use
    /// `edit`.
    pub fn set(&mut self, v: &K::T) -> Result<()> {
        self.whole(v, Op::Set)
    }

    /// Writes only what differs between `base` (what the app showed) and `new` (what the user
    /// produced), as path ops against the current state: a remote change made meanwhile to
    /// anything the user did not touch is kept.
    pub fn edit(&mut self, base: &K::T, new: &K::T) -> Result<()> {
        self.ok()?;
        let (b, n) = (self.key.encode(base), self.key.encode(new));
        self.key.validate(&n)?;
        let ak = ak_of(&self.key)?;
        let ops = match self.key.schema().and_then(|s| s.view(ak.as_str())) {
            Some(v) => diff_values(Some(&b), &n, &v),
            None => diff_values(Some(&b), &n, &AnyView),
        }
        .map_err(|e| Error::Invalid(e.to_string()))?;
        for op in ops {
            self.op(op)?;
        }
        Ok(())
    }

    /// Resets the aspect, then writes `v` (discards concurrent edits inside it).
    pub fn replace(&mut self, v: &K::T) -> Result<()> {
        self.whole(v, Op::Replace)
    }

    /// Removes the aspect.
    pub fn remove(&mut self) -> Result<()> {
        self.op(PathOp { path: Vec::new(), op: Op::RemoveAspect })
    }

    /// Counter increment (or max/min observation) at the root.
    pub fn inc<U: Codec>(&mut self, n: &U) -> Result<()> {
        self.path(Path::root()).inc(n)
    }

    /// Drops the aspect's whole history wherever the author may purge it (spec/commits.md §5,
    /// spec/permissions.md §8) and removes the aspect, in this commit.
    pub fn purge(&mut self) -> Result<()> {
        if !self.key.lifetime().is_durable() {
            return Err(Error::Invalid("purge applies to durable aspects only".into()));
        }
        self.remove()?;
        let key = self.ok()?;
        self.push(WriteOp::Purge { tid: self.tid, key });
        Ok(())
    }

    /// This write's delta expires at `t` (spec/commits.md §6); default from the key.
    /// Fails the following op with `Invalid` when `t` is not in the future.
    pub fn expires_at(mut self, t: WallMs) -> Self {
        if let Ok(key) = self.ix {
            if t <= self.w.db.now() {
                self.ix = Err(Error::Invalid(format!("expiry {} ms is not in the future", t.0)));
            } else {
                self.push(WriteOp::Expires { tid: self.tid, key, at: t });
            }
        }
        self
    }

    /// This write's delta expires `d` from now.
    pub fn expires_in(self, d: Duration) -> Self {
        self.expires(Some(d))
    }

    /// `expires_in(d)` for `Some(d)`; `None` keeps the key's default.
    pub fn expires(mut self, d: Option<Duration>) -> Self {
        match d.map(|d| expiry_in(self.w.db, d)) {
            None => self,
            Some(Ok(t)) => self.expires_at(t),
            Some(Err(e)) => {
                if self.ix.is_ok() {
                    self.ix = Err(e);
                }
                self
            }
        }
    }

    /// Retention of this write's delta instead of the key's default (spec/commits.md §5);
    /// checked at commit (`Invalid`).
    pub fn retention(mut self, r: Retention) -> Self {
        if let Ok(key) = self.ix {
            self.push(WriteOp::Retention { tid: self.tid, key, r });
        }
        self
    }

    /// A position inside the value, for path ops. Index paths resolve at commit time.
    pub fn path(&mut self, p: Path) -> PathWrite<'_, 'w, 'd, K> {
        PathWrite { a: self, path: p }
    }
}

/// Ops at one position inside an aspect.
pub struct PathWrite<'a, 'w, 'd, K> {
    a: &'a mut AspectWrite<'w, 'd, K>,
    path: Path,
}

impl<K: AspectKey> PathWrite<'_, '_, '_, K> {
    fn at(&mut self, extra: Option<PathSeg>, op: Op) -> Result<()> {
        let mut path = segs(&self.path)?;
        path.extend(extra);
        self.a.op(PathOp { path, op })
    }

    /// Validates `v` against the writer's schema at the path (plus one step).
    fn check(&self, extra: Option<Step>, v: &Value) -> Result<()> {
        let (Some(s), Some(ty)) = (self.a.key.schema(), self.a.key.ty()) else { return Ok(()) };
        let mut p = self.path.clone();
        p.0.extend(extra);
        let (t, _) = type_at(s, ty, &p)?;
        // the error's path from the aspect's root, not from this position
        validate_write(s, v, &t).map_err(|e| PathError::new(Path(self.path.0.iter().cloned().chain(e.path.0.iter().cloned()).collect()), e.kind))?;
        Ok(())
    }

    fn checked<U: Codec>(&self, extra: Option<Step>, v: &U) -> Result<Value> {
        let v = v.to_value();
        self.check(extra, &v)?;
        Ok(v)
    }

    /// The key's schema type at this position (`None`: untyped).
    pub(crate) fn position_type(&self) -> Result<Option<osis_schema::Type>> {
        crate::large::type_of(&self.a.key, &self.path)
    }

    /// `set` of an untyped value, checked against the schema.
    pub(crate) fn set_value(&mut self, v: Value) -> Result<()> {
        self.check(None, &v)?;
        self.at(None, Op::Set(v))
    }

    /// Makes the position read `v` (structural diff).
    pub fn set<U: Codec>(&mut self, v: &U) -> Result<()> {
        let v = self.checked(None, v)?;
        self.at(None, Op::Set(v))
    }

    /// Resets the position, then writes `v`.
    pub fn replace<U: Codec>(&mut self, v: &U) -> Result<()> {
        let v = self.checked(None, v)?;
        self.at(None, Op::Replace(v))
    }

    /// Removes the position: a map entry, a set element or a list element.
    pub fn remove(&mut self) -> Result<()> {
        let mut parent = self.path.clone();
        let last = parent.0.pop();
        let op = match last {
            Some(Step::Key(k)) => Op::Remove(k),
            Some(Step::Elem(e)) => Op::Remove(e),
            Some(Step::Index(i)) => Op::Delete { at: i, len: 1 },
            _ => return Err(Error::Invalid("only a map entry, set element or list element can be removed (remove() the aspect, or set the field)".into())),
        };
        PathWrite { a: &mut *self.a, path: parent }.at(None, op)
    }

    /// Sets an enum position to `case` with an optional payload.
    pub fn set_case(&mut self, case: CaseId, payload: Option<Value>) -> Result<()> {
        self.set_value(Value::Enum(case.0, payload.map(Box::new)))
    }

    /// List: inserts `items` before visible index `at`.
    pub fn insert<U: Codec>(&mut self, at: usize, items: &[U]) -> Result<()> {
        let items = items.iter().map(|x| self.checked(Some(Step::Index(0)), x)).collect::<Result<Vec<_>>>()?;
        self.at(None, Op::Insert { at, items })
    }

    /// List or text: deletes the visible range.
    pub fn delete(&mut self, r: Range<usize>) -> Result<()> {
        self.at(None, Op::Delete { at: r.start, len: r.len() })
    }

    /// List or text: moves the range so it starts at index `to` of the sequence without it.
    pub fn move_range(&mut self, r: Range<usize>, to: usize) -> Result<()> {
        self.at(None, Op::Move { at: r.start, len: r.len(), to })
    }

    /// Text: replaces the range with `s`.
    pub fn splice(&mut self, r: Range<usize>, s: &str) -> Result<()> {
        if !r.is_empty() {
            self.delete(r.clone())?;
        }
        if s.is_empty() {
            return Ok(());
        }
        self.at(None, Op::Insert { at: r.start, items: vec![Value::Str(s.into())] })
    }

    /// Set: adds `v`.
    pub fn add<U: Codec>(&mut self, v: &U) -> Result<()> {
        let v = v.to_value();
        self.check(Some(Step::Elem(v.clone())), &v)?;
        self.at(None, Op::Add(v))
    }

    /// Set: removes `v`.
    pub fn remove_elem<U: Codec>(&mut self, v: &U) -> Result<()> {
        self.at(None, Op::Remove(v.to_value()))
    }

    /// Map: makes entry `k` read `v`.
    pub fn put<Kk: Codec, U: Codec>(&mut self, k: &Kk, v: &U) -> Result<()> {
        let k = k.to_value();
        let v = self.checked(Some(Step::Key(k.clone())), v)?;
        self.at(Some(PathSeg::Key(k)), Op::Set(v))
    }

    /// Map: removes entry `k`.
    pub fn remove_key<Kk: Codec>(&mut self, k: &Kk) -> Result<()> {
        self.at(None, Op::Remove(k.to_value()))
    }

    /// Counter: adds `n` (int or float).
    pub fn inc<U: Codec>(&mut self, n: &U) -> Result<()> {
        self.at(None, Op::Inc(n.to_value()))
    }

    /// Max/min: observes `v`.
    pub fn observe<U: Codec>(&mut self, v: &U) -> Result<()> {
        self.at(None, Op::Inc(v.to_value()))
    }
}
