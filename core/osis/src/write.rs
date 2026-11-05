//! Writes (notes/api.md Writes): a `Write` batch becomes one atomic commit over every touched
//! thing, of any size, or one per expiry and per `nobody` or other purgeable-by among its writes
//! (spec/commits.md §5, §6), the creating one first. `set` makes a value equal (structural diff, spec/crdt.md §9), `edit`
//! writes only what changed between what the app showed and what the user produced, `overwrite`
//! resets then writes, path ops change one position. Rights are checked locally before signing.
//!
//! A batch records its API ops in wire-ready form (`WriteOp`, notes/client-port.md §1), checking
//! each as it is recorded; `commit` builds the engine `Mutation` from them under the lock.

use crate::error::{Error, Result};
use crate::handle::Osis;
use crate::share::Member;
use crate::sources::Source;
use crate::keys::Key;
use crate::read::{Reader, ak_of};
use osis_base::{Ak, CreationRecord, Role, Tid, Ts, Value, WallMs};
use osis_commit::PurgeItem;
use osis_crdt::{AnyView, Op, PathOp, PathSeg, diff_values};
use osis_node::{ChangeId, Mutation};
use osis_schema::ApiKey;
use osis_schema::core_types::{GROUP, is_role_class};
use osis_schema::{AspectKey, Codec, Path, PathError, Retention, Schema, Step, type_at, validate_write};
use std::collections::{BTreeMap, BTreeSet};
use std::ops::Range;
use std::time::Duration;

/// A written batch.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Committed {
    /// Its first change, which creates the things the batch creates.
    pub id: ChangeId,
    /// When it was written.
    pub ts: Ts,
    /// Its other changes: writes with different expiries or retention go separately. History
    /// lists each, and `revert` takes each alone.
    pub also: Vec<ChangeId>,
}

/// When a write stops counting: it goes from every node that holds it, by itself. Without one a
/// write expires as its key says.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Expiry {
    /// At this time.
    At(WallMs),
    /// This long from now.
    In(Duration),
}

/// What `AspectWrite::purge` drops, for everyone. Each write goes only where the writer may purge
/// it: under retention `author` or `nobody` an admin's request drops nothing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Purge {
    /// The aspect's whole history, and the aspect itself with it.
    All,
    /// One change's write. Its entry stays in the history as purged. If it is what the aspect
    /// reads now the value goes with it: `set` in the same batch to keep one.
    Change(ChangeId),
    /// Every write by this actor stamped before this commit, those arriving later too. What the
    /// actor writes later stays.
    Author(Tid),
}

/// One API op of a batch in wire-ready form: tids resolved, aspects by index into the batch's
/// key table (`Write::keys`), values untyped and validated, expiry as wall time.
#[derive(Clone, Debug)]
pub(crate) enum WriteOp {
    /// A new thing; its record fixes its tid.
    Create(CreationRecord),
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
    /// Purges one commit's deltas on the aspect.
    PurgeCommit { tid: Tid, key: u32, commit: osis_base::CommitId },
    /// Purges an author's deltas on the aspect.
    PurgeAuthor { tid: Tid, key: u32, actor: Tid },
    /// Removes the thing's aspects and the placements this node may remove, as held at commit.
    Delete(Tid),
}

impl WriteOp {
    /// The thing it names; `None` for a create (it goes where its batch goes).
    fn tid(&self) -> Option<Tid> {
        match self {
            WriteOp::Create(_) => None,
            WriteOp::Delete(t) | WriteOp::Group { g: t, .. } => Some(*t),
            WriteOp::Path { tid, .. } | WriteOp::Expires { tid, .. } | WriteOp::Retention { tid, .. } | WriteOp::Purge { tid, .. } | WriteOp::PurgeCommit { tid, .. } | WriteOp::PurgeAuthor { tid, .. } => Some(*tid),
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
    group_exp: BTreeMap<Tid, Option<Expiry>>,
    /// A thing that must still be known (`Osis::knows`) when the batch commits, checked under
    /// the commit's lock: a text session never recreates a thing deleted since it knew it.
    pub(crate) alive: Option<Tid>,
    /// `Osis::add_with_grant`: a grant follows; no report that holders may not read what this
    /// places.
    pub(crate) sharing: bool,
}

impl Committed {
    pub(crate) fn of(w: osis_node::Written) -> Committed {
        Committed { id: w.id, ts: w.ts, also: w.also.into_iter().map(ChangeId::Commit).collect() }
    }
}

impl Osis {
    /// A new write batch acting as `me()`.
    pub fn write(&self) -> Write<'_> {
        Write { db: self, ops: Vec::new(), keys: Vec::new(), key_ix: BTreeMap::new(), actor: self.me(), created: Vec::new(), group_exp: BTreeMap::new(), alive: None, sharing: false }
    }
}

/// Synthetic aspects and `created.0`: never written by ops.
fn read_only(ak: &str) -> bool {
    matches!(ak, "tid.0" | "aspects.0" | "groups.0" | "created.0")
}

/// Why no op may name `ak`: the engine's, the sharing calls', or a group's members, which change
/// by the group calls alone (they check sync and clean up grants made with the membership).
fn not_writable(ak: &str) -> Option<String> {
    if ak == GROUP.ak() {
        return Some(format!("{ak} is written only by Write::group"));
    }
    (read_only(ak) || is_role_class(ak)).then(|| format!("{ak} is written only by the engine or the sharing calls"))
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

/// The wall time of `e`; `Invalid` unless it is in the future.
fn expiry_at(db: &Osis, e: Expiry) -> Result<WallMs> {
    let now = db.now()?;
    let at = match e {
        Expiry::At(t) => t,
        Expiry::In(d) => WallMs(now.0.saturating_add(u64::try_from(d.as_millis()).unwrap_or(u64::MAX))),
    };
    if at <= now {
        return Err(Error::Invalid(format!("expiry {e:?} is not in the future")));
    }
    Ok(at)
}

/// `group.0` as a key of the shared core schema.
fn group_key() -> Key {
    Key { ak: Ak::new(GROUP.ak()).unwrap_or_else(|_| unreachable!("a core AK")), schema: Some(crate::keys::core_schema()) }
}

/// Records that a batch writes `g`'s `group.0` with expiry `d`; `Invalid` when another write
/// of it in the batch asked for a different one. `true` when this is its first.
fn note_expiry(exp: &mut BTreeMap<Tid, Option<Expiry>>, g: Tid, d: Option<Expiry>) -> Result<bool> {
    match exp.get(&g) {
        Some(x) if *x == d => Ok(false),
        Some(_) => Err(Error::Invalid(format!("this batch writes the members of {g} with different expiries: a batch's writes of a group's members are one write, so use one batch each"))),
        None => {
            exp.insert(g, d);
            Ok(true)
        }
    }
}

impl<'d> Write<'d> {
    /// Writes as `actor` instead of `me()`; this node needs that actor's roles.
    pub fn act_as(&mut self, actor: Tid) -> &mut Self {
        self.actor = actor;
        self
    }

    /// `t`, failing `UnknownThing` when it is not held; a remote node checks at replay.
    fn known(&self, t: Tid) -> Result<Tid> {
        if self.created.contains(&t) || !self.db.is_local(t) || self.db.holds(t) { Ok(t) } else { Err(Error::UnknownThing { tid: t }) }
    }

    /// The index of `key` (AK `ak`) in the key table: one entry, and one copy of its schema,
    /// per (AK, schema) of the batch. A schema is told apart by address: keys borrow theirs
    /// from a static or an `Arc` the table shares, so the address is not reused meanwhile.
    fn intern<K: ApiKey>(&mut self, ak: Ak, key: &K) -> u32 {
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

    /// A new thing, the acting actor its first admin. It is held in memory, and gone at restart,
    /// until its first durable write, which keeps it with its tid and its memberships. `Invalid`
    /// at commit on a thin client's handle: its actor goes with the client, so what it makes
    /// names who stays (`create_with_admin`).
    pub fn create(&mut self) -> Result<Tid> {
        self.create_owned_by(self.actor)
    }

    /// `create`, with `admin` as the first admin in place of the acting actor: a group or account
    /// this actor may write (`Permission` at commit otherwise). Beside `create` because a thing's
    /// first admin is fixed when it is made: a thin client's things need one that outlives the
    /// client, and a thing made for a group's holders needs no grant to reach them.
    // Today `admin` is its owner; the owner work makes this the record's first admin
    // (issues/api-refactor.md Decided).
    pub fn create_with_admin(&mut self, admin: Tid) -> Result<Tid> {
        self.create_owned_by(admin)
    }

    /// A new thing owned by `owner` (fixed forever; needs write on it).
    // Removed with owners (issues/api-refactor.md Decided).
    #[doc(hidden)]
    pub fn create_owned_by(&mut self, owner: Tid) -> Result<Tid> {
        let owner = self.known(owner)?;
        let rec = self.db.engine(|e| e.thing_record(owner));
        let t = rec.tid();
        self.ops.push(WriteOp::Create(rec));
        self.created.push(t);
        Ok(t)
    }

    /// The members of `group`: what it contains, to add or remove.
    pub fn group(&mut self, group: Tid) -> GroupWrite<'_, 'd> {
        GroupWrite { w: self, group }
    }

    /// Records that this batch writes `g`'s `group.0` with expiry `e`; `Invalid` when another
    /// write of it in this batch asked for a different one.
    fn group_expiry(&mut self, g: Tid, e: Option<Expiry>) -> Result<()> {
        if !note_expiry(&mut self.group_exp, g, e)? {
            return Ok(());
        }
        if let Some(e) = e {
            let at = expiry_at(self.db, e)?;
            let key = self.intern(group_key().ak, &group_key());
            self.ops.push(WriteOp::Expires { tid: g, key, at });
        }
        Ok(())
    }

    fn member(&mut self, g: Tid, m: Member, add: bool, e: Option<Expiry>) -> Result<()> {
        let g = self.known(g)?;
        self.group_expiry(g, e)?;
        let (member, subgroup) = m.parts();
        // an ephemeral item's placement is an ephemeral write (notes/ephemeral.md Ephemeral
        // placements): `Engine::write` splits the group ops by what persists
        self.ops.push(WriteOp::Group { g, member, items: !subgroup, add });
        Ok(())
    }

    /// Removes every aspect the node knows of `tid` and its placements and subgroup memberships in
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
        if let Some(why) = not_writable(key.ak.as_str()) {
            return Err(Error::Invalid(why));
        }
        let key = self.intern(key.ak.clone(), key);
        self.ops.push(WriteOp::Path { tid: t, key, op });
        Ok(())
    }

    /// One aspect of a thing, for whole-value and path ops.
    pub fn at<K: ApiKey>(&mut self, tid: Tid, key: K) -> AspectWrite<'_, 'd, K> {
        let ix = match ak_of(&key) {
            Err(e) => Err(e),
            Ok(ak) => match not_writable(ak.as_str()) {
                Some(why) => Err(Error::Invalid(why)),
                None => Ok(self.intern(ak, &key)),
            },
        };
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

    /// Writes every op: the durable ones atomically, as one change per expiry and retention
    /// (`Committed::also`), the ephemeral ones in memory; `None` when nothing changes. Fails before anything applies with `Permission`,
    /// `UnknownThing` or `Invalid`; `OutcomeUnknown`, only through another node, may have applied:
    /// read before repeating it.
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
                && !crate::read::knows_in(e, t)?
            {
                return Err(Error::UnknownThing { tid: t });
            }
            let actor = db.acting;
            let sharing = self.sharing;
            let Built { mut m, placed, unplaced, cut } = self.build(&mut Reader { e, limit, actor })?;
            let carried = carried_under(e, &cut);
            // whatever actor the batch names, an acting handle's write is that actor's alone
            if let Some(a) = actor {
                m.confine(a);
            }
            let r = match e.write(m)? {
                Some(w) => {
                    if w.id.commit().is_some() {
                        not_synced(e, &placed, sharing);
                        cut_off(e, carried);
                    }
                    Some(Committed::of(w))
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
                    WriteOp::Group { g, member, items, add } => vec![u(2), t(*g), t(*member), Value::Bool(*items), Value::Bool(*add)],
                    WriteOp::Path { tid, key, op } => vec![u(3), t(*tid), u(u64::from(*key)), op_v(op)?],
                    WriteOp::Expires { tid, key, at } => vec![u(4), t(*tid), u(u64::from(*key)), u(at.0)],
                    WriteOp::Retention { tid, key, r } => vec![u(5), t(*tid), u(u64::from(*key)), retention_v(r)],
                    WriteOp::Purge { tid, key } => vec![u(6), t(*tid), u(u64::from(*key))],
                    WriteOp::Delete(x) => vec![u(7), t(*x)],
                    WriteOp::PurgeCommit { tid, key, commit } => vec![u(8), t(*tid), u(u64::from(*key)), Value::bytes(&commit.0)],
                    WriteOp::PurgeAuthor { tid, key, actor } => vec![u(9), t(*tid), u(u64::from(*key)), t(*actor)],
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
        let mut b = Built { m: Mutation::new(), placed: Vec::new(), unplaced: Vec::new(), cut: Vec::new() };
        let key = |i: u32| keys.get(i as usize).ok_or_else(|| Error::Invalid("op names no key of its batch".into()));
        for op in ops {
            match op {
                WriteOp::Create(rec) => {
                    // the account's devices administer what a client makes through the groups;
                    // the client's actor goes away with the client (notes/client-port.md §3)
                    if let (Some(a), CreationRecord::Thing { owner, .. }) = (acting, &rec)
                        && *owner == a
                    {
                        return Err(Error::Invalid("a thin client's actor goes with it, so it creates nothing of its own: name a group that stays (create_with_admin)".into()));
                    }
                    b.m.create(rec);
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
                WriteOp::PurgeCommit { tid, key: k, commit } => {
                    b.m.op(tid, &osis_schema::core_types::PURGE, PathOp { path: Vec::new(), op: Op::Replace(r.e.now().to_value()) })?;
                    b.m.purge(PurgeItem::Commit { commit, tid, ak: key(k)?.ak.clone() });
                }
                WriteOp::PurgeAuthor { tid, key: k, actor } => {
                    b.m.op(tid, &osis_schema::core_types::PURGE, PathOp { path: Vec::new(), op: Op::Replace(r.e.now().to_value()) })?;
                    b.m.purge(PurgeItem::Author { tid, ak: key(k)?.ak.clone(), actor });
                }
                WriteOp::Delete(t) => {
                    for ak in r.aspects(t)?.iter().filter(|a| !read_only(a.as_str()) && osis_schema::core_types::is_content(a.as_str())) {
                        // the key decides the side that holds it
                        b.m.remove_aspect(t, ak)?;
                    }
                    let gs = r.groups_of(t);
                    let writable = |r: &Reader<'_>, g: &Tid| matches!(r.role_on(*g), Some(Role::Write | Role::Admin));
                    let items: Vec<Tid> = gs.item_of.into_iter().filter(|g| *g != t && writable(r, g)).collect();
                    let subs: Vec<Tid> = gs.subgroup_of.into_iter().filter(|g| *g != t && writable(r, g)).collect();
                    for (g, items) in items.into_iter().map(|g| (g, true)).chain(subs.into_iter().map(|g| (g, false))) {
                        // as `GroupWrite::remove` would record it
                        if !created.contains(&g) && !r.holds(g) {
                            return Err(Error::UnknownThing { tid: g });
                        }
                        note_expiry(&mut group_exp, g, None)?;
                        b.group(&gk, g, t, items, false)?;
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
    /// and checked as the recorder checks them locally, keys typed by this node's schemas.
    pub(crate) fn replay(&self, args: Vec<Value>) -> Result<Option<Committed>> {
        use crate::port::codec::{Args, bad, op, retention};
        let mut a = Args::of(args);
        let actor = a.tid()?;
        if self.acting.is_some_and(|x| x != actor) {
            return Err(Error::Invalid("a client writes only as its own actor".into()));
        }
        let keys: Vec<Key> = a.list()?.iter().map(|v| crate::port::codec::ak(v).and_then(|ak| self.key(ak.as_str()))).collect::<Result<_>>()?;
        // `group.0` is in the table for a placement's expiry alone (`Write::group_expiry`)
        if let Some(why) = keys.iter().filter(|k| k.ak.as_str() != GROUP.ak()).find_map(|k| not_writable(k.ak.as_str())) {
            return Err(Error::Invalid(why));
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
                    if !matches!(rec, CreationRecord::Thing { .. }) {
                        return Err(bad("creation record"));
                    }
                    w.created.push(rec.tid());
                    WriteOp::Create(rec)
                }
                2 => WriteOp::Group { g: w.known(o.tid()?)?, member: o.tid()?, items: o.bool()?, add: o.bool()? },
                3 => {
                    let (tid, k, p) = (o.tid()?, key(o.uint()?)?, op(o.next()?)?);
                    // a link is the node's: this one would name a blob of something it may not
                    // read, or none at all, for every reader of the aspect
                    if self.acting.is_some() && op_links(&p) {
                        return Err(Error::Invalid("a client writes values, not links".into()));
                    }
                    WriteOp::Path { tid, key: k, op: p }
                }
                4 => {
                    let (tid, k, at) = (o.tid()?, key(o.uint()?)?, WallMs(o.uint()?));
                    expiring.push(tid);
                    WriteOp::Expires { tid, key: k, at }
                }
                5 => WriteOp::Retention { tid: o.tid()?, key: key(o.uint()?)?, r: retention(o.next()?)? },
                6 => WriteOp::Purge { tid: o.tid()?, key: key(o.uint()?)? },
                7 => WriteOp::Delete(w.known(o.tid()?)?),
                8 => WriteOp::PurgeCommit { tid: o.tid()?, key: key(o.uint()?)?, commit: crate::port::codec::commit_id(o.next()?)? },
                9 => WriteOp::PurgeAuthor { tid: o.tid()?, key: key(o.uint()?)?, actor: o.tid()? },
                _ => return Err(bad("op kind")),
            };
            o.end()?;
            if let WriteOp::Path { key: k, .. } | WriteOp::Retention { key: k, .. } | WriteOp::Purge { key: k, .. } | WriteOp::PurgeCommit { key: k, .. } | WriteOp::PurgeAuthor { key: k, .. } = &op
                && let Some(why) = w.keys.get(*k as usize).and_then(|x| not_writable(x.ak.as_str()))
            {
                return Err(Error::Invalid(why));
            }
            // a group written with an expiry: a `delete` of the batch removing a placement there
            // fails as it would locally (`note_expiry`)
            if let WriteOp::Group { g, .. } = &op {
                w.group_exp.entry(*g).or_insert(None);
            }
            w.ops.push(op);
        }
        for g in expiring {
            if let Some(e) = w.group_exp.get_mut(&g) {
                *e = Some(Expiry::In(Duration::MAX));
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
    /// Things placed into groups and the group (the `NotSynced` check).
    placed: Vec<(Tid, Tid)>,
    /// (thing, group) placements and subgroup edges removed: their tied edges go after the
    /// commit where that is a self-removal (`Osis::untie_now`).
    unplaced: Vec<(Tid, Tid)>,
    /// Subgroups cut from a parent (the `NotSynced` check).
    cut: Vec<Tid>,
}

impl Built {
    fn group(&mut self, gk: &Key, g: Tid, member: Tid, items: bool, add: bool) -> Result<()> {
        self.m.op(g, gk, group_op(items, member, add))?;
        if items && add {
            self.m.require_synced(member, g);
            self.placed.push((member, g));
        }
        if !add {
            self.unplaced.push((member, g));
            if !items {
                self.cut.push(member);
            }
        }
        Ok(())
    }
}

/// Whether a label carries `t` (a subgroup's own aspects go by its own placements, not its parents).
fn carried(e: &osis_node::Engine, labeled: &BTreeSet<Tid>, t: &Tid) -> bool {
    labeled.contains(t) || e.durable_groups_of(t).iter().any(|g| labeled.contains(g))
}

/// What the cut subgroups hold that a label carries, before the commit cuts them.
fn carried_under(e: &osis_node::Engine, cut: &[Tid]) -> BTreeSet<Tid> {
    if cut.is_empty() {
        return BTreeSet::new();
    }
    let labeled: BTreeSet<Tid> = e.labeled_groups().into_iter().collect();
    cut.iter().flat_map(|sub| e.closure(sub).iter().filter(|t| *t != sub && carried(e, &labeled, t)).copied().collect::<Vec<_>>()).collect()
}

/// Reports what the commit took out of every synced group, of `was` (`carried_under`): it stays on
/// this device from now on.
fn cut_off(e: &mut osis_node::Engine, was: BTreeSet<Tid>) {
    if was.is_empty() {
        return;
    }
    let labeled: BTreeSet<Tid> = e.labeled_groups().into_iter().collect();
    for t in was {
        if !carried(e, &labeled, &t) {
            e.report(osis_node::Diagnostic { kind: osis_node::DiagnosticKind::NotSynced, tids: vec![t], commit: None, peer: None, detail: "a subgroup left the synced group that held it: this stays on this device".into() });
        }
    }
}

/// Reports things placed only where no synced group holds them (spec/requirements.md, Offline
/// and network): durable closures only, what sync carries.
fn not_synced(e: &mut osis_node::Engine, placed: &[(Tid, Tid)], sharing: bool) {
    if placed.is_empty() {
        return;
    }
    let labeled = e.labeled_groups();
    for (t, g) in placed {
        if e.ephemeral_thing(t).is_some() {
            continue;
        }
        // entitlement (spec/sync.md §3): the group's holders read what it owns or was given
        if labeled.contains(g) && !e.may_read(&e.group_actor(g), t) {
            if sharing {
                continue;
            }
            e.report(osis_node::Diagnostic { kind: osis_node::DiagnosticKind::NotSynced, tids: vec![*t, *g], commit: None, peer: None, detail: "placed in a group whose holders may not read it: it does not reach them (add_with_grant)".into() });
        } else if !(labeled.contains(t) || e.durable_groups_of(t).iter().any(|g| labeled.contains(g))) {
            e.report(osis_node::Diagnostic { kind: osis_node::DiagnosticKind::NotSynced, tids: vec![*t], commit: None, peer: None, detail: "placed only in groups no synced group holds: it stays on this device".into() });
        }
    }
}

/// The members of one group inside a `Write`.
pub struct GroupWrite<'w, 'd> {
    w: &'w mut Write<'d>,
    group: Tid,
}

impl<'w, 'd> GroupWrite<'w, 'd> {
    /// Membership that expires: the member leaves by itself at that time (a disappearing message
    /// leaves its group). A batch's writes of one group's members are one write with one expiry,
    /// so all of them must ask for the same one, else `Invalid`; a removal, which never expires,
    /// goes in another batch. Writes expiring otherwise than the batch's others are a change of
    /// their own (`Committed::also`).
    pub fn expires(self, e: Expiry) -> ExpiringGroupWrite<'w, 'd> {
        ExpiringGroupWrite { w: self.w, group: self.group, e }
    }

    /// Adds a member. A thing becomes a group with its first member. A new thing still in memory
    /// joins in memory, and for good when it is kept; else the add is durable, and keeps the group.
    ///
    /// A group's items sync only through groups listing it as a subgroup: its members are its
    /// items and its subgroups' members, not its items' items. So when an item stays durable, is
    /// in no synced group, and the group's own aspects sync (the group is an item of a synced
    /// group, no subgroup of one), the commit fails `Invalid` before anything applies: add the
    /// group as a subgroup too. An item only in groups that do not sync at all (device-local
    /// data) is allowed and reported by a `NotSynced` diagnostic, as is one in a synced group
    /// whose holders may not read it: it does not reach them (`Osis::add_with_grant`).
    pub fn add(&mut self, member: Member) -> Result<()> {
        self.w.member(self.group, member, true, None)
    }

    /// Removes a member. A grant made with the membership (`Osis::add_with_grant`) goes in a
    /// commit right after when this node may remove it as a self-removal; otherwise a node that
    /// may remove it does so later. What a removed subgroup was the last way into a synced group
    /// for stops syncing, each reported `NotSynced`.
    pub fn remove(&mut self, member: Member) -> Result<()> {
        self.w.member(self.group, member, false, None)
    }
}

/// A group's members, added with an expiry (`GroupWrite::expires`).
pub struct ExpiringGroupWrite<'w, 'd> {
    w: &'w mut Write<'d>,
    group: Tid,
    e: Expiry,
}

impl ExpiringGroupWrite<'_, '_> {
    /// Adds a member, as `GroupWrite::add`, until the expiry.
    pub fn add(&mut self, member: Member) -> Result<()> {
        self.w.member(self.group, member, true, Some(self.e))
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

impl<'w, 'd, K: ApiKey> AspectWrite<'w, 'd, K> {
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

    /// Makes the aspect read `v`, writing only what differs from what it reads now: a value equal
    /// to it writes nothing and tells no one, and a concurrent change inside the value survives,
    /// though a field the app did not touch is written back if it differs. For "must be exactly
    /// this"; what users edit takes `edit`; what must count as written each time, such as a
    /// message in a log, takes `overwrite`.
    ///
    /// The same as `path(Path::root()).set(v)`, but for checking `v`'s type at compile time.
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

    /// Writes `v` whole, always, in place of all the aspect holds: an equal value still counts
    /// as a write, and a concurrent change inside it is lost. A write of a map costs what the
    /// aspect's earlier writes left behind: on an aspect written over and over, write a scalar.
    ///
    /// The same as `path(Path::root()).overwrite(v)`, but for checking `v`'s type at compile time.
    pub fn overwrite(&mut self, v: &K::T) -> Result<()> {
        self.whole(v, Op::Replace)
    }

    /// Removes the aspect, as `path(Path::root()).remove()` does: every position takes `remove`,
    /// and this is its usual one.
    pub fn remove(&mut self) -> Result<()> {
        self.op(PathOp { path: Vec::new(), op: Op::RemoveAspect })
    }

    /// Drops writes on the aspect for everyone (`Purge`). A request for one change or one author
    /// is itself a write on the thing, so it fails `Permission` without write on the thing.
    pub fn purge(&mut self, what: Purge) -> Result<()> {
        if !self.key.lifetime().is_durable() {
            return Err(Error::Invalid("purge applies to durable aspects only".into()));
        }
        let key = self.ok()?;
        match what {
            Purge::All => {
                self.remove()?;
                self.push(WriteOp::Purge { tid: self.tid, key });
            }
            Purge::Change(ChangeId::Commit(commit)) => self.push(WriteOp::PurgeCommit { tid: self.tid, key, commit }),
            Purge::Change(ChangeId::Ephemeral(_)) => return Err(Error::Invalid("an ephemeral batch has no write to purge".into())),
            Purge::Author(actor) => self.push(WriteOp::PurgeAuthor { tid: self.tid, key, actor }),
        }
        Ok(())
    }

    /// When this write expires instead of when the key says. Writes of one batch with different
    /// expiries go as different changes (`Committed::also`): creating a thing with expiring
    /// content takes two, its record first. The following op fails `Invalid` when the time is not
    /// in the future.
    pub fn expires(mut self, e: Expiry) -> Self {
        if let Ok(key) = self.ix {
            match expiry_at(self.w.db, e) {
                Ok(at) => self.push(WriteOp::Expires { tid: self.tid, key, at }),
                Err(x) => self.ix = Err(x),
            }
        }
        self
    }

    /// How this write is kept, instead of as the key says; checked at commit (`Invalid`).
    pub fn retention(mut self, r: Retention) -> Self {
        if let Ok(key) = self.ix {
            self.push(WriteOp::Retention { tid: self.tid, key, r });
        }
        self
    }

    /// A position inside the value, for path ops; the empty path is the whole value. Index paths
    /// resolve at commit time.
    pub fn path(&mut self, p: Path) -> PathWrite<'_, 'w, 'd, K> {
        PathWrite { a: self, path: p }
    }
}

/// Ops at one position inside an aspect.
pub struct PathWrite<'a, 'w, 'd, K> {
    a: &'a mut AspectWrite<'w, 'd, K>,
    path: Path,
}

impl<K: ApiKey> PathWrite<'_, '_, '_, K> {
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

    /// Makes the position read `v`, writing only what differs (`AspectWrite::set`). A map entry
    /// that does not exist yet is made.
    pub fn set<U: Codec>(&mut self, v: &U) -> Result<()> {
        let v = self.checked(None, v)?;
        self.at(None, Op::Set(v))
    }

    /// Writes `v` whole, always, in place of all the position holds (`AspectWrite::overwrite`).
    pub fn overwrite<U: Codec>(&mut self, v: &U) -> Result<()> {
        let v = self.checked(None, v)?;
        self.at(None, Op::Replace(v))
    }

    /// Removes the position: the aspect at the empty path, else a map entry, a set element or a
    /// list element. A range of a list or text: `splice`.
    pub fn remove(&mut self) -> Result<()> {
        let mut parent = self.path.clone();
        let last = parent.0.pop();
        let op = match last {
            None => Op::RemoveAspect,
            Some(Step::Key(k)) => Op::Remove(k),
            Some(Step::Elem(e)) => Op::Remove(e),
            Some(Step::Index(i)) => Op::Delete { at: i, len: 1 },
            _ => return Err(Error::Invalid("only a map entry, set element or list element can be removed (remove() the aspect, or set the field)".into())),
        };
        PathWrite { a: &mut *self.a, path: parent }.at(None, op)
    }

    /// Replaces the visible range of a list or text with `items`: a slice of items in a list, a
    /// `&str` in text, `()` for nothing, which deletes. An empty range inserts.
    pub fn splice(&mut self, r: Range<usize>, items: impl SpliceItems) -> Result<()> {
        if r.start > r.end {
            return Err(Error::Invalid(format!("bad range {r:?}")));
        }
        let items = match items.items() {
            Items::Text(s) => {
                self.not_a_list()?;
                if s.is_empty() { Vec::new() } else { vec![Value::Str(s)] }
            }
            Items::List(l) => {
                for v in &l {
                    self.check(Some(Step::Index(0)), v)?;
                }
                l
            }
        };
        if !r.is_empty() {
            self.at(None, Op::Delete { at: r.start, len: r.len() })?;
        }
        if items.is_empty() {
            return Ok(());
        }
        self.at(None, Op::Insert { at: r.start, items })
    }

    /// `Invalid` where the key's schema says a list: its items are no text.
    fn not_a_list(&self) -> Result<()> {
        let (Some(s), Some(t)) = (self.a.key.schema(), self.position_type()?) else { return Ok(()) };
        if matches!(s.expand(&t).as_deref(), Ok(osis_schema::Type::List(_))) {
            return Err(Error::Invalid("a list takes a slice of items, not a string".into()));
        }
        Ok(())
    }

    /// List or text: moves the range so it starts at index `to` of the sequence without it.
    pub fn move_range(&mut self, r: Range<usize>, to: usize) -> Result<()> {
        if r.start > r.end {
            return Err(Error::Invalid(format!("backward range {r:?}")));
        }
        self.at(None, Op::Move { at: r.start, len: r.len(), to })
    }

    /// Set: adds `v`.
    pub fn add<U: Codec>(&mut self, v: &U) -> Result<()> {
        let v = v.to_value();
        self.check(Some(Step::Elem(v.clone())), &v)?;
        self.at(None, Op::Add(v))
    }

    /// Counter: adds `v` (int or float). Max or min: records `v` as an observation. Both are one
    /// contribution: concurrent ones all count.
    pub fn contribute<U: Codec>(&mut self, v: &U) -> Result<()> {
        self.at(None, Op::Inc(v.to_value()))
    }
}

/// What `PathWrite::splice` puts into a sequence: a slice of items in a list, a `&str` in text,
/// `()` for nothing.
pub trait SpliceItems: seal::Sealed {
    #[doc(hidden)]
    fn items(self) -> Items;
}

mod seal {
    pub trait Sealed {}
}

#[doc(hidden)]
pub enum Items {
    Text(String),
    List(Vec<Value>),
}

fn list<U: Codec>(items: &[U]) -> Items {
    Items::List(items.iter().map(Codec::to_value).collect())
}

impl seal::Sealed for () {}
impl SpliceItems for () {
    fn items(self) -> Items {
        Items::List(Vec::new())
    }
}
impl seal::Sealed for &str {}
impl SpliceItems for &str {
    fn items(self) -> Items {
        Items::Text(self.to_string())
    }
}
impl<U: Codec> seal::Sealed for &[U] {}
impl<U: Codec> SpliceItems for &[U] {
    fn items(self) -> Items {
        list(self)
    }
}
impl<U: Codec, const N: usize> seal::Sealed for &[U; N] {}
impl<U: Codec, const N: usize> SpliceItems for &[U; N] {
    fn items(self) -> Items {
        list(self)
    }
}
impl<U: Codec> seal::Sealed for &Vec<U> {}
impl<U: Codec> SpliceItems for &Vec<U> {
    fn items(self) -> Items {
        list(self)
    }
}
