//! Writes (notes/api.md Writes): a `Write` becomes one atomic commit over every touched thing, of
//! any size, or fails before anything applies, naming what cannot share a commit (spec/commits.md
//! §5, §6; `Engine::write`). `set` makes a value equal (structural diff, spec/crdt.md §9), `edit`
//! writes only what changed between what the app showed and what the user produced, `overwrite`
//! resets then writes, path ops change one position. Rights are checked locally before signing.
//!
//! A `Write` records its API ops in wire-ready form (`WriteOp`, notes/client-port.md §1), checking
//! each as it is recorded; `commit` builds the engine `Mutation` from them under the lock.

use crate::error::{Error, Result};
use crate::handle::Osis;
use crate::share::Member;
use crate::sources::Source;
use crate::keys::DynamicAspectKey;
use crate::read::{Reader, ak_of};
use osis_base::{Ak, CreationRecord, Role, Tid, Value, Time};
use osis_commit::PurgeItem;
use osis_crdt::{AnyView, Op, PathOp, PathSeg, diff_values};
use crate::commit_id::CommitId;
use osis_node::Mutation;
use osis_schema::{AspectKey, SignalKey, ValueKey};
use osis_schema::core_types::{GROUP, is_role_class};
use osis_schema::{RawKey, Codec, Path, PathError, Retention, Schema, Step, type_at, validate_write};
use crate::commits::Commit;
use std::collections::{BTreeMap, BTreeSet};
use std::ops::Range;
use std::time::Duration;

/// When a commit stops counting: it goes from every node that holds it, by itself (`Write::expires`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Expiry {
    /// At this time.
    At(Time),
    /// This long from now.
    In(Duration),
}

/// What `AspectWrite::purge` drops, for everyone. Each write goes only where the writer may purge
/// it: under retention `author` or `nobody` an admin's request drops nothing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Purge {
    /// The aspect's whole history, and the aspect itself with it.
    All,
    /// One commit's write. Its part stays listed as `Body::Purged` where it would be. If it is what the aspect
    /// reads now the value goes with it: `set` in the same commit to keep a value.
    Commit(CommitId),
    /// Every write by this actor stamped before this commit, those arriving later too. What the
    /// actor writes later stays.
    Author(Tid),
}

/// One API op of a write in wire-ready form: tids resolved, aspects by index into the write's
/// key table (`Write::keys`), values untyped and validated.
#[derive(Clone, Debug)]
pub(crate) enum WriteOp {
    /// A new thing; its record fixes its tid.
    Create(CreationRecord),
    /// Adds (removes) `member` to the items, or the subgroups, of `g`.
    Group { g: Tid, member: Tid, items: bool, add: bool },
    /// An op at a path of a value aspect (whole-value ops at the root).
    Path { tid: Tid, key: u32, op: PathOp },
    /// A fire of a signal with `v`.
    Fire { tid: Tid, key: u32, v: Value },
    /// The aspect's delta in this write has retention `r`.
    Retention { tid: Tid, key: u32, r: Retention },
    /// Purges the aspect's history, removing a value aspect.
    Purge { tid: Tid, key: u32 },
    /// Purges one commit's deltas on the aspect.
    PurgeCommit { tid: Tid, key: u32, commit: osis_base::CommitId },
    /// Purges an author's deltas on the aspect.
    PurgeAuthor { tid: Tid, key: u32, actor: Tid },
    /// Removes the thing's aspects and the memberships this node may remove, as held at commit.
    Delete(Tid),
}

impl WriteOp {
    /// The thing it names; `None` for a create (it goes where its write goes).
    fn tid(&self) -> Option<Tid> {
        match self {
            WriteOp::Create(_) => None,
            WriteOp::Delete(t) | WriteOp::Group { g: t, .. } => Some(*t),
            WriteOp::Path { tid, .. } | WriteOp::Fire { tid, .. } | WriteOp::Retention { tid, .. } | WriteOp::Purge { tid, .. } | WriteOp::PurgeCommit { tid, .. } | WriteOp::PurgeAuthor { tid, .. } => Some(*tid),
        }
    }
}

/// Writes that become one commit (two: below), all or nothing. Reads meanwhile do not see them. What cannot share
/// a commit fails `commit` with `Invalid`, naming what clashed; writing it as several commits is up
/// to the app:
/// - A commit has one expiry: `expires`, else what its keys say, which must then agree. A thing's
///   record never expires, so the commit creating a thing has none: expiring content goes in a
///   later commit.
/// - A write under retention `nobody` shares a commit only with others like it.
/// - A commit is durable or ephemeral (keys marked `+`), and an ephemeral signal (keys marked `+~`)
///   is a commit of its own. A new thing is durable, so ephemeral writes on it go in a later commit.
///
/// This is judged on what the ops ask, not on what they turn out to write: a `set` of the value
/// already there still counts.
///
/// Dropped uncommitted, its writes are lost, and forgetting to commit is a lint:
/// ```compile_fail
/// #![deny(unused_must_use)]
/// let db = osis::Osis::create(osis::Store::Memory(osis::MemStore::new()), &[], osis::Config::default()).unwrap();
/// db.write();
/// ```
#[must_use = "a Write does nothing until commit()"]
pub struct Write<'d> {
    db: &'d Osis,
    ops: Vec<WriteOp>,
    /// The aspect keys the ops name, each once per (AK, schema).
    keys: Vec<DynamicAspectKey>,
    /// `keys` by AK and the address of the writer's schema (0: untyped).
    key_ix: BTreeMap<(Ak, usize), u32>,
    actor: Tid,
    created: Vec<Tid>,
    /// `Write::expires`.
    expires: Option<Expiry>,
    /// A thing that must still be known (`Osis::knows`) when the write commits, checked under
    /// the commit's lock: a text session never recreates a thing deleted since it knew it.
    pub(crate) alive: Option<Tid>,
    /// `Osis::add_with_grant`: a grant follows; no report that holders may not read what this
    /// places.
    pub(crate) sharing: bool,
}

impl Osis {
    /// A new write acting as `me()`.
    pub fn write(&self) -> Write<'_> {
        Write { db: self, ops: Vec::new(), keys: Vec::new(), key_ix: BTreeMap::new(), actor: self.me(), created: Vec::new(), expires: None, alive: None, sharing: false }
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
    let f = if items { crate::internals::GROUP_ITEMS } else { crate::internals::GROUP_SUBGROUPS };
    PathOp { path: vec![PathSeg::Field(f.0)], op: if add { Op::Add(v) } else { Op::Remove(v) } }
}

/// The wall time of `e`; `Invalid` unless it is in the future.
fn expiry_at(db: &Osis, e: Expiry) -> Result<Time> {
    let now = db.now()?;
    let at = match e {
        Expiry::At(t) => t,
        Expiry::In(d) => Time(now.0.saturating_add(u64::try_from(d.as_millis()).unwrap_or(u64::MAX))),
    };
    if at <= now {
        return Err(Error::Invalid(format!("expiry {e:?} is not in the future")));
    }
    Ok(at)
}

impl<'d> Write<'d> {
    /// Writes as `actor` instead of `me()`; this node needs that actor's roles.
    pub fn act_as(&mut self, actor: Tid) -> &mut Self {
        self.actor = actor;
        self
    }

    /// When this commit expires, in place of what its keys say. A later call replaces it. `commit`
    /// fails `Invalid` when the time is not in the future, or beside what cannot expire: a removal
    /// from a group, a `delete`, a purge, or a thing this commit first keeps. A commit writing into
    /// a value that expires sooner (a reaction to a disappearing message) expires with that value,
    /// whatever this says: it means nothing once the value is gone.
    pub fn expires(&mut self, e: Expiry) -> &mut Self {
        self.expires = Some(e);
        self
    }

    /// `t`, failing `UnknownThing` when it is not held; a node it goes to checks at replay.
    fn known(&self, t: Tid) -> Result<Tid> {
        if self.created.contains(&t) || !self.db.is_local(t) || self.db.holds(t) { Ok(t) } else { Err(Error::UnknownThing { tid: t }) }
    }

    /// The index of `key` (AK `ak`) in the key table: one entry, and one copy of its schema,
    /// per (AK, schema) of the write. A schema is told apart by address: keys borrow theirs
    /// from a static or an `Arc` the table shares, so the address is not reused meanwhile.
    fn intern<K: AspectKey>(&mut self, ak: Ak, key: &K) -> u32 {
        let at = key.schema().map_or(0, |s: &Schema| std::ptr::from_ref(s).addr());
        let id = (ak, at);
        if let Some(i) = self.key_ix.get(&id) {
            return *i;
        }
        let i = u32::try_from(self.keys.len()).unwrap_or(u32::MAX);
        self.keys.push(DynamicAspectKey { ak: id.0.clone(), schema: key.shared_schema() });
        self.key_ix.insert(id, i);
        i
    }

    /// A new thing, the acting actor its first admin, stored with this commit. `Invalid` at
    /// commit on a thin client's handle: its actor goes with the client, so what it makes
    /// names who stays (`create_with_admin`).
    pub fn create(&mut self) -> Result<Tid> {
        self.create_with_admin(self.actor)
    }

    /// `create`, with `admin` as the first admin in place of the acting actor: a group or account
    /// this actor may write (`Permission` at commit otherwise). Beside `create` because a thing's
    /// first admin is fixed when it is made: a thin client's things need one that outlives the
    /// client, and a thing made for a group's holders needs no grant to reach them. The first
    /// admin is an ordinary admin, removable like any other (spec/permissions.md §1).
    pub fn create_with_admin(&mut self, admin: Tid) -> Result<Tid> {
        let admin = self.known(admin)?;
        let rec = self.db.engine(|e| e.thing_record(admin));
        let t = rec.tid();
        self.ops.push(WriteOp::Create(rec));
        self.created.push(t);
        Ok(t)
    }

    /// The members of `group`: what it contains, to add or remove.
    pub fn group(&mut self, group: Tid) -> GroupWrite<'_, 'd> {
        GroupWrite { w: self, group }
    }

    fn member(&mut self, g: Tid, m: Member, add: bool) -> Result<()> {
        let g = self.known(g)?;
        let (member, subgroup) = m.parts();
        self.ops.push(WriteOp::Group { g, member, items: !subgroup, add });
        Ok(())
    }

    /// Removes every aspect the node knows of `tid` and its memberships in
    /// every group this node may write (one it may not keeps listing it; it reads deleted
    /// there), as held when the write commits. Afterwards `has_content(tid)` is `false`; the tid stays
    /// valid and a later write recreates the thing. Its ephemeral (`+`) values are dropped here
    /// and not written: other nodes holding them keep them until they restart or the values end
    /// (expiry, their author leaving), in no group they read.
    pub fn delete(&mut self, tid: Tid) -> Result<()> {
        let t = self.known(tid)?;
        self.ops.push(WriteOp::Delete(t));
        Ok(())
    }

    /// A raw path op through `key` (text sessions).
    pub(crate) fn raw_op(&mut self, tid: Tid, key: &DynamicAspectKey, op: PathOp) -> Result<()> {
        let t = self.known(tid)?;
        if let Some(why) = not_writable(key.ak.as_str()) {
            return Err(Error::Invalid(why));
        }
        let key = self.intern(key.ak.clone(), key);
        self.ops.push(WriteOp::Path { tid: t, key, op });
        Ok(())
    }

    /// One aspect of a thing, for whole-value and path ops.
    pub fn at<K: AspectKey>(&mut self, tid: Tid, key: K) -> AspectWrite<'_, 'd, K> {
        let ix = match ak_of(&key) {
            Err(e) => Err(e),
            Ok(ak) => match not_writable(ak.as_str()) {
                Some(why) => Err(Error::Invalid(why)),
                None => Ok(self.intern(ak, &key)),
            },
        };
        AspectWrite { w: self, tid, key, ix }
    }

    /// The things that decide the write's source: those it names but does not create; creates
    /// only: their first admins.
    fn deciders(&self) -> Vec<Tid> {
        let named: Vec<Tid> = self.ops.iter().filter_map(WriteOp::tid).filter(|t| !self.created.contains(t)).collect();
        if !named.is_empty() {
            return named;
        }
        self.ops.iter().filter_map(|o| if let WriteOp::Create(CreationRecord::Thing { admin, .. }) = o { Some(*admin) } else { None }).filter(|t| !self.created.contains(t)).collect()
    }

    /// Writes every op as one commit (two for what `Write` names); `None` when nothing changes. Fails before anything applies
    /// with `Permission`, `UnknownThing`, or `Invalid` (also when the ops cannot share a commit:
    /// `Write`, or past 1024 ops through another node); `OutcomeUnknown`, only through another node,
    /// may have applied: read before repeating it.
    pub fn commit(self) -> Result<Option<Commit>> {
        let deciders = self.deciders();
        if let Source::Node(r) = self.db.source_write_all(&deciders)? {
            let db = self.db;
            if self.alive.is_some() {
                return Err(Error::Unsupported("text sessions through another node".into()));
            }
            return db.node_write(&r, self.wire(&r)?);
        }
        let db = self.db;
        db.after_source();
        let limit = db.inner.limit;
        let expires = self.expires.map(|e| expiry_at(db, e)).transpose()?;
        let (r, removed) = db.locked(|l| {
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
            let who = self.actor;
            let sharing = self.sharing;
            let Built { mut m, added, removed, cut } = self.build(&mut Reader { e, limit, actor }, expires)?;
            let carried = carried_under(e, &cut);
            // whatever actor the write names, an acting handle's write is that actor's alone
            if let Some(a) = actor {
                m.confine(a);
            }
            let r = match e.write(m)? {
                Some(w) => {
                    if !e.holds_memory(&w.id) {
                        not_synced(e, &added, sharing);
                        cut_off(e, carried);
                    }
                    Some(crate::commits::written_in(&mut Reader { e, limit, actor }, w, who)?.reporting(db))
                }
                None => None,
            };
            Ok((r, removed))
        })?;
        db.untie_now(&removed);
        Ok(r)
    }

    /// The write in its wire form (notes/client-port.md §2): `[actor, [ak*], [op*], expires?]`.
    fn wire(&self, there: &crate::port::client::Connection) -> Result<Vec<Value>> {
        use crate::port::codec::{op_v, opt, retention_v, u};
        if self.ops.len() > crate::port::MAX_WRITE_OPS {
            return Err(Error::Invalid(format!("a write to another node holds at most {} ops", crate::port::MAX_WRITE_OPS)));
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
                    WriteOp::Retention { tid, key, r } => vec![u(5), t(*tid), u(u64::from(*key)), retention_v(r)],
                    WriteOp::Purge { tid, key } => vec![u(6), t(*tid), u(u64::from(*key))],
                    WriteOp::Delete(x) => vec![u(7), t(*x)],
                    WriteOp::PurgeCommit { tid, key, commit } => vec![u(8), t(*tid), u(u64::from(*key)), Value::bytes(&commit.0)],
                    WriteOp::PurgeAuthor { tid, key, actor } => vec![u(9), t(*tid), u(u64::from(*key)), t(*actor)],
                    WriteOp::Fire { tid, key, v } => vec![u(10), t(*tid), u(u64::from(*key)), v.clone()],
                }))
            })
            .collect::<Result<Vec<Value>>>()?;
        // not named by `act_as`: whoever this process is at that node
        let actor = if self.actor == self.db.me() { there.acts_as().unwrap_or(self.actor) } else { self.actor };
        let expires = self.expires.map(|e| expiry_at(self.db, e)).transpose()?;
        Ok(vec![t(actor), Value::List(self.keys.iter().map(|k| crate::port::codec::ak_v(&k.ak)).collect()), Value::List(ops), opt(expires, |at| u(at.0))])
    }

    /// The engine mutation of the recorded ops, against the state `r` holds (`delete`).
    fn build(self, r: &mut Reader<'_>, expires: Option<Time>) -> Result<Built> {
        let (acting, db) = (self.db.acting, self.db);
        let Write { ops, keys, actor, created, .. } = self;
        let gk = DynamicAspectKey { ak: Ak::new(GROUP.ak()).unwrap_or_else(|_| unreachable!("a core AK")), schema: Some(crate::keys::core_schema()) };
        let mut b = Built { m: Mutation::new(), added: Vec::new(), removed: Vec::new(), cut: Vec::new() };
        let key = |i: u32| keys.get(i as usize).ok_or_else(|| Error::Invalid("op names no key of its write".into()));
        for op in ops {
            match op {
                WriteOp::Create(rec) => {
                    // the account's nodes administer what a client makes through the groups;
                    // the client's actor goes away with the client (notes/client-port.md §3)
                    if let (Some(a), CreationRecord::Thing { admin, .. }) = (acting, &rec)
                        && *admin == a
                    {
                        return Err(Error::Invalid("a thin client's actor goes with it, so it creates nothing of its own: name a group that stays (create_with_admin)".into()));
                    }
                    b.m.create(rec);
                }
                WriteOp::Group { add: false, .. } | WriteOp::Delete(_) if expires.is_some() => return Err(Error::Invalid("a removal from a group or a delete does not expire: this write has an expiry, so write it as a commit of its own".into())),
                WriteOp::Group { g, member, items, add } => b.group(&gk, g, member, items, add)?,
                // a dynamic key's kind is known only now: a write of the other kind never
                // silently does nothing
                WriteOp::Path { tid, key: k, op } => {
                    let k = key(k)?;
                    if k.signal() {
                        return Err(Error::Invalid(format!("{} is a signal: it is fired, not written (fire)", k.ak)));
                    }
                    b.m.op(tid, k, op)?;
                }
                WriteOp::Fire { tid, key: k, v } => {
                    let k = key(k)?;
                    if !k.signal() {
                        return Err(Error::Invalid(format!("{} is a value aspect: it is written, not fired (set)", k.ak)));
                    }
                    b.m.op(tid, k, PathOp { path: Vec::new(), op: Op::Set(v) })?;
                }
                WriteOp::Retention { tid, key: k, r } => {
                    b.m.retention(tid, key(k)?, r)?;
                }
                // each request carries a delta: a value aspect's removal, else `purge.0`
                WriteOp::Purge { tid, key: k } => {
                    let k = key(k)?;
                    if k.signal() {
                        b.m.op(tid, &osis_schema::core_types::PURGE, PathOp { path: Vec::new(), op: Op::Replace(r.e.now().to_value()) })?;
                    } else {
                        b.m.op(tid, k, PathOp { path: Vec::new(), op: Op::RemoveAspect })?;
                    }
                    b.m.purge(PurgeItem::Aspect { tid, ak: k.ak.clone() });
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
                    // the durable aspects: its ephemeral state is dropped here, not written
                    // (`Mutation::deleting`). Each removal typed as `aspect_key` types it, so it
                    // keeps the history its schema keeps and the delete undoes (spec/crdt.md §4.6)
                    for ak in r.aspects(t)?.iter().filter(|a| !read_only(a.as_str()) && osis_schema::core_types::is_content(a.as_str()) && !a.ephemeral()) {
                        b.m.remove_aspect(t, &db.aspect_key(ak.as_str())?)?;
                    }
                    let gs = r.groups_of(t);
                    let mut writable = |g: &Tid| -> Result<bool> { Ok(*g != t && matches!(r.role_on(*g)?, Some(Role::Write | Role::Admin))) };
                    let mut items = Vec::new();
                    for g in gs.item_of {
                        if writable(&g)? {
                            items.push(g);
                        }
                    }
                    let mut subs = Vec::new();
                    for g in gs.subgroup_of {
                        if writable(&g)? {
                            subs.push(g);
                        }
                    }
                    for (g, items) in items.into_iter().map(|g| (g, true)).chain(subs.into_iter().map(|g| (g, false))) {
                        // as `GroupWrite::remove` would record it
                        if !created.contains(&g) && !r.holds(g) {
                            return Err(Error::UnknownThing { tid: g });
                        }
                        b.group(&gk, g, t, items, false)?;
                    }
                    b.m.deleting(t);
                }
            }
        }
        b.m.act_as(actor);
        if let Some(at) = expires {
            b.m.expires_all(at);
        }
        Ok(b)
    }
}

impl Osis {
    /// Commits a write received in wire form (`Write::wire`) as this node's own: tids resolved
    /// and checked as the recorder checks them locally, keys typed by this node's schemas.
    pub(crate) fn replay(&self, args: Vec<Value>) -> Result<Option<Commit>> {
        use crate::port::codec::{Args, bad, op, retention};
        let mut a = Args::of(args);
        let actor = a.tid()?;
        if self.acting.is_some_and(|x| x != actor) {
            return Err(Error::Invalid("a client writes only as its own actor".into()));
        }
        let keys: Vec<DynamicAspectKey> = a.list()?.iter().map(|v| crate::port::codec::ak(v).and_then(|ak| self.aspect_key(ak.as_str()))).collect::<Result<_>>()?;
        if let Some(why) = keys.iter().find_map(|k| not_writable(k.ak.as_str())) {
            return Err(Error::Invalid(why));
        }
        let raw = a.list()?;
        let expires = a.opt()?.map(|v| crate::port::codec::Args::of(vec![v]).uint().map(|t| Expiry::At(Time(t)))).transpose()?;
        a.end()?;
        if raw.len() > crate::port::MAX_WRITE_OPS {
            return Err(bad("write (too many ops)"));
        }
        let mut w = self.write();
        w.act_as(actor);
        w.expires = expires;
        w.keys = keys;
        let nkeys = w.keys.len();
        let key = |k: u64| u32::try_from(k).ok().filter(|k| (*k as usize) < nkeys).ok_or_else(|| bad("key index"));
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
                5 => WriteOp::Retention { tid: o.tid()?, key: key(o.uint()?)?, r: retention(o.next()?)? },
                6 => WriteOp::Purge { tid: o.tid()?, key: key(o.uint()?)? },
                7 => WriteOp::Delete(w.known(o.tid()?)?),
                8 => WriteOp::PurgeCommit { tid: o.tid()?, key: key(o.uint()?)?, commit: crate::port::codec::raw_commit_id(o.next()?)? },
                9 => WriteOp::PurgeAuthor { tid: o.tid()?, key: key(o.uint()?)?, actor: o.tid()? },
                10 => {
                    let (tid, k, v) = (o.tid()?, key(o.uint()?)?, o.next()?);
                    if self.acting.is_some() && op_links(&PathOp { path: Vec::new(), op: Op::Set(v.clone()) }) {
                        return Err(Error::Invalid("a client writes values, not links".into()));
                    }
                    WriteOp::Fire { tid, key: k, v }
                }
                _ => return Err(bad("op kind")),
            };
            o.end()?;
            w.ops.push(op);
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

/// A write's engine mutation and the memberships its commit acts on.
struct Built {
    m: Mutation,
    /// Things added to groups and the group (the `NotSynced` check).
    added: Vec<(Tid, Tid)>,
    /// (thing, group) memberships removed, items and subgroups: their tied grants go after the
    /// commit where that is a self-removal (`Osis::untie_now`).
    removed: Vec<(Tid, Tid)>,
    /// Subgroups cut from a parent (the `NotSynced` check).
    cut: Vec<Tid>,
}

impl Built {
    fn group(&mut self, gk: &DynamicAspectKey, g: Tid, member: Tid, items: bool, add: bool) -> Result<()> {
        self.m.op(g, gk, group_op(items, member, add))?;
        if items && add {
            self.m.require_synced(member, g);
            self.added.push((member, g));
        }
        if !add {
            self.removed.push((member, g));
            if !items {
                self.cut.push(member);
            }
        }
        Ok(())
    }
}

/// Whether a label carries `t` (a subgroup's own aspects go by its own memberships, not its parents).
fn carried(e: &osis_node::Engine, labeled: &BTreeSet<Tid>, t: &Tid) -> bool {
    labeled.contains(t) || e.groups_of(t).iter().any(|g| labeled.contains(g))
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
/// this node from now on.
fn cut_off(e: &mut osis_node::Engine, was: BTreeSet<Tid>) {
    if was.is_empty() {
        return;
    }
    let labeled: BTreeSet<Tid> = e.labeled_groups().into_iter().collect();
    for t in was {
        if !carried(e, &labeled, &t) {
            e.report(osis_node::Diagnostic { kind: osis_node::DiagnosticKind::NotSynced, tids: vec![t], commit: None, peer: None, detail: "a subgroup left the synced group that held it: this stays on this node".into() });
        }
    }
}

/// Reports added things that no synced group holds (spec/requirements.md, Offline
/// and network).
fn not_synced(e: &mut osis_node::Engine, added: &[(Tid, Tid)], sharing: bool) {
    if added.is_empty() {
        return;
    }
    let labeled = e.labeled_groups();
    for (t, g) in added {
        // entitlement (spec/sync.md §3): the group's holders read what is under it or was given
        if labeled.contains(g) && !e.may_read(&e.group_actor(g), t) {
            if sharing {
                continue;
            }
            e.report(osis_node::Diagnostic { kind: osis_node::DiagnosticKind::NotSynced, tids: vec![*t, *g], commit: None, peer: None, detail: "in a group whose holders may not read it: it does not reach them (add_with_grant)".into() });
        } else if !carried(e, &labeled.iter().copied().collect(), t) {
            e.report(osis_node::Diagnostic { kind: osis_node::DiagnosticKind::NotSynced, tids: vec![*t], commit: None, peer: None, detail: "only in groups no synced group holds: it stays on this node".into() });
        }
    }
}

/// The members of one group inside a `Write`.
pub struct GroupWrite<'w, 'd> {
    w: &'w mut Write<'d>,
    group: Tid,
}

impl<'w, 'd> GroupWrite<'w, 'd> {
    /// Adds a member. A thing becomes a group with its first member. In a commit that expires
    /// (`Write::expires`) the member leaves by itself at that time: a disappearing message leaves
    /// its group.
    ///
    /// A group's items sync only through groups listing it as a subgroup: its members are its
    /// items and its subgroups' members, not its items' items. So when an item is in no synced
    /// group, and the group's own aspects sync (the group is an item of a synced
    /// group, no subgroup of one), the commit fails `Invalid` before anything applies: add the
    /// group as a subgroup too. An item only in groups that do not sync at all (node-local
    /// data) is allowed and reported by a `NotSynced` diagnostic, as is one in a synced group
    /// whose holders may not read it: it does not reach them (`Osis::add_with_grant`).
    pub fn add(&mut self, member: Member) -> Result<()> {
        self.w.member(self.group, member, true)
    }

    /// Removes a member. A grant made with the membership (`Osis::add_with_grant`) goes in a
    /// commit right after when this node may remove it as a self-removal; otherwise a node that
    /// may remove it does so later. What a removed subgroup was the last way into a synced group
    /// for stops syncing, each reported `NotSynced`. `commit` fails `Invalid` in a commit that
    /// expires.
    pub fn remove(&mut self, member: Member) -> Result<()> {
        self.w.member(self.group, member, false)
    }
}

/// Ops on one aspect inside a `Write`.
pub struct AspectWrite<'w, 'd, K> {
    w: &'w mut Write<'d>,
    tid: Tid,
    key: K,
    /// The key's index in the write's key table, or why no op on it may be recorded.
    ix: Result<u32>,
}

impl<'w, 'd, K: AspectKey> AspectWrite<'w, 'd, K> {
    fn ok(&self) -> Result<u32> {
        self.ix.clone()
    }

    fn push(&mut self, op: WriteOp) {
        self.w.ops.push(op);
    }

    /// `v` encoded, validated against the writer's schema.
    fn encoded(&self, v: &K::T) -> Result<Value> {
        self.ok()?;
        let v = self.key.encode(v);
        self.key.validate(&v)?;
        Ok(v)
    }

    /// Drops writes on the aspect for everyone (`Purge`). A request for one commit or one author
    /// is itself a write on the thing, so it fails `Permission` without write on the thing.
    /// `Purge::All` of a value aspect removes it too.
    pub fn purge(&mut self, what: Purge) -> Result<()> {
        if self.key.ephemeral() {
            return Err(Error::Invalid("purge applies to durable aspects only".into()));
        }
        let key = self.ok()?;
        match what {
            Purge::All => self.push(WriteOp::Purge { tid: self.tid, key }),
            Purge::Commit(CommitId(commit)) => self.push(WriteOp::PurgeCommit { tid: self.tid, key, commit }),
            Purge::Author(actor) => self.push(WriteOp::PurgeAuthor { tid: self.tid, key, actor }),
        }
        Ok(())
    }

    /// How this write's history is held, instead of as the key says; checked at commit (`Invalid`).
    pub fn retention(mut self, r: crate::Retention) -> Self {
        if let Ok(key) = self.ix {
            self.push(WriteOp::Retention { tid: self.tid, key, r: r.into() });
        }
        self
    }
}

impl<K: SignalKey> AspectWrite<'_, '_, K> {
    /// Fires the signal with `v`: one commit that `on_fire` hears and, unless the key is
    /// ephemeral, `fired` lists. A signal has no current value, so each fire counts, an equal
    /// value too. A `Write` fires a signal once on a thing; `Invalid` at `commit` on a second
    /// fire, or on a dynamic key of a value aspect.
    pub fn fire(&mut self, v: &K::T) -> Result<()> {
        let v = self.encoded(v)?;
        let key = self.ok()?;
        self.push(WriteOp::Fire { tid: self.tid, key, v });
        Ok(())
    }
}

/// The value writes. `Invalid` at `commit` on a dynamic key of a signal.
impl<'w, 'd, K: ValueKey> AspectWrite<'w, 'd, K> {
    fn op(&mut self, op: PathOp) -> Result<()> {
        let key = self.ok()?;
        self.push(WriteOp::Path { tid: self.tid, key, op });
        Ok(())
    }

    /// A whole-value op of `v`, validated against the writer's schema.
    fn whole(&mut self, v: &K::T, op: fn(Value) -> Op) -> Result<()> {
        let v = self.encoded(v)?;
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

impl<K: ValueKey> PathWrite<'_, '_, '_, K> {
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
