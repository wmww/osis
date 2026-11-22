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
use crate::keys::DynamicAspectKey;
use crate::read::{Reader, ak_of};
use osis_base::{Ak, CreationRecord, Ref, Strong, Tid, Value, Time, Weak};
use osis_commit::PurgeItem;
use osis_crdt::{AnyView, Op, PathOp, PathSeg, diff_values};
use crate::commit_id::CommitId;
use osis_engine::Mutation;
use osis_schema::{AspectKey, SignalKey, ValueKey};
use osis_schema::core_types::is_role_class;
use osis_schema::{RawKey, Codec, Path, PathError, PurgeBy, Schema, Step, type_at, validate_write};
use crate::commits::Commit;
use std::collections::BTreeMap;
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
/// it (its purge-by; admins always may).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Purge {
    /// The aspect's whole history, and the aspect with it: it reads as absent.
    All,
    /// One commit's write. Its part stays listed as `Body::Purged` where it would be. If it is what the aspect
    /// reads now the value goes with it: `set` in the same commit to keep a value. A signal's fire
    /// goes with every replacement of it held here (`replace`): a replacement written meanwhile
    /// elsewhere, or later, still shows. A commit unknown here is refused (`Invalid`): this node
    /// holds nothing of that commit (never received, or forgotten once nothing of it was left).
    Commit(CommitId),
    /// Every write by this author (`Stamp::author`) stamped before this commit, those arriving
    /// later too. What the author writes later stays.
    Author(Tid),
}

/// One API op of a write in wire-ready form: tids resolved, aspects by index into the write's
/// key table (`Write::keys`), values untyped and validated.
#[derive(Clone, Debug)]
pub(crate) enum WriteOp {
    /// A new thing; its record fixes its tid.
    Create(CreationRecord),
    /// An op at a path of a value aspect (whole-value ops at the root).
    Path { tid: Tid, key: u32, op: PathOp },
    /// A fire of a signal with `v`, replacing fire `replaces`.
    Fire { tid: Tid, key: u32, v: Value, replaces: Option<osis_base::CommitId> },
    /// The aspect's delta in this write is purgeable by `by`.
    PurgeBy { tid: Tid, key: u32, by: PurgeBy },
    /// Purges the aspect's history, removing a value aspect.
    Purge { tid: Tid, key: u32 },
    /// Purges one commit's deltas on the aspect.
    PurgeCommit { tid: Tid, key: u32, commit: osis_base::CommitId },
    /// Purges an author's deltas on the aspect.
    PurgeAuthor { tid: Tid, key: u32, author: Tid },
    /// Destroys the thing for everyone: purges its creation.
    PurgeThing(Tid),
}

/// Writes that become one commit (two: below), all or nothing. Reads meanwhile do not see them. What cannot share
/// a commit fails `commit` with `Invalid`, naming what clashed; writing it as several commits is up
/// to the app:
/// - A commit has one expiry: `expires`, else that of a thing it creates (`create`), else what
///   its keys say, which must then agree.
/// - A commit is durable or ephemeral (keys marked `+`; a purge is durable whatever it names), and
///   an ephemeral signal (keys marked `+~`) is a commit of its own. A new thing is durable, so ephemeral writes on it go in a later commit.
///
/// This is judged on what the ops ask, not on what they turn out to write: a `set` of the value
/// already there still counts.
///
/// Dropped uncommitted, its writes are lost, and forgetting to commit is a lint:
/// ```compile_fail
/// #![deny(unused_must_use)]
/// let db = osis::Osis::create(osis::Store::Memory(osis::MemStore::new()), osis::Config::default()).unwrap();
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
    /// Why a chained modifier (`purge_by`) could not be recorded: `commit` fails
    /// with it.
    refused: Option<Error>,
}

impl Osis {
    /// A new write acting as `me()`.
    pub fn write(&self) -> Write<'_> {
        Write { db: self, ops: Vec::new(), keys: Vec::new(), key_ix: BTreeMap::new(), actor: self.me(), created: Vec::new(), expires: None, alive: None, refused: None }
    }
}

/// Synthetic aspects and `created.0`: never written by ops.
fn read_only(ak: &str) -> bool {
    matches!(ak, "aspects.0" | "created.0")
}

/// Why no op may name `ak`: the engine's or the sharing calls'.
fn not_writable(ak: &str) -> Option<String> {
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
    /// The handle this write commits on (`internals::Held`).
    pub(crate) fn db(&self) -> &'d Osis {
        self.db
    }

    /// Writes as `actor` instead of `me()`; this node needs that actor's roles.
    pub fn act_as(&mut self, actor: Tid) -> &mut Self {
        self.actor = actor;
        self
    }

    /// When this commit expires, in place of what its keys say. A later call replaces it. `commit`
    /// fails `Invalid` when the time is not in the future, or beside what cannot expire: a `purge`
    /// of a thing, or a purge naming anything but commits expiring no
    /// later on a thing the write also writes. A commit writing into
    /// a value that expires sooner (a reaction to a disappearing message) expires with that value,
    /// whatever this says: it means nothing once the value is gone.
    pub fn expires(&mut self, e: Expiry) -> &mut Self {
        self.expires = Some(e);
        self
    }

    /// `t`, failing `UnknownThing` when it is not held; one at another node is that node's to
    /// judge, at commit.
    fn known(&self, t: Tid) -> Result<Tid> {
        if self.created.contains(&t) || matches!(self.db.source(t)?, crate::sources::Source::Node(_)) || self.db.has_record(t) { Ok(t) } else { Err(Error::UnknownThing { tid: t }) }
    }

    /// The things the ops name: where the write goes.
    pub(crate) fn things(&self) -> Vec<Tid> {
        let mut ts: Vec<Tid> = self
            .ops
            .iter()
            .flat_map(|o| match o {
                WriteOp::Create(r) => match r {
                    CreationRecord::Thing { admin, .. } => vec![r.tid(), *admin],
                    CreationRecord::KeyActor { .. } => vec![r.tid()],
                },
                WriteOp::Path { tid, .. } | WriteOp::Fire { tid, .. } | WriteOp::PurgeBy { tid, .. } | WriteOp::Purge { tid, .. } | WriteOp::PurgeCommit { tid, .. } | WriteOp::PurgeAuthor { tid, .. } => vec![*tid],
                WriteOp::PurgeThing(t) => vec![*t],
            })
            .filter(|t| !self.created.contains(t))
            .collect();
        ts.sort();
        ts.dedup();
        ts
    }

    /// Per thing written, the targets of the strongs its ops write (spec/sync-set.md §2 Not
    /// carried): O(the ops' values).
    fn strongs_written(&self) -> BTreeMap<Tid, std::collections::BTreeSet<Tid>> {
        let mut out: BTreeMap<Tid, std::collections::BTreeSet<Tid>> = BTreeMap::new();
        for o in &self.ops {
            let (tid, vals): (Tid, Vec<&Value>) = match o {
                WriteOp::Path { tid, op, .. } => {
                    let mut v: Vec<&Value> = op.path.iter().filter_map(|s| if let PathSeg::Key(k) = s { Some(k) } else { None }).collect();
                    match &op.op {
                        Op::Set(x) | Op::Replace(x) | Op::Put(x) | Op::Add(x) | Op::Inc(x) | Op::Edit { new: x, .. } => v.push(x),
                        Op::Insert { items, .. } | Op::InsertAfter { items, .. } => v.extend(items),
                        _ => {}
                    }
                    (*tid, v)
                }
                WriteOp::Fire { tid, v, .. } => (*tid, vec![v]),
                _ => continue,
            };
            for v in vals {
                osis_engine::strongs_in(v, out.entry(tid).or_default());
            }
        }
        out.retain(|_, t| !t.is_empty());
        out
    }

    /// The write as the client port carries it (`WRITE`, notes/client-port.md §2): `[actor,
    /// [ak*], [op*], Opt(expiry)]`, the nonce put before it as it is sent; an expiry `[0, at]`
    /// or `[1, ms from now]`.
    fn wire(self) -> Result<Vec<Value>> {
        use crate::port::codec::{Form, write_op_to};
        let aks: Vec<Ak> = self.keys.iter().map(|k| k.ak.clone()).collect();
        let ops = self.ops.iter().map(write_op_to).collect::<Result<Vec<_>>>()?;
        Ok(vec![self.actor.to_wire(), aks.to_wire(), Value::List(ops), self.expires.to_wire()])
    }

    /// The write a client port's `WRITE` carries (`wire`), on `db`, its keys typed as `db` types
    /// them; refused past `MAX_WRITE_OPS` ops.
    pub(crate) fn from_wire(db: &'d Osis, args: Vec<Value>) -> Result<Write<'d>> {
        use crate::port::codec::{Form, write_op_from};
        let (actor, aks, ops, expires): (Tid, Vec<Ak>, Vec<Value>, Option<Expiry>) = Form::from_wire(Value::List(args))?;
        if ops.len() > crate::port::MAX_WRITE_OPS {
            return Err(Error::Invalid(format!("a write through another node has at most {} ops", crate::port::MAX_WRITE_OPS)));
        }
        let mut w = db.write();
        w.actor = actor;
        w.expires = expires;
        for a in aks {
            let k = db.aspect_key(a.as_str())?;
            let i = u32::try_from(w.keys.len()).unwrap_or(u32::MAX);
            w.key_ix.insert((a, 0), i);
            w.keys.push(k);
        }
        for o in ops {
            let o = write_op_from(o)?;
            if let WriteOp::Create(r) = &o {
                w.created.push(r.tid());
            }
            w.ops.push(o);
        }
        Ok(w)
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

    /// A new thing with admin `admin` (its mint admin), stored with this commit: a thing or account
    /// this actor may write (`Permission` at commit otherwise). The mint admin is an ordinary
    /// admin, removable like any other (spec/permissions.md §1).
    ///
    /// With `expires` the thing ends then, whole, at every node, and nothing can keep it longer:
    /// the expiry is part of what makes its tid. This commit expires with it, so its other writes
    /// go then too (`Invalid` at once when the time is not in the future, and at commit beside
    /// another expiry).
    ///
    /// With a thing as admin (usually the one that holds it), whoever reads that thing reads it, and
    /// until it is first shared directly it may be up to ten times lighter to make and sync than one
    /// with an account (`me()`) as admin. A thin client's own actor goes with the client, so it is
    /// refused as admin (`Invalid` at commit).
    ///
    /// The same write must hold it: a strong to it from a thing this node holds (the account
    /// root's `holds.0` for an account-wide thing), else the commit is `Invalid`. It syncs with
    /// what holds it.
    pub fn create(&mut self, admin: Tid, expires: Option<Expiry>) -> Result<Tid> {
        let admin = self.known(admin)?;
        let at = expires.map(|e| expiry_at(self.db, e)).transpose()?;
        let rec = self.db.engine(|e| e.thing_record(admin, at.map(|t| osis_base::WallMs(t.0))));
        let t = rec.tid();
        self.ops.push(WriteOp::Create(rec));
        self.created.push(t);
        Ok(t)
    }

    /// `holder` holds `t`: a strong to `t` in `holder`'s `holds.0`, so `t` syncs with `holder`
    /// wherever `holder` is held (spec/sync-set.md §2) and stays while some held thing holds it.
    /// Holding a thing made in this write is what keeps it (`create`); holding one granted here
    /// accepts it (spec/sync-set.md §4). This node's own hold, held by no other node of the
    /// account, is `Osis::hold`: a commit of the node's, never part of a write.
    pub fn hold(&mut self, holder: Tid, t: Tid) -> Result<()> {
        self.at(holder, crate::core::HOLDS).path(osis_schema::p![]).add(&Ref::Strong(Strong(t)))
    }

    /// `holder` holds `t` no more: every reference to `t` in `holder`'s `holds.0` goes, strong or
    /// weak. What no held thing holds then leaves every node (spec/sync-set.md §3).
    pub fn unhold(&mut self, holder: Tid, t: Tid) -> Result<()> {
        for r in [Ref::Strong(Strong(t)), Ref::Weak(Weak(t))] {
            self.at(holder, crate::core::HOLDS).path(Path(vec![Step::Elem(Codec::to_value(&r))])).remove()?;
        }
        Ok(())
    }

    /// Destroys `tid` for everyone by purging its creation: every node drops the thing, whole, and
    /// ignores what is written on it later. It cannot be undone. What depends on it
    /// lives on: rights others held through it stand as they were, and what a destroyed account
    /// signed still verifies. Only an admin of the thing may purge it (`Permission` otherwise); an
    /// account purges itself. A thing created with an expiry is destroyed the same way then.
    pub fn purge(&mut self, tid: Tid) -> Result<()> {
        let t = self.known(tid)?;
        self.ops.push(WriteOp::PurgeThing(t));
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

    /// Writes every op as one commit (two for what `Write` names; a thing made directly under an
    /// account is recorded first, in commits of its own); `None` when it writes none (nothing
    /// changes). Fails before anything applies
    /// with `Permission`, `UnknownThing`, or `Invalid` (also when the ops cannot share a commit:
    /// `Write`, or past 1024 ops through another node); `OutcomeUnknown`, only through another node,
    /// may have applied: read before repeating it.
    pub fn commit(self) -> Result<Option<Commit>> {
        if let Some(e) = self.refused {
            return Err(e);
        }
        let db = self.db;
        // a handle acting for a client of this node never writes through another node (the port
        // never waits on one): what it may not read here is unknown to it, below
        if db.acting.is_none()
            && let crate::sources::Source::Node(at) = db.source_of_all(&self.things())?
        {
            return db.remote_write(&at, self.wire()?);
        }
        let limit = db.inner.limit;
        // a thing made here expiring sets the commit's expiry, which `expires` must then agree with
        let made = self.ops.iter().find_map(|o| match o {
            WriteOp::Create(r) => r.expires().map(Time),
            _ => None,
        });
        let expires = match (self.expires.map(|e| expiry_at(db, e)).transpose()?, made) {
            (Some(a), Some(b)) if a != b => return Err(Error::Invalid(format!("this write creates a thing expiring at {}, and expires at {}: a commit has one expiry", b.0, a.0))),
            (a, b) => a.or(b),
        };
        let r = db.locked(|l| {
            // the source invariant's second half: under the lock this commit takes, every thing it
            // writes is still this engine's. A write decided Local before a move fails here, never
            // lands in a sync unit that no longer syncs (crate::sources)
            let e = l.engine();
            if let Some(t) = self.alive
                && !crate::read::knows_in(e, t)?
            {
                return Err(Error::UnknownThing { tid: t });
            }
            let actor = db.acting;
            // what the acting actor may not read is a thing this node does not know, writes
            // included (spec/wire.md §11.2): no Permission tells it apart
            if actor.is_some() {
                let r = Reader { e: &mut *e, limit, actor };
                if let Some(t) = self.things().into_iter().find(|t| r.hidden(*t)) {
                    return Err(Error::UnknownThing { tid: t });
                }
            }
            let who = self.actor;
            let strongs = self.strongs_written();
            let mut m = self.build(&mut Reader { e, limit, actor }, expires)?;
            // whatever actor the write names, an acting handle's write is that actor's alone
            if let Some(a) = actor {
                m.confine(a);
            }
            let r = match e.write(m)? {
                Some(w) => Some(crate::commits::written_in(&mut Reader { e, limit, actor }, w, who)?.reporting(db)),
                None => None,
            };
            // a strong it writes whose target nothing carries is no error: it is reported at once
            // (spec/sync-set.md §2 Not carried), O(the strongs written)
            for (t, ys) in strongs {
                for target in e.not_carried_among(&t, &ys)? {
                    let detail = format!("{t} references {target}, which is neither in its sync unit nor held otherwise: it reaches no other node by it");
                    e.report(osis_engine::Diagnostic { kind: osis_engine::DiagnosticKind::NotCarried, tids: vec![t, target], commit: None, peer: None, detail });
                }
            }
            Ok(r)
        })?;
        Ok(r)
    }

    /// The engine mutation of the recorded ops, against the state `r` holds.
    fn build(self, r: &mut Reader<'_>, expires: Option<Time>) -> Result<Mutation> {
        let acting = self.db.acting;
        let Write { ops, keys, actor, .. } = self;
        let mut m = Mutation::new();
        let key = |i: u32| keys.get(i as usize).ok_or_else(|| Error::Invalid("op names no key of its write".into()));
        for op in ops {
            match op {
                WriteOp::Create(rec) => {
                    // the client's actor goes away with the client (notes/client-port.md §3)
                    if let (Some(a), CreationRecord::Thing { admin, .. }) = (acting, &rec)
                        && *admin == a
                    {
                        return Err(Error::Invalid("a thin client's actor goes with it, so it creates nothing under it: name a thing that stays".into()));
                    }
                    m.create(rec);
                }
                WriteOp::PurgeThing(_) if expires.is_some() => return Err(Error::Invalid("a purge of a thing does not expire: this write has an expiry, so write it as a commit of its own".into())),
                // a dynamic key's kind is known only now: a write of the other kind never
                // silently does nothing
                WriteOp::Path { tid, key: k, op } => {
                    let k = key(k)?;
                    if k.signal() {
                        return Err(Error::Invalid(format!("{} is a signal: it is fired, not written (fire)", k.ak)));
                    }
                    m.op(tid, k, op)?;
                }
                WriteOp::Fire { tid, key: k, v, replaces } => {
                    let k = key(k)?;
                    if !k.signal() {
                        return Err(Error::Invalid(format!("{} is a value aspect: it is written, not fired (set)", k.ak)));
                    }
                    m.op(tid, k, PathOp { path: Vec::new(), op: Op::Set(v) })?;
                    // a replacement is written only where it is honored: never one standing as a
                    // fire of its own elsewhere (spec/commits.md §5 Signals)
                    if let Some(o) = replaces {
                        if k.ak.ephemeral() {
                            return Err(Error::Invalid(format!("{} is ephemeral: nobody holds its fires, so none is replaced", k.ak)));
                        }
                        if !r.e.replaceable(&tid, &k.ak, &o, &acting.unwrap_or(actor))? {
                            return Err(Error::Invalid(format!("{} on {tid} is not a fire of this actor listed here, valid, that replaces none itself", CommitId(o))));
                        }
                        m.replaces(tid, k, o)?;
                    }
                }
                WriteOp::PurgeBy { tid, key: k, by } => {
                    m.purge_by(tid, key(k)?, by)?;
                }
                // each request carries a delta on its thing: a value aspect's removal, else
                // `purge.0` (the engine leaves it out of a commit that expires)
                WriteOp::Purge { tid, key: k } => {
                    let k = key(k)?;
                    // an ephemeral aspect's removal would be an ephemeral write: the request
                    // alone holds its writes value-less
                    if k.signal() || k.ephemeral() {
                        m.op(tid, &osis_schema::core_types::PURGE, PathOp { path: Vec::new(), op: Op::Replace(r.e.now().to_value()) })?;
                    } else {
                        m.op(tid, k, PathOp { path: Vec::new(), op: Op::RemoveAspect })?;
                    }
                    m.purge(PurgeItem::Aspect { tid, ak: k.ak.clone() });
                }
                WriteOp::PurgeCommit { tid, key: k, commit } => {
                    m.op(tid, &osis_schema::core_types::PURGE, PathOp { path: Vec::new(), op: Op::Replace(r.e.now().to_value()) })?;
                    let ak = key(k)?.ak.clone();
                    // a fire's replacements held here go with it: a purge of a message purges
                    // every version of it
                    for v in r.e.claims_on(&tid, &ak, &commit) {
                        m.purge_commit(v, tid, ak.clone());
                    }
                    m.purge_commit(commit, tid, ak);
                }
                WriteOp::PurgeAuthor { tid, key: k, author } => {
                    m.op(tid, &osis_schema::core_types::PURGE, PathOp { path: Vec::new(), op: Op::Replace(r.e.now().to_value()) })?;
                    m.purge(PurgeItem::Author { tid, ak: key(k)?.ak.clone(), author });
                }
                WriteOp::PurgeThing(tid) => {
                    m.op(tid, &osis_schema::core_types::PURGE, PathOp { path: Vec::new(), op: Op::Replace(r.e.now().to_value()) })?;
                    m.purge(PurgeItem::Aspect { tid, ak: osis_schema::core_types::CREATED.name() });
                }
            }
        }
        m.act_as(actor);
        if let Some(at) = expires {
            m.expires_all(at);
        }
        Ok(m)
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

    /// A chained modifier that could not be recorded: `commit` fails with `e`.
    fn refuse(&mut self, e: Error) {
        self.w.refused.get_or_insert(e);
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
    /// `Purge::All` of a value aspect removes it too. A purge is a durable write, also on an
    /// ephemeral aspect: beside an ephemeral write it fails `commit` with `Invalid`.
    pub fn purge(&mut self, what: Purge) -> Result<()> {
        let key = self.ok()?;
        match what {
            Purge::All => self.push(WriteOp::Purge { tid: self.tid, key }),
            Purge::Commit(CommitId(commit)) => self.push(WriteOp::PurgeCommit { tid: self.tid, key, commit }),
            Purge::Author(author) => self.push(WriteOp::PurgeAuthor { tid: self.tid, key, author }),
        }
        Ok(())
    }

    /// Who besides admins may purge this write, instead of as the key says
    /// (`DynamicAspectKey::default_purge_by`); checked at commit (`Invalid`).
    pub fn purge_by(mut self, by: PurgeBy) -> Self {
        match self.ix.clone() {
            Ok(key) => self.push(WriteOp::PurgeBy { tid: self.tid, key, by }),
            Err(e) => self.refuse(e),
        }
        self
    }
}

impl<K: SignalKey> AspectWrite<'_, '_, K> {
    /// Fires the signal with `v`: one commit that `on_fire` hears and, unless the key is
    /// ephemeral, `fired` lists. A signal has no current value, so each fire counts, an equal
    /// value too. A `Write` fires a signal once on a thing (a `replace` counts); `Invalid` at
    /// `commit` on a second fire, or on a dynamic key of a value aspect. An external signal (an
    /// `@` key) needs no write on the thing while the thing's setting has an entry for it
    /// (`core::RetentionSetting::rules`); otherwise `NotEnabled` at `commit`.
    pub fn fire(&mut self, v: &K::T) -> Result<()> {
        let v = self.encoded(v)?;
        let key = self.ok()?;
        self.push(WriteOp::Fire { tid: self.tid, key, v, replaces: None });
        Ok(())
    }

    /// Replaces this actor's fire `original` with `v`, whole: listings and `commit` show the fire
    /// in its place, under its id, reading `v` (`Part::edited`), and `on_fire` hears it as a
    /// change of `original`; earlier versions stay listed by `versions` until their own keep
    /// bound, expiry or purge. To drop the earlier text, purge `original` in the same write
    /// (`Purge::Commit` takes every version but this one). It is a fire of the write, as `fire`,
    /// and ends with `original` unless it says otherwise; the commit `commit` returns has no part
    /// here, as it lists under `original`. `Invalid` at `commit` unless `original`
    /// is this actor's fire of this durable signal, listed here and valid, and replaces none
    /// itself (`replace` the fire, never a replacement), or when the thing's setting refuses
    /// replacements (`RetentionEntry::refuse_replace`).
    pub fn replace(&mut self, original: CommitId, v: &K::T) -> Result<()> {
        let v = self.encoded(v)?;
        let key = self.ok()?;
        self.push(WriteOp::Fire { tid: self.tid, key, v, replaces: Some(original.0) });
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
