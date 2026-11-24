//! Reads and watches (notes/api.md Reads, Watching): synchronous reads of local state, large values materialized up to the bound, typed reads failing
//! with the path; watches and callbacks over the dispatcher.

use crate::error::{Error, Result};
use crate::handle::{Osis, ReadOnly};
use std::borrow::Borrow;
use crate::watch::{Callback, Change, Delivery, Filter, Msg, Origin, ReadAt, Subscription, Watch, digest};
use crate::commit_id::{CommitId, CommitPos};
use osis_base::{Ak, Role, Tid, Ts, Value, Time};
use osis_engine::{Diagnostic, Engine};
use osis_schema::{AspectKey, ValueKey};
use crate::track::{thing, thing_key};
use osis_schema::{Codec, Path, PathError, PathErrorKind, Schema, Step, Type, misplaced_link, type_at, typed_read, value_at};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

/// A role granted to one holder (`Osis::grants`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Grant {
    /// The role.
    pub role: Role,
    /// The grant ends at this time.
    pub until: Option<Time>,
    /// When `until` passes, the holder's nodes retain a read-only copy of what it could read.
    pub retain_copy: bool,
    /// The holder may add new holders, up to its own role.
    pub may_grant: bool,
    /// The holder reads the values as they stood at its first grant and what was written after,
    /// no earlier commit (`Reads::FromNow`).
    pub from_now: bool,
}

/// A commit's author and time, as the commit itself signs them (a `CommitKind::Snapshot` is reported
/// as itself, never as the writes it stands in for): why a watch fired, a commit's, a thing's
/// creation or last change (`Osis::created`, `Osis::changed`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Stamp {
    /// The commit.
    pub id: CommitId,
    /// Whom it is by: the identity it was written as (the writer's account, or what it acted as).
    /// Checked only where a part of the commit is valid (`Part::valid`): the device that signed
    /// it wrote through that identity. It says who made this commit, not who first wrote a value
    /// the commit carries (a `CommitKind::Snapshot` is by the snapshot's writer).
    pub author: Tid,
    /// When it was written, by the author's clock: the same on every node.
    pub written: Time,
    /// When this node received it (per node).
    pub received: Time,
    /// `written` with what orders commits of one moment.
    pub(crate) ts: Ts,
}

impl Stamp {
    pub(crate) fn new(id: CommitId, author: Tid, ts: Ts, received: Time) -> Stamp {
        Stamp { id, author, written: ts.wall_ms(), received, ts }
    }

    /// The time to show and sort by: the earlier of `written` and `received`, as an author's clock
    /// may run ahead.
    pub fn shown(&self) -> Time {
        self.written.min(self.received)
    }

    pub(crate) fn pos(&self) -> CommitPos {
        CommitPos::of(self.ts, self.id)
    }
}

fn stamp(c: osis_engine::Creation) -> Stamp {
    Stamp::new(CommitId(c.commit), c.purge_author, c.ts, c.received)
}

/// The grants on a thing, by holder.
pub type Grants = BTreeMap<Tid, Grant>;

pub(crate) fn ak_of<K: AspectKey>(key: &K) -> Result<Ak> {
    Ak::new(key.ak()).map_err(|_| Error::Invalid(format!("bad AK {:?}", key.ak())))
}

/// A link's value, `None` when it cannot be read here (spec/data-model.md §6): a blob of its
/// tree is not held (not fetched yet, or named by no blob) or fails verification (another
/// thing's dedup secret, bad bytes, an unknown format). The bound and local storage failures
/// stay errors.
fn read_link(e: &mut Engine, tid: &Tid, l: &osis_base::Link, at: usize, limit: usize, budget: &mut usize, bad: &mut Vec<osis_blob::Error>) -> Result<Option<Value>> {
    use osis_base::{Classified, ErrorClass};
    let too_large = Error::TooLarge { limit };
    let (x, decoded) = match e.read_large_max(tid, l, *budget, osis_base::format::MAX_VALUE_DEPTH.saturating_sub(at)) {
        Ok(x) => x,
        // past what the budget leaves of the bound: the bound is the read's
        Err(osis_engine::Error::PastBound { .. }) => return Err(too_large),
        Err(osis_engine::Error::Data(err)) if err == osis_blob::Error::Missing || err.class() != ErrorClass::Local => {
            bad.push(err);
            return Ok(None);
        }
        Err(other) => return Err(other.into()),
    };
    // the budget bounds both what the links' bytes and their decodes take (notes/decode-bounds.md)
    let n = osis_base::cbor::encoded_len(&x).max(decoded);
    *budget = budget.checked_sub(n).ok_or(too_large)?;
    Ok(Some(x))
}

/// `v`, read at depth `at`, with its links replaced; `None` when `v` itself is gone. An
/// unreadable link (`read_link`: also one whose value would read deeper than the levels left
/// where it sits, spec/data-model.md §5) is gone, and with it the list or set element, map entry
/// (struct field) or enum it is in or is; the rest stays.
fn materialize_in(e: &mut Engine, tid: &Tid, v: Value, at: usize, limit: usize, budget: &mut usize, bad: &mut Vec<osis_blob::Error>) -> Result<Option<Value>> {
    if let Value::Link(l) = v {
        return read_link(e, tid, &l, at, limit, budget, bad);
    }
    let mut m = |x: Value, by: usize| materialize_in(e, tid, x, at + by, limit, budget, bad);
    Ok(Some(match v {
        Value::List(l) => Value::List(l.into_iter().filter_map(|x| m(x, 1).transpose()).collect::<Result<_>>()?),
        Value::Set(s) => Value::Set(s.into_iter().filter_map(|x| m(x, 2).transpose()).collect::<Result<_>>()?),
        Value::Map(map) => {
            // `collect`: a link's content sorts elsewhere than the link, so an insert per key is O(n)
            let mut out = Vec::with_capacity(map.len());
            for (k, x) in map {
                if let (Some(k), Some(x)) = (m(k, 1)?, m(x, 1)?) {
                    out.push((k, x));
                }
            }
            Value::Map(out.into_iter().collect())
        }
        Value::Enum(c, Some(p)) => match m(*p, 2)? {
            Some(p) => Value::Enum(c, Some(Box::new(p))),
            None => return Ok(None),
        },
        v => v,
    }))
}

/// Replaces every link of `v` (read at depth `at`) by its value, dropping unreadable ones into
/// `bad` (`materialize_in`); fails `TooLarge` past `limit` canonical bytes, or bytes its links
/// decode to.
fn materialize(e: &mut Engine, tid: &Tid, v: Value, at: usize, limit: usize, bad: &mut Vec<osis_blob::Error>) -> Result<Option<Value>> {
    let mut budget = limit;
    let v = materialize_in(e, tid, v, at, limit, &mut budget, bad)?;
    if v.as_ref().is_some_and(|v| osis_base::cbor::encoded_len(v) > limit) {
        return Err(Error::TooLarge { limit });
    }
    Ok(v)
}

/// The levels a value at `path` sits below its aspect's root as read (spec/data-model.md §5): a
/// field, key or index step one (the array or map it reads in), a case or set element step two
/// (the tag and its array).
fn read_depth(path: &Path) -> usize {
    path.0.iter().map(|s| if matches!(s, Step::Case(_) | Step::Elem(_)) { 2 } else { 1 }).sum()
}

/// The diagnostic for a stored value of `tid`'s `ak` that a typed read could not decode.
pub(crate) fn mismatch(tid: Tid, ak: &Ak, e: &PathError) -> Diagnostic {
    Diagnostic { kind: osis_engine::DiagnosticKind::Mismatch, tids: vec![tid], commit: None, peer: None, detail: format!("{ak}: type error at {}: {}", e.path, e.kind) }
}

/// A typed decode of stored data (notes/api.md Typed reads): a value that does not match the
/// reader's type reads as absent and reports a `Mismatch` diagnostic. Stored data is others'
/// input; a caller cannot act on an error (the untyped read shows the value).
pub(crate) fn lenient<T>(tid: Tid, ak: &Ak, r: std::result::Result<T, PathError>, report: impl FnOnce(Diagnostic)) -> Option<T> {
    r.map_err(|e| report(mismatch(tid, ak, &e))).ok()
}

/// One locked view of the engine: what every single read uses.
pub(crate) struct Reader<'a> {
    pub(crate) e: &'a mut Engine,
    pub(crate) limit: usize,
    /// Reads as this actor (`Osis::act_as`): a thing it may not read answers exactly as a thing
    /// this node does not know, through every method below.
    pub(crate) actor: Option<Tid>,
}

/// How a handle reads (its bound and acting actor), carried into callbacks that outlive it.
#[derive(Clone, Copy)]
pub(crate) struct ReadAs {
    pub(crate) limit: usize,
    pub(crate) actor: Option<Tid>,
}

impl ReadAs {
    /// The node's own read that materializes nothing (a check, a digest of grants).
    pub(crate) const NODE: ReadAs = ReadAs { limit: 0, actor: None };

    /// A reader on `e`, an engine already locked.
    pub(crate) fn on(self, e: &mut Engine) -> Reader<'_> {
        Reader { e, limit: self.limit, actor: self.actor }
    }

    /// Reads with `f` on `db`'s engine, under its lock.
    pub(crate) fn read<R>(self, db: &ReadOnly, f: impl FnOnce(&mut Reader<'_>) -> R) -> R {
        db.locked(|l| f(&mut self.on(l.engine())))
    }
}

/// `Reader::knows` on an engine already locked (a check inside a commit).
pub(crate) fn knows_in(e: &mut Engine, tid: Tid) -> Result<bool> {
    ReadAs::NODE.on(e).knows(tid)
}

impl Reader<'_> {
    /// Whether the acting actor may not read `t` (never without one).
    pub(crate) fn hidden(&self, t: Tid) -> bool {
        self.actor.is_some_and(|a| !self.e.readable_by(&a, &t))
    }

    /// The stored value of `tid` (its tid returned too), large values still links.
    pub(crate) fn raw(&mut self, tid: Tid, ak: &Ak) -> Result<(Tid, Option<Value>)> {
        if self.hidden(tid) {
            return Ok((tid, None));
        }
        Ok((tid, self.e.get_within(&tid, ak, Some(self.limit))?))
    }

    /// `v` (of `tid`'s `ak`) materialized up to the bound; an unreadable link reads as absent at
    /// its position with an `Unreadable` diagnostic (spec/data-model.md §6), `None` when it is
    /// `v` itself or the enum `v` is. A blob not held is noted: its arrival re-delivers the aspect
    /// to watches (`Engine::missed_blob`).
    fn materialize(&mut self, tid: &Tid, ak: &Ak, v: Value, path: &Path) -> Result<Option<Value>> {
        let mut bad = Vec::new();
        let v = materialize(self.e, tid, v, read_depth(path), self.limit, &mut bad)?;
        if bad.contains(&osis_blob::Error::Missing) {
            self.e.missed_blob(*tid, ak.clone(), None);
        }
        if !bad.is_empty() {
            // each kind of failure once: the detail stays small however many links fail
            let why = bad.iter().map(|e| e.to_string()).collect::<std::collections::BTreeSet<_>>().into_iter().collect::<Vec<_>>().join("; ");
            self.e.report(Diagnostic { kind: osis_engine::DiagnosticKind::Unreadable, tids: vec![*tid], commit: None, peer: None, detail: format!("{ak}: {} link(s) read as absent: {why}", bad.len()) });
        }
        Ok(v)
    }

    /// `v` (the body of `id`'s part on `tid`'s `ak`) with its links replaced, up to `limit`
    /// bytes; any unreadable link fails it whole. A blob not held is noted: its arrival tells the
    /// commit to its listeners again (`Engine::missed_blob`).
    pub(crate) fn materialized(&mut self, tid: &Tid, ak: &Ak, id: osis_base::CommitId, v: Value, limit: usize) -> Result<Value> {
        let mut bad = Vec::new();
        let v = materialize(self.e, tid, v, 0, limit, &mut bad)?;
        if bad.contains(&osis_blob::Error::Missing) {
            self.e.missed_blob(*tid, ak.clone(), Some(id));
        }
        match (bad.into_iter().next(), v) {
            (None, Some(v)) => Ok(v),
            (err, _) => Err(Error::Invalid(err.map_or_else(|| "unreadable link".into(), |e| e.to_string()))),
        }
    }

    /// The whole value of an aspect, untyped, materialized up to the bound.
    pub fn value(&mut self, tid: Tid, ak: &Ak) -> Result<Option<Value>> {
        let (tid, v) = self.raw(tid, ak)?;
        Ok(match v {
            Some(v) => self.materialize(&tid, ak, v, &Path::root())?,
            None => None,
        })
    }

    /// A typed read: `None` when absent, and when the stored value
    /// does not match the key's type (a `Mismatch` diagnostic).
    pub fn get<K: AspectKey>(&mut self, tid: Tid, key: &K) -> Result<Option<K::T>> {
        let ak = ak_of(key)?;
        let (t, Some(raw)) = self.raw(tid, &ak)? else { return Ok(None) };
        let v = match (key.schema(), key.ty()) {
            (Some(s), Some(ty)) => match self.materialize_typed(t, &ak, s, raw, ty, false, &Path::root())? {
                Some(v) => v,
                None => return Ok(None),
            },
            _ => match self.materialize(&t, &ak, raw, &Path::root())? {
                Some(v) => v,
                None => return Ok(None),
            },
        };
        Ok(lenient(t, &ak, key.decode(&v), |d| self.e.report(d)))
    }

    /// `v`, of `tid`'s `ak` at `path` (type `ty`, `atomic` inside a set element or map key),
    /// materialized; `None` with a `Mismatch` diagnostic when it holds a link where the type takes
    /// none (spec/data-model.md §6): a mismatch like any other, never fetched. An unreadable link
    /// where the type takes one reads as absent at its position (`materialize`).
    #[allow(clippy::too_many_arguments)]
    fn materialize_typed(&mut self, tid: Tid, ak: &Ak, s: &Schema, v: Value, ty: &Type, atomic: bool, path: &Path) -> Result<Option<Value>> {
        if misplaced_link(s, &v, ty, atomic) {
            self.e.report(mismatch(tid, ak, &PathError::new(path.clone(), PathErrorKind::Mismatch { expected: "no link here" })));
            return Ok(None);
        }
        self.materialize(&tid, ak, v, path)
    }

    /// The stored value at `path` inside `tid`'s `ak`, large values still links: only that
    /// position is read (a set element's step reads the set it is in).
    pub(crate) fn raw_at(&mut self, tid: Tid, ak: &Ak, path: &Path) -> Result<Option<Value>> {
        let cut = path.0.iter().position(|s| matches!(s, Step::Elem(_))).unwrap_or(path.0.len());
        let (to, rest) = path.0.split_at(cut);
        let rest = Path(rest.to_vec());
        if to.is_empty() {
            let (_, v) = self.raw(tid, ak)?;
            return Ok(v.and_then(|v| value_at(&v, &rest).cloned()));
        }
        if self.hidden(tid) {
            return Ok(None);
        }
        let v = self.e.get_at_within(&tid, ak, &crate::write::segs(&Path(to.to_vec()))?, Some(self.limit))?;
        Ok(v.and_then(|v| value_at(&v, &rest).cloned()))
    }

    /// The value at `path` inside an aspect (typed projection through the key's schema when it
    /// has one); `None` when the path leads nowhere or the value there does not match the
    /// schema (a `Mismatch` diagnostic). A path the schema does not have fails `Type`. Only
    /// that position is read and materialized.
    pub fn get_path<K: AspectKey>(&mut self, tid: Tid, key: &K, path: &Path) -> Result<Option<Value>> {
        let ak = ak_of(key)?;
        let (Some(s), Some(ty)) = (key.schema(), key.ty()) else {
            let Some(sub) = self.raw_at(tid, &ak, path)? else { return Ok(None) };
            return self.materialize(&tid, &ak, sub, path);
        };
        let (t, atomic) = type_at(s, ty, path)?;
        if let Some(sub) = self.raw_at(tid, &ak, path)? {
            let Some(sub) = self.materialize_typed(tid, &ak, s, sub, &t, atomic, path)? else { return Ok(None) };
            return Ok(lenient(tid, &ak, typed_read(s, &sub, &t), |d| self.e.report(d)));
        }
        // an absent struct field reads as its default (spec/versioning.md §5): project the parent
        let Some((Step::Field(id), parent)) = path.0.split_last() else { return Ok(None) };
        let parent = Path(parent.to_vec());
        let Some(sub) = self.raw_at(tid, &ak, &parent)? else { return Ok(None) };
        let (pt, atomic) = type_at(s, ty, &parent)?;
        let Some(sub) = self.materialize_typed(tid, &ak, s, sub, &pt, atomic, &parent)? else { return Ok(None) };
        let Some(projected) = lenient(tid, &ak, typed_read(s, &sub, &pt), |d| self.e.report(d)) else { return Ok(None) };
        Ok(value_at(&projected, &Path(vec![Step::Field(*id)])).cloned())
    }

    /// AKs present on the thing; `TooLarge` when telling a state's presence would hold past the bound.
    pub fn aspects(&mut self, tid: Tid) -> Result<Vec<Ak>> {
        if self.hidden(tid) {
            return Ok(Vec::new());
        }
        Ok(self.e.aspects_within(&tid, Some(self.limit))?)
    }

    /// What actor `t` is, from its creation record.
    pub(crate) fn holder_kind(&self, t: Tid) -> crate::HolderKind {
        match self.e.core.created(&t) {
            Some(r) if r.is_link() => crate::HolderKind::Link,
            Some(osis_base::CreationRecord::KeyActor { .. }) => crate::HolderKind::Key,
            _ => crate::HolderKind::Actor,
        }
    }

    /// The grants on `thing`, shown only to a reader of it (`shows_roster`).
    pub fn grants(&self, thing: Tid) -> Grants {
        if !self.shows_roster(thing) {
            return Grants::new();
        }
        self.e.roster(&thing).into_iter().map(|(m, e)| (m, Grant { role: e.role, until: e.until, retain_copy: e.until.is_some() && e.retain, may_grant: e.may_grant, from_now: e.floor.is_some() })).collect()
    }

    /// Whether `thing`'s roster is shown here: to a reader of it, or of the target a link's actor
    /// stands for (its joiners are the target's). A node holds edge writes of actors it does not
    /// read (its holders' chains, the demotions their keysets carry, spec/crypto.md §4), which are
    /// not its to show.
    pub(crate) fn shows_roster(&self, thing: Tid) -> bool {
        if self.hidden(thing) {
            return false;
        }
        if self.actor.is_some() {
            return true;
        }
        let reads = |t: &Tid| self.e.role_on(t) >= Some(osis_base::Role::Read);
        reads(&thing) || self.e.core.created(&thing).and_then(|r| r.link_target()).is_some_and(|t| reads(&t))
    }

    /// This node's effective role on `tid` now (`None`: no access); the acting actor's when
    /// there is one. A write or admin role reads as read until this node holds the thing's delete
    /// keys, which every write on it lists (spec/crypto.md §7): until then a write is `Permission`.
    pub fn role_on(&mut self, tid: Tid) -> Result<Option<Role>> {
        let role = match self.actor {
            Some(a) => self.e.actor_role(&a, &tid).filter(|_| !self.hidden(tid)),
            None => self.e.role_on(&tid),
        };
        // the engine's one rule for every route to a role (spec/crypto.md §7)
        Ok(self.e.usable_role(&tid, role)?)
    }

    /// Whether the thing is here with content: its creation is held and some aspect a `Write`
    /// sets is present. `false` for an unknown thing and for one with no content, never written
    /// or cleared (a thing just created, an actor carrying only role data).
    pub fn knows(&mut self, tid: Tid) -> Result<bool> {
        if self.hidden(tid) {
            return Ok(false);
        }
        Ok(self.e.knows(&tid) && self.e.has_content(&tid)?)
    }

    /// Whether the thing's creation is held: what a write or grant needs.
    pub(crate) fn has_record(&self, tid: Tid) -> bool {
        !self.hidden(tid) && self.e.knows(&tid)
    }

    /// When the thing was created: the oldest valid commit carrying its `created.0` that is no
    /// snapshot; `None` while it is unknown or destroyed, or only a snapshot carrying its `created.0` is here.
    pub fn created(&self, tid: Tid) -> Option<Stamp> {
        if self.hidden(tid) || self.e.destroyed(&tid) {
            return None;
        }
        self.e.creation(&tid).map(stamp)
    }

    /// When the thing's content last changed: of the held commits and reverts writing its aspects (not `created.0` or role-class ones: sharing is no
    /// content write; not ephemeral writes), the one with the latest `shown()`, else its creation. A commit known here only from a
    /// snapshot is not seen.
    pub fn changed(&self, tid: Tid) -> Option<Stamp> {
        if self.hidden(tid) || self.e.destroyed(&tid) {
            return None;
        }
        self.e.changed(&tid).map(stamp)
    }
}

impl ReadOnly {
    /// How this handle reads.
    pub(crate) fn read_as(&self) -> ReadAs {
        ReadAs { limit: self.inner.limit, actor: self.acting }
    }

    /// Runs `f` on this process's engine (callers pick the source first).
    pub(crate) fn read_local<R>(&self, f: impl FnOnce(&mut Reader<'_>) -> R) -> R {
        drop(osis_base::costs::span("read: engine"));
        self.read_as().read(self, f)
    }

    /// An aspect, for reads (`None` when absent or the thing is unknown), paths and callbacks.
    pub fn at<K: AspectKey>(&self, tid: Tid, key: K) -> AspectRef<'_, K, ReadOnly> {
        AspectRef { db: self, tid, key }
    }

    /// The aspects that read as present on the thing, core ones included (`created.0`). A register
    /// whose live write was purged reads absent, and is not listed.
    pub fn aspects(&self, tid: Tid) -> Result<Vec<Ak>> {
        self.thing_read(tid, "aspects", crate::port::method::ASPECTS, thing(tid), move |r| r.aspects(tid))
    }

    /// A read of thing `tid` (`what`): through method row `method` at the node it is read at, else
    /// `read` here, listened to at `at` on a tracking handle.
    pub(crate) fn thing_read<R: crate::port::codec::Form + std::fmt::Debug>(&self, tid: Tid, what: &'static str, method: u64, at: Filter, read: impl Fn(&mut Reader<'_>) -> Result<R> + Send + Sync + 'static) -> Result<R> {
        if let Some(node) = self.remote(tid, what)? {
            return self.forward(&node, method, (tid,));
        }
        self.read_answer(|| thing_key(what, tid), at, read)
    }

    /// Where a read of `t` goes when not here: the node's address. A tracked read (`tracking`)
    /// of a thing at another node is not built: `Unsupported`, named `what`.
    pub(crate) fn remote(&self, t: Tid, what: &str) -> Result<Option<crate::share::Address>> {
        match self.source(t)? {
            crate::sources::Source::Local => Ok(None),
            crate::sources::Source::Node(_) if self.tracking.is_some() => Err(Error::Unsupported(format!("a tracked {what} of a thing at another node"))),
            crate::sources::Source::Node(a) => Ok(Some(a)),
        }
    }

    /// The value at `path` of `tid`'s `key` at the node at `at`: read there untyped, projected
    /// here through the key's schema (typing is the client's), as `Reader::get_path` reads it.
    pub(crate) fn remote_path<K: AspectKey>(&self, at: &crate::share::Address, tid: Tid, key: &K, path: &Path) -> Result<Option<Value>> {
        let ak = ak_of(key)?;
        let (Some(s), Some(ty)) = (key.schema(), key.ty()) else { return self.remote_get(at, tid, &ak, path) };
        type_at(s, ty, path)?;
        let (from, field) = remote_path_parts(s, ty, path);
        let Some(v) = self.remote_get(at, tid, &ak, &from)? else { return Ok(None) };
        Ok(project(s, ty, &from, field, tid, &ak, &v))
    }

    /// The roles granted on `thing`, by holder; empty unless this node reads `thing` (or the
    /// thing a link's actor stands for): a node holds others' grants it is not entitled to show.
    /// Whoever holds through those: `holders`.
    pub fn grants(&self, thing: Tid) -> Result<Grants> {
        self.thing_read(thing, "grants", crate::port::method::GRANTS, Filter::Grants(thing), move |r| Ok(r.grants(thing)))
    }

    /// This node's effective role on `tid` now (`None`: no access). A write or admin role reads as
    /// read until this node can write the thing: the keys a write needs can arrive after the role
    /// (on another node of the account, say), and a write before then fails `Permission`.
    pub fn role_on(&self, tid: Tid) -> Result<Option<Role>> {
        self.thing_read(tid, "role_on", crate::port::method::ROLE_ON, Filter::Due(Watch::RoleGraph), move |r| r.role_on(tid))
    }

    /// Whether the thing is here with content. `false` for an unknown thing and for one with no
    /// content, one cleared and equally one never written: a thing just created, or only
    /// granted. Its creation being here needs no content, and is all a write needs.
    pub fn has_content(&self, tid: Tid) -> Result<bool> {
        self.thing_read(tid, "has_content", crate::port::method::HAS_CONTENT, thing(tid), move |r| r.knows(tid))
    }

    pub(crate) fn has_record(&self, tid: Tid) -> bool {
        self.read_local(|r| r.has_record(tid))
    }

    /// When the thing was created: the oldest valid commit carrying its creation; `None` while it
    /// is unknown here, or once it was destroyed (`Write::purge`, an expiry).
    pub fn created(&self, tid: Tid) -> Result<Option<Stamp>> {
        self.thing_read(tid, "created", crate::port::method::CREATED, Filter::Due(Watch::CommitsOf(tid)), move |r| Ok(r.created(tid)))
    }

    /// When the thing's content last changed (membership and sharing are no content write, a delete
    /// is); its creation if never since. A commit known here only from a `CommitKind::Snapshot` is
    /// not seen.
    pub fn changed(&self, tid: Tid) -> Result<Option<Stamp>> {
        self.thing_read(tid, "changed", crate::port::method::CHANGED, Filter::Due(Watch::CommitsOf(tid)), move |r| Ok(r.changed(tid)))
    }

    /// Reads with `read` and runs `also` under the same engine lock (the dispatcher queues the
    /// events whose effect the read shows).
    pub(crate) fn read_with<R>(&self, read: impl FnOnce(&mut Reader<'_>) -> R, also: impl FnOnce()) -> R {
        self.read_as().read(self, |r| {
            let v = read(r);
            also();
            v
        })
    }
}

impl Osis {
    /// An aspect, as `ReadOnly::at`, with its listeners.
    pub fn at<K: AspectKey>(&self, tid: Tid, key: K) -> AspectRef<'_, K> {
        AspectRef { db: self, tid, key }
    }

    /// This node's wall clock: the time it stamps commits with,
    /// for app timestamps. On a thin client, its node's: `Network` when it cannot be
    /// reached.
    pub fn now(&self) -> Result<Time> {
        if !self.has_store() {
            let at = self.locked(|l| l.remotes.first().map(|r| r.addr.clone())).ok_or_else(|| Error::Network("not connected".into()))?;
            return self.forward(&at, crate::port::method::NOW, ());
        }
        Ok(self.engine(|e| e.now()))
    }

    /// Registers a callback built by `make` under the engine lock (so whatever `make` reads is
    /// atomic with the registration: nothing committed after it is missed or seen twice);
    /// `initial` queues one `Delivery::Initial` call through the dispatcher.
    pub(crate) fn subscribe(&self, filter: Filter, initial: bool, make: impl FnOnce(&mut Reader<'_>) -> Callback) -> Subscription {
        let ra = self.read_as();
        self.locked(|l| {
            let cb = make(&mut ra.on(l.engine()));
            self.subscribe_in(l, filter, initial, cb)
        })
    }

    /// Calls `f` with every change of any aspect of `tid`, first
    /// once per present aspect (`Origin::Initial`, through the dispatcher). Like every
    /// callback, `f` gets a handle reading as this one, so it need not capture one (a captured clone in
    /// a detached callback keeps the node open; capture `Osis::downgrade()` instead).
    /// Fails `Network` when `tid` is at a node that cannot be reached now. A live watch hears a
    /// lost connection as an `Err` value, and the aspects again once it is back.
    pub fn on_thing_change(&self, tid: Tid, mut f: impl FnMut(&Osis, Change<Value>) + Send + 'static) -> Result<Subscription> {
        if let Some(at) = self.remote(tid, "on_thing_change")? {
            return self.remote_thing_watch(&at, tid, f);
        }
        let mut failed = None;
        let sub = self.subscribe(Filter::Thing(tid), true, |r| {
            let mut first: BTreeMap<Ak, Result<Option<Value>>> = BTreeMap::new();
            match r.aspects(tid) {
                Ok(aks) => {
                    for ak in aks {
                        let v = r.value(tid, &ak);
                        first.insert(ak, v);
                    }
                }
                Err(e) => failed = Some(e),
            }
            let mut last: BTreeMap<Ak, Option<crate::watch::Digest>> = first.iter().map(|(ak, v)| (ak.clone(), digest(v))).collect();
            let mut first = Some(first);
            Box::new(move |db, d| match d {
                Delivery::Initial => {
                    for (ak, v) in first.take().unwrap_or_default() {
                        f(db, Change { tid, ak, value: v, origin: Origin::Initial });
                    }
                }
                Delivery::Aspect { tid, ak, origin, value } => tell_changed(&mut last, db, Change { tid, ak, value, origin }, &mut f),
                // every aspect it showed or holds now, read again
                Delivery::Reread => {
                    let reads: Vec<(Ak, Result<Option<Value>>)> = db.read_local(|r| {
                        let mut aks: BTreeSet<Ak> = last.keys().cloned().collect();
                        aks.extend(r.aspects(tid).unwrap_or_default());
                        aks.into_iter().map(|ak| (ak.clone(), r.value(tid, &ak))).collect()
                    });
                    for (ak, value) in reads {
                        tell_changed(&mut last, db, Change { tid, ak, value, origin: Origin::Derived(crate::DerivedFrom::Recovered) }, &mut f);
                    }
                }
                _ => {}
            })
        });
        failed.map_or(Ok(sub), Err)
    }

    /// Calls `f` with `grants(thing)` now (through the dispatcher) and on every change. Fails
    /// `Network` when `thing` is at a node that cannot be reached now; a live watch hears a lost
    /// connection as an `Err`, and the grants again once it is back.
    pub fn on_grants_change(&self, thing: Tid, mut f: impl FnMut(&Osis, Result<Grants>) + Send + 'static) -> Result<Subscription> {
        if let Some(at) = self.remote(thing, "on_grants_change")? {
            return self.remote_grants_watch(&at, thing, f);
        }
        Ok(self.subscribe(Filter::Grants(thing), true, move |r| {
            let first = r.grants(thing);
            let mut last = Some(first.clone());
            Box::new(move |db, d| match d {
                Delivery::Initial => f(db, Ok(first.clone())),
                Delivery::Grants | Delivery::Due => crate::watch::tell_new(&mut last, db.grants(thing), |g| f(db, g)),
                _ => {}
            })
        }))
    }

    /// Calls `f` with every diagnostic (deduped and rate-limited). On a thin client, those
    /// of its node: while it cannot be reached none come, and
    /// `status` says so; a session the node has ended fails as its calls do.
    pub fn on_diagnostic(&self, mut f: impl FnMut(&Osis, crate::Diagnostic) + Send + 'static) -> Result<Subscription> {
        if let Some(at) = self.process_at("on_diagnostic")? {
            return self.remote_diagnostics(&at, f);
        }
        Ok(self.subscribe(Filter::Diagnostics, false, |_| {
            Box::new(move |db, d| {
                if let Delivery::Diagnostic(x) = d {
                    f(db, x.into())
                }
            })
        }))
    }
}

/// Where a typed path read at another node reads: the path, or for a struct field its struct
/// (an absent field reads as its default, spec/versioning.md §5), and the field.
fn remote_path_parts(s: &Schema, ty: &Type, path: &Path) -> (Path, Option<u64>) {
    match path.0.split_last() {
        Some((Step::Field(f), parent)) if type_at(s, ty, &Path(parent.to_vec())).is_ok() => (Path(parent.to_vec()), Some(*f)),
        _ => (path.clone(), None),
    }
}

/// `v`, read untyped at `from` (`remote_path_parts`), projected through the schema, then its
/// `field`; `None` when it does not match (no diagnostic here: the node holds the data).
fn project(s: &Schema, ty: &Type, from: &Path, field: Option<u64>, tid: Tid, ak: &Ak, v: &Value) -> Option<Value> {
    let (t, _) = type_at(s, ty, from).ok()?;
    let p = lenient(tid, ak, typed_read(s, v, &t), |_| {})?;
    match field {
        Some(f) => value_at(&p, &Path(vec![Step::Field(f)])).cloned(),
        None => Some(p),
    }
}

/// A value read's address in a `ReadSet`.
pub(crate) fn value_key(tid: Tid, ak: &Ak, path: &Path) -> String {
    format!("value {tid} {ak} {path:?}")
}

/// An aspect of a thing: a value aspect's reads, path reads and listeners, a signal's fires. Its
/// listeners are on `Osis`'s only.
pub struct AspectRef<'d, K, H = Osis> {
    pub(crate) db: &'d H,
    pub(crate) tid: Tid,
    pub(crate) key: K,
}

impl<'d, K, H: Borrow<ReadOnly>> AspectRef<'d, K, H> {
    /// The handle this reads through.
    pub(crate) fn ro(&self) -> &'d ReadOnly {
        self.db.borrow()
    }
}

impl<'d, K: ValueKey, H: Borrow<ReadOnly>> AspectRef<'d, K, H> {
    /// The value now; `None` when it is absent or does not read as the key's type.
    pub fn get(&self) -> Result<Option<K::T>> {
        if let Some(at) = self.ro().remote(self.tid, "get")? {
            let ak = ak_of(&self.key)?;
            let v = self.ro().remote_get(&at, self.tid, &ak, &Path::root())?;
            return Ok(v.and_then(|x| lenient(self.tid, &ak, self.key.decode(&x), |_| {})));
        }
        if self.ro().tracking.is_none() {
            return self.ro().read_local(|r| r.get(self.tid, &self.key));
        }
        // the same address `on_change` reads
        let (tid, ak) = (self.tid, ak_of(&self.key)?);
        let ak2 = ak.clone();
        let v = self.ro().read_value(tid, &ak, value_key(tid, &ak, &Path::root()), ReadAt::new(move |r| r.value(tid, &ak2)))?;
        let db = self.ro();
        Ok(v.and_then(|x| lenient(tid, &ak, self.key.decode(&x), |d| db.engine(|e| e.report(d)))))
    }

    /// A position inside the value.
    pub fn path(&self, path: Path) -> PathRef<'_, 'd, K, H> {
        PathRef { a: self, path }
    }
}

impl<K: ValueKey + Clone + Send + 'static> AspectRef<'_, K> {
    /// Calls `f` once with the value at registration (`Origin::Initial`, through the
    /// dispatcher like every later call), then each time the value differs after a change,
    /// whatever caused it; `f` gets a handle reading as this one. Calls coalesce: one call may show several
    /// commits' effect and carries the newest one's origin; an unchanged value is not repeated,
    /// an error always is. `path(p).on_change` hears one position inside the value.
    ///
    /// For async code, forward to a channel of any runtime and await that: the first value and
    /// every later one arrive in order, with no gap between reading and subscribing.
    pub fn on_change(&self, mut f: impl FnMut(&Osis, Change<K::T>) + Send + 'static) -> Result<Subscription> {
        let (tid, ak, key) = (self.tid, ak_of(&self.key)?, self.key.clone());
        if let Some(at) = self.db.remote(tid, "watch")? {
            return self.db.remote_watch(&at, tid, ak, &Path::root(), move |db, ch| {
                let value = ch.value.map(|v| v.and_then(|x| lenient(ch.tid, &ch.ak, key.decode(&x), |_| {})));
                f(db, Change { tid: ch.tid, ak: ch.ak, value, origin: ch.origin })
            });
        }
        let ak2 = ak.clone();
        let read = ReadAt::new(move |r| r.value(tid, &ak2));
        self.db.watch_value(tid, ak, read, move |db, ch| {
            let value = ch.value.map(|v| v.and_then(|x| lenient(ch.tid, &ch.ak, key.decode(&x), |d| db.report(d))));
            f(db, Change { tid: ch.tid, ak: ch.ak, value, origin: ch.origin })
        })
    }
}

impl Osis {
    /// A value watch at `path` of `tid`'s `ak`: `read` here, the node's path read at a
    /// connected node. `f` hears the value once, then each time it reads otherwise.
    fn watch_value(&self, tid: Tid, ak: Ak, read: ReadAt, mut f: impl FnMut(&Osis, Change<Value>) + Send + 'static) -> Result<Subscription> {
        Ok(self.subscribe(Filter::Aspect(tid, ak.clone(), read.clone()), true, move |r| {
            let first = read.0(r);
            let mut last = digest(&first);
            let mut first = Some(first);
            Box::new(move |db, d| match d {
                Delivery::Initial => f(db, Change { tid, ak: ak.clone(), value: first.take().unwrap_or(Ok(None)), origin: Origin::Initial }),
                Delivery::Aspect { tid, origin, value, .. } if value.is_err() || digest(&value) != last => {
                    last = digest(&value);
                    f(db, Change { tid, ak: ak.clone(), value, origin });
                }
                _ => {}
            })
        }))
    }

    /// Reports a diagnostic at this node.
    fn report(&self, d: Diagnostic) {
        self.engine(|e| e.report(d))
    }
}

/// A position inside an aspect's value.
pub struct PathRef<'a, 'd, K, H = Osis> {
    a: &'a AspectRef<'d, K, H>,
    path: Path,
}

impl<'d, K: ValueKey> PathRef<'_, 'd, K> {
    pub(crate) fn parts(&self) -> (&'d Osis, Tid, &K, &Path) {
        (self.a.db, self.a.tid, &self.a.key, &self.path)
    }
}

impl<'d, K: ValueKey, H: Borrow<ReadOnly>> PathRef<'_, 'd, K, H> {
    /// What this reads: handle, thing, key, path.
    pub(crate) fn read_parts(&self) -> (&'d ReadOnly, Tid, &K, &Path) {
        (self.a.ro(), self.a.tid, &self.a.key, &self.path)
    }
}

impl<'d, K: ValueKey + Clone + Send + 'static, H: Borrow<ReadOnly>> PathRef<'_, 'd, K, H> {
    /// The untyped value at the path (typed projection when the key has a schema).
    fn value(&self) -> Result<Option<Value>> {
        let (db, tid, ak) = (self.a.ro(), self.a.tid, ak_of(&self.a.key)?);
        if let Some(at) = db.remote(tid, "get")? {
            return db.remote_path(&at, tid, &self.a.key, &self.path);
        }
        if db.tracking.is_none() {
            return db.read_local(|r| r.get_path(tid, &self.a.key, &self.path));
        }
        let (path, k) = (self.path.clone(), std::sync::Mutex::new(self.a.key.clone()));
        db.read_value(tid, &ak, value_key(tid, &ak, &self.path), ReadAt::new(move |r| r.get_path(tid, &*crate::watch::lock(&k), &path)))
    }

    /// The value at the path as `U`; one bad element of a large collection reads as absent
    /// alone (a `Mismatch` diagnostic).
    pub fn get<U: Codec>(&self) -> Result<Option<U>> {
        let Some(v) = self.value()? else { return Ok(None) };
        let db = self.a.ro();
        let ak = ak_of(&self.a.key)?;
        Ok(lenient(self.a.tid, &ak, U::from_value(&v), |d| db.engine(|e| e.report(d))))
    }
}

impl<K: ValueKey + Clone + Send + 'static> PathRef<'_, '_, K> {
    /// `on_change` of the value at the path as `U`, as `get` reads it: called once with it, then
    /// each time it reads otherwise after a change, whatever caused it (a write elsewhere in the
    /// aspect calls nothing). A path the schema does not have fails `Type`.
    pub fn on_change<U: Codec>(&self, mut f: impl FnMut(&Osis, Change<U>) + Send + 'static) -> Result<Subscription> {
        let (db, tid, key) = (self.a.db, self.a.tid, self.a.key.clone());
        let ak = ak_of(&key)?;
        if let (Some(s), Some(ty)) = (key.schema(), key.ty()) {
            type_at(s, ty, &self.path)?;
        }
        if let Some(at) = db.remote(tid, "watch")? {
            // read there untyped, projected here as `remote_path` projects it
            let typed = key.schema().zip(key.ty()).map(|(s, ty)| (Arc::new(s.clone()), ty.clone()));
            let (from, field) = match &typed {
                Some((s, ty)) => remote_path_parts(s, ty, &self.path),
                None => (self.path.clone(), None),
            };
            let at_path = from.clone();
            return db.remote_watch(&at, tid, ak, &at_path, move |db, ch| {
                let projected = |v: Value| match &typed {
                    Some((s, ty)) => project(s, ty, &from, field, ch.tid, &ch.ak, &v),
                    None => Some(v),
                };
                let value = ch.value.map(|v| v.and_then(projected).and_then(|x| lenient(ch.tid, &ch.ak, U::from_value(&x), |_| {})));
                f(db, Change { tid: ch.tid, ak: ch.ak, value, origin: ch.origin })
            });
        }
        let (path, k) = (self.path.clone(), std::sync::Mutex::new(key));
        let read = ReadAt::new(move |r| r.get_path(tid, &*crate::watch::lock(&k), &path));
        db.watch_value(tid, ak, read, move |db, ch| {
            let value = ch.value.map(|v| v.and_then(|x| lenient(ch.tid, &ch.ak, U::from_value(&x), |d| db.report(d))));
            f(db, Change { tid: ch.tid, ak: ch.ak, value, origin: ch.origin })
        })
    }
}

impl crate::handle::ReadOnly {
    /// `subscribe` under the lock a caller holds (with what it read for it).
    pub(crate) fn subscribe_in(&self, l: &mut crate::handle::Locked, filter: Filter, initial: bool, cb: Callback) -> Subscription {
        let d = &self.inner.dispatch;
        match &filter {
            Filter::Commits(_) => l.engine().listen_commits(d.commit_listened()),
            Filter::Due(Watch::CommitsOf(_)) => l.engine().watch_commits(),
            _ => {}
        }
        let sub = d.register(l.seq + 1, filter, self.acting, cb);
        if initial && let Some(id) = sub.id() {
            l.seq += 1;
            d.send(l.seq, Msg::Initial(id));
        }
        sub
    }
}

/// `on_thing_change`'s `f` hears `c` when it differs from the last value it heard there, absent
/// where it heard none (an error always).
pub(crate) fn tell_changed(last: &mut BTreeMap<Ak, Option<crate::watch::Digest>>, db: &Osis, c: Change<Value>, f: &mut impl FnMut(&Osis, Change<Value>)) {
    if c.value.is_err() || last.get(&c.ak).copied().unwrap_or(digest(&Ok(None))) != digest(&c.value) {
        last.insert(c.ak.clone(), digest(&c.value));
        f(db, c);
    }
}
