//! The client port's values (notes/client-port.md §2): how the method table's arguments and
//! results, write ops, read results, origins and commits travel as untyped `Value`s, and how an
//! API error maps onto a Reply's outcome and back (spec/wire.md §11.2 Outcome error codes). One
//! encoder and one decoder per form, used by both sides.

use crate::commit_id::{CommitFrom, CommitId, CommitPos};
use crate::commits::{Address, Body, Commit, CommitEvent, CommitKind, CommitPage, CommitQuery, NotUndoableReason, Part, Scope};
use crate::error::{Error, Result};
use crate::read::{Grant, Grants, Stamp};
use crate::share::{ContactCard, Holder, HolderKind, ShareLink};
use crate::syncing::{Status, SyncScope, SyncState, UnitSync};
use crate::watch::{DerivedFrom, Origin};
use crate::write::WriteOp;
use osis_base::{Ak, CommitId as RawCommitId, CreationRecord, Role, Tid, Time, Ts, Value};
use osis_crdt::{Op, PathOp, PathSeg};
use osis_engine::DiagnosticKind;
use osis_proto::api::{ApiCode, Outcome};
use osis_schema::{Path, PurgeBy, Step};

/// What a malformed argument is.
pub(crate) fn bad(what: &str) -> Error {
    Error::Invalid(format!("malformed {what}"))
}

pub(crate) fn list(v: Value, what: &str) -> Result<Vec<Value>> {
    match v {
        Value::List(l) => Ok(l),
        _ => Err(bad(what)),
    }
}

pub(crate) fn uint(v: &Value, what: &str) -> Result<u64> {
    v.as_uint().ok_or_else(|| bad(what))
}

/// A tid in a structure (spec/wire.md §1): a 15-byte byte string.
pub(crate) fn tid(v: &Value) -> Result<Tid> {
    v.as_array().map(Tid::from_bytes).ok_or_else(|| bad("tid"))
}

pub(crate) fn tid_to(t: &Tid) -> Value {
    Value::bytes(t.as_bytes())
}

pub(crate) fn ak(v: &Value) -> Result<Ak> {
    match v {
        Value::Str(s) => Ak::new(s).map_err(|_| bad("aspect key")),
        _ => Err(bad("aspect key")),
    }
}

pub(crate) fn ak_to(a: &Ak) -> Value {
    Value::Str(a.as_str().to_string())
}

/// `Opt(x)`: `[]` or `[x]`.
pub(crate) fn opt(v: Option<Value>) -> Value {
    Value::List(v.into_iter().collect())
}

pub(crate) fn opt_from(v: Value, what: &str) -> Result<Option<Value>> {
    let mut l = list(v, what)?;
    match l.len() {
        0 => Ok(None),
        1 => Ok(l.pop()),
        _ => Err(bad(what)),
    }
}

fn commit_id_to(c: &RawCommitId) -> Value {
    Value::Bytes(c.0.to_vec())
}

fn commit_id_from(v: &Value) -> Result<RawCommitId> {
    let b: [u8; 32] = v.as_bytes().and_then(|b| b.try_into().ok()).ok_or_else(|| bad("commit id"))?;
    Ok(RawCommitId(b))
}

fn bool_from(v: &Value, what: &str) -> Result<bool> {
    match v {
        Value::Bool(b) => Ok(*b),
        _ => Err(bad(what)),
    }
}

/// A path: one `[0, field] | [1, case] | [2, key] | [3, index] | [4, element]` per step.
pub(crate) fn path_to(p: &Path) -> Value {
    Value::List(
        p.0.iter()
            .map(|s| {
                Value::List(match s {
                    Step::Field(f) => vec![Value::uint(0), Value::uint(*f)],
                    Step::Case(c) => vec![Value::uint(1), Value::uint(*c)],
                    Step::Key(k) => vec![Value::uint(2), k.clone()],
                    Step::Index(i) => vec![Value::uint(3), Value::uint(*i as u64)],
                    Step::Elem(e) => vec![Value::uint(4), e.clone()],
                })
            })
            .collect(),
    )
}

pub(crate) fn path_from(v: Value) -> Result<Path> {
    let steps = list(v, "path")?
        .into_iter()
        .map(|s| {
            let [k, x] = <[Value; 2]>::try_from(list(s, "path step")?).map_err(|_| bad("path step"))?;
            Ok(match uint(&k, "path step")? {
                0 => Step::Field(uint(&x, "field")?),
                1 => Step::Case(uint(&x, "case")?),
                2 => Step::Key(x),
                3 => Step::Index(usize::try_from(uint(&x, "index")?).map_err(|_| bad("index"))?),
                4 => Step::Elem(x),
                _ => return Err(bad("path step")),
            })
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(Path(steps))
}

fn seg_to(s: &PathSeg) -> Value {
    Value::List(match s {
        PathSeg::Field(f) => vec![Value::uint(0), Value::uint(*f)],
        PathSeg::Case(c) => vec![Value::uint(1), Value::uint(*c)],
        PathSeg::Key(k) => vec![Value::uint(2), k.clone()],
        PathSeg::Index(i) => vec![Value::uint(3), Value::uint(*i as u64)],
    })
}

fn seg_from(v: Value) -> Result<PathSeg> {
    let [k, x] = <[Value; 2]>::try_from(list(v, "path step")?).map_err(|_| bad("path step"))?;
    Ok(match uint(&k, "path step")? {
        0 => PathSeg::Field(uint(&x, "field")?),
        1 => PathSeg::Case(uint(&x, "case")?),
        2 => PathSeg::Key(x),
        3 => PathSeg::Index(usize::try_from(uint(&x, "index")?).map_err(|_| bad("index"))?),
        _ => return Err(bad("path step")),
    })
}

fn usize_to(n: usize) -> Value {
    Value::uint(n as u64)
}

fn usize_from(v: &Value) -> Result<usize> {
    usize::try_from(uint(v, "index")?).map_err(|_| bad("index"))
}

/// A path op `[[seg*], op]`, op `[case, arg*]`. The ops that name sequence elements by their
/// placement (a text session's) are no API op: refused.
pub(crate) fn path_op_to(p: &PathOp) -> Result<Value> {
    let u = Value::uint;
    let op = match &p.op {
        Op::Set(v) => vec![u(0), v.clone()],
        Op::Replace(v) => vec![u(1), v.clone()],
        Op::Put(v) => vec![u(2), v.clone()],
        Op::RemoveAspect => vec![u(3)],
        Op::Add(v) => vec![u(4), v.clone()],
        Op::Remove(v) => vec![u(5), v.clone()],
        Op::Inc(v) => vec![u(6), v.clone()],
        Op::Insert { at, items } => vec![u(7), usize_to(*at), Value::List(items.clone())],
        Op::Delete { at, len } => vec![u(8), usize_to(*at), usize_to(*len)],
        Op::Move { at, len, to } => vec![u(9), usize_to(*at), usize_to(*len), usize_to(*to)],
        Op::Edit { base, new } => vec![u(10), base.clone(), new.clone()],
        Op::InsertAfter { .. } | Op::DeleteDots { .. } | Op::Paste { .. } => return Err(Error::Unsupported("a text session's ops do not go through a connection".into())),
    };
    Ok(Value::List(vec![Value::List(p.path.iter().map(seg_to).collect()), Value::List(op)]))
}

pub(crate) fn path_op_from(v: Value) -> Result<PathOp> {
    let [path, op] = <[Value; 2]>::try_from(list(v, "path op")?).map_err(|_| bad("path op"))?;
    let path = list(path, "path")?.into_iter().map(seg_from).collect::<Result<Vec<_>>>()?;
    let mut a = list(op, "op")?.into_iter();
    let case = uint(&a.next().ok_or_else(|| bad("op"))?, "op")?;
    let mut next = || a.next().ok_or_else(|| bad("op"));
    let op = match case {
        0 => Op::Set(next()?),
        1 => Op::Replace(next()?),
        2 => Op::Put(next()?),
        3 => Op::RemoveAspect,
        4 => Op::Add(next()?),
        5 => Op::Remove(next()?),
        6 => Op::Inc(next()?),
        7 => Op::Insert { at: usize_from(&next()?)?, items: list(next()?, "items")? },
        8 => Op::Delete { at: usize_from(&next()?)?, len: usize_from(&next()?)? },
        9 => Op::Move { at: usize_from(&next()?)?, len: usize_from(&next()?)?, to: usize_from(&next()?)? },
        10 => Op::Edit { base: next()?, new: next()? },
        _ => return Err(bad("op")),
    };
    if a.next().is_some() {
        return Err(bad("op"));
    }
    Ok(PathOp { path, op })
}

fn retention_to(r: &PurgeBy) -> Value {
    Value::uint(*r as u64)
}

fn retention_from(v: &Value) -> Result<PurgeBy> {
    PurgeBy::from_id(uint(v, "retention")?).ok_or_else(|| bad("retention"))
}

/// A write op `[case, arg*]`; aspects by index into the write's AK list.
pub(crate) fn write_op_to(o: &WriteOp) -> Result<Value> {
    let u = Value::uint;
    let k = |k: &u32| u(u64::from(*k));
    Ok(Value::List(match o {
        WriteOp::Create(rec) => vec![u(0), rec.to_value()],
        WriteOp::Path { tid, key, op } => vec![u(2), tid_to(tid), k(key), path_op_to(op)?],
        WriteOp::Fire { tid, key, v, replaces } => vec![u(3), tid_to(tid), k(key), v.clone(), opt(replaces.as_ref().map(commit_id_to))],
        WriteOp::Retention { tid, key, r } => vec![u(4), tid_to(tid), k(key), retention_to(r)],
        WriteOp::Purge { tid, key } => vec![u(5), tid_to(tid), k(key)],
        WriteOp::PurgeCommit { tid, key, commit } => vec![u(6), tid_to(tid), k(key), commit_id_to(commit)],
        WriteOp::PurgeAuthor { tid, key, author } => vec![u(7), tid_to(tid), k(key), tid_to(author)],
        WriteOp::PurgeThing(t) => vec![u(9), tid_to(t)],
    }))
}

pub(crate) fn write_op_from(v: Value) -> Result<WriteOp> {
    let a = list(v, "write op")?;
    let case = uint(a.first().ok_or_else(|| bad("write op"))?, "write op")?;
    let arg = |i: usize| a.get(i).ok_or_else(|| bad("write op"));
    let t = |i: usize| tid(arg(i)?);
    let k = |i: usize| -> Result<u32> { u32::try_from(uint(arg(i)?, "key index")?).map_err(|_| bad("key index")) };
    let want = |n: usize| if a.len() == n { Ok(()) } else { Err(bad("write op")) };
    let op = match case {
        0 => {
            want(2)?;
            WriteOp::Create(CreationRecord::from_value(arg(1)?).ok_or_else(|| bad("creation record"))?)
        }
        2 => {
            want(4)?;
            WriteOp::Path { tid: t(1)?, key: k(2)?, op: path_op_from(arg(3)?.clone())? }
        }
        3 => {
            want(5)?;
            let replaces = opt_from(arg(4)?.clone(), "replaces")?.map(|c| commit_id_from(&c)).transpose()?;
            WriteOp::Fire { tid: t(1)?, key: k(2)?, v: arg(3)?.clone(), replaces }
        }
        4 => {
            want(4)?;
            WriteOp::Retention { tid: t(1)?, key: k(2)?, r: retention_from(arg(3)?)? }
        }
        5 => {
            want(3)?;
            WriteOp::Purge { tid: t(1)?, key: k(2)? }
        }
        6 => {
            want(4)?;
            WriteOp::PurgeCommit { tid: t(1)?, key: k(2)?, commit: commit_id_from(arg(3)?)? }
        }
        7 => {
            want(4)?;
            WriteOp::PurgeAuthor { tid: t(1)?, key: k(2)?, author: t(3)? }
        }
        9 => {
            want(2)?;
            WriteOp::PurgeThing(t(1)?)
        }
        _ => return Err(bad("write op")),
    };
    Ok(op)
}

/// A read's result: `[0, Opt(value)]` or an error's outcome.
pub(crate) fn read_to(r: &Result<Option<Value>>) -> Value {
    match r {
        Ok(v) => Outcome::Ok { value: opt(v.clone()) }.to_value(),
        Err(e) => outcome_of(e).to_value(),
    }
}

pub(crate) fn read_from(v: Value) -> Result<Result<Option<Value>>> {
    let a = list(v, "read result")?;
    match a.as_slice() {
        [c, v] if c.as_uint() == Some(0) => Ok(Ok(opt_from(v.clone(), "read result")?)),
        [c, code, detail @ ..] if c.as_uint() == Some(1) => Ok(Err(error_of(uint(code, "error code")?, detail))),
        _ => Err(bad("read result")),
    }
}

const DERIVED: [DerivedFrom; 7] = [DerivedFrom::ValidityChanged, DerivedFrom::Expired, DerivedFrom::Purged, DerivedFrom::Arrived, DerivedFrom::LostAccess, DerivedFrom::Recovered, DerivedFrom::Released];

/// An origin: `[0] | [1, stamp] | [2, stamp] | [3, derived]`.
pub(crate) fn origin_to(o: &Origin) -> Value {
    let u = Value::uint;
    Value::List(match o {
        Origin::Initial => vec![u(0)],
        Origin::Local(s) => vec![u(1), s.to_wire()],
        Origin::Remote(s) => vec![u(2), s.to_wire()],
        Origin::Derived(d) => vec![u(3), u(DERIVED.iter().position(|x| x == d).unwrap_or(0) as u64)],
    })
}

pub(crate) fn origin_from(v: Value) -> Result<Origin> {
    let mut a = list(v, "origin")?.into_iter();
    let case = uint(&a.next().ok_or_else(|| bad("origin"))?, "origin")?;
    let o = match (case, a.next()) {
        (0, None) => Origin::Initial,
        (1, Some(s)) => Origin::Local(Stamp::from_wire(s)?),
        (2, Some(s)) => Origin::Remote(Stamp::from_wire(s)?),
        (3, Some(d)) => Origin::Derived(*DERIVED.get(usize_from(&d)?).ok_or_else(|| bad("origin"))?),
        _ => return Err(bad("origin")),
    };
    if a.next().is_some() {
        return Err(bad("origin"));
    }
    Ok(o)
}

const KINDS: [CommitKind; 4] = [CommitKind::Content, CommitKind::Revert, CommitKind::Role, CommitKind::Snapshot];

fn body_to(b: &Body<Value>) -> Value {
    let u = Value::uint;
    Value::List(match b {
        Body::Held(v) => vec![u(0), opt(v.clone())],
        Body::TooLarge { limit } => vec![u(1), u(*limit)],
        Body::Purged { by, author } => vec![u(2), commit_id_to(&by.0), opt(author.as_ref().map(tid_to))],
        Body::NotFetched => vec![u(3)],
    })
}

fn body_from(v: Value) -> Result<Body<Value>> {
    let a = list(v, "body")?;
    Ok(match a.as_slice() {
        [c, v] if c.as_uint() == Some(0) => Body::Held(opt_from(v.clone(), "body")?),
        [c, n] if c.as_uint() == Some(1) => Body::TooLarge { limit: uint(n, "body")? },
        [c, by, author] if c.as_uint() == Some(2) => Body::Purged { by: CommitId(commit_id_from(by)?), author: opt_from(author.clone(), "body")?.map(|t| tid(&t)).transpose()? },
        [c] if c.as_uint() == Some(3) => Body::NotFetched,
        _ => return Err(bad("body")),
    })
}

fn pos_to(p: &CommitPos) -> Value {
    Value::List(vec![Value::uint(p.0.ts.to_u64()), commit_id_to(&p.0.id)])
}

fn pos_from(v: Value) -> Result<CommitPos> {
    let [ts, id] = <[Value; 2]>::try_from(list(v, "position")?).map_err(|_| bad("position"))?;
    let ts = Ts::from_u64(uint(&ts, "position")?).ok_or_else(|| bad("position"))?;
    Ok(CommitPos::of(ts, CommitId(commit_id_from(&id)?)))
}

/// A commit: `[stamp, kind, Opt(reverts), [reverted_by*], in_effect, [part*]]`, a part
/// `[tid, ak, valid, body, Opt(edited)]`.
pub(crate) fn commit_to(c: &Commit) -> Value {
    let parts = c
        .parts()
        .map(|(t, ak, p)| Value::List(vec![tid_to(&t), ak_to(ak), Value::Bool(p.valid), body_to(&p.body), opt(p.edited.as_ref().map(pos_to))]))
        .collect();
    Value::List(vec![
        c.stamp.to_wire(),
        Value::uint(KINDS.iter().position(|k| *k == c.kind).unwrap_or(0) as u64),
        opt(c.reverts.map(|r| commit_id_to(&r.0))),
        Value::List(c.reverted_by.iter().map(|r| commit_id_to(&r.0)).collect()),
        Value::Bool(c.in_effect),
        Value::List(parts),
    ])
}

pub(crate) fn commit_from(v: Value) -> Result<Commit> {
    let [stamp, kind, reverts, reverted_by, in_effect, parts] = <[Value; 6]>::try_from(list(v, "commit")?).map_err(|_| bad("commit"))?;
    let parts = list(parts, "parts")?
        .into_iter()
        .map(|p| {
            let [t, a, valid, body, edited] = <[Value; 5]>::try_from(list(p, "part")?).map_err(|_| bad("part"))?;
            Ok((tid(&t)?, ak(&a)?, Part { valid: bool_from(&valid, "part")?, body: body_from(body)?, edited: opt_from(edited, "part")?.map(pos_from).transpose()? }))
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(Commit::of(
        Stamp::from_wire(stamp)?,
        *KINDS.get(usize_from(&kind)?).ok_or_else(|| bad("commit kind"))?,
        opt_from(reverts, "commit")?.map(|r| commit_id_from(&r).map(CommitId)).transpose()?,
        list(reverted_by, "commit")?.iter().map(|r| commit_id_from(r).map(CommitId)).collect::<Result<Vec<_>>>()?,
        bool_from(&in_effect, "commit")?,
        parts,
    ))
}

fn tids_to(t: &[Tid]) -> Value {
    Value::List(t.iter().map(tid_to).collect())
}

fn tids_from(v: Value, what: &str) -> Result<Vec<Tid>> {
    list(v, what)?.iter().map(tid).collect()
}

fn time_to(t: Option<Time>) -> Value {
    opt(t.map(|t| Value::uint(t.0)))
}

fn time_from(v: Value, what: &str) -> Result<Option<Time>> {
    opt_from(v, what)?.map(|t| uint(&t, what).map(Time)).transpose()
}

pub(crate) fn role_to(r: Role) -> Value {
    Value::uint(u64::from(r.id()))
}

pub(crate) fn role_from(v: &Value) -> Result<Role> {
    Role::from_id(uint(v, "role")?).ok_or_else(|| bad("role"))
}

/// `grants`: `[[holder, role, Opt(until), retain_copy, Opt(may_grant), from_now]*]`.
impl Form for Grants {
    fn to_wire(&self) -> Value {
        Value::List(self.iter().map(|(h, g)| Value::List(vec![tid_to(h), role_to(g.role), time_to(g.until), Value::Bool(g.retain_copy), opt(g.may_grant.map(role_to)), Value::Bool(g.from_now)])).collect())
    }
    fn from_wire(v: Value) -> Result<Grants> {
        list(v, "grants")?
            .into_iter()
            .map(|g| {
                let [h, role, until, retain, may, from_now] = <[Value; 6]>::try_from(list(g, "grant")?).map_err(|_| bad("grant"))?;
                let may_grant = opt_from(may, "grant")?.map(|r| role_from(&r)).transpose()?;
                Ok((tid(&h)?, Grant { role: role_from(&role)?, until: time_from(until, "grant")?, retain_copy: bool_from(&retain, "grant")?, may_grant, from_now: bool_from(&from_now, "grant")? }))
            })
            .collect()
    }
}

const HOLDER_KINDS: [HolderKind; 3] = [HolderKind::Actor, HolderKind::Link, HolderKind::Key];

/// A holder (`holders`): `[actor, kind, role, Opt(until), [through*]]`, kind 0 an actor, 1 a
/// link's, 2 a key.
impl Form for Holder {
    fn to_wire(&self) -> Value {
        Value::List(vec![tid_to(&self.actor), Value::uint(HOLDER_KINDS.iter().position(|k| *k == self.kind).unwrap_or(0) as u64), role_to(self.role), time_to(self.until), tids_to(&self.through)])
    }
    fn from_wire(v: Value) -> Result<Holder> {
        let [actor, kind, role, until, through] = <[Value; 5]>::try_from(list(v, "holder")?).map_err(|_| bad("holder"))?;
        let kind = *HOLDER_KINDS.get(usize_from(&kind)?).ok_or_else(|| bad("holder kind"))?;
        Ok(Holder { actor: tid(&actor)?, kind, role: role_from(&role)?, until: time_from(until, "holder")?, through: tids_from(through, "holder")? })
    }
}

/// An origin's, a commit's, and `created`, `changed` (in an `Opt`): `[commit id, author, ts, received]`.
impl Form for Stamp {
    fn to_wire(&self) -> Value {
        Value::List(vec![commit_id_to(&self.id.0), tid_to(&self.author), Value::uint(self.ts.to_u64()), Value::uint(self.received.0)])
    }
    fn from_wire(v: Value) -> Result<Stamp> {
        let [id, author, ts, received] = <[Value; 4]>::try_from(list(v, "stamp")?).map_err(|_| bad("stamp"))?;
        let ts = Ts::from_u64(uint(&ts, "stamp")?).ok_or_else(|| bad("stamp"))?;
        Ok(Stamp::new(CommitId(commit_id_from(&id)?), tid(&author)?, ts, Time(uint(&received, "stamp")?)))
    }
}

const STATES: [SyncState; 4] = [SyncState::Synced, SyncState::Syncing, SyncState::NotConnected, SyncState::Stranded];

/// `status`: `[connected, [[tid, state, not_taking]*]]`, state 0 synced, 1 syncing, 2 not
/// connected, 3 stranded.
impl Form for Status {
    fn to_wire(&self) -> Value {
        let units = self.units.iter().map(|(t, g)| Value::List(vec![tid_to(t), Value::uint(STATES.iter().position(|x| *x == g.state).unwrap_or(0) as u64), usize_to(g.not_taking)]));
        Value::List(vec![usize_to(self.connected), Value::List(units.collect())])
    }
    fn from_wire(v: Value) -> Result<Status> {
        let [connected, units] = <[Value; 2]>::try_from(list(v, "status")?).map_err(|_| bad("status"))?;
        let units = list(units, "status")?
            .into_iter()
            .map(|g| {
                let [t, state, not_taking] = <[Value; 3]>::try_from(list(g, "status")?).map_err(|_| bad("status"))?;
                let state = *STATES.get(usize_from(&state)?).ok_or_else(|| bad("sync state"))?;
                Ok((tid(&t)?, UnitSync { state, not_taking: usize_from(&not_taking)? }))
            })
            .collect::<Result<_>>()?;
        Ok(Status { connected: usize_from(&connected)?, units })
    }
}

/// A scope: `[0, tid]` a thing, `[1, [[tid, ak]*]]` aspects.
pub(crate) fn scope_to(s: &Scope) -> Value {
    Value::List(match s {
        Scope::Thing(t) => vec![Value::uint(0), tid_to(t)],
        Scope::Aspects(v) => vec![Value::uint(1), Value::List(v.iter().map(|(t, a)| Value::List(vec![tid_to(t), ak_to(a)])).collect())],
    })
}

pub(crate) fn scope_from(v: Value) -> Result<Scope> {
    let [k, x] = <[Value; 2]>::try_from(list(v, "scope")?).map_err(|_| bad("scope"))?;
    Ok(match uint(&k, "scope")? {
        0 => Scope::Thing(tid(&x)?),
        1 => Scope::Aspects(
            list(x, "scope")?
                .into_iter()
                .map(|p| {
                    let [t, a] = <[Value; 2]>::try_from(list(p, "scope")?).map_err(|_| bad("scope"))?;
                    Ok((tid(&t)?, ak(&a)?))
                })
                .collect::<Result<_>>()?,
        ),
        _ => return Err(bad("scope")),
    })
}

pub(crate) fn commit_ref_to(c: CommitId) -> Value {
    commit_id_to(&c.0)
}

pub(crate) fn commit_ref_from(v: &Value) -> Result<CommitId> {
    commit_id_from(v).map(CommitId)
}

const REASONS: [NotUndoableReason; 2] = [NotUndoableReason::NotKept, NotUndoableReason::Superseded];

/// An API error as a Reply's outcome (spec/wire.md §11.2 Outcome error codes).
pub(crate) fn outcome_of(e: &Error) -> Outcome {
    let text = |s: &str| vec![Value::Str(s.to_string())];
    let (code, detail) = match e {
        Error::UnknownThing { tid } => (ApiCode::UNKNOWN_THING, vec![tid_to(tid)]),
        Error::UnknownActor { tid } => (ApiCode::UNKNOWN_ACTOR, vec![tid_to(tid)]),
        Error::Permission { tid, needs } => (ApiCode::PERMISSION, vec![tid_to(tid), Value::uint(u64::from(needs.id()))]),
        Error::NotEnabled { tid, signal } => (ApiCode::NOT_ENABLED, vec![tid_to(tid), Value::Str(signal.as_str().to_string())]),
        Error::LeavesNoAdmin { tid } => (ApiCode::LEAVES_NO_ADMIN, vec![tid_to(tid)]),
        Error::Type { path, reason } => (ApiCode::TYPE, vec![path_to(path), Value::Str(reason.clone())]),
        Error::TooLarge { limit } => (ApiCode::TOO_LARGE, vec![Value::uint(*limit as u64)]),
        Error::Stranded { things } => (ApiCode::STRANDED, vec![Value::List(things.iter().map(tid_to).collect())]),
        Error::Invalid(m) => (ApiCode::INVALID, text(m)),
        Error::Storage(m) => (ApiCode::STORAGE, text(m)),
        Error::Network(m) => (ApiCode::NETWORK, text(m)),
        Error::Unsupported(m) => (ApiCode::UNSUPPORTED, text(m)),
        Error::OutcomeUnknown => (ApiCode::OUTCOME_UNKNOWN, Vec::new()),
        Error::Refused(m) => (ApiCode::REFUSED, text(m)),
        Error::Closed => (ApiCode::CLOSED, Vec::new()),
        Error::InUse => (ApiCode::IN_USE, Vec::new()),
        Error::NotUndoable { commit, reason } => (ApiCode::NOT_UNDOABLE, vec![commit_ref_to(*commit), Value::uint(REASONS.iter().position(|r| r == reason).unwrap_or(0) as u64)]),
        // no code of its own on the wire: told as what it is
        e @ Error::NotBuilt => (ApiCode::INVALID, text(&e.to_string())),
    };
    Outcome::Err { code, detail }
}

/// The API error a Reply's error outcome stands for; a detail that does not read as its code's
/// is told as text.
pub(crate) fn error_of(code: u64, detail: &[Value]) -> Error {
    let text = || detail.iter().find_map(|v| if let Value::Str(s) = v { Some(s.clone()) } else { None }).unwrap_or_default();
    let t = || detail.first().and_then(|v| tid(v).ok());
    match code {
        ApiCode::UNKNOWN_THING => t().map_or_else(|| Error::Invalid(text()), |tid| Error::UnknownThing { tid }),
        ApiCode::UNKNOWN_ACTOR => t().map_or_else(|| Error::Invalid(text()), |tid| Error::UnknownActor { tid }),
        ApiCode::LEAVES_NO_ADMIN => t().map_or_else(|| Error::Invalid(text()), |tid| Error::LeavesNoAdmin { tid }),
        ApiCode::PERMISSION => match (t(), detail.get(1).and_then(Value::as_uint).and_then(Role::from_id)) {
            (Some(tid), Some(needs)) => Error::Permission { tid, needs },
            _ => Error::Invalid(text()),
        },
        ApiCode::NOT_ENABLED => match (t(), detail.get(1).and_then(|v| if let Value::Str(s) = v { Ak::new(s.clone()).ok() } else { None })) {
            (Some(tid), Some(signal)) => Error::NotEnabled { tid, signal },
            _ => Error::Invalid(text()),
        },
        ApiCode::TYPE => match detail.first().cloned().map(path_from) {
            Some(Ok(path)) => Error::Type { path, reason: text() },
            _ => Error::Invalid(text()),
        },
        ApiCode::NOT_UNDOABLE => match (detail.first().map(commit_ref_from), detail.get(1).and_then(Value::as_uint).and_then(|n| REASONS.get(usize::try_from(n).ok()?))) {
            (Some(Ok(commit)), Some(reason)) => Error::NotUndoable { commit, reason: *reason },
            _ => Error::Invalid(text()),
        },
        ApiCode::TOO_LARGE => Error::TooLarge { limit: detail.first().and_then(Value::as_uint).map_or(0, |n| usize::try_from(n).unwrap_or(usize::MAX)) },
        ApiCode::STRANDED => Error::Stranded { things: detail.first().cloned().and_then(|g| list(g, "things").ok()).unwrap_or_default().iter().filter_map(|g| tid(g).ok()).collect() },
        ApiCode::STORAGE => Error::Storage(text()),
        ApiCode::NETWORK => Error::Network(text()),
        ApiCode::UNSUPPORTED => Error::Unsupported(text()),
        ApiCode::OUTCOME_UNKNOWN => Error::OutcomeUnknown,
        ApiCode::REFUSED => Error::Refused(text()),
        ApiCode::CLOSED => Error::Closed,
        ApiCode::IN_USE => Error::InUse,
        _ => Error::Invalid(text()),
    }
}

/// An outcome carried as a value (`[0, value]` or `[1, code, detail*]`, a wait's Notify) as a
/// call's result.
pub(crate) fn outcome_from(v: Value) -> Result<Value> {
    let mut a = list(v, "outcome")?.into_iter();
    match (a.next().and_then(|c| c.as_uint()), a.next()) {
        (Some(0), Some(v)) if a.len() == 0 => Ok(v),
        (Some(1), Some(code)) => Err(error_of(uint(&code, "error code")?, &a.collect::<Vec<_>>())),
        _ => Err(bad("outcome")),
    }
}

/// A Reply's outcome as a call's result.
pub(crate) fn result_of(o: Outcome) -> Result<Value> {
    match o {
        Outcome::Ok { value } => Ok(value),
        Outcome::Err { code, detail } => Err(error_of(code, &detail)),
    }
}

/// A method row's argument list or result as it travels (`port::serve::row`,
/// `ReadOnly::forward`): one encoder and one decoder per type, used by both sides, so a row is
/// its API call with nothing hand-written per side.
pub(crate) trait Form: Sized {
    fn to_wire(&self) -> Value;
    fn from_wire(v: Value) -> Result<Self>;
}

impl Form for Value {
    fn to_wire(&self) -> Value {
        self.clone()
    }
    fn from_wire(v: Value) -> Result<Value> {
        Ok(v)
    }
}

impl Form for () {
    fn to_wire(&self) -> Value {
        Value::List(Vec::new())
    }
    fn from_wire(v: Value) -> Result<()> {
        if list(v, "nothing")?.is_empty() { Ok(()) } else { Err(bad("nothing")) }
    }
}

impl Form for bool {
    fn to_wire(&self) -> Value {
        Value::Bool(*self)
    }
    fn from_wire(v: Value) -> Result<bool> {
        bool_from(&v, "bool")
    }
}

impl Form for Tid {
    fn to_wire(&self) -> Value {
        tid_to(self)
    }
    fn from_wire(v: Value) -> Result<Tid> {
        tid(&v)
    }
}

impl Form for Role {
    fn to_wire(&self) -> Value {
        role_to(*self)
    }
    fn from_wire(v: Value) -> Result<Role> {
        role_from(&v)
    }
}

impl Form for Ak {
    fn to_wire(&self) -> Value {
        ak_to(self)
    }
    fn from_wire(v: Value) -> Result<Ak> {
        ak(&v)
    }
}

impl Form for CommitId {
    fn to_wire(&self) -> Value {
        commit_ref_to(*self)
    }
    fn from_wire(v: Value) -> Result<CommitId> {
        commit_ref_from(&v)
    }
}

impl<T: Form> Form for Option<T> {
    fn to_wire(&self) -> Value {
        opt(self.as_ref().map(T::to_wire))
    }
    fn from_wire(v: Value) -> Result<Option<T>> {
        opt_from(v, "option")?.map(T::from_wire).transpose()
    }
}

impl<T: Form> Form for Vec<T> {
    fn to_wire(&self) -> Value {
        Value::List(self.iter().map(T::to_wire).collect())
    }
    fn from_wire(v: Value) -> Result<Vec<T>> {
        list(v, "list")?.into_iter().map(T::from_wire).collect()
    }
}

/// An argument list: `[a, ..]`.
macro_rules! form_tuple {
    ($n:literal; $($t:ident $v:ident),+) => {
        impl<$($t: Form),+> Form for ($($t,)+) {
            fn to_wire(&self) -> Value {
                let ($($v,)+) = self;
                Value::List(vec![$($v.to_wire()),+])
            }
            fn from_wire(v: Value) -> Result<Self> {
                let [$($v),+] = <[Value; $n]>::try_from(list(v, "arguments")?).map_err(|_| bad("arguments"))?;
                Ok(($($t::from_wire($v)?,)+))
            }
        }
    };
}
form_tuple!(1; A a);
form_tuple!(2; A a, B b);
form_tuple!(3; A a, B b, C c);

impl Form for Commit {
    fn to_wire(&self) -> Value {
        commit_to(self)
    }
    fn from_wire(v: Value) -> Result<Commit> {
        commit_from(v)
    }
}

impl Form for Scope {
    fn to_wire(&self) -> Value {
        scope_to(self)
    }
    fn from_wire(v: Value) -> Result<Scope> {
        scope_from(v)
    }
}

/// A listing's address: `[0, scope]` a scope's writes, `[1, tid, ak]` a signal's fires, `[2,
/// tid, ak, commit id]` a fire's versions.
impl Form for Address {
    fn to_wire(&self) -> Value {
        Value::List(match self {
            Address::Writes(s) => vec![Value::uint(0), scope_to(s)],
            Address::Fired(t, a) => vec![Value::uint(1), tid_to(t), ak_to(a)],
            Address::Versions(t, a, c) => vec![Value::uint(2), tid_to(t), ak_to(a), commit_ref_to(*c)],
        })
    }
    fn from_wire(v: Value) -> Result<Address> {
        let mut a = list(v, "address")?.into_iter();
        let case = uint(&a.next().ok_or_else(|| bad("address"))?, "address")?;
        let rest: Vec<Value> = a.collect();
        Ok(match (case, rest.as_slice()) {
            (0, [s]) => Address::Writes(scope_from(s.clone())?),
            (1, [t, k]) => Address::Fired(tid(t)?, ak(k)?),
            (2, [t, k, c]) => Address::Versions(tid(t)?, ak(k)?, commit_ref_from(c)?),
            _ => return Err(bad("address")),
        })
    }
}

/// `[0]` newest, `[1]` oldest, `[2, position]` before it, `[3, position]` after it.
impl Form for CommitFrom {
    fn to_wire(&self) -> Value {
        Value::List(match self {
            CommitFrom::Newest => vec![Value::uint(0)],
            CommitFrom::Oldest => vec![Value::uint(1)],
            CommitFrom::Before(p) => vec![Value::uint(2), pos_to(p)],
            CommitFrom::After(p) => vec![Value::uint(3), pos_to(p)],
        })
    }
    fn from_wire(v: Value) -> Result<CommitFrom> {
        let a = list(v, "from")?;
        Ok(match a.as_slice() {
            [c] if c.as_uint() == Some(0) => CommitFrom::Newest,
            [c] if c.as_uint() == Some(1) => CommitFrom::Oldest,
            [c, p] if c.as_uint() == Some(2) => CommitFrom::Before(pos_from(p.clone())?),
            [c, p] if c.as_uint() == Some(3) => CommitFrom::After(pos_from(p.clone())?),
            _ => return Err(bad("from")),
        })
    }
}

impl Form for CommitKind {
    fn to_wire(&self) -> Value {
        Value::uint(KINDS.iter().position(|k| k == self).unwrap_or(0) as u64)
    }
    fn from_wire(v: Value) -> Result<CommitKind> {
        KINDS.get(usize_from(&v)?).copied().ok_or_else(|| bad("commit kind"))
    }
}

/// `[from, Opt(limit), [actor*], [kind*], Opt(reverts), Opt(reverted_by), Opt(in_effect)]`.
impl Form for CommitQuery {
    fn to_wire(&self) -> Value {
        Value::List(vec![
            self.from.to_wire(),
            opt(self.limit.map(usize_to)),
            self.authors.to_wire(),
            self.kinds.to_wire(),
            self.reverts.to_wire(),
            self.reverted_by.to_wire(),
            self.in_effect.to_wire(),
        ])
    }
    fn from_wire(v: Value) -> Result<CommitQuery> {
        let [from, limit, authors, kinds, reverts, reverted_by, in_effect] = <[Value; 7]>::try_from(list(v, "query")?).map_err(|_| bad("query"))?;
        Ok(CommitQuery {
            from: Form::from_wire(from)?,
            limit: opt_from(limit, "query")?.map(|n| usize_from(&n)).transpose()?,
            authors: Form::from_wire(authors)?,
            kinds: Form::from_wire(kinds)?,
            reverts: Form::from_wire(reverts)?,
            reverted_by: Form::from_wire(reverted_by)?,
            in_effect: Form::from_wire(in_effect)?,
        })
    }
}

/// `[[commit*], more, complete]`.
impl Form for CommitPage {
    fn to_wire(&self) -> Value {
        Value::List(vec![self.commits.to_wire(), Value::Bool(self.more), Value::Bool(self.complete)])
    }
    fn from_wire(v: Value) -> Result<CommitPage> {
        let (commits, more, complete) = Form::from_wire(v)?;
        Ok(CommitPage { commits, more, complete })
    }
}

/// A commit listener's event: `[0, commit id, Opt(commit)]`, `[1]` read again, `[2, code,
/// detail*]` ended.
impl Form for CommitEvent {
    fn to_wire(&self) -> Value {
        match self {
            CommitEvent::Commit { id, commit } => Value::List(vec![Value::uint(0), commit_ref_to(*id), commit.to_wire()]),
            CommitEvent::Reread => Value::List(vec![Value::uint(1)]),
            CommitEvent::Ended(e) => {
                let Outcome::Err { code, detail } = outcome_of(e) else { return Value::List(vec![Value::uint(1)]) };
                let mut v = vec![Value::uint(2), Value::uint(code)];
                v.extend(detail);
                Value::List(v)
            }
        }
    }
    fn from_wire(v: Value) -> Result<CommitEvent> {
        let a = list(v, "commit event")?;
        Ok(match a.as_slice() {
            [c, id, commit] if c.as_uint() == Some(0) => CommitEvent::Commit { id: commit_ref_from(id)?, commit: Form::from_wire(commit.clone())? },
            [c] if c.as_uint() == Some(1) => CommitEvent::Reread,
            [c, code, detail @ ..] if c.as_uint() == Some(2) => CommitEvent::Ended(error_of(uint(code, "error code")?, detail)),
            _ => return Err(bad("commit event")),
        })
    }
}

/// A text form (a card, a link) as its text.
macro_rules! form_text {
    ($($t:ty),+) => {$(
        impl Form for $t {
            fn to_wire(&self) -> Value {
                Value::Str(self.to_string())
            }
            fn from_wire(v: Value) -> Result<$t> {
                match v {
                    Value::Str(s) => s.parse(),
                    _ => Err(bad("text")),
                }
            }
        }
    )+};
}
form_text!(ContactCard, ShareLink);

/// `[0]` all, `[1, tid]` a thing.
impl Form for SyncScope {
    fn to_wire(&self) -> Value {
        Value::List(match self {
            SyncScope::All => vec![Value::uint(0)],
            SyncScope::Thing(t) => vec![Value::uint(1), tid_to(t)],
        })
    }
    fn from_wire(v: Value) -> Result<SyncScope> {
        let a = list(v, "sync scope")?;
        Ok(match a.as_slice() {
            [c] if c.as_uint() == Some(0) => SyncScope::All,
            [c, t] if c.as_uint() == Some(1) => SyncScope::Thing(tid(t)?),
            _ => return Err(bad("sync scope")),
        })
    }
}

/// A read's result (`read_to`).
impl Form for Result<Option<Value>> {
    fn to_wire(&self) -> Value {
        read_to(self)
    }
    fn from_wire(v: Value) -> Result<Result<Option<Value>>> {
        read_from(v)
    }
}

impl Form for Path {
    fn to_wire(&self) -> Value {
        path_to(self)
    }
    fn from_wire(v: Value) -> Result<Path> {
        path_from(v)
    }
}

/// Wall ms.
impl Form for Time {
    fn to_wire(&self) -> Value {
        Value::uint(self.0)
    }
    fn from_wire(v: Value) -> Result<Time> {
        uint(&v, "time").map(Time)
    }
}

const DIAGNOSTICS: [DiagnosticKind; 22] = {
    use DiagnosticKind as K;
    [
        K::BadInput,
        K::CollidingRecord,
        K::Parked,
        K::Pending,
        K::OverlappingCounters,
        K::Removed,
        K::Callback,
        K::NotCarried,
        K::Stranded,
        K::Uncommitted,
        K::EphemeralRefused,
        K::Mismatch,
        K::Storage,
        K::Repair,
        K::OwnWriteInvalid,
        K::Unreadable,
        K::DisputesUnexamined,
        K::OwnWriteFailed,
        K::SyncStopped,
        K::ClockSkew,
        K::InputCapped,
        K::Connection,
    ]
};

/// A diagnostic: `[kind, [tid*], Opt(commit id), Opt(peer), detail]`, kind by its place in
/// `DIAGNOSTICS`; one of a kind this side does not know reads as `BadInput` (told as handled).
impl Form for osis_engine::Diagnostic {
    fn to_wire(&self) -> Value {
        Value::List(vec![
            Value::uint(DIAGNOSTICS.iter().position(|k| *k == self.kind).unwrap_or(0) as u64),
            tids_to(&self.tids),
            opt(self.commit.as_ref().map(commit_id_to)),
            self.peer.to_wire(),
            Value::Str(self.detail.clone()),
        ])
    }
    fn from_wire(v: Value) -> Result<osis_engine::Diagnostic> {
        let [kind, tids, commit, peer, detail] = <[Value; 5]>::try_from(list(v, "diagnostic")?).map_err(|_| bad("diagnostic"))?;
        let Value::Str(detail) = detail else { return Err(bad("diagnostic")) };
        Ok(osis_engine::Diagnostic {
            kind: DIAGNOSTICS.get(usize_from(&kind)?).copied().unwrap_or(DiagnosticKind::BadInput),
            tids: tids_from(tids, "diagnostic")?,
            commit: opt_from(commit, "diagnostic")?.map(|c| commit_id_from(&c)).transpose()?,
            peer: Form::from_wire(peer)?,
            detail,
        })
    }
}
