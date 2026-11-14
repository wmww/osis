//! The client port's values (notes/client-port.md §2): how the method table's arguments and
//! results, write ops, read results, origins and commits travel as untyped `Value`s, and how an
//! API error maps onto a Reply's outcome and back (spec/wire.md §11.2 Outcome error codes). One
//! encoder and one decoder per form, used by both sides.

use crate::commit_id::{CommitId, CommitPos};
use crate::commits::{Body, Commit, CommitKind, NotUndoableReason, Part, Scope};
use crate::error::{Error, Result};
use crate::read::{Grant, Grants, GroupsOf, Stamp, ThingStamp};
use crate::share::{Holder, HolderKind};
use crate::syncing::{GroupSync, Status, SyncState};
use crate::watch::{DerivedFrom, Origin};
use crate::write::WriteOp;
use osis_base::{Ak, CommitId as RawCommitId, CreationRecord, Role, Tid, Time, Ts, Value};
use osis_crdt::{Op, PathOp, PathSeg};
use osis_proto::api::{ApiCode, Outcome};
use osis_schema::{Path, Retention, Step};

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

pub(crate) fn tid(v: &Value) -> Result<Tid> {
    match v {
        Value::Tid(t) => Ok(*t),
        _ => Err(bad("tid")),
    }
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

fn retention_to(r: &Retention) -> Value {
    Value::uint(r.by as u64)
}

fn retention_from(v: &Value) -> Result<Retention> {
    let n = uint(v, "retention")?;
    let by = osis_schema::PurgeBy::from_id(n).ok_or_else(|| bad("retention"))?;
    Ok(Retention { by })
}

/// A write op `[case, arg*]`; aspects by index into the write's AK list.
pub(crate) fn write_op_to(o: &WriteOp) -> Result<Value> {
    let u = Value::uint;
    let k = |k: &u32| u(u64::from(*k));
    Ok(Value::List(match o {
        WriteOp::Create(rec) => vec![u(0), rec.to_value()],
        WriteOp::Group { g, member, items, add } => vec![u(1), Value::Tid(*g), Value::Tid(*member), Value::Bool(*items), Value::Bool(*add)],
        WriteOp::Path { tid, key, op } => vec![u(2), Value::Tid(*tid), k(key), path_op_to(op)?],
        WriteOp::Fire { tid, key, v, replaces } => vec![u(3), Value::Tid(*tid), k(key), v.clone(), opt(replaces.as_ref().map(commit_id_to))],
        WriteOp::Retention { tid, key, r } => vec![u(4), Value::Tid(*tid), k(key), retention_to(r)],
        WriteOp::Purge { tid, key } => vec![u(5), Value::Tid(*tid), k(key)],
        WriteOp::PurgeCommit { tid, key, commit } => vec![u(6), Value::Tid(*tid), k(key), commit_id_to(commit)],
        WriteOp::PurgeAuthor { tid, key, actor } => vec![u(7), Value::Tid(*tid), k(key), Value::Tid(*actor)],
        WriteOp::Delete(t) => vec![u(8), Value::Tid(*t)],
        WriteOp::PurgeThing(t) => vec![u(9), Value::Tid(*t)],
        WriteOp::Release(t) => vec![u(10), Value::Tid(*t)],
        WriteOp::Retain { by, key, thing } => vec![u(11), Value::Tid(*by), k(key), Value::Tid(*thing)],
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
        1 => {
            want(5)?;
            WriteOp::Group { g: t(1)?, member: t(2)?, items: bool_from(arg(3)?, "items")?, add: bool_from(arg(4)?, "add")? }
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
            WriteOp::PurgeAuthor { tid: t(1)?, key: k(2)?, actor: t(3)? }
        }
        8 => {
            want(2)?;
            WriteOp::Delete(t(1)?)
        }
        9 => {
            want(2)?;
            WriteOp::PurgeThing(t(1)?)
        }
        10 => {
            want(2)?;
            WriteOp::Release(t(1)?)
        }
        11 => {
            want(4)?;
            WriteOp::Retain { by: t(1)?, key: k(2)?, thing: t(3)? }
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

fn stamp_to(s: &Stamp) -> Value {
    Value::List(vec![commit_id_to(&s.id.0), Value::Tid(s.actor), Value::uint(s.ts.to_u64()), Value::uint(s.received.0)])
}

fn stamp_from(v: Value) -> Result<Stamp> {
    let [id, actor, ts, received] = <[Value; 4]>::try_from(list(v, "stamp")?).map_err(|_| bad("stamp"))?;
    let ts = Ts::from_u64(uint(&ts, "stamp")?).ok_or_else(|| bad("stamp"))?;
    Ok(Stamp::new(CommitId(commit_id_from(&id)?), tid(&actor)?, ts, Time(uint(&received, "stamp")?)))
}

const DERIVED: [DerivedFrom; 7] = [DerivedFrom::ValidityChanged, DerivedFrom::Expired, DerivedFrom::Purged, DerivedFrom::Arrived, DerivedFrom::LostAccess, DerivedFrom::Recovered, DerivedFrom::Unsynced];

/// An origin: `[0] | [1, stamp] | [2, stamp] | [3, derived]`.
pub(crate) fn origin_to(o: &Origin) -> Value {
    let u = Value::uint;
    Value::List(match o {
        Origin::Initial => vec![u(0)],
        Origin::Local(s) => vec![u(1), stamp_to(s)],
        Origin::Remote(s) => vec![u(2), stamp_to(s)],
        Origin::Derived(d) => vec![u(3), u(DERIVED.iter().position(|x| x == d).unwrap_or(0) as u64)],
    })
}

pub(crate) fn origin_from(v: Value) -> Result<Origin> {
    let mut a = list(v, "origin")?.into_iter();
    let case = uint(&a.next().ok_or_else(|| bad("origin"))?, "origin")?;
    let o = match (case, a.next()) {
        (0, None) => Origin::Initial,
        (1, Some(s)) => Origin::Local(stamp_from(s)?),
        (2, Some(s)) => Origin::Remote(stamp_from(s)?),
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
        Body::Purged { by, actor } => vec![u(2), commit_id_to(&by.0), opt(actor.map(Value::Tid))],
        Body::NotFetched => vec![u(3)],
    })
}

fn body_from(v: Value) -> Result<Body<Value>> {
    let a = list(v, "body")?;
    Ok(match a.as_slice() {
        [c, v] if c.as_uint() == Some(0) => Body::Held(opt_from(v.clone(), "body")?),
        [c, n] if c.as_uint() == Some(1) => Body::TooLarge { limit: uint(n, "body")? },
        [c, by, actor] if c.as_uint() == Some(2) => Body::Purged { by: CommitId(commit_id_from(by)?), actor: opt_from(actor.clone(), "body")?.map(|t| tid(&t)).transpose()? },
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
        .map(|(t, ak, p)| Value::List(vec![Value::Tid(t), ak_to(ak), Value::Bool(p.valid), body_to(&p.body), opt(p.edited.as_ref().map(pos_to))]))
        .collect();
    Value::List(vec![
        stamp_to(&c.stamp),
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
        stamp_from(stamp)?,
        *KINDS.get(usize_from(&kind)?).ok_or_else(|| bad("commit kind"))?,
        opt_from(reverts, "commit")?.map(|r| commit_id_from(&r).map(CommitId)).transpose()?,
        list(reverted_by, "commit")?.iter().map(|r| commit_id_from(r).map(CommitId)).collect::<Result<Vec<_>>>()?,
        bool_from(&in_effect, "commit")?,
        parts,
    ))
}

fn tids_to(t: &[Tid]) -> Value {
    Value::List(t.iter().map(|t| Value::Tid(*t)).collect())
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

/// `groups_of`: `[[item_of*], [subgroup_of*], [within*]]`.
pub(crate) fn groups_of_to(g: &GroupsOf) -> Value {
    Value::List(vec![tids_to(&g.item_of), tids_to(&g.subgroup_of), tids_to(&g.within)])
}

pub(crate) fn groups_of_from(v: Value) -> Result<GroupsOf> {
    let [i, s, w] = <[Value; 3]>::try_from(list(v, "groups")?).map_err(|_| bad("groups"))?;
    Ok(GroupsOf { item_of: tids_from(i, "groups")?, subgroup_of: tids_from(s, "groups")?, within: tids_from(w, "groups")? })
}

/// `grants`: `[[holder, role, Opt(until), Opt(may_grant), with_membership, from_now]*]`.
pub(crate) fn grants_to(g: &Grants) -> Value {
    Value::List(g.iter().map(|(h, g)| Value::List(vec![Value::Tid(*h), role_to(g.role), time_to(g.until), opt(g.may_grant.map(role_to)), Value::Bool(g.with_membership), Value::Bool(g.from_now)])).collect())
}

pub(crate) fn grants_from(v: Value) -> Result<Grants> {
    list(v, "grants")?
        .into_iter()
        .map(|g| {
            let [h, role, until, may, with, from_now] = <[Value; 6]>::try_from(list(g, "grant")?).map_err(|_| bad("grant"))?;
            let may_grant = opt_from(may, "grant")?.map(|r| role_from(&r)).transpose()?;
            Ok((tid(&h)?, Grant { role: role_from(&role)?, until: time_from(until, "grant")?, may_grant, with_membership: bool_from(&with, "grant")?, from_now: bool_from(&from_now, "grant")? }))
        })
        .collect()
}

const HOLDER_KINDS: [HolderKind; 3] = [HolderKind::Actor, HolderKind::Link, HolderKind::Key];

/// `holders`: `[[actor, kind, role, Opt(until), [through*]]*]`, kind 0 an actor, 1 a link's, 2
/// a key.
pub(crate) fn holders_to(hs: &[Holder]) -> Value {
    Value::List(
        hs.iter()
            .map(|h| Value::List(vec![Value::Tid(h.actor), Value::uint(HOLDER_KINDS.iter().position(|k| *k == h.kind).unwrap_or(0) as u64), role_to(h.role), time_to(h.until), tids_to(&h.through)]))
            .collect(),
    )
}

pub(crate) fn holders_from(v: Value) -> Result<Vec<Holder>> {
    list(v, "holders")?
        .into_iter()
        .map(|h| {
            let [actor, kind, role, until, through] = <[Value; 5]>::try_from(list(h, "holder")?).map_err(|_| bad("holder"))?;
            let kind = *HOLDER_KINDS.get(usize_from(&kind)?).ok_or_else(|| bad("holder kind"))?;
            Ok(Holder { actor: tid(&actor)?, kind, role: role_from(&role)?, until: time_from(until, "holder")?, through: tids_from(through, "holder")? })
        })
        .collect()
}

/// `created`, `changed`: `Opt([commit id, actor, ts, received])`.
pub(crate) fn thing_stamp_to(s: Option<ThingStamp>) -> Value {
    opt(s.map(|s| Value::List(vec![commit_id_to(&s.id.0), Value::Tid(s.actor), Value::uint(s.ts.to_u64()), Value::uint(s.received.0)])))
}

pub(crate) fn thing_stamp_from(v: Value) -> Result<Option<ThingStamp>> {
    opt_from(v, "stamp")?.map(stamp_from).transpose().map(|s| s.map(|s| ThingStamp { id: s.id, actor: s.actor, written: s.written, received: s.received, ts: s.ts }))
}

const STATES: [SyncState; 4] = [SyncState::Synced, SyncState::Syncing, SyncState::NotConnected, SyncState::Stranded];

/// `status`: `[connected, [[tid, state, not_taking, leaving]*]]`, state 0 synced, 1 syncing, 2
/// not connected, 3 stranded.
pub(crate) fn status_to(s: &Status) -> Value {
    let groups = s.groups.iter().map(|(t, g)| Value::List(vec![Value::Tid(*t), Value::uint(STATES.iter().position(|x| *x == g.state).unwrap_or(0) as u64), usize_to(g.not_taking), Value::Bool(g.leaving)]));
    Value::List(vec![usize_to(s.connected), Value::List(groups.collect())])
}

pub(crate) fn status_from(v: Value) -> Result<Status> {
    let [connected, groups] = <[Value; 2]>::try_from(list(v, "status")?).map_err(|_| bad("status"))?;
    let groups = list(groups, "status")?
        .into_iter()
        .map(|g| {
            let [t, state, not_taking, leaving] = <[Value; 4]>::try_from(list(g, "status")?).map_err(|_| bad("status"))?;
            let state = *STATES.get(usize_from(&state)?).ok_or_else(|| bad("sync state"))?;
            Ok((tid(&t)?, GroupSync { state, not_taking: usize_from(&not_taking)?, leaving: bool_from(&leaving, "status")? }))
        })
        .collect::<Result<_>>()?;
    Ok(Status { connected: usize_from(&connected)?, groups })
}

/// A scope: `[0, tid]` a thing, `[1, [[tid, ak]*]]` aspects, `[2, tid]` a group.
pub(crate) fn scope_to(s: &Scope) -> Value {
    Value::List(match s {
        Scope::Thing(t) => vec![Value::uint(0), Value::Tid(*t)],
        Scope::Aspects(v) => vec![Value::uint(1), Value::List(v.iter().map(|(t, a)| Value::List(vec![Value::Tid(*t), ak_to(a)])).collect())],
        Scope::Group(g) => vec![Value::uint(2), Value::Tid(*g)],
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
        2 => Scope::Group(tid(&x)?),
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
        Error::UnknownThing { tid } => (ApiCode::UNKNOWN_THING, vec![Value::Tid(*tid)]),
        Error::UnknownActor { tid } => (ApiCode::UNKNOWN_ACTOR, vec![Value::Tid(*tid)]),
        Error::Permission { tid, needs } => (ApiCode::PERMISSION, vec![Value::Tid(*tid), Value::uint(u64::from(needs.id()))]),
        Error::Type { path, reason } => (ApiCode::TYPE, vec![path_to(path), Value::Str(reason.clone())]),
        Error::TooLarge { limit } => (ApiCode::TOO_LARGE, vec![Value::uint(*limit as u64)]),
        Error::Stranded { groups } => (ApiCode::STRANDED, vec![Value::List(groups.iter().map(|g| Value::Tid(*g)).collect())]),
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
        ApiCode::PERMISSION => match (t(), detail.get(1).and_then(Value::as_uint).and_then(Role::from_id)) {
            (Some(tid), Some(needs)) => Error::Permission { tid, needs },
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
        ApiCode::STRANDED => Error::Stranded { groups: detail.first().cloned().and_then(|g| list(g, "groups").ok()).unwrap_or_default().iter().filter_map(|g| tid(g).ok()).collect() },
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

/// A Reply's outcome as a call's result.
pub(crate) fn result_of(o: Outcome) -> Result<Value> {
    match o {
        Outcome::Ok { value } => Ok(value),
        Outcome::Err { code, detail } => Err(error_of(code, &detail)),
    }
}

