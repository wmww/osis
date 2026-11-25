//! The client port's values (notes/client-port.md §2): how the method table's arguments and
//! results, write ops, read results, origins and commits travel as untyped `Value`s, and how an
//! API error maps onto a Reply's outcome and back (spec/wire.md §11.2 Outcome error codes). One
//! encoder and one decoder per form, used by both sides.

use crate::commit_id::{CommitFrom, CommitId, CommitPos};
use crate::commits::{Address, Body, Commit, CommitEvent, CommitKind, CommitPage, CommitQuery, NotUndoableReason, Part, Scope};
use crate::error::{Error, Result};
use crate::read::{Grant, Grants, Stamp};
use crate::share::{Holder, HolderKind, ShareLink};
use crate::syncing::{Status, SyncScope, SyncState, UnitSync};
use crate::watch::{DerivedFrom, Origin};
use crate::write::{Expiry, WriteOp};
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

/// `[x*]` as exactly `N` values.
pub(crate) fn fixed<const N: usize>(v: Value, what: &str) -> Result<[Value; N]> {
    <[Value; N]>::try_from(list(v, what)?).map_err(|_| bad(what))
}

/// `[case, x*]`: the case and the rest.
fn tagged(v: Value, what: &str) -> Result<(u64, Vec<Value>)> {
    let mut a = list(v, what)?.into_iter();
    let case = a.next().and_then(|c| c.as_uint()).ok_or_else(|| bad(what))?;
    Ok((case, a.collect()))
}

/// `x` as its place in `table`.
fn place_to<T: PartialEq>(table: &[T], x: &T) -> Value {
    usize_to(table.iter().position(|k| k == x).unwrap_or(0))
}

/// The entry of `table` at the place `v` names.
fn place_from<T: Copy>(table: &[T], v: &Value, what: &str) -> Result<T> {
    table.get(usize_from(v)?).copied().ok_or_else(|| bad(what))
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
impl Form for Path {
    fn to_wire(&self) -> Value {
        let step = |s: &Step| {
            Value::List(match s {
                Step::Field(f) => vec![Value::uint(0), Value::uint(*f)],
                Step::Case(c) => vec![Value::uint(1), Value::uint(*c)],
                Step::Key(k) => vec![Value::uint(2), k.clone()],
                Step::Index(i) => vec![Value::uint(3), usize_to(*i)],
                Step::Elem(e) => vec![Value::uint(4), e.clone()],
            })
        };
        Value::List(self.0.iter().map(step).collect())
    }
    fn from_wire(v: Value) -> Result<Path> {
        let step = |s: Value| {
            let [k, x] = fixed(s, "path step")?;
            Ok(match uint(&k, "path step")? {
                0 => Step::Field(uint(&x, "field")?),
                1 => Step::Case(uint(&x, "case")?),
                2 => Step::Key(x),
                3 => Step::Index(usize_from(&x)?),
                4 => Step::Elem(x),
                _ => return Err(bad("path step")),
            })
        };
        Ok(Path(list(v, "path")?.into_iter().map(step).collect::<Result<_>>()?))
    }
}

fn usize_to(n: usize) -> Value {
    Value::uint(n as u64)
}

fn usize_from(v: &Value) -> Result<usize> {
    usize::try_from(uint(v, "index")?).map_err(|_| bad("index"))
}

/// A path op `[path, op]` (a path's form, no element step), op `[case, arg*]`. The ops that name
/// sequence elements by their placement (a text session's) are no API op: refused.
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
    let step = |s: &PathSeg| match s {
        PathSeg::Field(f) => Step::Field(*f),
        PathSeg::Case(c) => Step::Case(*c),
        PathSeg::Key(k) => Step::Key(k.clone()),
        PathSeg::Index(i) => Step::Index(*i),
    };
    Ok(Value::List(vec![Path(p.path.iter().map(step).collect()).to_wire(), Value::List(op)]))
}

pub(crate) fn path_op_from(v: Value) -> Result<PathOp> {
    let [path, op] = fixed(v, "path op")?;
    let path = crate::write::segs(&Path::from_wire(path)?)?;
    let (case, a) = tagged(op, "op")?;
    let n = usize_from;
    let op = match (case, a.as_slice()) {
        (0, [v]) => Op::Set(v.clone()),
        (1, [v]) => Op::Replace(v.clone()),
        (2, [v]) => Op::Put(v.clone()),
        (3, []) => Op::RemoveAspect,
        (4, [v]) => Op::Add(v.clone()),
        (5, [v]) => Op::Remove(v.clone()),
        (6, [v]) => Op::Inc(v.clone()),
        (7, [at, items]) => Op::Insert { at: n(at)?, items: list(items.clone(), "items")? },
        (8, [at, len]) => Op::Delete { at: n(at)?, len: n(len)? },
        (9, [at, len, to]) => Op::Move { at: n(at)?, len: n(len)?, to: n(to)? },
        (10, [base, new]) => Op::Edit { base: base.clone(), new: new.clone() },
        _ => return Err(bad("op")),
    };
    Ok(PathOp { path, op })
}

/// A write op `[case, arg*]`; aspects by index into the write's AK list.
pub(crate) fn write_op_to(o: &WriteOp) -> Result<Value> {
    let u = Value::uint;
    let k = |k: &u32| u(u64::from(*k));
    Ok(Value::List(match o {
        WriteOp::Create(rec) => vec![u(0), rec.to_value()],
        WriteOp::Path { tid, key, op } => vec![u(2), tid_to(tid), k(key), path_op_to(op)?],
        WriteOp::Fire { tid, key, v, replaces } => vec![u(3), tid_to(tid), k(key), v.clone(), opt(replaces.as_ref().map(commit_id_to))],
        WriteOp::PurgeBy { tid, key, by } => vec![u(4), tid_to(tid), k(key), u(*by as u64)],
        WriteOp::Purge { tid, key } => vec![u(5), tid_to(tid), k(key)],
        WriteOp::PurgeCommit { tid, key, commit } => vec![u(6), tid_to(tid), k(key), commit_id_to(commit)],
        WriteOp::PurgeAuthor { tid, key, author } => vec![u(7), tid_to(tid), k(key), tid_to(author)],
        WriteOp::PurgeThing(t) => vec![u(9), tid_to(t)],
    }))
}

pub(crate) fn write_op_from(v: Value) -> Result<WriteOp> {
    let (case, a) = tagged(v, "write op")?;
    let k = |v: &Value| u32::try_from(uint(v, "key index")?).map_err(|_| bad("key index"));
    Ok(match (case, a.as_slice()) {
        (0, [r]) => WriteOp::Create(CreationRecord::from_value(r).ok_or_else(|| bad("creation record"))?),
        (2, [t, key, op]) => WriteOp::Path { tid: tid(t)?, key: k(key)?, op: path_op_from(op.clone())? },
        (3, [t, key, v, replaces]) => {
            let replaces = opt_from(replaces.clone(), "replaces")?.map(|c| commit_id_from(&c)).transpose()?;
            WriteOp::Fire { tid: tid(t)?, key: k(key)?, v: v.clone(), replaces }
        }
        (4, [t, key, by]) => WriteOp::PurgeBy { tid: tid(t)?, key: k(key)?, by: PurgeBy::from_id(uint(by, "purge by")?).ok_or_else(|| bad("purge by"))? },
        (5, [t, key]) => WriteOp::Purge { tid: tid(t)?, key: k(key)? },
        (6, [t, key, c]) => WriteOp::PurgeCommit { tid: tid(t)?, key: k(key)?, commit: commit_id_from(c)? },
        (7, [t, key, author]) => WriteOp::PurgeAuthor { tid: tid(t)?, key: k(key)?, author: tid(author)? },
        (9, [t]) => WriteOp::PurgeThing(tid(t)?),
        _ => return Err(bad("write op")),
    })
}

/// An outcome `[0, value] | [1, code, detail*]` (a Reply's, a read's, a wait's Notify) as a
/// call's result; the outer `Err` when malformed.
fn outcome_value(v: Value) -> Result<Result<Value>> {
    let (case, a) = tagged(v, "outcome")?;
    match (case, a.as_slice()) {
        (0, [v]) => Ok(Ok(v.clone())),
        (1, [code, detail @ ..]) => Ok(Err(error_of(uint(code, "error code")?, detail))),
        _ => Err(bad("outcome")),
    }
}

/// An outcome carried as a value (a wait's Notify) as a call's result.
pub(crate) fn outcome_from(v: Value) -> Result<Value> {
    outcome_value(v)?
}

/// A call's result as an outcome.
pub(crate) fn outcome(r: Result<Value>) -> Outcome {
    match r {
        Ok(value) => Outcome::Ok { value },
        Err(e) => outcome_of(&e),
    }
}

/// A read's result: `[0, Opt(value)]` or an error's outcome.
impl Form for Result<Option<Value>> {
    fn to_wire(&self) -> Value {
        match self {
            Ok(v) => Outcome::Ok { value: opt(v.clone()) },
            Err(e) => outcome_of(e),
        }
        .to_value()
    }
    fn from_wire(v: Value) -> Result<Result<Option<Value>>> {
        Ok(match outcome_value(v)? {
            Ok(v) => Ok(opt_from(v, "read result")?),
            Err(e) => Err(e),
        })
    }
}

const DERIVED: [DerivedFrom; 7] = [DerivedFrom::ValidityChanged, DerivedFrom::Expired, DerivedFrom::Purged, DerivedFrom::Arrived, DerivedFrom::LostAccess, DerivedFrom::Recovered, DerivedFrom::Released];

/// An origin: `[0] | [1, stamp] | [2, stamp] | [3, derived]`.
impl Form for Origin {
    fn to_wire(&self) -> Value {
        let u = Value::uint;
        Value::List(match self {
            Origin::Initial => vec![u(0)],
            Origin::Local(s) => vec![u(1), s.to_wire()],
            Origin::Remote(s) => vec![u(2), s.to_wire()],
            Origin::Derived(d) => vec![u(3), place_to(&DERIVED, d)],
        })
    }
    fn from_wire(v: Value) -> Result<Origin> {
        let (case, a) = tagged(v, "origin")?;
        Ok(match (case, a.as_slice()) {
            (0, []) => Origin::Initial,
            (1, [s]) => Origin::Local(Stamp::from_wire(s.clone())?),
            (2, [s]) => Origin::Remote(Stamp::from_wire(s.clone())?),
            (3, [d]) => Origin::Derived(place_from(&DERIVED, d, "origin")?),
            _ => return Err(bad("origin")),
        })
    }
}

const KINDS: [CommitKind; 4] = [CommitKind::Content, CommitKind::Revert, CommitKind::Role, CommitKind::Snapshot];

fn body_to(b: &Body<Value>) -> Value {
    let u = Value::uint;
    Value::List(match b {
        Body::Held(v) => vec![u(0), opt(v.clone())],
        Body::TooLarge { limit } => vec![u(1), u(*limit)],
        Body::Purged { by, author } => vec![u(2), by.to_wire(), opt(author.as_ref().map(tid_to))],
        Body::NotFetched => vec![u(3)],
    })
}

fn body_from(v: Value) -> Result<Body<Value>> {
    let (case, a) = tagged(v, "body")?;
    Ok(match (case, a.as_slice()) {
        (0, [v]) => Body::Held(opt_from(v.clone(), "body")?),
        (1, [n]) => Body::TooLarge { limit: uint(n, "body")? },
        (2, [by, author]) => Body::Purged { by: CommitId::from_wire(by.clone())?, author: opt_from(author.clone(), "body")?.map(|t| tid(&t)).transpose()? },
        (3, []) => Body::NotFetched,
        _ => return Err(bad("body")),
    })
}

fn pos_to(p: &CommitPos) -> Value {
    Value::List(vec![Value::uint(p.0.ts.to_u64()), commit_id_to(&p.0.id)])
}

fn pos_from(v: Value) -> Result<CommitPos> {
    let [ts, id] = fixed(v, "position")?;
    let ts = Ts::from_u64(uint(&ts, "position")?).ok_or_else(|| bad("position"))?;
    Ok(CommitPos::of(ts, CommitId::from_wire(id)?))
}

/// A commit: `[stamp, kind, Opt(reverts), [reverted_by*], in_effect, [part*]]`, a part
/// `[tid, ak, valid, body, Opt(edited)]`.
impl Form for Commit {
    fn to_wire(&self) -> Value {
        let parts = self
            .parts()
            .map(|(t, ak, p)| Value::List(vec![tid_to(&t), ak_to(ak), Value::Bool(p.valid), body_to(&p.body), opt(p.edited.as_ref().map(pos_to))]))
            .collect();
        Value::List(vec![self.stamp.to_wire(), self.kind.to_wire(), self.reverts.to_wire(), self.reverted_by.to_wire(), Value::Bool(self.in_effect), Value::List(parts)])
    }
    fn from_wire(v: Value) -> Result<Commit> {
        let [stamp, kind, reverts, reverted_by, in_effect, parts] = fixed(v, "commit")?;
        let parts = list(parts, "parts")?
            .into_iter()
            .map(|p| {
                let [t, a, valid, body, edited] = fixed(p, "part")?;
                Ok((tid(&t)?, ak(&a)?, Part { valid: bool_from(&valid, "part")?, body: body_from(body)?, edited: opt_from(edited, "part")?.map(pos_from).transpose()? }))
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(Commit::of(Stamp::from_wire(stamp)?, Form::from_wire(kind)?, Form::from_wire(reverts)?, Form::from_wire(reverted_by)?, bool_from(&in_effect, "commit")?, parts))
    }
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

/// `grants`: `[[holder, role, Opt(until), retain_copy, may_grant, from_now]*]`.
impl Form for Grants {
    fn to_wire(&self) -> Value {
        Value::List(self.iter().map(|(h, g)| Value::List(vec![tid_to(h), role_to(g.role), time_to(g.until), Value::Bool(g.retain_copy), Value::Bool(g.may_grant), Value::Bool(g.from_now)])).collect())
    }
    fn from_wire(v: Value) -> Result<Grants> {
        list(v, "grants")?
            .into_iter()
            .map(|g| {
                let [h, role, until, retain, may, from_now] = fixed(g, "grant")?;
                Ok((tid(&h)?, Grant { role: role_from(&role)?, until: time_from(until, "grant")?, retain_copy: bool_from(&retain, "grant")?, may_grant: bool_from(&may, "grant")?, from_now: bool_from(&from_now, "grant")? }))
            })
            .collect()
    }
}

const HOLDER_KINDS: [HolderKind; 3] = [HolderKind::Actor, HolderKind::Link, HolderKind::Key];

/// A holder (`holders`): `[actor, kind, role, Opt(until), [through*]]`, kind 0 an actor, 1 a
/// link's, 2 a key.
impl Form for Holder {
    fn to_wire(&self) -> Value {
        Value::List(vec![tid_to(&self.actor), place_to(&HOLDER_KINDS, &self.kind), role_to(self.role), time_to(self.until), tids_to(&self.through)])
    }
    fn from_wire(v: Value) -> Result<Holder> {
        let [actor, kind, role, until, through] = fixed(v, "holder")?;
        Ok(Holder { actor: tid(&actor)?, kind: place_from(&HOLDER_KINDS, &kind, "holder kind")?, role: role_from(&role)?, until: time_from(until, "holder")?, through: tids_from(through, "holder")? })
    }
}

/// An origin's, a commit's, and `created`, `changed` (in an `Opt`): `[commit id, author, ts, received]`.
impl Form for Stamp {
    fn to_wire(&self) -> Value {
        Value::List(vec![self.id.to_wire(), tid_to(&self.author), Value::uint(self.ts.to_u64()), Value::uint(self.received.0)])
    }
    fn from_wire(v: Value) -> Result<Stamp> {
        let [id, author, ts, received] = fixed(v, "stamp")?;
        let ts = Ts::from_u64(uint(&ts, "stamp")?).ok_or_else(|| bad("stamp"))?;
        Ok(Stamp::new(CommitId::from_wire(id)?, tid(&author)?, ts, Time(uint(&received, "stamp")?)))
    }
}

const STATES: [SyncState; 4] = [SyncState::Synced, SyncState::Syncing, SyncState::NotConnected, SyncState::Stranded];

/// `status`: `[connected, [[tid, state, not_taking]*]]`, state 0 synced, 1 syncing, 2 not
/// connected, 3 stranded.
impl Form for Status {
    fn to_wire(&self) -> Value {
        let units = self.units.iter().map(|(t, g)| Value::List(vec![tid_to(t), place_to(&STATES, &g.state), usize_to(g.not_taking)]));
        Value::List(vec![usize_to(self.connected), Value::List(units.collect())])
    }
    fn from_wire(v: Value) -> Result<Status> {
        let [connected, units] = fixed(v, "status")?;
        let units = list(units, "status")?
            .into_iter()
            .map(|g| {
                let [t, state, not_taking] = fixed(g, "status")?;
                Ok((tid(&t)?, UnitSync { state: place_from(&STATES, &state, "sync state")?, not_taking: usize_from(&not_taking)? }))
            })
            .collect::<Result<_>>()?;
        Ok(Status { connected: usize_from(&connected)?, units })
    }
}

/// A scope: `[0, tid]` a thing, `[1, [[tid, ak]*]]` aspects.
impl Form for Scope {
    fn to_wire(&self) -> Value {
        Value::List(match self {
            Scope::Thing(t) => vec![Value::uint(0), tid_to(t)],
            Scope::Aspects(v) => vec![Value::uint(1), v.to_wire()],
        })
    }
    fn from_wire(v: Value) -> Result<Scope> {
        let [k, x] = fixed(v, "scope")?;
        Ok(match uint(&k, "scope")? {
            0 => Scope::Thing(tid(&x)?),
            1 => Scope::Aspects(Form::from_wire(x)?),
            _ => return Err(bad("scope")),
        })
    }
}

const REASONS: [NotUndoableReason; 2] = [NotUndoableReason::NotKept, NotUndoableReason::Superseded];

/// An API error as a Reply's outcome (spec/wire.md §11.2 Outcome error codes).
pub(crate) fn outcome_of(e: &Error) -> Outcome {
    let text = |s: &str| vec![Value::Str(s.to_string())];
    let (code, detail) = match e {
        Error::UnknownThing { tid } => (ApiCode::UNKNOWN_THING, vec![tid_to(tid)]),
        Error::UnknownActor { tid } => (ApiCode::UNKNOWN_ACTOR, vec![tid_to(tid)]),
        Error::Permission { tid, needs } => (ApiCode::PERMISSION, vec![tid_to(tid), role_to(*needs)]),
        Error::NotEnabled { tid, signal } => (ApiCode::NOT_ENABLED, vec![tid_to(tid), ak_to(signal)]),
        Error::LeavesNoAdmin { tid } => (ApiCode::LEAVES_NO_ADMIN, vec![tid_to(tid)]),
        Error::Type { path, reason } => (ApiCode::TYPE, vec![path.to_wire(), Value::Str(reason.clone())]),
        Error::TooLarge { limit } => (ApiCode::TOO_LARGE, vec![usize_to(*limit)]),
        Error::Stranded { things } => (ApiCode::STRANDED, vec![tids_to(things)]),
        Error::Invalid(m) => (ApiCode::INVALID, text(m)),
        Error::Storage(m) => (ApiCode::STORAGE, text(m)),
        Error::Network(m) => (ApiCode::NETWORK, text(m)),
        Error::Unsupported(m) => (ApiCode::UNSUPPORTED, text(m)),
        Error::OutcomeUnknown => (ApiCode::OUTCOME_UNKNOWN, Vec::new()),
        Error::Refused(m) => (ApiCode::REFUSED, text(m)),
        Error::Closed => (ApiCode::CLOSED, Vec::new()),
        Error::InUse => (ApiCode::IN_USE, Vec::new()),
        Error::NotUndoable { commit, reason } => (ApiCode::NOT_UNDOABLE, vec![commit.to_wire(), place_to(&REASONS, reason)]),
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
    let second = || detail.get(1).ok_or_else(|| bad("detail"));
    let decoded = match code {
        ApiCode::UNKNOWN_THING => t().map(|tid| Error::UnknownThing { tid }),
        ApiCode::UNKNOWN_ACTOR => t().map(|tid| Error::UnknownActor { tid }),
        ApiCode::LEAVES_NO_ADMIN => t().map(|tid| Error::LeavesNoAdmin { tid }),
        ApiCode::PERMISSION => t().zip(second().and_then(role_from).ok()).map(|(tid, needs)| Error::Permission { tid, needs }),
        ApiCode::NOT_ENABLED => t().zip(second().and_then(ak).ok()).map(|(tid, signal)| Error::NotEnabled { tid, signal }),
        ApiCode::TYPE => detail.first().cloned().and_then(|p| Path::from_wire(p).ok()).map(|path| Error::Type { path, reason: text() }),
        ApiCode::NOT_UNDOABLE => {
            let commit = detail.first().cloned().and_then(|c| CommitId::from_wire(c).ok());
            commit.zip(second().and_then(|r| place_from(&REASONS, r, "reason")).ok()).map(|(commit, reason)| Error::NotUndoable { commit, reason })
        }
        ApiCode::TOO_LARGE => Some(Error::TooLarge { limit: detail.first().and_then(Value::as_uint).map_or(0, |n| usize::try_from(n).unwrap_or(usize::MAX)) }),
        ApiCode::STRANDED => Some(Error::Stranded { things: detail.first().cloned().and_then(|g| list(g, "things").ok()).unwrap_or_default().iter().filter_map(|g| tid(g).ok()).collect() }),
        ApiCode::STORAGE => Some(Error::Storage(text())),
        ApiCode::NETWORK => Some(Error::Network(text())),
        ApiCode::UNSUPPORTED => Some(Error::Unsupported(text())),
        ApiCode::OUTCOME_UNKNOWN => Some(Error::OutcomeUnknown),
        ApiCode::REFUSED => Some(Error::Refused(text())),
        ApiCode::CLOSED => Some(Error::Closed),
        ApiCode::IN_USE => Some(Error::InUse),
        _ => None,
    };
    decoded.unwrap_or_else(|| Error::Invalid(text()))
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
        fixed::<0>(v, "nothing").map(drop)
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
        commit_id_to(&self.0)
    }
    fn from_wire(v: Value) -> Result<CommitId> {
        commit_id_from(&v).map(CommitId)
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
                let [$($v),+] = fixed::<$n>(v, "arguments")?;
                Ok(($($t::from_wire($v)?,)+))
            }
        }
    };
}
form_tuple!(1; A a);
form_tuple!(2; A a, B b);
form_tuple!(3; A a, B b, C c);
form_tuple!(4; A a, B b, C c, D d);

/// A listing's address: `[0, scope]` a scope's writes, `[1, tid, ak]` a signal's fires, `[2,
/// tid, ak, commit id]` a fire's versions.
impl Form for Address {
    fn to_wire(&self) -> Value {
        Value::List(match self {
            Address::Writes(s) => vec![Value::uint(0), s.to_wire()],
            Address::Fired(t, a) => vec![Value::uint(1), tid_to(t), ak_to(a)],
            Address::Versions(t, a, c) => vec![Value::uint(2), tid_to(t), ak_to(a), c.to_wire()],
        })
    }
    fn from_wire(v: Value) -> Result<Address> {
        let (case, a) = tagged(v, "address")?;
        Ok(match (case, a.as_slice()) {
            (0, [s]) => Address::Writes(Scope::from_wire(s.clone())?),
            (1, [t, k]) => Address::Fired(tid(t)?, ak(k)?),
            (2, [t, k, c]) => Address::Versions(tid(t)?, ak(k)?, CommitId::from_wire(c.clone())?),
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
        let (case, a) = tagged(v, "from")?;
        Ok(match (case, a.as_slice()) {
            (0, []) => CommitFrom::Newest,
            (1, []) => CommitFrom::Oldest,
            (2, [p]) => CommitFrom::Before(pos_from(p.clone())?),
            (3, [p]) => CommitFrom::After(pos_from(p.clone())?),
            _ => return Err(bad("from")),
        })
    }
}

impl Form for CommitKind {
    fn to_wire(&self) -> Value {
        place_to(&KINDS, self)
    }
    fn from_wire(v: Value) -> Result<CommitKind> {
        place_from(&KINDS, &v, "commit kind")
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
        let [from, limit, authors, kinds, reverts, reverted_by, in_effect] = fixed(v, "query")?;
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
            CommitEvent::Commit { id, commit } => Value::List(vec![Value::uint(0), id.to_wire(), commit.to_wire()]),
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
        let (case, a) = tagged(v, "commit event")?;
        Ok(match (case, a.as_slice()) {
            (0, [id, commit]) => CommitEvent::Commit { id: CommitId::from_wire(id.clone())?, commit: Form::from_wire(commit.clone())? },
            (1, []) => CommitEvent::Reread,
            (2, [code, detail @ ..]) => CommitEvent::Ended(error_of(uint(code, "error code")?, detail)),
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
form_text!(ShareLink);

/// `[0]` all, `[1, tid]` a thing.
impl Form for SyncScope {
    fn to_wire(&self) -> Value {
        Value::List(match self {
            SyncScope::All => vec![Value::uint(0)],
            SyncScope::Thing(t) => vec![Value::uint(1), tid_to(t)],
        })
    }
    fn from_wire(v: Value) -> Result<SyncScope> {
        let (case, a) = tagged(v, "sync scope")?;
        Ok(match (case, a.as_slice()) {
            (0, []) => SyncScope::All,
            (1, [t]) => SyncScope::Thing(tid(t)?),
            _ => return Err(bad("sync scope")),
        })
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

/// An expiry: `[0, at]` or `[1, ms from now]`.
impl Form for Expiry {
    fn to_wire(&self) -> Value {
        Value::List(match self {
            Expiry::At(t) => vec![Value::uint(0), Value::uint(t.0)],
            Expiry::In(d) => vec![Value::uint(1), Value::uint(u64::try_from(d.as_millis()).unwrap_or(u64::MAX))],
        })
    }
    fn from_wire(v: Value) -> Result<Expiry> {
        let [case, n] = fixed(v, "expiry")?;
        let n = uint(&n, "expiry")?;
        Ok(match uint(&case, "expiry")? {
            0 => Expiry::At(Time(n)),
            1 => Expiry::In(std::time::Duration::from_millis(n)),
            _ => return Err(bad("expiry")),
        })
    }
}

const DIAGNOSTICS: [DiagnosticKind; 21] = {
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
        K::OwnWriteInvalid,
        K::Unreadable,
        K::OwnWriteFailed,
        K::SyncStopped,
        K::ClockSkew,
        K::InputCapped,
        K::Connection,
        K::Fault,
    ]
};

/// A diagnostic: `[kind, [tid*], Opt(commit id), Opt(peer), detail]`, kind by its place in
/// `DIAGNOSTICS`; one of a kind this side does not know reads as `BadInput` (told as handled).
impl Form for osis_engine::Diagnostic {
    fn to_wire(&self) -> Value {
        Value::List(vec![place_to(&DIAGNOSTICS, &self.kind), tids_to(&self.tids), opt(self.commit.as_ref().map(commit_id_to)), self.peer.to_wire(), Value::Str(self.detail.clone())])
    }
    fn from_wire(v: Value) -> Result<osis_engine::Diagnostic> {
        let [kind, tids, commit, peer, detail] = fixed(v, "diagnostic")?;
        let Value::Str(detail) = detail else { return Err(bad("diagnostic")) };
        Ok(osis_engine::Diagnostic {
            kind: place_from(&DIAGNOSTICS, &kind, "diagnostic").unwrap_or(DiagnosticKind::BadInput),
            tids: tids_from(tids, "diagnostic")?,
            commit: opt_from(commit, "diagnostic")?.map(|c| commit_id_from(&c)).transpose()?,
            peer: Form::from_wire(peer)?,
            detail,
        })
    }
}
