//! The client port's values (notes/client-port.md §2): how the method table's arguments and
//! results, write ops, read results, origins and commits travel as untyped `Value`s, and how an
//! API error maps onto a Reply's outcome and back (spec/wire.md §11.2 Outcome error codes). One
//! `Form` per type, used by both sides; a write op, which may refuse to travel, has its own pair.

use crate::commit_id::{CommitFrom, CommitId, CommitPos};
use crate::commits::{Address, Body, Commit, CommitEvent, CommitKind, CommitPage, CommitQuery, NotUndoableReason, Part, Scope};
use crate::error::{Error, Result};
use crate::read::{Grant, Grants, Stamp};
use crate::share::{GrantOpts, Holder, HolderKind, Keys, Link, LinkId, LinkInfo, Reads, SetRoleOpts};
use crate::backlinks::{Backlink, BacklinkPage, BacklinkQuery};
use crate::clients::{Client, ClientSecret};
use crate::disputes::{Dispute, DisputeId, Side};
use crate::syncing::{Status, SyncScope, SyncState, UnitSync};
use crate::watch::{DerivedFrom, Origin};
use crate::write::{Expiry, WriteOp};
use osis_base::{Ak, CommitId as RawCommitId, CreationRecord, RefKind, Role, Tid, Time, Ts, Value};
use osis_crdt::{Op, PathOp, PathSeg};
use osis_engine::DiagnosticKind;
use osis_proto::api::{ApiCode, Outcome};
use osis_schema::{Path, PurgeBy, Step};

/// A method row's argument list or result as it travels (`port::serve::row`,
/// `ReadOnly::forward`), and every value inside one: one encoder and one decoder per type, used
/// by both sides, so a row is its API call with nothing hand-written per side.
pub(crate) trait Form: Sized {
    fn to_wire(&self) -> Value;
    fn from_wire(v: Value) -> Result<Self>;
}

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

/// `x*` as exactly `N` values.
fn args<const N: usize>(a: Vec<Value>, what: &str) -> Result<[Value; N]> {
    <[Value; N]>::try_from(a).map_err(|_| bad(what))
}

/// `[x*]` as exactly `N` values.
pub(crate) fn fixed<const N: usize>(v: Value, what: &str) -> Result<[Value; N]> {
    args(list(v, what)?, what)
}

/// `[case, x*]`: the case and the rest.
fn tagged(v: Value, what: &str) -> Result<(u64, Vec<Value>)> {
    let mut a = list(v, what)?.into_iter();
    let case = a.next().and_then(|c| c.as_uint()).ok_or_else(|| bad(what))?;
    Ok((case, a.collect()))
}

/// A case no form has: refused.
fn case_of<T>(what: &str) -> Result<T> {
    Err(bad(what))
}

pub(crate) fn uint(v: &Value, what: &str) -> Result<u64> {
    v.as_uint().ok_or_else(|| bad(what))
}

/// A size limit (a too-large outcome's, a too-large push's); one past `usize` as the largest.
pub(crate) fn limit_of(v: &Value) -> usize {
    v.as_uint().map_or(0, |n| usize::try_from(n).unwrap_or(usize::MAX))
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
        match v {
            Value::Bool(b) => Ok(b),
            _ => Err(bad("bool")),
        }
    }
}

/// An index or count.
impl Form for usize {
    fn to_wire(&self) -> Value {
        Value::uint(*self as u64)
    }
    fn from_wire(v: Value) -> Result<usize> {
        usize::try_from(uint(&v, "index")?).map_err(|_| bad("index"))
    }
}

/// A tid in a structure (spec/wire.md §1): a 15-byte byte string.
impl Form for Tid {
    fn to_wire(&self) -> Value {
        Value::bytes(self.as_bytes())
    }
    fn from_wire(v: Value) -> Result<Tid> {
        v.as_array().map(Tid::from_bytes).ok_or_else(|| bad("tid"))
    }
}

impl Form for Role {
    fn to_wire(&self) -> Value {
        Value::uint(u64::from(self.id()))
    }
    fn from_wire(v: Value) -> Result<Role> {
        Role::from_id(uint(&v, "role")?).ok_or_else(|| bad("role"))
    }
}

impl Form for Ak {
    fn to_wire(&self) -> Value {
        Value::Str(self.as_str().to_string())
    }
    fn from_wire(v: Value) -> Result<Ak> {
        match v {
            Value::Str(s) => Ak::new(&s).map_err(|_| bad("aspect key")),
            _ => Err(bad("aspect key")),
        }
    }
}

impl Form for RawCommitId {
    fn to_wire(&self) -> Value {
        Value::Bytes(self.0.to_vec())
    }
    fn from_wire(v: Value) -> Result<RawCommitId> {
        let b: [u8; 32] = v.as_bytes().and_then(|b| b.try_into().ok()).ok_or_else(|| bad("commit id"))?;
        Ok(RawCommitId(b))
    }
}

impl Form for CommitId {
    fn to_wire(&self) -> Value {
        self.0.to_wire()
    }
    fn from_wire(v: Value) -> Result<CommitId> {
        RawCommitId::from_wire(v).map(CommitId)
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

impl Form for Ts {
    fn to_wire(&self) -> Value {
        Value::uint(self.to_u64())
    }
    fn from_wire(v: Value) -> Result<Ts> {
        Ts::from_u64(uint(&v, "timestamp")?).ok_or_else(|| bad("timestamp"))
    }
}

/// `Opt(x)`: `[]` or `[x]`.
impl<T: Form> Form for Option<T> {
    fn to_wire(&self) -> Value {
        Value::List(self.iter().map(T::to_wire).collect())
    }
    fn from_wire(v: Value) -> Result<Option<T>> {
        let mut l = list(v, "option")?;
        match l.len() {
            0 => Ok(None),
            1 => l.pop().map(T::from_wire).transpose(),
            _ => Err(bad("option")),
        }
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
form_tuple!(5; A a, B b, C c, D d, E e);
form_tuple!(6; A a, B b, C c, D d, E e, F f);

/// A fieldless enum as its place in a table of its cases.
macro_rules! form_place {
    ($t:ty, $what:literal, [$($case:expr),+ $(,)?]) => {
        impl Form for $t {
            fn to_wire(&self) -> Value {
                const CASES: &[$t] = &[$($case),+];
                Value::uint(CASES.iter().position(|k| k == self).unwrap_or(0) as u64)
            }
            fn from_wire(v: Value) -> Result<$t> {
                const CASES: &[$t] = &[$($case),+];
                CASES.get(usize::from_wire(v)?).copied().ok_or_else(|| bad($what))
            }
        }
    };
}
form_place!(DerivedFrom, "origin", [DerivedFrom::ValidityChanged, DerivedFrom::Expired, DerivedFrom::Purged, DerivedFrom::Arrived, DerivedFrom::LostAccess, DerivedFrom::Recovered, DerivedFrom::Released]);
form_place!(CommitKind, "commit kind", [CommitKind::Content, CommitKind::Revert, CommitKind::Role, CommitKind::Snapshot]);
form_place!(HolderKind, "holder kind", [HolderKind::Thing, HolderKind::Link, HolderKind::Key, HolderKind::Public]);
form_place!(SyncState, "sync state", [SyncState::Synced, SyncState::Syncing, SyncState::NotConnected, SyncState::Stranded]);
form_place!(NotUndoableReason, "reason", [NotUndoableReason::NotKept, NotUndoableReason::Superseded]);
form_place!(DiagnosticKind, "diagnostic", [
    DiagnosticKind::BadInput,
    DiagnosticKind::CollidingRecord,
    DiagnosticKind::Parked,
    DiagnosticKind::Pending,
    DiagnosticKind::OverlappingCounters,
    DiagnosticKind::Removed,
    DiagnosticKind::Callback,
    DiagnosticKind::NotCarried,
    DiagnosticKind::Stranded,
    DiagnosticKind::Uncommitted,
    DiagnosticKind::EphemeralRefused,
    DiagnosticKind::Mismatch,
    DiagnosticKind::Storage,
    DiagnosticKind::OwnWriteInvalid,
    DiagnosticKind::Unreadable,
    DiagnosticKind::OwnWriteFailed,
    DiagnosticKind::SyncStopped,
    DiagnosticKind::ClockSkew,
    DiagnosticKind::InputCapped,
    DiagnosticKind::Connection,
    DiagnosticKind::Fault,
]);

/// A type with a text form (`Display`, `FromStr`) as its text.
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
form_text!(Link, Keys, DisputeId);

/// A link's id: its thing.
impl Form for LinkId {
    fn to_wire(&self) -> Value {
        self.0.to_wire()
    }
    fn from_wire(v: Value) -> Result<LinkId> {
        Tid::from_wire(v).map(LinkId)
    }
}
form_place!(RefKind, "reference kind", [RefKind::Strong, RefKind::Weak]);
form_place!(Reads, "reads", [Reads::Kept, Reads::FromNow, Reads::All]);
form_place!(Side, "side", [Side::Author, Side::Holder]);

/// `GrantOpts`: `[Opt(until), Opt(retain_copy), may_grant, reads, leave_adminless, quiet]`.
impl Form for GrantOpts {
    fn to_wire(&self) -> Value {
        (self.until, self.retain_copy, self.may_grant, self.reads, self.leave_adminless, self.quiet).to_wire()
    }
    fn from_wire(v: Value) -> Result<GrantOpts> {
        let (until, retain_copy, may_grant, reads, leave_adminless, quiet) = Form::from_wire(v)?;
        Ok(GrantOpts { until, retain_copy, may_grant, reads, leave_adminless, quiet })
    }
}

/// `SetRoleOpts`: `[Opt(retain_copy), leave_adminless]`.
impl Form for SetRoleOpts {
    fn to_wire(&self) -> Value {
        (self.retain_copy, self.leave_adminless).to_wire()
    }
    fn from_wire(v: Value) -> Result<SetRoleOpts> {
        let (retain_copy, leave_adminless) = Form::from_wire(v)?;
        Ok(SetRoleOpts { retain_copy, leave_adminless })
    }
}

/// `LinkInfo`: `[id, target, role, Opt(until), single_use]`.
impl Form for LinkInfo {
    fn to_wire(&self) -> Value {
        (self.id, self.target, self.role, self.until, self.single_use).to_wire()
    }
    fn from_wire(v: Value) -> Result<LinkInfo> {
        let (id, target, role, until, single_use) = Form::from_wire(v)?;
        Ok(LinkInfo { id, target, role, until, single_use })
    }
}

/// A removal dispute: `[id, target, author, holder, commit id, side, chosen]`.
impl Form for Dispute {
    fn to_wire(&self) -> Value {
        let Dispute::Removal { id, target, author, holder, commit, side, chosen } = self;
        Value::List(vec![id.to_wire(), target.to_wire(), author.to_wire(), holder.to_wire(), commit.to_wire(), side.to_wire(), chosen.to_wire()])
    }
    fn from_wire(v: Value) -> Result<Dispute> {
        let [id, target, author, holder, commit, side, chosen] = fixed(v, "dispute")?;
        Ok(Dispute::Removal { id: Form::from_wire(id)?, target: Form::from_wire(target)?, author: Form::from_wire(author)?, holder: Form::from_wire(holder)?, commit: Form::from_wire(commit)?, side: Form::from_wire(side)?, chosen: Form::from_wire(chosen)? })
    }
}

/// A client (`clients`): `[thing, Opt(until)]`.
impl Form for Client {
    fn to_wire(&self) -> Value {
        (self.thing, self.until).to_wire()
    }
    fn from_wire(v: Value) -> Result<Client> {
        let (thing, until) = Form::from_wire(v)?;
        Ok(Client { thing, until })
    }
}

/// A client's secret: its 32 bytes.
impl Form for ClientSecret {
    fn to_wire(&self) -> Value {
        Value::bytes(self.expose())
    }
    fn from_wire(v: Value) -> Result<ClientSecret> {
        v.as_array().map(ClientSecret::from_bytes).ok_or_else(|| bad("secret"))
    }
}

/// A backlink: `[ak, tid, kind]`, kind 0 strong, 1 weak.
impl Form for Backlink {
    fn to_wire(&self) -> Value {
        (self.ak.clone(), self.tid, self.kind).to_wire()
    }
    fn from_wire(v: Value) -> Result<Backlink> {
        let (ak, tid, kind) = Form::from_wire(v)?;
        Ok(Backlink { ak, tid, kind })
    }
}

/// `BacklinkQuery`: `[Opt(ak), Opt(after), Opt(limit)]`.
impl Form for BacklinkQuery {
    fn to_wire(&self) -> Value {
        (self.aspect.clone(), self.after.clone(), self.limit).to_wire()
    }
    fn from_wire(v: Value) -> Result<BacklinkQuery> {
        let (aspect, after, limit) = Form::from_wire(v)?;
        Ok(BacklinkQuery { aspect, after, limit })
    }
}

/// `BacklinkPage`: `[[backlink*], more]`.
impl Form for BacklinkPage {
    fn to_wire(&self) -> Value {
        (self.backlinks.clone(), self.more).to_wire()
    }
    fn from_wire(v: Value) -> Result<BacklinkPage> {
        let (backlinks, more) = Form::from_wire(v)?;
        Ok(BacklinkPage { backlinks, more })
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
                Step::Index(i) => vec![Value::uint(3), i.to_wire()],
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
                3 => Step::Index(usize::from_wire(x)?),
                4 => Step::Elem(x),
                _ => return Err(bad("path step")),
            })
        };
        Ok(Path(list(v, "path")?.into_iter().map(step).collect::<Result<_>>()?))
    }
}

/// A path op `[path, op]` (a path's form, no element step), op `[case, arg*]`. The ops that name
/// sequence elements by their placement (a text session's) are no API op: refused.
fn path_op_to(p: &PathOp) -> Result<Value> {
    let u = Value::uint;
    let op = match &p.op {
        Op::Set(v) => vec![u(0), v.clone()],
        Op::Replace(v) => vec![u(1), v.clone()],
        Op::Put(v) => vec![u(2), v.clone()],
        Op::RemoveAspect => vec![u(3)],
        Op::Add(v) => vec![u(4), v.clone()],
        Op::Remove(v) => vec![u(5), v.clone()],
        Op::Inc(v) => vec![u(6), v.clone()],
        Op::Insert { at, items } => vec![u(7), at.to_wire(), Value::List(items.clone())],
        Op::Delete { at, len } => vec![u(8), at.to_wire(), len.to_wire()],
        Op::Move { at, len, to } => vec![u(9), at.to_wire(), len.to_wire(), to.to_wire()],
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

fn path_op_from(v: Value) -> Result<PathOp> {
    let [path, op] = fixed(v, "path op")?;
    let path = crate::write::segs(&Path::from_wire(path)?)?;
    let (case, a) = tagged(op, "op")?;
    let w = "op";
    let n = usize::from_wire;
    let op = match case {
        0 => args(a, w).map(|[v]| Op::Set(v))?,
        1 => args(a, w).map(|[v]| Op::Replace(v))?,
        2 => args(a, w).map(|[v]| Op::Put(v))?,
        3 => args(a, w).map(|[]| Op::RemoveAspect)?,
        4 => args(a, w).map(|[v]| Op::Add(v))?,
        5 => args(a, w).map(|[v]| Op::Remove(v))?,
        6 => args(a, w).map(|[v]| Op::Inc(v))?,
        7 => {
            let [at, items] = args(a, w)?;
            Op::Insert { at: n(at)?, items: list(items, "items")? }
        }
        8 => {
            let [at, len] = args(a, w)?;
            Op::Delete { at: n(at)?, len: n(len)? }
        }
        9 => {
            let [at, len, to] = args(a, w)?;
            Op::Move { at: n(at)?, len: n(len)?, to: n(to)? }
        }
        10 => args(a, w).map(|[base, new]| Op::Edit { base, new })?,
        _ => return case_of(w),
    };
    Ok(PathOp { path, op })
}

/// A write op `[case, arg*]`; aspects by index into the write's AK list. Its own pair, not a
/// `Form`: a text session's op refuses to travel.
pub(crate) fn write_op_to(o: &WriteOp) -> Result<Value> {
    let u = Value::uint;
    let k = |k: &u32| u(u64::from(*k));
    Ok(Value::List(match o {
        WriteOp::Create(rec) => vec![u(0), rec.to_value()],
        WriteOp::CreateWithKeys(rec) => vec![u(1), rec.to_value()],
        WriteOp::Path { tid, key, op } => vec![u(2), tid.to_wire(), k(key), path_op_to(op)?],
        WriteOp::Fire { tid, key, v, replaces } => vec![u(3), tid.to_wire(), k(key), v.clone(), replaces.to_wire()],
        WriteOp::PurgeBy { tid, key, by } => vec![u(4), tid.to_wire(), k(key), u(*by as u64)],
        WriteOp::Purge { tid, key } => vec![u(5), tid.to_wire(), k(key)],
        WriteOp::PurgeCommit { tid, key, commit } => vec![u(6), tid.to_wire(), k(key), commit.to_wire()],
        WriteOp::PurgeAuthor { tid, key, author } => vec![u(7), tid.to_wire(), k(key), author.to_wire()],
        WriteOp::PurgeThing(t) => vec![u(9), t.to_wire()],
        WriteOp::Inbox { of, inbox } => vec![u(10), of.to_wire(), inbox.to_wire()],
    }))
}

pub(crate) fn write_op_from(v: Value) -> Result<WriteOp> {
    let (case, a) = tagged(v, "write op")?;
    let w = "write op";
    let k = |v: Value| u32::try_from(uint(&v, "key index")?).map_err(|_| bad("key index"));
    let record = |r: Value| CreationRecord::from_value(&r).ok_or_else(|| bad("creation record"));
    Ok(match case {
        0 => args(a, w).and_then(|[r]| record(r)).map(WriteOp::Create)?,
        1 => args(a, w).and_then(|[r]| record(r)).map(WriteOp::CreateWithKeys)?,
        2 => {
            let [t, key, op] = args(a, w)?;
            WriteOp::Path { tid: Form::from_wire(t)?, key: k(key)?, op: path_op_from(op)? }
        }
        3 => {
            let [t, key, v, replaces] = args(a, w)?;
            WriteOp::Fire { tid: Form::from_wire(t)?, key: k(key)?, v, replaces: Form::from_wire(replaces)? }
        }
        4 => {
            let [t, key, by] = args(a, w)?;
            WriteOp::PurgeBy { tid: Form::from_wire(t)?, key: k(key)?, by: PurgeBy::from_id(uint(&by, "purge by")?).ok_or_else(|| bad("purge by"))? }
        }
        5 => {
            let [t, key] = args(a, w)?;
            WriteOp::Purge { tid: Form::from_wire(t)?, key: k(key)? }
        }
        6 => {
            let [t, key, c] = args(a, w)?;
            WriteOp::PurgeCommit { tid: Form::from_wire(t)?, key: k(key)?, commit: Form::from_wire(c)? }
        }
        7 => {
            let [t, key, author] = args(a, w)?;
            WriteOp::PurgeAuthor { tid: Form::from_wire(t)?, key: k(key)?, author: Form::from_wire(author)? }
        }
        9 => args(a, w).and_then(|[t]| Tid::from_wire(t)).map(WriteOp::PurgeThing)?,
        10 => {
            let [of, inbox] = args(a, w)?;
            WriteOp::Inbox { of: Form::from_wire(of)?, inbox: Form::from_wire(inbox)? }
        }
        _ => return case_of(w),
    })
}

/// An outcome `[0, value] | [1, code, detail*]` (a Reply's, a read's, a wait's Notify) as a
/// call's result; the outer `Err` when malformed.
fn outcome_value(v: Value) -> Result<Result<Value>> {
    let (case, a) = tagged(v, "outcome")?;
    match case {
        0 => args(a, "outcome").map(|[v]| Ok(v)),
        1 => error_from(a).map(Err),
        _ => case_of("outcome"),
    }
}

/// An error outcome's `code, detail*` as its API error.
fn error_from(a: Vec<Value>) -> Result<Error> {
    let mut a = a.into_iter();
    let code = a.next().ok_or_else(|| bad("error code"))?;
    Ok(error_of(uint(&code, "error code")?, a.collect()))
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
            Ok(v) => Outcome::Ok { value: v.to_wire() },
            Err(e) => outcome_of(e),
        }
        .to_value()
    }
    fn from_wire(v: Value) -> Result<Result<Option<Value>>> {
        Ok(match outcome_value(v)? {
            Ok(v) => Ok(Form::from_wire(v)?),
            Err(e) => Err(e),
        })
    }
}

/// An origin: `[0] | [1, stamp] | [2, stamp] | [3, derived]`.
impl Form for Origin {
    fn to_wire(&self) -> Value {
        let u = Value::uint;
        Value::List(match self {
            Origin::Initial => vec![u(0)],
            Origin::Local(s) => vec![u(1), s.to_wire()],
            Origin::Remote(s) => vec![u(2), s.to_wire()],
            Origin::Derived(d) => vec![u(3), d.to_wire()],
        })
    }
    fn from_wire(v: Value) -> Result<Origin> {
        let (case, a) = tagged(v, "origin")?;
        let w = "origin";
        match case {
            0 => args(a, w).map(|[]| Origin::Initial),
            1 => args(a, w).and_then(|[s]| Form::from_wire(s)).map(Origin::Local),
            2 => args(a, w).and_then(|[s]| Form::from_wire(s)).map(Origin::Remote),
            3 => args(a, w).and_then(|[d]| Form::from_wire(d)).map(Origin::Derived),
            _ => case_of(w),
        }
    }
}

/// A part's body: `[0, Opt(value)] | [1, limit] | [2, by, Opt(author)] | [3]`.
impl Form for Body<Value> {
    fn to_wire(&self) -> Value {
        let u = Value::uint;
        Value::List(match self {
            Body::Held(v) => vec![u(0), v.to_wire()],
            Body::TooLarge { limit } => vec![u(1), u(*limit)],
            Body::Purged { by, author } => vec![u(2), by.to_wire(), author.to_wire()],
            Body::NotFetched => vec![u(3)],
        })
    }
    fn from_wire(v: Value) -> Result<Body<Value>> {
        let (case, a) = tagged(v, "body")?;
        let w = "body";
        match case {
            0 => args(a, w).and_then(|[v]| Form::from_wire(v)).map(Body::Held),
            1 => args(a, w).and_then(|[n]| uint(&n, w)).map(|limit| Body::TooLarge { limit }),
            2 => {
                let [by, author] = args(a, w)?;
                Ok(Body::Purged { by: Form::from_wire(by)?, author: Form::from_wire(author)? })
            }
            3 => args(a, w).map(|[]| Body::NotFetched),
            _ => case_of(w),
        }
    }
}

/// A commit's position: `[ts, commit id]`.
impl Form for CommitPos {
    fn to_wire(&self) -> Value {
        Value::List(vec![self.0.ts.to_wire(), self.0.id.to_wire()])
    }
    fn from_wire(v: Value) -> Result<CommitPos> {
        let [ts, id] = fixed(v, "position")?;
        Ok(CommitPos::of(Form::from_wire(ts)?, Form::from_wire(id)?))
    }
}

/// A commit: `[stamp, kind, Opt(reverts), [reverted_by*], in_effect, [part*]]`, a part
/// `[tid, ak, valid, body, Opt(edited)]`.
impl Form for Commit {
    fn to_wire(&self) -> Value {
        let parts = self.parts().map(|(t, ak, p)| Value::List(vec![t.to_wire(), ak.to_wire(), p.valid.to_wire(), p.body.to_wire(), p.edited.to_wire()])).collect();
        Value::List(vec![self.stamp.to_wire(), self.kind.to_wire(), self.reverts.to_wire(), self.reverted_by.to_wire(), self.in_effect.to_wire(), Value::List(parts)])
    }
    fn from_wire(v: Value) -> Result<Commit> {
        let [stamp, kind, reverts, reverted_by, in_effect, parts] = fixed(v, "commit")?;
        let parts = list(parts, "parts")?
            .into_iter()
            .map(|p| {
                let [t, a, valid, body, edited] = fixed(p, "part")?;
                Ok((Form::from_wire(t)?, Form::from_wire(a)?, Part { valid: Form::from_wire(valid)?, body: Form::from_wire(body)?, edited: Form::from_wire(edited)? }))
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(Commit::of(Form::from_wire(stamp)?, Form::from_wire(kind)?, Form::from_wire(reverts)?, Form::from_wire(reverted_by)?, Form::from_wire(in_effect)?, parts))
    }
}

/// `grants`: `[[holder, role, Opt(until), retain_copy, may_grant, from_now]*]`.
impl Form for Grants {
    fn to_wire(&self) -> Value {
        Value::List(self.iter().map(|(h, g)| Value::List(vec![h.to_wire(), g.role.to_wire(), g.until.to_wire(), g.retain_copy.to_wire(), g.may_grant.to_wire(), g.from_now.to_wire()])).collect())
    }
    fn from_wire(v: Value) -> Result<Grants> {
        list(v, "grants")?
            .into_iter()
            .map(|g| {
                let [h, role, until, retain, may, from_now] = fixed(g, "grant")?;
                let grant = Grant { role: Form::from_wire(role)?, until: Form::from_wire(until)?, retain_copy: Form::from_wire(retain)?, may_grant: Form::from_wire(may)?, from_now: Form::from_wire(from_now)? };
                Ok((Form::from_wire(h)?, grant))
            })
            .collect()
    }
}

/// A holder (`holders`): `[thing, kind, role, Opt(until), [through*]]`, kind 0 a thing, 1 a
/// link's, 2 a key, 3 the public.
impl Form for Holder {
    fn to_wire(&self) -> Value {
        Value::List(vec![self.thing.to_wire(), self.kind.to_wire(), self.role.to_wire(), self.until.to_wire(), self.through.to_wire()])
    }
    fn from_wire(v: Value) -> Result<Holder> {
        let [thing, kind, role, until, through] = fixed(v, "holder")?;
        Ok(Holder { thing: Form::from_wire(thing)?, kind: Form::from_wire(kind)?, role: Form::from_wire(role)?, until: Form::from_wire(until)?, through: Form::from_wire(through)? })
    }
}

/// An origin's, a commit's, and `created`, `changed` (in an `Opt`): `[commit id, author, ts, received]`.
impl Form for Stamp {
    fn to_wire(&self) -> Value {
        Value::List(vec![self.id.to_wire(), self.author.to_wire(), self.ts.to_wire(), self.received.to_wire()])
    }
    fn from_wire(v: Value) -> Result<Stamp> {
        let [id, author, ts, received] = fixed(v, "stamp")?;
        Ok(Stamp::new(Form::from_wire(id)?, Form::from_wire(author)?, Form::from_wire(ts)?, Form::from_wire(received)?))
    }
}

/// `status`: `[connected, [[tid, state, not_taking]*]]`, state 0 synced, 1 syncing, 2 not
/// connected, 3 stranded.
impl Form for Status {
    fn to_wire(&self) -> Value {
        let units = self.units.iter().map(|(t, g)| Value::List(vec![t.to_wire(), g.state.to_wire(), g.not_taking.to_wire()]));
        Value::List(vec![self.connected.to_wire(), Value::List(units.collect())])
    }
    fn from_wire(v: Value) -> Result<Status> {
        let [connected, units] = fixed(v, "status")?;
        let units = list(units, "status")?
            .into_iter()
            .map(|g| {
                let [t, state, not_taking] = fixed(g, "status")?;
                Ok((Form::from_wire(t)?, UnitSync { state: Form::from_wire(state)?, not_taking: Form::from_wire(not_taking)? }))
            })
            .collect::<Result<_>>()?;
        Ok(Status { connected: Form::from_wire(connected)?, units })
    }
}

/// A scope: `[0, tid]` a thing, `[1, [[tid, ak]*]]` aspects.
impl Form for Scope {
    fn to_wire(&self) -> Value {
        Value::List(match self {
            Scope::Thing(t) => vec![Value::uint(0), t.to_wire()],
            Scope::Aspects(v) => vec![Value::uint(1), v.to_wire()],
        })
    }
    fn from_wire(v: Value) -> Result<Scope> {
        let [k, x] = fixed(v, "scope")?;
        match uint(&k, "scope")? {
            0 => Form::from_wire(x).map(Scope::Thing),
            1 => Form::from_wire(x).map(Scope::Aspects),
            _ => case_of("scope"),
        }
    }
}

/// A listing's address: `[0, scope]` a scope's writes, `[1, tid, ak]` a signal's fires, `[2,
/// tid, ak, commit id]` a fire's versions.
impl Form for Address {
    fn to_wire(&self) -> Value {
        Value::List(match self {
            Address::Writes(s) => vec![Value::uint(0), s.to_wire()],
            Address::Fired(t, a) => vec![Value::uint(1), t.to_wire(), a.to_wire()],
            Address::Versions(t, a, c) => vec![Value::uint(2), t.to_wire(), a.to_wire(), c.to_wire()],
        })
    }
    fn from_wire(v: Value) -> Result<Address> {
        let (case, a) = tagged(v, "address")?;
        let w = "address";
        match case {
            0 => args(a, w).and_then(|[s]| Form::from_wire(s)).map(Address::Writes),
            1 => {
                let [t, k] = args(a, w)?;
                Ok(Address::Fired(Form::from_wire(t)?, Form::from_wire(k)?))
            }
            2 => {
                let [t, k, c] = args(a, w)?;
                Ok(Address::Versions(Form::from_wire(t)?, Form::from_wire(k)?, Form::from_wire(c)?))
            }
            _ => case_of(w),
        }
    }
}

/// `[0]` newest, `[1]` oldest, `[2, position]` before it, `[3, position]` after it.
impl Form for CommitFrom {
    fn to_wire(&self) -> Value {
        Value::List(match self {
            CommitFrom::Newest => vec![Value::uint(0)],
            CommitFrom::Oldest => vec![Value::uint(1)],
            CommitFrom::Before(p) => vec![Value::uint(2), p.to_wire()],
            CommitFrom::After(p) => vec![Value::uint(3), p.to_wire()],
        })
    }
    fn from_wire(v: Value) -> Result<CommitFrom> {
        let (case, a) = tagged(v, "from")?;
        let w = "from";
        match case {
            0 => args(a, w).map(|[]| CommitFrom::Newest),
            1 => args(a, w).map(|[]| CommitFrom::Oldest),
            2 => args(a, w).and_then(|[p]| Form::from_wire(p)).map(CommitFrom::Before),
            3 => args(a, w).and_then(|[p]| Form::from_wire(p)).map(CommitFrom::After),
            _ => case_of(w),
        }
    }
}

/// `[from, Opt(limit), [actor*], [kind*], Opt(reverts), Opt(reverted_by), Opt(in_effect)]`.
impl Form for CommitQuery {
    fn to_wire(&self) -> Value {
        Value::List(vec![
            self.from.to_wire(),
            self.limit.to_wire(),
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
            limit: Form::from_wire(limit)?,
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
        Value::List(vec![self.commits.to_wire(), self.more.to_wire(), self.complete.to_wire()])
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
        let w = "commit event";
        match case {
            0 => {
                let [id, commit] = args(a, w)?;
                Ok(CommitEvent::Commit { id: Form::from_wire(id)?, commit: Form::from_wire(commit)? })
            }
            1 => args(a, w).map(|[]| CommitEvent::Reread),
            2 => error_from(a).map(CommitEvent::Ended),
            _ => case_of(w),
        }
    }
}

/// `[0]` all, `[1, tid]` a thing.
impl Form for SyncScope {
    fn to_wire(&self) -> Value {
        Value::List(match self {
            SyncScope::All => vec![Value::uint(0)],
            SyncScope::Thing(t) => vec![Value::uint(1), t.to_wire()],
        })
    }
    fn from_wire(v: Value) -> Result<SyncScope> {
        let (case, a) = tagged(v, "sync scope")?;
        let w = "sync scope";
        match case {
            0 => args(a, w).map(|[]| SyncScope::All),
            1 => args(a, w).and_then(|[t]| Form::from_wire(t)).map(SyncScope::Thing),
            _ => case_of(w),
        }
    }
}

/// An expiry: `[0, at]` or `[1, ms from now]`.
impl Form for Expiry {
    fn to_wire(&self) -> Value {
        Value::List(match self {
            Expiry::At(t) => vec![Value::uint(0), t.to_wire()],
            Expiry::In(d) => vec![Value::uint(1), Value::uint(u64::try_from(d.as_millis()).unwrap_or(u64::MAX))],
        })
    }
    fn from_wire(v: Value) -> Result<Expiry> {
        let [case, n] = fixed(v, "expiry")?;
        let n = uint(&n, "expiry")?;
        match uint(&case, "expiry")? {
            0 => Ok(Expiry::At(Time(n))),
            1 => Ok(Expiry::In(std::time::Duration::from_millis(n))),
            _ => case_of("expiry"),
        }
    }
}

/// A diagnostic: `[kind, [tid*], Opt(commit id), Opt(peer), detail]`; one of a kind this side
/// does not know reads as `BadInput` (told as handled).
impl Form for osis_engine::Diagnostic {
    fn to_wire(&self) -> Value {
        Value::List(vec![self.kind.to_wire(), self.tids.to_wire(), self.commit.to_wire(), self.peer.to_wire(), Value::Str(self.detail.clone())])
    }
    fn from_wire(v: Value) -> Result<osis_engine::Diagnostic> {
        let [kind, tids, commit, peer, detail] = fixed(v, "diagnostic")?;
        let Value::Str(detail) = detail else { return Err(bad("diagnostic")) };
        Ok(osis_engine::Diagnostic {
            kind: Form::from_wire(kind).unwrap_or(DiagnosticKind::BadInput),
            tids: Form::from_wire(tids)?,
            commit: Form::from_wire(commit)?,
            peer: Form::from_wire(peer)?,
            detail,
        })
    }
}

/// An API error as a Reply's outcome (spec/wire.md §11.2 Outcome error codes).
pub(crate) fn outcome_of(e: &Error) -> Outcome {
    let text = |s: &str| vec![Value::Str(s.to_string())];
    let (code, detail) = match e {
        Error::UnknownThing { tid } => (ApiCode::UNKNOWN_THING, vec![tid.to_wire()]),
        Error::UnknownKeys { tid } => (ApiCode::UNKNOWN_KEYS, vec![tid.to_wire()]),
        Error::Permission { tid, needs } => (ApiCode::PERMISSION, vec![tid.to_wire(), needs.to_wire()]),
        Error::NotEnabled { tid, signal } => (ApiCode::NOT_ENABLED, vec![tid.to_wire(), signal.to_wire()]),
        Error::LeavesNoAdmin { tid } => (ApiCode::LEAVES_NO_ADMIN, vec![tid.to_wire()]),
        Error::Type { path, reason } => (ApiCode::TYPE, vec![path.to_wire(), Value::Str(reason.clone())]),
        Error::TooLarge { limit } => (ApiCode::TOO_LARGE, vec![limit.to_wire()]),
        Error::Stranded { things } => (ApiCode::STRANDED, vec![things.to_wire()]),
        Error::Invalid(m) => (ApiCode::INVALID, text(m)),
        Error::Storage(m) => (ApiCode::STORAGE, text(m)),
        Error::Network(m) => (ApiCode::NETWORK, text(m)),
        Error::Unsupported(m) => (ApiCode::UNSUPPORTED, text(m)),
        Error::OutcomeUnknown => (ApiCode::OUTCOME_UNKNOWN, Vec::new()),
        Error::Refused(m) => (ApiCode::REFUSED, text(m)),
        Error::Closed => (ApiCode::CLOSED, Vec::new()),
        Error::InUse => (ApiCode::IN_USE, Vec::new()),
        Error::NotUndoable { commit, reason } => (ApiCode::NOT_UNDOABLE, vec![commit.to_wire(), reason.to_wire()]),
        // no code of its own on the wire: told as what it is
        e @ Error::NotBuilt => (ApiCode::INVALID, text(&e.to_string())),
    };
    Outcome::Err { code, detail }
}

/// The API error a Reply's error outcome stands for; a detail that does not read as its code's
/// is told as text.
pub(crate) fn error_of(code: u64, detail: Vec<Value>) -> Error {
    fn read<T: Form>(v: Option<Value>) -> Option<T> {
        v.and_then(|v| T::from_wire(v).ok())
    }
    let text = detail.iter().find_map(|v| if let Value::Str(s) = v { Some(s.clone()) } else { None }).unwrap_or_default();
    let mut d = detail.into_iter();
    let (first, second) = (d.next(), d.next());
    let decoded = match code {
        ApiCode::UNKNOWN_THING => read(first).map(|tid| Error::UnknownThing { tid }),
        ApiCode::UNKNOWN_KEYS => read(first).map(|tid| Error::UnknownKeys { tid }),
        ApiCode::LEAVES_NO_ADMIN => read(first).map(|tid| Error::LeavesNoAdmin { tid }),
        ApiCode::PERMISSION => read(first).zip(read(second)).map(|(tid, needs)| Error::Permission { tid, needs }),
        ApiCode::NOT_ENABLED => read(first).zip(read(second)).map(|(tid, signal)| Error::NotEnabled { tid, signal }),
        ApiCode::TYPE => read(first).map(|path| Error::Type { path, reason: text.clone() }),
        ApiCode::NOT_UNDOABLE => read(first).zip(read(second)).map(|(commit, reason)| Error::NotUndoable { commit, reason }),
        ApiCode::TOO_LARGE => Some(Error::TooLarge { limit: first.as_ref().map_or(0, limit_of) }),
        ApiCode::STRANDED => Some(Error::Stranded { things: first.and_then(|g| list(g, "things").ok()).unwrap_or_default().into_iter().filter_map(|g| Tid::from_wire(g).ok()).collect() }),
        ApiCode::STORAGE => Some(Error::Storage(text.clone())),
        ApiCode::NETWORK => Some(Error::Network(text.clone())),
        ApiCode::UNSUPPORTED => Some(Error::Unsupported(text.clone())),
        ApiCode::OUTCOME_UNKNOWN => Some(Error::OutcomeUnknown),
        ApiCode::REFUSED => Some(Error::Refused(text.clone())),
        ApiCode::CLOSED => Some(Error::Closed),
        ApiCode::IN_USE => Some(Error::InUse),
        _ => None,
    };
    decoded.unwrap_or(Error::Invalid(text))
}

/// A Reply's outcome as a call's result.
pub(crate) fn result_of(o: Outcome) -> Result<Value> {
    match o {
        Outcome::Ok { value } => Ok(value),
        Outcome::Err { code, detail } => Err(error_of(code, detail)),
    }
}
