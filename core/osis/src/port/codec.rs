//! Values of the client port's method table (notes/client-port.md §2): API types to and from
//! untyped `Value`s (`Port`), and API errors to and from Reply error codes (`osis_proto::ApiCode`).
//! A type of fixed positions is declared once (`port_struct!`, `port_enum!`, `port_index!`), which
//! gives both directions; only shapes that are not a plain list of fields or a tagged case
//! (a map flattened into rows, a constructor deriving fields, ops a node may refuse) are written
//! by hand, each direction beside the other.

use crate::commits::{Address as At, Body, Commit, CommitKind, CommitPage, CommitQuery, NotUndoableReason, Part, Scope};
use crate::error::{Error, Result};
use crate::read::{Grant, Grants, GroupsOf, Stamp, ThingStamp};
use crate::share::{AccountNode, ContactCard, GrantOpts, GroupSync, Holder, HolderKind, Address, InviteId, LinkId, LinkInfo, Member, Reads, SetRoleOpts, ShareLink, Status, SyncScope, SyncState};
use crate::account::{PairOffer, PairReply, PairRequest};
use crate::clients::{Client, ClientSecret};
use crate::serving::SyncId;
use crate::watch::{DerivedFrom, Origin};
use crate::backlinks::{Backlink, BacklinkPage, BacklinkQuery};
use crate::commit_id::{CommitFrom, CommitId, CommitPos};
use osis_base::{Ak, CommitId as RawCommitId, Role, Tid, Ts, Value, Time};
use osis_crdt::{Op, PathOp, PathSeg};
use osis_node::{Diagnostic, DiagnosticKind};
use osis_proto::{ApiCode, Outcome};
use osis_schema::{Path, PurgeBy, Retention, Step};

pub(crate) fn bad(what: &str) -> Error {
    Error::Invalid(format!("port: malformed {what}"))
}

pub(crate) fn u(n: u64) -> Value {
    Value::uint(n)
}

/// A type as a port value, both directions (`internals::Port` for tests).
#[doc(hidden)]
pub trait Port: Sized {
    fn to_port(&self) -> Value;
    fn from_port(v: Value) -> Result<Self>;
}

/// `v` read as a `T`.
pub(crate) fn of<T: Port>(v: Value) -> Result<T> {
    T::from_port(v)
}

/// `v` as bytes.
pub(crate) fn bytes(v: Value) -> Result<Vec<u8>> {
    match v {
        Value::Bytes(b) => Ok(b),
        _ => Err(bad("bytes")),
    }
}

/// `v` as a list.
pub(crate) fn list(v: Value) -> Result<Vec<Value>> {
    match v {
        Value::List(l) => Ok(l),
        _ => Err(bad("list")),
    }
}

/// Reads positions of a list value.
pub(crate) struct Args(std::vec::IntoIter<Value>);

impl Args {
    pub fn new(v: Value) -> Result<Args> {
        list(v).map(Args::of)
    }
    pub fn of(l: Vec<Value>) -> Args {
        Args(l.into_iter())
    }
    pub fn next(&mut self) -> Result<Value> {
        self.0.next().ok_or_else(|| bad("argument count"))
    }
    /// The next position as a `T`.
    pub fn get<T: Port>(&mut self) -> Result<T> {
        T::from_port(self.next()?)
    }
    pub fn uint(&mut self) -> Result<u64> {
        self.get()
    }
    pub fn bool(&mut self) -> Result<bool> {
        self.get()
    }
    pub fn tid(&mut self) -> Result<Tid> {
        self.get()
    }
    pub fn ak(&mut self) -> Result<Ak> {
        self.get()
    }
    pub fn text(&mut self) -> Result<String> {
        self.get()
    }
    pub fn bytes(&mut self) -> Result<Vec<u8>> {
        bytes(self.next()?)
    }
    pub fn list(&mut self) -> Result<Vec<Value>> {
        list(self.next()?)
    }
    pub fn opt(&mut self) -> Result<Option<Value>> {
        self.get()
    }
    /// The positions not read yet.
    pub fn rest(&mut self) -> Vec<Value> {
        self.0.by_ref().collect()
    }
    pub fn end(self) -> Result<()> {
        if self.0.len() == 0 { Ok(()) } else { Err(bad("argument count")) }
    }
}

/// A struct as the list of the named fields, in that order.
macro_rules! port_struct {
    ($t:ty { $($f:ident),+ $(,)? }) => {
        impl Port for $t {
            fn to_port(&self) -> Value {
                Value::List(vec![$(self.$f.to_port()),+])
            }
            fn from_port(v: Value) -> Result<Self> {
                let mut a = Args::new(v)?;
                let x = Self { $($f: a.get()?),+ };
                a.end()?;
                Ok(x)
            }
        }
    };
}

/// An enum as `[case, payload*]`: tuple cases list their fields in order, struct cases the
/// named fields in that order.
macro_rules! port_enum {
    ($t:ty, $what:literal { $($id:literal $c:ident $(($($x:ident),+))? $({$($f:ident),+})?),+ $(,)? }) => {
        impl Port for $t {
            fn to_port(&self) -> Value {
                match self {
                    $(Self::$c $(($($x),+))? $({$($f),+})? => Value::List(vec![u($id) $($(, $x.to_port())+)? $($(, $f.to_port())+)?]),)+
                }
            }
            fn from_port(v: Value) -> Result<Self> {
                let mut a = Args::new(v)?;
                let x = match a.uint()? {
                    $($id => Self::$c $(($(port_enum!(@get a $x)),+))? $({$($f: a.get()?),+})?,)+
                    _ => return Err(bad($what)),
                };
                a.end()?;
                Ok(x)
            }
        }
    };
    (@get $a:ident $x:ident) => { $a.get()? };
}

/// A unit-only enum as a bare uint.
macro_rules! port_index {
    ($t:ty, $what:literal { $($id:literal $c:ident),+ $(,)? }) => {
        impl Port for $t {
            fn to_port(&self) -> Value {
                u(match self {
                    $(Self::$c => $id,)+
                })
            }
            fn from_port(v: Value) -> Result<Self> {
                match v.as_uint() {
                    $(Some($id) => Ok(Self::$c),)+
                    _ => Err(bad($what)),
                }
            }
        }
    };
}

impl Port for Value {
    fn to_port(&self) -> Value {
        self.clone()
    }
    fn from_port(v: Value) -> Result<Value> {
        Ok(v)
    }
}

impl Port for Tid {
    fn to_port(&self) -> Value {
        Value::Tid(*self)
    }
    fn from_port(v: Value) -> Result<Tid> {
        match v {
            Value::Tid(t) => Ok(t),
            _ => Err(bad("tid")),
        }
    }
}

impl Port for bool {
    fn to_port(&self) -> Value {
        Value::Bool(*self)
    }
    fn from_port(v: Value) -> Result<bool> {
        match v {
            Value::Bool(b) => Ok(b),
            _ => Err(bad("bool")),
        }
    }
}

impl Port for u64 {
    fn to_port(&self) -> Value {
        u(*self)
    }
    fn from_port(v: Value) -> Result<u64> {
        v.as_uint().ok_or_else(|| bad("uint"))
    }
}

impl Port for usize {
    fn to_port(&self) -> Value {
        u(*self as u64)
    }
    fn from_port(v: Value) -> Result<usize> {
        v.as_uint().and_then(|n| usize::try_from(n).ok()).ok_or_else(|| bad("index"))
    }
}

impl Port for String {
    fn to_port(&self) -> Value {
        Value::Str(self.clone())
    }
    fn from_port(v: Value) -> Result<String> {
        match v {
            Value::Str(s) => Ok(s),
            _ => Err(bad("text")),
        }
    }
}

impl Port for Ak {
    fn to_port(&self) -> Value {
        Value::Str(self.as_str().to_owned())
    }
    fn from_port(v: Value) -> Result<Ak> {
        match v {
            Value::Str(s) => Ak::new(&s).map_err(|_| bad("AK")),
            _ => Err(bad("AK")),
        }
    }
}

impl Port for Time {
    fn to_port(&self) -> Value {
        u(self.0)
    }
    fn from_port(v: Value) -> Result<Time> {
        v.as_uint().map(Time).ok_or_else(|| bad("time"))
    }
}

impl Port for Ts {
    fn to_port(&self) -> Value {
        u(self.to_u64())
    }
    fn from_port(v: Value) -> Result<Ts> {
        v.as_uint().and_then(Ts::from_u64).ok_or_else(|| bad("ts"))
    }
}

impl Port for RawCommitId {
    fn to_port(&self) -> Value {
        Value::bytes(&self.0)
    }
    fn from_port(v: Value) -> Result<RawCommitId> {
        bytes(v)?.try_into().map(RawCommitId).map_err(|_| bad("commit id"))
    }
}

impl Port for CommitId {
    fn to_port(&self) -> Value {
        self.0.to_port()
    }
    fn from_port(v: Value) -> Result<CommitId> {
        of(v).map(CommitId)
    }
}

impl Port for LinkId {
    fn to_port(&self) -> Value {
        self.0.to_port()
    }
    fn from_port(v: Value) -> Result<LinkId> {
        of(v).map(LinkId)
    }
}

/// A type as its text (`Display`, checked by `FromStr`).
macro_rules! port_text {
    ($($t:ty),+) => {$(
        impl Port for $t {
            fn to_port(&self) -> Value {
                Value::Str(self.to_string())
            }
            fn from_port(v: Value) -> Result<Self> {
                of::<String>(v)?.parse()
            }
        }
    )+};
}

port_text!(Address, ShareLink, ContactCard, SyncId, PairOffer, PairRequest, PairReply);

impl Port for InviteId {
    fn to_port(&self) -> Value {
        Value::bytes(self.bytes())
    }
    fn from_port(v: Value) -> Result<InviteId> {
        InviteId::from_bytes(&bytes(v)?)
    }
}

impl Port for ClientSecret {
    fn to_port(&self) -> Value {
        Value::bytes(self.expose())
    }
    fn from_port(v: Value) -> Result<ClientSecret> {
        v.as_array::<32>().map(ClientSecret::from_bytes).ok_or_else(|| bad("client secret"))
    }
}

/// `[0, value]`, or an error as a Reply's (`[1, code, detail*]`).
impl<T: Port> Port for Result<T> {
    fn to_port(&self) -> Value {
        match self {
            Ok(x) => Value::List(vec![u(0), x.to_port()]),
            Err(e) => outcome_err(e).to_value(),
        }
    }
    fn from_port(v: Value) -> Result<Result<T>> {
        let mut a = Args::new(v)?;
        match a.uint()? {
            0 => {
                let x = a.get()?;
                a.end()?;
                Ok(Ok(x))
            }
            1 => {
                let code = a.uint()?;
                Ok(Err(error_of(code, a.rest())))
            }
            _ => Err(bad("result")),
        }
    }
}

/// `[]` or `[x]`.
impl<T: Port> Port for Option<T> {
    fn to_port(&self) -> Value {
        Value::opt(self.as_ref().map(T::to_port))
    }
    fn from_port(v: Value) -> Result<Option<T>> {
        let mut l = list(v)?;
        match l.len() {
            0 => Ok(None),
            1 => l.pop().map(T::from_port).transpose(),
            _ => Err(bad("option")),
        }
    }
}

impl<T: Port> Port for Vec<T> {
    fn to_port(&self) -> Value {
        Value::List(self.iter().map(T::to_port).collect())
    }
    fn from_port(v: Value) -> Result<Vec<T>> {
        list(v)?.into_iter().map(T::from_port).collect()
    }
}

impl<A: Port, B: Port> Port for (A, B) {
    fn to_port(&self) -> Value {
        Value::List(vec![self.0.to_port(), self.1.to_port()])
    }
    fn from_port(v: Value) -> Result<(A, B)> {
        let mut a = Args::new(v)?;
        let x = (a.get()?, a.get()?);
        a.end()?;
        Ok(x)
    }
}

port_index!(Role, "role" { 0 Read, 1 Write, 2 Admin, 3 Sync });
port_index!(HolderKind, "holder kind" { 0 Actor, 1 Link, 2 Key });
port_index!(Reads, "reads" { 0 Kept, 1 FromNow, 2 All });
port_index!(CommitKind, "commit kind" { 0 Content, 1 Revert, 2 Role, 3 Snapshot });
port_index!(SyncState, "state" { 0 Synced, 1 Syncing, 2 NotConnected, 3 Refused, 4 Stranded });
port_index!(DerivedFrom, "reason" { 0 ValidityChanged, 1 Expired, 2 Purged, 3 Arrived, 4 LostAccess, 5 Recovered });
port_index!(DiagnosticKind, "diagnostic kind" {
    0 BadInput,
    1 CollidingRecord,
    2 Parked,
    3 Pending,
    4 OverlappingCounters,
    5 Removed,
    6 Callback,
    7 NotSynced,
    8 Stranded,
    9 Uncommitted,
    10 EphemeralRefused,
    11 Mismatch,
    12 Storage,
    13 Repair,
    14 OwnWriteInvalid,
    15 Unreadable,
    16 SyncStopped,
    17 DisputesUnexamined,
    18 OwnWriteFailed,
    19 ClockSkew,
    20 InputCapped,
});

port_enum!(Step, "path step" { 0 Field(f), 1 Case(c), 2 Key(k), 3 Index(i), 4 Elem(e) });
port_enum!(PathSeg, "path segment" { 0 Field(f), 1 Case(c), 2 Key(k), 3 Index(i) });
port_enum!(Origin, "source" { 0 Initial, 1 Local(s), 2 Remote(s), 3 Derived(c) });
port_enum!(Scope, "scope" { 0 Thing(t), 1 Aspects(v), 2 Group(t) });
// `[0, scope]` a scope's writes (an aspect's: `Scope::Aspects` naming it), `[1, tid, ak]` a
// signal's fires, `[2, tid, ak, commit id]` a fire's versions.
port_enum!(At, "address" { 0 Writes(s), 1 Fired(t, k), 2 Versions(t, k, o) });
port_enum!(Body<Value>, "part body" { 0 Held(v), 1 TooLarge { limit }, 2 Purged { by, actor }, 3 NotFetched });
// A member of a group: `[0, tid]` item, `[1, tid]` subgroup.
port_enum!(Member, "member" { 0 Item(t), 1 Subgroup(t) });

port_struct!(GroupsOf { item_of, subgroup_of, within });
port_struct!(Diagnostic { kind, tids, commit, peer, detail });
port_struct!(CommitQuery { from, limit, actors, kinds, reverts, reverted_by, in_effect });
port_struct!(CommitPage { commits, more, complete });
port_struct!(GrantOpts { until, may_grant, reads });
port_struct!(SetRoleOpts { retain_copy });
port_struct!(Holder { actor, kind, role, until, through });
port_struct!(LinkInfo { id, target, role, until, single_use });
port_struct!(Backlink { tid, ak });
port_struct!(BacklinkQuery { after, limit });
port_struct!(BacklinkPage { backlinks, more });
port_struct!(AccountNode { node, role });
port_struct!(Client { actor, until });

impl Port for Path {
    fn to_port(&self) -> Value {
        self.0.to_port()
    }
    fn from_port(v: Value) -> Result<Path> {
        of(v).map(Path)
    }
}

/// `[ts, commit id]`.
impl Port for CommitPos {
    fn to_port(&self) -> Value {
        Value::List(vec![self.0.ts.to_port(), self.0.id.to_port()])
    }
    fn from_port(v: Value) -> Result<CommitPos> {
        let (ts, id) = of(v)?;
        Ok(CommitPos::of(ts, id))
    }
}

/// `[0]` newest, `[1]` oldest, `[2, ts, commit id]` before, `[3, ts, commit id]` after.
impl Port for CommitFrom {
    fn to_port(&self) -> Value {
        let at = |k: u64, p: &CommitPos| vec![u(k), p.0.ts.to_port(), p.0.id.to_port()];
        Value::List(match self {
            CommitFrom::Newest => vec![u(0)],
            CommitFrom::Oldest => vec![u(1)],
            CommitFrom::Before(p) => at(2, p),
            CommitFrom::After(p) => at(3, p),
        })
    }
    fn from_port(v: Value) -> Result<CommitFrom> {
        let mut a = Args::new(v)?;
        let f = match a.uint()? {
            0 => CommitFrom::Newest,
            1 => CommitFrom::Oldest,
            k @ (2 | 3) => {
                let p = CommitPos::of(a.get()?, a.get()?);
                if k == 2 { CommitFrom::Before(p) } else { CommitFrom::After(p) }
            }
            _ => return Err(bad("commit place")),
        };
        a.end()?;
        Ok(f)
    }
}

/// `[commit id, actor, ts, received]` (`written` is the ts's).
impl Port for Stamp {
    fn to_port(&self) -> Value {
        Value::List(vec![self.id.to_port(), self.actor.to_port(), self.ts.to_port(), self.received.to_port()])
    }
    fn from_port(v: Value) -> Result<Stamp> {
        let mut a = Args::new(v)?;
        let s = Stamp::new(a.get()?, a.get()?, a.get()?, a.get()?);
        a.end()?;
        Ok(s)
    }
}

/// As `Stamp`.
impl Port for ThingStamp {
    fn to_port(&self) -> Value {
        Stamp::new(self.id, self.actor, self.ts, self.received).to_port()
    }
    fn from_port(v: Value) -> Result<ThingStamp> {
        let Stamp { id, actor, written, received, ts } = of(v)?;
        Ok(ThingStamp { id, actor, written, received, ts })
    }
}

/// `[[holder, role, Opt(until), Opt(may grant), with membership, from now]*]`.
impl Port for Grants {
    fn to_port(&self) -> Value {
        Value::List(self.iter().map(|(t, e)| Value::List(vec![t.to_port(), e.role.to_port(), e.until.to_port(), e.may_grant.to_port(), e.with_membership.to_port(), e.from_now.to_port()])).collect())
    }
    fn from_port(v: Value) -> Result<Grants> {
        let mut out = Grants::new();
        for x in list(v)? {
            let mut a = Args::new(x)?;
            let t = a.tid()?;
            let e = Grant { role: a.get()?, until: a.get()?, may_grant: a.get()?, with_membership: a.get()?, from_now: a.get()? };
            a.end()?;
            out.insert(t, e);
        }
        Ok(out)
    }
}

/// `[connected, [[group, state, Opt(last sync), [refused by*], leaving]*], [two sources*]]`.
impl Port for Status {
    fn to_port(&self) -> Value {
        let groups = self.groups.iter().map(|(g, x)| Value::List(vec![g.to_port(), x.state.to_port(), x.last_sync.to_port(), x.refused_by.to_port(), x.leaving.to_port()]));
        Value::List(vec![self.connected.to_port(), Value::List(groups.collect()), Value::List(self.two_sources.iter().map(Tid::to_port).collect())])
    }
    fn from_port(v: Value) -> Result<Status> {
        let mut a = Args::new(v)?;
        let mut st = Status { connected: a.get()?, groups: Default::default(), node_connections: Vec::new(), two_sources: Default::default() };
        for g in a.list()? {
            let mut b = Args::new(g)?;
            let t = b.tid()?;
            let s = GroupSync { state: b.get()?, last_sync: b.get()?, refused_by: b.get()?, leaving: b.get()? };
            b.end()?;
            st.groups.insert(t, s);
        }
        st.two_sources = a.get::<Vec<Tid>>()?.into_iter().collect();
        a.end()?;
        Ok(st)
    }
}

/// `[stamp, kind, Opt(reverts), [reverted by*], in effect, [[tid, ak, valid, body, Opt(edited)]*]]`
impl Port for Commit {
    fn to_port(&self) -> Value {
        let parts = self.raw_parts().iter().map(|(t, k, p)| Value::List(vec![t.to_port(), k.to_port(), p.valid.to_port(), p.body.to_port(), p.edited.to_port()]));
        Value::List(vec![self.stamp.to_port(), self.kind.to_port(), self.reverts.to_port(), self.reverted_by.to_port(), self.in_effect.to_port(), Value::List(parts.collect())])
    }
    fn from_port(v: Value) -> Result<Commit> {
        let mut a = Args::new(v)?;
        let (stamp, kind, reverts, reverted_by, in_effect) = (a.get()?, a.get()?, a.get()?, a.get()?, a.get()?);
        let parts = a.list()?.into_iter().map(|p| {
            let mut a = Args::new(p)?;
            let x = (a.get()?, a.get()?, Part { valid: a.get()?, body: a.get()?, edited: a.get()? });
            a.end()?;
            Ok::<_, Error>(x)
        });
        let parts = parts.collect::<Result<_>>()?;
        a.end()?;
        Ok(Commit::of_parts(stamp, kind, reverts, reverted_by, in_effect, parts))
    }
}

/// `by`.
impl Port for Retention {
    fn to_port(&self) -> Value {
        u(self.by as u64)
    }
    fn from_port(v: Value) -> Result<Retention> {
        let by = v.as_uint().and_then(PurgeBy::from_id).ok_or_else(|| bad("purge class"))?;
        Ok(Retention { by })
    }
}

/// A sync scope: `[]` all, `[tid]` what carries it, `[true]` the pending deliveries.
impl Port for SyncScope {
    fn to_port(&self) -> Value {
        Value::List(match self {
            SyncScope::All => vec![],
            SyncScope::Thing(t) => vec![Value::Tid(*t)],
            SyncScope::Deliveries => vec![Value::Bool(true)],
        })
    }
    fn from_port(v: Value) -> Result<SyncScope> {
        let mut a = Args::new(v)?;
        match a.rest().as_slice() {
            [] => Ok(SyncScope::All),
            [Value::Bool(true)] => Ok(SyncScope::Deliveries),
            [v] => Ok(SyncScope::Thing(of(v.clone())?)),
            _ => Err(bad("sync scope")),
        }
    }
}

/// A path op `[path, [op, arg*]]`; ops by dot (text sessions) do not go to a node yet, so
/// encoding may fail.
pub(crate) fn op_v(p: &PathOp) -> Result<Value> {
    let o = match &p.op {
        Op::Set(v) => vec![u(0), v.clone()],
        Op::Replace(v) => vec![u(1), v.clone()],
        Op::Put(v) => vec![u(2), v.clone()],
        Op::RemoveAspect => vec![u(3)],
        Op::Add(v) => vec![u(4), v.clone()],
        Op::Remove(v) => vec![u(5), v.clone()],
        Op::Inc(v) => vec![u(6), v.clone()],
        Op::Insert { at, items } => vec![u(7), at.to_port(), Value::List(items.clone())],
        Op::Delete { at, len } => vec![u(8), at.to_port(), len.to_port()],
        Op::Move { at, len, to } => vec![u(9), at.to_port(), len.to_port(), to.to_port()],
        Op::Edit { base, new } => vec![u(10), base.clone(), new.clone()],
        Op::InsertAfter { .. } | Op::DeleteDots { .. } | Op::Paste { .. } => return Err(Error::Unsupported("text session ops through another node".into())),
    };
    Ok(Value::List(vec![p.path.to_port(), Value::List(o)]))
}

pub(crate) fn op(v: Value) -> Result<PathOp> {
    let mut a = Args::new(v)?;
    let path = a.get()?;
    let mut o = Args::of(a.list()?);
    a.end()?;
    let op = match o.uint()? {
        0 => Op::Set(o.next()?),
        1 => Op::Replace(o.next()?),
        2 => Op::Put(o.next()?),
        3 => Op::RemoveAspect,
        4 => Op::Add(o.next()?),
        5 => Op::Remove(o.next()?),
        6 => Op::Inc(o.next()?),
        7 => Op::Insert { at: o.get()?, items: o.list()? },
        8 => Op::Delete { at: o.get()?, len: o.get()? },
        9 => Op::Move { at: o.get()?, len: o.get()?, to: o.get()? },
        10 => Op::Edit { base: o.next()?, new: o.next()? },
        _ => return Err(bad("op")),
    };
    o.end()?;
    Ok(PathOp { path, op })
}

/// A call's result as a Reply outcome.
pub(crate) fn outcome(r: Result<Value>) -> Outcome {
    match r {
        Ok(value) => Outcome::Ok { value },
        Err(e) => outcome_err(&e),
    }
}

/// An error as a Reply outcome (spec/wire.md §11.2 codes).
pub(crate) fn outcome_err(e: &Error) -> Outcome {
    let t = |s: &str| Value::Str(s.to_owned());
    let (code, detail) = match e {
        Error::UnknownThing { tid } => (ApiCode::UNKNOWN_THING, vec![Value::Tid(*tid)]),
        Error::UnknownActor { tid } => (ApiCode::UNKNOWN_ACTOR, vec![Value::Tid(*tid)]),
        Error::Permission { tid, needs } => (ApiCode::PERMISSION, vec![Value::Tid(*tid), needs.to_port()]),
        Error::Type { path, reason } => (ApiCode::TYPE, vec![path.to_port(), t(reason)]),
        Error::TooLarge { limit } => (ApiCode::TOO_LARGE, vec![limit.to_port()]),
        Error::NotUndoable { commit, reason } => (ApiCode::NOT_UNDOABLE, vec![commit.to_port(), u(u64::from(*reason == NotUndoableReason::Superseded))]),
        Error::Unsynced { groups } => (ApiCode::UNSYNCED, vec![groups.to_port()]),
        Error::Invalid(m) => (ApiCode::INVALID, vec![t(m)]),
        Error::Storage(m) => (ApiCode::STORAGE, vec![t(m)]),
        Error::InUse => (ApiCode::IN_USE, vec![]),
        Error::Network(m) => (ApiCode::NETWORK, vec![t(m)]),
        Error::OutcomeUnknown => (ApiCode::OUTCOME_UNKNOWN, vec![]),
        Error::Unsupported(m) => (ApiCode::UNSUPPORTED, vec![t(m)]),
        Error::Refused(m) => (ApiCode::REFUSED, vec![t(m)]),
        Error::Closed => (ApiCode::CLOSED, vec![]),
    };
    Outcome::Err { code, detail }
}

/// The API error of a Reply error code; an unreadable one is `Invalid`.
pub(crate) fn error_of(code: u64, detail: Vec<Value>) -> Error {
    let mut a = Args::of(detail);
    let text = |a: &mut Args| a.text().unwrap_or_default();
    let r: Result<Error> = (|| {
        Ok(match code {
            ApiCode::UNKNOWN_THING => Error::UnknownThing { tid: a.tid()? },
            ApiCode::UNKNOWN_ACTOR => Error::UnknownActor { tid: a.tid()? },
            ApiCode::PERMISSION => Error::Permission { tid: a.tid()?, needs: a.get()? },
            ApiCode::TYPE => Error::Type { path: a.get()?, reason: a.text()? },
            ApiCode::TOO_LARGE => Error::TooLarge { limit: usize::try_from(a.uint()?).unwrap_or(usize::MAX) },
            ApiCode::NOT_UNDOABLE => Error::NotUndoable { commit: a.get()?, reason: if a.uint()? == 1 { NotUndoableReason::Superseded } else { NotUndoableReason::NotKept } },
            ApiCode::UNSYNCED => Error::Unsynced { groups: a.get()? },
            ApiCode::INVALID => Error::Invalid(text(&mut a)),
            ApiCode::STORAGE => Error::Storage(text(&mut a)),
            ApiCode::NETWORK => Error::Network(text(&mut a)),
            ApiCode::UNSUPPORTED => Error::Unsupported(text(&mut a)),
            ApiCode::REFUSED => Error::Refused(text(&mut a)),
            ApiCode::OUTCOME_UNKNOWN => Error::OutcomeUnknown,
            ApiCode::CLOSED => Error::Closed,
            ApiCode::IN_USE => Error::InUse,
            _ => Error::Invalid(format!("port: error code {code}")),
        })
    })();
    r.unwrap_or_else(|e| e)
}

/// `x` as a port value.
pub(crate) fn v<T: Port>(x: &T) -> Value {
    x.to_port()
}
