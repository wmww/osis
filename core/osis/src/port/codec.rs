//! Values of the client port's method table (notes/client-port.md §2): API types to and from
//! untyped `Value`s, and API errors to and from Reply error codes (`osis_proto::ApiCode`).

use crate::commits::{CommitEntry, CommitKind, CommitQuery, NotUndoableReason, Scope};
use crate::error::{Error, Result};
use crate::read::{Grant, Grants, GroupsOf, Stamp, ThingStamp};
use crate::share::{GrantOpts, GroupSync, Holder, Address, LinkId, LinkInfo, Member, SetRoleOpts, Status, SyncFirst, SyncScope, SyncState};
use crate::watch::{DerivedFrom, Origin};
use crate::write::Commit;
use crate::commit_id::CommitId;
use osis_base::{Ak, CommitId as RawCommitId, Role, Tid, Ts, Value, Time};
use osis_crdt::{Op, PathOp, PathSeg};
use osis_node::{ChangeId as RawChange, Diagnostic, DiagnosticKind, EphemeralId};
use osis_proto::{ApiCode, Outcome};
use osis_schema::{Bound, Path, PurgeBy, Retention, Step};

pub(crate) fn bad(what: &str) -> Error {
    Error::Invalid(format!("port: malformed {what}"))
}

pub(crate) fn u(n: u64) -> Value {
    Value::uint(n)
}

pub(crate) fn opt<T>(x: Option<T>, f: impl FnOnce(T) -> Value) -> Value {
    Value::opt(x.map(f))
}

/// Reads positions of a list value.
pub(crate) struct Args(std::vec::IntoIter<Value>);

impl Args {
    pub fn new(v: Value) -> Result<Args> {
        match v {
            Value::List(l) => Ok(Args(l.into_iter())),
            _ => Err(bad("list")),
        }
    }
    pub fn of(l: Vec<Value>) -> Args {
        Args(l.into_iter())
    }
    pub fn next(&mut self) -> Result<Value> {
        self.0.next().ok_or_else(|| bad("argument count"))
    }
    pub fn uint(&mut self) -> Result<u64> {
        self.next()?.as_uint().ok_or_else(|| bad("uint"))
    }
    pub fn bool(&mut self) -> Result<bool> {
        match self.next()? {
            Value::Bool(b) => Ok(b),
            _ => Err(bad("bool")),
        }
    }
    pub fn tid(&mut self) -> Result<Tid> {
        tid(&self.next()?)
    }
    pub fn ak(&mut self) -> Result<Ak> {
        ak(&self.next()?)
    }
    pub fn text(&mut self) -> Result<String> {
        match self.next()? {
            Value::Str(s) => Ok(s),
            _ => Err(bad("text")),
        }
    }
    pub fn bytes(&mut self) -> Result<Vec<u8>> {
        match self.next()? {
            Value::Bytes(b) => Ok(b),
            _ => Err(bad("bytes")),
        }
    }
    pub fn list(&mut self) -> Result<Vec<Value>> {
        match self.next()? {
            Value::List(l) => Ok(l),
            _ => Err(bad("list")),
        }
    }
    pub fn opt(&mut self) -> Result<Option<Value>> {
        let mut l = self.list()?;
        match l.len() {
            0 => Ok(None),
            1 => Ok(l.pop()),
            _ => Err(bad("option")),
        }
    }
    /// An optional wall time.
    pub fn opt_wall(&mut self) -> Result<Option<Time>> {
        self.opt()?.map(|w| wall(&w)).transpose()
    }
    /// A tid if one is left.
    pub fn opt_tid(&mut self) -> Result<Option<Tid>> {
        self.0.next().map(|v| tid(&v)).transpose()
    }
    /// The positions not read yet.
    pub fn rest(&mut self) -> Vec<Value> {
        self.0.by_ref().collect()
    }
    pub fn end(self) -> Result<()> {
        if self.0.len() == 0 { Ok(()) } else { Err(bad("argument count")) }
    }
}

pub(crate) fn tid(v: &Value) -> Result<Tid> {
    match v {
        Value::Tid(t) => Ok(*t),
        _ => Err(bad("tid")),
    }
}

pub(crate) fn ak(v: &Value) -> Result<Ak> {
    match v {
        Value::Str(s) => Ak::new(s).map_err(|_| bad("AK")),
        _ => Err(bad("AK")),
    }
}

pub(crate) fn ak_v(a: &Ak) -> Value {
    Value::Str(a.as_str().to_owned())
}

pub(crate) fn tids_v(ts: &[Tid]) -> Value {
    Value::List(ts.iter().map(|t| Value::Tid(*t)).collect())
}

pub(crate) fn tids(v: Value) -> Result<Vec<Tid>> {
    Args::of(vec![v]).list()?.iter().map(tid).collect()
}

pub(crate) fn role_v(r: Role) -> Value {
    u(match r {
        Role::Read => 0,
        Role::Write => 1,
        Role::Admin => 2,
    })
}

pub(crate) fn role(v: &Value) -> Result<Role> {
    match v.as_uint() {
        Some(0) => Ok(Role::Read),
        Some(1) => Ok(Role::Write),
        Some(2) => Ok(Role::Admin),
        _ => Err(bad("role")),
    }
}

pub(crate) fn path_v(p: &Path) -> Value {
    Value::List(
        p.0.iter()
            .map(|s| {
                Value::List(match s {
                    Step::Field(f) => vec![u(0), u(*f)],
                    Step::Case(c) => vec![u(1), u(*c)],
                    Step::Key(k) => vec![u(2), k.clone()],
                    Step::Index(i) => vec![u(3), u(*i as u64)],
                    Step::Elem(e) => vec![u(4), e.clone()],
                })
            })
            .collect(),
    )
}

pub(crate) fn path(v: Value) -> Result<Path> {
    let mut out = Vec::new();
    for s in Args::of(vec![v]).list()? {
        let mut a = Args::new(s)?;
        let st = match a.uint()? {
            0 => Step::Field(a.uint()?),
            1 => Step::Case(a.uint()?),
            2 => Step::Key(a.next()?),
            3 => Step::Index(usize::try_from(a.uint()?).map_err(|_| bad("index"))?),
            4 => Step::Elem(a.next()?),
            _ => return Err(bad("path step")),
        };
        a.end()?;
        out.push(st);
    }
    Ok(Path(out))
}

fn ts_v(t: Ts) -> Value {
    u(t.to_u64())
}

fn ts(v: &Value) -> Result<Ts> {
    v.as_uint().and_then(Ts::from_u64).ok_or_else(|| bad("ts"))
}

fn wall(v: &Value) -> Result<Time> {
    v.as_uint().map(Time).ok_or_else(|| bad("time"))
}

pub(crate) fn raw_commit_id(v: Value) -> Result<RawCommitId> {
    Args::of(vec![v]).bytes()?.try_into().map(RawCommitId).map_err(|_| bad("commit id"))
}

pub(crate) fn commit_id_v(c: &CommitId) -> Value {
    Value::List(match &c.0 {
        RawChange::Commit(c) => vec![u(0), Value::bytes(&c.0)],
        RawChange::Ephemeral(e) => vec![u(1), Value::bytes(&e.session), u(e.n)],
    })
}

pub(crate) fn commit_id(v: Value) -> Result<CommitId> {
    let mut a = Args::new(v)?;
    let c = match a.uint()? {
        0 => CommitId::commit(raw_commit_id(a.next()?)?),
        1 => CommitId(RawChange::Ephemeral(EphemeralId { session: a.bytes()?.try_into().map_err(|_| bad("session"))?, n: a.uint()? })),
        _ => return Err(bad("commit id")),
    };
    a.end()?;
    Ok(c)
}

pub(crate) fn commit_v(c: &Commit) -> Value {
    Value::List(vec![commit_id_v(&c.id), ts_v(c.ts)])
}

pub(crate) fn commit(v: Value) -> Result<Commit> {
    let mut a = Args::new(v)?;
    let (id, ts) = (commit_id(a.next()?)?, ts(&a.next()?)?);
    let c = Commit { id, written: ts.wall_ms(), ts };
    a.end()?;
    Ok(c)
}

pub(crate) fn stamp_v(i: &Stamp) -> Value {
    Value::List(vec![commit_id_v(&i.id), Value::Tid(i.actor), Value::Tid(i.node), ts_v(i.ts), u(i.received.0)])
}

pub(crate) fn stamp(v: Value) -> Result<Stamp> {
    let mut a = Args::new(v)?;
    let i = Stamp::new(commit_id(a.next()?)?, a.tid()?, a.tid()?, ts(&a.next()?)?, wall(&a.next()?)?);
    a.end()?;
    Ok(i)
}

pub(crate) fn thing_stamp_v(s: &ThingStamp) -> Value {
    Value::List(vec![opt(s.id, |c| commit_id_v(&c)), Value::Tid(s.actor), Value::Tid(s.node), ts_v(s.ts), u(s.received.0)])
}

pub(crate) fn thing_stamp(v: Value) -> Result<ThingStamp> {
    let mut a = Args::new(v)?;
    let (id, actor, node, t, received) = (a.opt()?.map(commit_id).transpose()?, a.tid()?, a.tid()?, ts(&a.next()?)?, wall(&a.next()?)?);
    let s = ThingStamp { id, actor, node, written: t.wall_ms(), ts: t, received };
    a.end()?;
    Ok(s)
}

pub(crate) fn groups_v(g: &GroupsOf) -> Value {
    Value::List(vec![tids_v(&g.item_of), tids_v(&g.subgroup_of), tids_v(&g.within)])
}

pub(crate) fn groups(v: Value) -> Result<GroupsOf> {
    let mut a = Args::new(v)?;
    let g = GroupsOf { item_of: tids(a.next()?)?, subgroup_of: tids(a.next()?)?, within: tids(a.next()?)? };
    a.end()?;
    Ok(g)
}

pub(crate) fn grants_v(r: &Grants) -> Value {
    Value::List(r.iter().map(|(t, e)| Value::List(vec![Value::Tid(*t), role_v(e.role), opt(e.until, |w| u(w.0)), opt(e.may_grant, role_v), Value::Bool(e.with_membership)])).collect())
}

pub(crate) fn grants(v: Value) -> Result<Grants> {
    let mut out = Grants::new();
    for x in Args::of(vec![v]).list()? {
        let mut a = Args::new(x)?;
        let t = a.tid()?;
        let e = Grant { role: role(&a.next()?)?, until: a.opt_wall()?, may_grant: a.opt()?.map(|r| role(&r)).transpose()?, with_membership: a.bool()? };
        a.end()?;
        out.insert(t, e);
    }
    Ok(out)
}

const REASONS: [DerivedFrom; 5] = [DerivedFrom::ValidityChanged, DerivedFrom::Expired, DerivedFrom::Purged, DerivedFrom::Arrived, DerivedFrom::LostAccess];

/// Fails to compile when a reason is added: list it in `REASONS` too.
#[allow(dead_code)]
fn reasons_listed(c: DerivedFrom) {
    match c {
        DerivedFrom::ValidityChanged | DerivedFrom::Expired | DerivedFrom::Purged | DerivedFrom::Arrived | DerivedFrom::LostAccess => {}
    }
}

pub(crate) fn origin_v(s: &Origin) -> Value {
    Value::List(match s {
        Origin::Initial => vec![u(0)],
        Origin::Local(i) => vec![u(1), stamp_v(i)],
        Origin::Remote(i) => vec![u(2), stamp_v(i)],
        Origin::Derived(c) => vec![u(3), u(REASONS.iter().position(|x| x == c).unwrap_or(0) as u64)],
    })
}

pub(crate) fn source(v: Value) -> Result<Origin> {
    let mut a = Args::new(v)?;
    let s = match a.uint()? {
        0 => Origin::Initial,
        1 => Origin::Local(stamp(a.next()?)?),
        2 => Origin::Remote(stamp(a.next()?)?),
        3 => Origin::Derived(*usize::try_from(a.uint()?).ok().and_then(|i| REASONS.get(i)).ok_or_else(|| bad("reason"))?),
        _ => return Err(bad("source")),
    };
    a.end()?;
    Ok(s)
}

/// A read's result: `[0, Opt(value)]` or an error.
pub(crate) fn read_v(r: &Result<Option<Value>>) -> Value {
    match r {
        Ok(v) => Value::List(vec![u(0), Value::opt(v.clone())]),
        Err(e) => outcome_err(e).to_value(),
    }
}

pub(crate) fn read(v: Value) -> Result<Result<Option<Value>>> {
    let mut a = Args::new(v)?;
    match a.uint()? {
        0 => {
            let x = a.opt()?;
            a.end()?;
            Ok(Ok(x))
        }
        1 => {
            let code = a.uint()?;
            Ok(Err(error_of(code, a.rest())))
        }
        _ => Err(bad("read result")),
    }
}

const STATES: [SyncState; 9] = [SyncState::Synced, SyncState::Syncing, SyncState::Connected, SyncState::Unreachable, SyncState::NoPeers, SyncState::Refused, SyncState::Stranded, SyncState::LogOnly, SyncState::NotCarried];

pub(crate) fn status_v(s: &Status) -> Value {
    let groups = s
        .groups
        .iter()
        .map(|(g, x)| {
            Value::List(vec![
                Value::Tid(*g),
                u(STATES.iter().position(|y| *y == x.state).unwrap_or(0) as u64),
                opt(x.last_sync, |w| u(w.0)),
                Value::List(x.refused_by.iter().map(|h| Value::Str(h.to_string())).collect()),
                Value::Bool(x.leaving),
                Value::List(x.not_carried_to.iter().map(|t| Value::Tid(*t)).collect()),
            ])
        })
        .collect();
    Value::List(vec![u(s.connected as u64), Value::List(groups), Value::List(s.two_sources.iter().map(|t| Value::Tid(*t)).collect())])
}

pub(crate) fn status(v: Value) -> Result<Status> {
    let mut a = Args::new(v)?;
    let connected = usize::try_from(a.uint()?).map_err(|_| bad("count"))?;
    let mut st = Status { connected, groups: Default::default(), client_connections: Vec::new(), two_sources: Default::default() };
    for g in a.list()? {
        let mut b = Args::new(g)?;
        let t = b.tid()?;
        let state = *usize::try_from(b.uint()?).ok().and_then(|i| STATES.get(i)).ok_or_else(|| bad("state"))?;
        let last_sync = b.opt_wall()?;
        let refused_by = b.list()?.into_iter().map(|h| Args::of(vec![h]).text().and_then(|t| t.parse::<Address>())).collect::<Result<_>>()?;
        let leaving = b.bool()?;
        let not_carried_to = b.list()?.into_iter().map(|t| Args::of(vec![t]).tid()).collect::<Result<_>>()?;
        b.end()?;
        st.groups.insert(t, GroupSync { state, last_sync, refused_by, leaving, not_carried_to });
    }
    for t in a.list()? {
        st.two_sources.insert(Args::of(vec![t]).tid()?);
    }
    a.end()?;
    Ok(st)
}

const KINDS: [DiagnosticKind; 20] = [
    DiagnosticKind::BadInput,
    DiagnosticKind::CollidingRecord,
    DiagnosticKind::Parked,
    DiagnosticKind::Pending,
    DiagnosticKind::OverlappingCounters,
    DiagnosticKind::Removed,
    DiagnosticKind::Callback,
    DiagnosticKind::NotSynced,
    DiagnosticKind::PlacementNotPersisted,
    DiagnosticKind::Unsynced,
    DiagnosticKind::Stranded,
    DiagnosticKind::Uncommitted,
    DiagnosticKind::EphemeralRefused,
    DiagnosticKind::Mismatch,
    DiagnosticKind::Misstated,
    DiagnosticKind::Storage,
    DiagnosticKind::Repair,
    DiagnosticKind::OwnWriteInvalid,
    DiagnosticKind::Unreadable,
    DiagnosticKind::SyncStopped,
];

/// Fails to compile when a kind is added: list it in `KINDS` too (an unlisted one went out as
/// `BadInput`).
#[allow(dead_code)]
fn kinds_listed(k: DiagnosticKind) {
    use DiagnosticKind::*;
    match k {
        BadInput | CollidingRecord | Parked | Pending | OverlappingCounters | Removed | Callback | NotSynced | PlacementNotPersisted | Unsynced | Stranded | Uncommitted | EphemeralRefused | Mismatch | Misstated | Storage | Repair | OwnWriteInvalid | Unreadable | SyncStopped => {}
    }
}

pub(crate) fn diag_v(d: &Diagnostic) -> Value {
    Value::List(vec![u(KINDS.iter().position(|k| *k == d.kind).unwrap_or(0) as u64), tids_v(&d.tids), opt(d.commit, |c| Value::bytes(&c.0)), opt(d.peer, Value::Tid), Value::Str(d.detail.clone())])
}

pub(crate) fn diag(v: Value) -> Result<Diagnostic> {
    let mut a = Args::new(v)?;
    let kind = *usize::try_from(a.uint()?).ok().and_then(|i| KINDS.get(i)).ok_or_else(|| bad("diagnostic kind"))?;
    let tids = tids(a.next()?)?;
    let commit = a.opt()?.map(raw_commit_id).transpose()?;
    let peer = a.opt()?.map(|p| tid(&p)).transpose()?;
    let detail = a.text()?;
    a.end()?;
    Ok(Diagnostic { kind, tids, commit, peer, detail })
}

fn aspects_v(v: &[(Tid, Ak)]) -> Value {
    Value::List(v.iter().map(|(t, a)| Value::List(vec![Value::Tid(*t), ak_v(a)])).collect())
}

fn aspects(v: Value) -> Result<Vec<(Tid, Ak)>> {
    Args::of(vec![v]).list()?.into_iter().map(|x| {
        let mut p = Args::new(x)?;
        let r = (p.tid()?, p.ak()?);
        p.end()?;
        Ok(r)
    }).collect()
}

pub(crate) fn scope_v(s: &Scope) -> Value {
    Value::List(match s {
        Scope::Thing(t) => vec![u(0), Value::Tid(*t)],
        Scope::Aspects(v) => vec![u(1), aspects_v(v)],
        Scope::Group(t) => vec![u(2), Value::Tid(*t)],
    })
}

pub(crate) fn scope(v: Value) -> Result<Scope> {
    let mut a = Args::new(v)?;
    let s = match a.uint()? {
        0 => Scope::Thing(a.tid()?),
        1 => Scope::Aspects(aspects(a.next()?)?),
        2 => Scope::Group(a.tid()?),
        _ => return Err(bad("scope")),
    };
    a.end()?;
    Ok(s)
}

const CKINDS: [CommitKind; 5] = [CommitKind::Content, CommitKind::Revert, CommitKind::Role, CommitKind::Snapshot, CommitKind::Ephemeral];

fn ckind_v(k: &CommitKind) -> Value {
    u(CKINDS.iter().position(|x| x == k).unwrap_or(0) as u64)
}

fn ckind(v: &Value) -> Result<CommitKind> {
    v.as_uint().and_then(|i| CKINDS.get(usize::try_from(i).ok()?).copied()).ok_or_else(|| bad("commit kind"))
}

pub(crate) fn query_v(q: &CommitQuery) -> Value {
    Value::List(vec![
        opt(q.scope.as_ref(), scope_v),
        tids_v(&q.actors),
        Value::List(q.kinds.iter().map(ckind_v).collect()),
        opt(q.reverts.as_ref(), commit_id_v),
        opt(q.reverted_by.as_ref(), commit_id_v),
        opt(q.in_effect, Value::Bool),
        opt(q.since, |t| u(t.0)),
        opt(q.until, |t| u(t.0)),
        opt(q.after.as_ref(), commit_id_v),
        opt(q.limit, |n| u(n as u64)),
    ])
}

pub(crate) fn query(v: Value) -> Result<CommitQuery> {
    let mut a = Args::new(v)?;
    let q = CommitQuery {
        scope: a.opt()?.map(scope).transpose()?,
        actors: tids(a.next()?)?,
        kinds: a.list()?.iter().map(ckind).collect::<Result<_>>()?,
        reverts: a.opt()?.map(commit_id).transpose()?,
        reverted_by: a.opt()?.map(commit_id).transpose()?,
        in_effect: a.opt()?.map(|b| Args::of(vec![b]).bool()).transpose()?,
        since: a.opt_wall()?,
        until: a.opt_wall()?,
        after: a.opt()?.map(commit_id).transpose()?,
        limit: a.opt()?.map(|n| n.as_uint().and_then(|n| usize::try_from(n).ok()).ok_or_else(|| bad("limit"))).transpose()?,
    };
    a.end()?;
    Ok(q)
}

pub(crate) fn from_v(f: &crate::HistoryFrom) -> Value {
    use crate::HistoryFrom as F;
    let at = |p: &crate::HistoryPos| vec![ts_v(p.0.ts), commit_id_v(&CommitId(p.0.id))];
    Value::List(match f {
        F::Newest => vec![u(0)],
        F::Oldest => vec![u(1)],
        F::Before(p) => [vec![u(2)], at(p)].concat(),
        F::After(p) => [vec![u(3)], at(p)].concat(),
    })
}

pub(crate) fn from(v: Value) -> Result<crate::HistoryFrom> {
    use crate::{HistoryFrom as F, HistoryPos};
    let mut a = Args::new(v)?;
    let f = match a.uint()? {
        0 => F::Newest,
        1 => F::Oldest,
        k @ (2 | 3) => {
            let p = HistoryPos::of(ts(&a.next()?)?, commit_id(a.next()?)?);
            if k == 2 { F::Before(p) } else { F::After(p) }
        }
        _ => return Err(bad("history start")),
    };
    a.end()?;
    Ok(f)
}

pub(crate) fn hist_entry_v(e: &crate::HistoryEntry<Value>) -> Value {
    use crate::HistoryBody as B;
    let body = match &e.body {
        B::Held(v) => vec![u(0), opt(v.clone(), |x| x)],
        B::TooLarge { limit } => vec![u(1), u(*limit as u64)],
        B::Purged { by, actor } => vec![u(2), commit_id_v(by), opt(*actor, Value::Tid)],
        B::Gone => vec![u(3)],
        B::NotFetched => vec![u(4)],
    };
    Value::List(vec![stamp_v(&e.commit), ckind_v(&e.kind), Value::Bool(e.valid), Value::List(body)])
}

pub(crate) fn hist_entry(v: Value) -> Result<crate::HistoryEntry<Value>> {
    use crate::HistoryBody as B;
    let mut a = Args::new(v)?;
    let (commit, kind, valid) = (stamp(a.next()?)?, ckind(&a.next()?)?, a.bool()?);
    let mut b = Args::new(a.next()?)?;
    a.end()?;
    let body = match b.uint()? {
        0 => B::Held(b.opt()?),
        1 => B::TooLarge { limit: usize::try_from(b.uint()?).unwrap_or(usize::MAX) },
        2 => B::Purged { by: commit_id(b.next()?)?, actor: b.opt()?.map(|v| Args::of(vec![v]).tid()).transpose()? },
        3 => B::Gone,
        4 => B::NotFetched,
        _ => return Err(bad("history body")),
    };
    b.end()?;
    Ok(crate::HistoryEntry { commit, kind, valid, body })
}

pub(crate) fn hist_page_v(p: &crate::HistoryPage<Value>) -> Value {
    Value::List(vec![Value::List(p.entries.iter().map(hist_entry_v).collect()), Value::Bool(p.more), Value::Bool(p.complete)])
}

pub(crate) fn hist_page(v: Value) -> Result<crate::HistoryPage<Value>> {
    let mut a = Args::new(v)?;
    let entries = a.list()?.into_iter().map(hist_entry).collect::<Result<_>>()?;
    let (more, complete) = (a.bool()?, a.bool()?);
    a.end()?;
    Ok(crate::HistoryPage { entries, more, complete })
}

pub(crate) fn entry_v(e: &CommitEntry) -> Value {
    Value::List(vec![
        stamp_v(&e.commit),
        ckind_v(&e.kind),
        opt(e.reverts.as_ref(), commit_id_v),
        Value::List(e.reverted_by.iter().map(commit_id_v).collect()),
        Value::Bool(e.in_effect),
        aspects_v(&e.aspects),
        Value::Bool(e.content_gone),
        Value::List(e.purged.iter().map(|(t, k, by)| Value::List(vec![Value::Tid(*t), ak_v(k), commit_id_v(by)])).collect()),
    ])
}

fn purged_one(v: Value) -> Result<(Tid, Ak, CommitId)> {
    let mut a = Args::new(v)?;
    let x = (a.tid()?, a.ak()?, commit_id(a.next()?)?);
    a.end()?;
    Ok(x)
}

pub(crate) fn entry(v: Value) -> Result<CommitEntry> {
    let mut a = Args::new(v)?;
    let e = CommitEntry {
        commit: stamp(a.next()?)?,
        kind: ckind(&a.next()?)?,
        reverts: a.opt()?.map(commit_id).transpose()?,
        reverted_by: a.list()?.into_iter().map(commit_id).collect::<Result<_>>()?,
        in_effect: a.bool()?,
        aspects: aspects(a.next()?)?,
        content_gone: a.bool()?,
        purged: a.list()?.into_iter().map(purged_one).collect::<Result<_>>()?,
    };
    a.end()?;
    Ok(e)
}

fn seg_v(s: &PathSeg) -> Value {
    Value::List(match s {
        PathSeg::Field(f) => vec![u(0), u(*f)],
        PathSeg::Case(c) => vec![u(1), u(*c)],
        PathSeg::Key(k) => vec![u(2), k.clone()],
        PathSeg::Index(i) => vec![u(3), u(*i as u64)],
    })
}

fn seg(v: Value) -> Result<PathSeg> {
    let mut a = Args::new(v)?;
    let s = match a.uint()? {
        0 => PathSeg::Field(a.uint()?),
        1 => PathSeg::Case(a.uint()?),
        2 => PathSeg::Key(a.next()?),
        3 => PathSeg::Index(usize::try_from(a.uint()?).map_err(|_| bad("index"))?),
        _ => return Err(bad("path segment")),
    };
    a.end()?;
    Ok(s)
}

fn usz(a: &mut Args) -> Result<usize> {
    usize::try_from(a.uint()?).map_err(|_| bad("index"))
}

/// A path op; ops by dot (text sessions) are not remote yet.
pub(crate) fn op_v(p: &PathOp) -> Result<Value> {
    let o = match &p.op {
        Op::Set(v) => vec![u(0), v.clone()],
        Op::Replace(v) => vec![u(1), v.clone()],
        Op::Put(v) => vec![u(2), v.clone()],
        Op::RemoveAspect => vec![u(3)],
        Op::Add(v) => vec![u(4), v.clone()],
        Op::Remove(v) => vec![u(5), v.clone()],
        Op::Inc(v) => vec![u(6), v.clone()],
        Op::Insert { at, items } => vec![u(7), u(*at as u64), Value::List(items.clone())],
        Op::Delete { at, len } => vec![u(8), u(*at as u64), u(*len as u64)],
        Op::Move { at, len, to } => vec![u(9), u(*at as u64), u(*len as u64), u(*to as u64)],
        Op::Edit { base, new } => vec![u(10), base.clone(), new.clone()],
        Op::InsertAfter { .. } | Op::DeleteDots { .. } | Op::Paste { .. } => return Err(Error::Unsupported("text session ops through a remote node".into())),
    };
    Ok(Value::List(vec![Value::List(p.path.iter().map(seg_v).collect()), Value::List(o)]))
}

pub(crate) fn op(v: Value) -> Result<PathOp> {
    let mut a = Args::new(v)?;
    let path = a.list()?.into_iter().map(seg).collect::<Result<_>>()?;
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
        7 => Op::Insert { at: usz(&mut o)?, items: o.list()? },
        8 => Op::Delete { at: usz(&mut o)?, len: usz(&mut o)? },
        9 => Op::Move { at: usz(&mut o)?, len: usz(&mut o)?, to: usz(&mut o)? },
        10 => Op::Edit { base: o.next()?, new: o.next()? },
        _ => return Err(bad("op")),
    };
    o.end()?;
    Ok(PathOp { path, op })
}

fn bound_v(b: &Bound) -> Value {
    Value::List(vec![opt(b.abs, u), opt(b.rel, u)])
}

fn bound(v: Value) -> Result<Bound> {
    let mut a = Args::new(v)?;
    let b = Bound { abs: a.opt()?.map(|x| x.as_uint().ok_or_else(|| bad("bound"))).transpose()?, rel: a.opt()?.map(|x| x.as_uint().ok_or_else(|| bad("bound"))).transpose()? };
    a.end()?;
    Ok(b)
}

pub(crate) fn retention_v(r: &Retention) -> Value {
    Value::List(vec![u(r.by as u64), bound_v(&r.at_least), bound_v(&r.at_most)])
}

pub(crate) fn retention(v: Value) -> Result<Retention> {
    let mut a = Args::new(v)?;
    let by = PurgeBy::from_id(a.uint()?).ok_or_else(|| bad("purge class"))?;
    let r = Retention { by, at_least: bound(a.next()?)?, at_most: bound(a.next()?)? };
    a.end()?;
    Ok(r)
}

/// Grant options: `[Opt(until), Opt(invite)]`.
pub(crate) fn grant_opts_v(o: &GrantOpts) -> Value {
    Value::List(vec![opt(o.until, |w| u(w.0)), opt(o.may_grant, role_v)])
}

pub(crate) fn grant_opts(v: Value) -> Result<GrantOpts> {
    let mut a = Args::new(v)?;
    let until = a.opt_wall()?;
    let invite = a.opt()?.map(|r| role(&r)).transpose()?;
    a.end()?;
    Ok(GrantOpts { until, may_grant: invite })
}

/// A member of a group: `[0, tid]` item, `[1, tid]` subgroup.
pub(crate) fn member_v(m: Member) -> Value {
    Value::List(match m {
        Member::Item(t) => vec![u(0), Value::Tid(t)],
        Member::Subgroup(t) => vec![u(1), Value::Tid(t)],
    })
}

pub(crate) fn member(v: Value) -> Result<Member> {
    let mut a = Args::new(v)?;
    let m = match a.uint()? {
        0 => Member::Item(a.tid()?),
        1 => Member::Subgroup(a.tid()?),
        _ => return Err(bad("member")),
    };
    a.end()?;
    Ok(m)
}

pub(crate) fn holders_v(h: &[Holder]) -> Value {
    Value::List(h.iter().map(|x| Value::List(vec![Value::Tid(x.actor), role_v(x.role), opt(x.until, |w| u(w.0)), tids_v(&x.through)])).collect())
}

pub(crate) fn holders(v: Value) -> Result<Vec<Holder>> {
    Args::of(vec![v]).list()?.into_iter().map(|x| {
        let mut a = Args::new(x)?;
        let (actor, r, until) = (a.tid()?, role(&a.next()?)?, a.opt_wall()?);
        let through = a.list()?.into_iter().map(|t| Args::of(vec![t]).tid()).collect::<Result<Vec<Tid>>>()?;
        a.end()?;
        Ok(Holder { actor, role: r, until, through })
    }).collect()
}

pub(crate) fn links_v(l: &[LinkInfo]) -> Value {
    Value::List(l.iter().map(|x| Value::List(vec![Value::Tid(x.id.0), Value::Tid(x.target), role_v(x.role), opt(x.until, |w| u(w.0)), Value::Bool(x.single_use)])).collect())
}

pub(crate) fn links(v: Value) -> Result<Vec<LinkInfo>> {
    Args::of(vec![v]).list()?.into_iter().map(|x| {
        let mut a = Args::new(x)?;
        let r = LinkInfo { id: LinkId(a.tid()?), target: a.tid()?, role: role(&a.next()?)?, until: a.opt_wall()?, single_use: a.bool()? };
        a.end()?;
        Ok(r)
    }).collect()
}

/// A sync scope: `[]` all, `[tid]` the groups holding it.
pub(crate) fn sync_scope_v(s: SyncScope) -> Value {
    Value::List(match s {
        SyncScope::AllWithPeers => vec![],
        SyncScope::Thing(t) => vec![Value::Tid(t)],
    })
}

pub(crate) fn sync_scope(v: Value) -> Result<SyncScope> {
    let mut a = Args::new(v)?;
    let s = match a.opt_tid()? {
        None => SyncScope::AllWithPeers,
        Some(t) => SyncScope::Thing(t),
    };
    a.end()?;
    Ok(s)
}

/// A `SyncFirst`: `[0]` required, `[1, ms]` try (`u64::MAX`: as long as it takes), `[2]` skip, `[3, time]` backdate.
pub(crate) fn sync_first_v(s: SyncFirst) -> Value {
    Value::List(match s {
        SyncFirst::Required => vec![u(0)],
        SyncFirst::Try(d) => vec![u(1), u(u64::try_from(d.as_millis()).unwrap_or(u64::MAX))],
        SyncFirst::Skip => vec![u(2)],
        SyncFirst::Backdate(w) => vec![u(3), u(w.0)],
    })
}

pub(crate) fn sync_first(v: Value) -> Result<SyncFirst> {
    let mut a = Args::new(v)?;
    let s = match a.uint()? {
        0 => SyncFirst::Required,
        1 => SyncFirst::Try(std::time::Duration::from_millis(a.uint()?)),
        2 => SyncFirst::Skip,
        3 => SyncFirst::Backdate(osis_base::Time(a.uint()?)),
        _ => return Err(bad("sync first")),
    };
    a.end()?;
    Ok(s)
}

/// A `SetRoleOpts`: `[sync first, Opt(keep)]`.
pub(crate) fn set_role_v(o: &SetRoleOpts) -> Value {
    Value::List(vec![sync_first_v(o.sync), opt(o.retain_copy, Value::Bool)])
}

pub(crate) fn set_role(v: Value) -> Result<SetRoleOpts> {
    let mut a = Args::new(v)?;
    let sync = sync_first(a.next()?)?;
    let keep = a.opt()?.map(|k| Args::of(vec![k]).bool()).transpose()?;
    a.end()?;
    Ok(SetRoleOpts { sync, retain_copy: keep })
}

/// `SyncOptions`' fields.
pub(crate) fn sync_options_v(o: &crate::SyncOptions) -> Vec<Value> {
    let reach = match o.share_address {
        crate::ShareAddress::Auto => None,
        crate::ShareAddress::Always => Some(true),
        crate::ShareAddress::Never => Some(false),
    };
    vec![opt(reach, Value::Bool), Value::Bool(o.mode == crate::SyncMode::LogOnly)]
}

pub(crate) fn sync_options(a: &mut Args) -> Result<crate::SyncOptions> {
    let reach = match a.opt()?.map(|k| Args::of(vec![k]).bool()).transpose()? {
        None => crate::ShareAddress::Auto,
        Some(true) => crate::ShareAddress::Always,
        Some(false) => crate::ShareAddress::Never,
    };
    Ok(crate::SyncOptions { share_address: reach, mode: if a.bool()? { crate::SyncMode::LogOnly } else { crate::SyncMode::Full } })
}

/// An outcome carried as a value (a row that waits): the Reply's own forms.
pub(crate) fn outcome_of(v: Value) -> Result<Result<Value>> {
    let mut a = Args::new(v)?;
    match a.uint()? {
        0 => Ok(Ok(a.next()?)),
        1 => {
            let code = a.uint()?;
            Ok(Err(error_of(code, a.rest())))
        }
        _ => Err(bad("result")),
    }
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
        Error::Permission { tid, needs } => (ApiCode::PERMISSION, vec![Value::Tid(*tid), role_v(*needs)]),
        Error::Type { path, reason } => (ApiCode::TYPE, vec![path_v(path), t(reason)]),
        Error::TooLarge { limit } => (ApiCode::TOO_LARGE, vec![u(*limit as u64)]),
        Error::NotUndoable { commit, reason } => (ApiCode::NOT_UNDOABLE, vec![commit_id_v(commit), u(u64::from(*reason == NotUndoableReason::Superseded))]),
        Error::Unsynced { groups } => (ApiCode::UNSYNCED, vec![tids_v(groups)]),
        Error::Invalid(m) => (ApiCode::INVALID, vec![t(m)]),
        Error::Storage(m) => (ApiCode::STORAGE, vec![t(m)]),
        Error::Network(m) => (ApiCode::NETWORK, vec![t(m)]),
        Error::OutcomeUnknown => (ApiCode::OUTCOME_UNKNOWN, vec![]),
        Error::Unsupported(m) => (ApiCode::UNSUPPORTED, vec![t(m)]),
        Error::Refused(m) => (ApiCode::REFUSED, vec![t(m)]),
        Error::Closed => (ApiCode::STORAGE, vec![t("the node closed")]),
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
            ApiCode::PERMISSION => Error::Permission { tid: a.tid()?, needs: role(&a.next()?)? },
            ApiCode::TYPE => Error::Type { path: path(a.next()?)?, reason: a.text()? },
            ApiCode::TOO_LARGE => Error::TooLarge { limit: usize::try_from(a.uint()?).unwrap_or(usize::MAX) },
            ApiCode::NOT_UNDOABLE => Error::NotUndoable { commit: commit_id(a.next()?)?, reason: if a.uint()? == 1 { NotUndoableReason::Superseded } else { NotUndoableReason::ContentGone } },
            ApiCode::UNSYNCED => Error::Unsynced { groups: tids(a.next()?)? },
            ApiCode::INVALID => Error::Invalid(text(&mut a)),
            ApiCode::STORAGE => Error::Storage(text(&mut a)),
            ApiCode::NETWORK => Error::Network(text(&mut a)),
            ApiCode::UNSUPPORTED => Error::Unsupported(text(&mut a)),
            ApiCode::REFUSED => Error::Refused(text(&mut a)),
            ApiCode::OUTCOME_UNKNOWN => Error::OutcomeUnknown,
            _ => Error::Invalid(format!("port: error code {code}")),
        })
    })();
    r.unwrap_or_else(|e| e)
}
