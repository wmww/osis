//! Values of the client port's method table (notes/client-port.md §2): API types to and from
//! untyped `Value`s, and API errors to and from Reply error codes (`osis_proto::ApiCode`).

use crate::commits::{CommitEntry, CommitKind, CommitQuery, DropReason, Next, Scope};
use crate::error::{Error, Result};
use crate::read::{Edge, GroupsOf, Roster, Stamp};
use crate::share::{EdgeOpts, GroupReach, GroupSync, HostAddr, LinkInfo, Share, Status, SyncScope, SyncState};
use crate::watch::{CommitInfo, Source};
use crate::write::Committed;
use osis_base::{Ak, CommitId, LabelId, Role, Tid, Ts, Value, WallMs};
use osis_crdt::{Op, PathOp, PathSeg};
use osis_node::{Cause, ChangeId, Diagnostic, DiagnosticKind, EphemeralId};
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
    pub fn opt_wall(&mut self) -> Result<Option<WallMs>> {
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

fn wall(v: &Value) -> Result<WallMs> {
    v.as_uint().map(WallMs).ok_or_else(|| bad("time"))
}

pub(crate) fn commit_id(v: Value) -> Result<CommitId> {
    Args::of(vec![v]).bytes()?.try_into().map(CommitId).map_err(|_| bad("commit id"))
}

pub(crate) fn change_v(c: &ChangeId) -> Value {
    Value::List(match c {
        ChangeId::Commit(c) => vec![u(0), Value::bytes(&c.0)],
        ChangeId::Ephemeral(e) => vec![u(1), Value::bytes(&e.session), u(e.n)],
    })
}

pub(crate) fn change(v: Value) -> Result<ChangeId> {
    let mut a = Args::new(v)?;
    let c = match a.uint()? {
        0 => ChangeId::Commit(commit_id(a.next()?)?),
        1 => ChangeId::Ephemeral(EphemeralId { session: a.bytes()?.try_into().map_err(|_| bad("session"))?, n: a.uint()? }),
        _ => return Err(bad("change")),
    };
    a.end()?;
    Ok(c)
}

pub(crate) fn committed_v(c: &Committed) -> Value {
    Value::List(vec![change_v(&c.id), ts_v(c.ts), Value::List(c.also.iter().map(|x| Value::bytes(&x.0)).collect())])
}

pub(crate) fn committed(v: Value) -> Result<Committed> {
    let mut a = Args::new(v)?;
    let (id, ts) = (change(a.next()?)?, ts(&a.next()?)?);
    let also = Args::of(vec![a.next()?]).list()?.into_iter().map(commit_id).collect::<Result<_>>()?;
    let c = Committed { id, ts, also };
    a.end()?;
    Ok(c)
}

pub(crate) fn stamp_v(s: &Stamp) -> Value {
    Value::List(vec![opt(s.commit, |c| Value::bytes(&c.0)), ts_v(s.ts), Value::Tid(s.node), Value::Tid(s.actor), u(s.received.0)])
}

pub(crate) fn stamp(v: Value) -> Result<Stamp> {
    let mut a = Args::new(v)?;
    let commit = a.opt()?.map(commit_id).transpose()?;
    let s = Stamp { commit, ts: ts(&a.next()?)?, node: a.tid()?, actor: a.tid()?, received: wall(&a.next()?)? };
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

pub(crate) fn roster_v(r: &Roster) -> Value {
    Value::List(r.iter().map(|(t, e)| Value::List(vec![Value::Tid(*t), role_v(e.role), opt(e.until, |w| u(w.0)), opt(e.invite, role_v), Value::Bool(e.tied)])).collect())
}

pub(crate) fn roster(v: Value) -> Result<Roster> {
    let mut out = Roster::new();
    for x in Args::of(vec![v]).list()? {
        let mut a = Args::new(x)?;
        let t = a.tid()?;
        let e = Edge { role: role(&a.next()?)?, until: a.opt_wall()?, invite: a.opt()?.map(|r| role(&r)).transpose()?, tied: a.bool()? };
        a.end()?;
        out.insert(t, e);
    }
    Ok(out)
}

const CAUSES: [Cause; 6] = [Cause::Validity, Cause::Expiry, Cause::Purge, Cause::LateDelta, Cause::LostAccess, Cause::Fetched];

/// Fails to compile when a cause is added: list it in `CAUSES` too.
#[allow(dead_code)]
fn causes_listed(c: Cause) {
    match c {
        Cause::Validity | Cause::Expiry | Cause::Purge | Cause::LateDelta | Cause::LostAccess | Cause::Fetched => {}
    }
}

fn info_v(i: &CommitInfo) -> Value {
    Value::List(vec![change_v(&i.id), Value::Tid(i.actor), Value::Tid(i.node), ts_v(i.ts), u(i.received.0)])
}

fn info(v: Value) -> Result<CommitInfo> {
    let mut a = Args::new(v)?;
    let i = CommitInfo { id: change(a.next()?)?, actor: a.tid()?, node: a.tid()?, ts: ts(&a.next()?)?, received: wall(&a.next()?)? };
    a.end()?;
    Ok(i)
}

pub(crate) fn source_v(s: &Source) -> Value {
    Value::List(match s {
        Source::Initial => vec![u(0)],
        Source::Local(i) => vec![u(1), info_v(i)],
        Source::Remote(i) => vec![u(2), info_v(i)],
        Source::Derived(c) => vec![u(3), u(CAUSES.iter().position(|x| x == c).unwrap_or(0) as u64)],
    })
}

pub(crate) fn source(v: Value) -> Result<Source> {
    let mut a = Args::new(v)?;
    let s = match a.uint()? {
        0 => Source::Initial,
        1 => Source::Local(info(a.next()?)?),
        2 => Source::Remote(info(a.next()?)?),
        3 => Source::Derived(*usize::try_from(a.uint()?).ok().and_then(|i| CAUSES.get(i)).ok_or_else(|| bad("cause"))?),
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

const STATES: [SyncState; 8] = [SyncState::Synced, SyncState::Syncing, SyncState::Unreachable, SyncState::NoHosts, SyncState::Refused, SyncState::Stranded, SyncState::ReceiptsOnly, SyncState::NoRoute];

pub(crate) fn status_v(s: &Status) -> Value {
    let groups = s
        .groups
        .iter()
        .map(|(g, x)| {
            Value::List(vec![
                Value::Tid(*g),
                u(STATES.iter().position(|y| *y == x.state).unwrap_or(0) as u64),
                opt(x.last_sync, |w| u(w.0)),
                Value::List(x.labels.iter().map(|l| Value::bytes(&l.0)).collect()),
                Value::List(x.not_admitted.iter().map(|h| Value::Str(h.to_string())).collect()),
                Value::Bool(x.leaving),
                Value::List(x.unrouted.iter().map(|t| Value::Tid(*t)).collect()),
            ])
        })
        .collect();
    Value::List(vec![u(s.connected as u64), Value::List(groups), Value::List(s.split.iter().map(|t| Value::Tid(*t)).collect())])
}

pub(crate) fn status(v: Value) -> Result<Status> {
    let mut a = Args::new(v)?;
    let connected = usize::try_from(a.uint()?).map_err(|_| bad("count"))?;
    let mut st = Status { connected, groups: Default::default(), remotes: Vec::new(), split: Default::default() };
    for g in a.list()? {
        let mut b = Args::new(g)?;
        let t = b.tid()?;
        let state = *usize::try_from(b.uint()?).ok().and_then(|i| STATES.get(i)).ok_or_else(|| bad("state"))?;
        let last_sync = b.opt_wall()?;
        let labels = b.list()?.into_iter().map(|l| Args::of(vec![l]).bytes().and_then(|x| x.try_into().map(LabelId).map_err(|_| bad("label")))).collect::<Result<_>>()?;
        let not_admitted = b.list()?.into_iter().map(|h| Args::of(vec![h]).text().and_then(|t| t.parse::<HostAddr>())).collect::<Result<_>>()?;
        let leaving = b.bool()?;
        let unrouted = b.list()?.into_iter().map(|t| Args::of(vec![t]).tid()).collect::<Result<_>>()?;
        b.end()?;
        st.groups.insert(t, GroupSync { state, last_sync, labels, not_admitted, leaving, unrouted });
    }
    for t in a.list()? {
        st.split.insert(Args::of(vec![t]).tid()?);
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
    let commit = a.opt()?.map(commit_id).transpose()?;
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

const CKINDS: [CommitKind; 5] = [CommitKind::Change, CommitKind::Revert, CommitKind::Role, CommitKind::Snapshot, CommitKind::Ephemeral];

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
        opt(q.reverts.as_ref(), change_v),
        opt(q.reverted_by.as_ref(), change_v),
        opt(q.in_effect, Value::Bool),
        opt(q.since, ts_v),
        opt(q.until, ts_v),
        opt(q.after.as_ref(), change_v),
        opt(q.limit, |n| u(n as u64)),
        opt(q.next, |n| u(u64::from(n == Next::Redo))),
    ])
}

pub(crate) fn query(v: Value) -> Result<CommitQuery> {
    let mut a = Args::new(v)?;
    let q = CommitQuery {
        scope: a.opt()?.map(scope).transpose()?,
        actors: tids(a.next()?)?,
        kinds: a.list()?.iter().map(ckind).collect::<Result<_>>()?,
        reverts: a.opt()?.map(change).transpose()?,
        reverted_by: a.opt()?.map(change).transpose()?,
        in_effect: a.opt()?.map(|b| Args::of(vec![b]).bool()).transpose()?,
        since: a.opt()?.map(|t| ts(&t)).transpose()?,
        until: a.opt()?.map(|t| ts(&t)).transpose()?,
        after: a.opt()?.map(change).transpose()?,
        limit: a.opt()?.map(|n| n.as_uint().and_then(|n| usize::try_from(n).ok()).ok_or_else(|| bad("limit"))).transpose()?,
        next: a.opt()?.map(|n| match n.as_uint() {
            Some(0) => Ok(Next::Undo),
            Some(1) => Ok(Next::Redo),
            _ => Err(bad("next")),
        }).transpose()?,
    };
    a.end()?;
    Ok(q)
}

pub(crate) fn from_v(f: &crate::HistoryFrom) -> Value {
    use crate::HistoryFrom as F;
    let at = |p: &crate::HistoryPos| vec![ts_v(p.ts), change_v(&p.id)];
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
            let p = HistoryPos { ts: ts(&a.next()?)?, id: change(a.next()?)? };
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
        B::Purged { by, actor } => vec![u(2), change_v(by), opt(*actor, Value::Tid)],
        B::Dropped => vec![u(3)],
        B::NotFetched => vec![u(4)],
    };
    Value::List(vec![info_v(&e.commit), ckind_v(&e.kind), Value::Bool(e.valid), Value::List(body)])
}

pub(crate) fn hist_entry(v: Value) -> Result<crate::HistoryEntry<Value>> {
    use crate::HistoryBody as B;
    let mut a = Args::new(v)?;
    let (commit, kind, valid) = (info(a.next()?)?, ckind(&a.next()?)?, a.bool()?);
    let mut b = Args::new(a.next()?)?;
    a.end()?;
    let body = match b.uint()? {
        0 => B::Held(b.opt()?),
        1 => B::TooLarge { limit: usize::try_from(b.uint()?).unwrap_or(usize::MAX) },
        2 => B::Purged { by: change(b.next()?)?, actor: b.opt()?.map(|v| Args::of(vec![v]).tid()).transpose()? },
        3 => B::Dropped,
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
        info_v(&e.commit),
        ckind_v(&e.kind),
        opt(e.reverts.as_ref(), change_v),
        Value::List(e.reverted_by.iter().map(change_v).collect()),
        Value::Bool(e.in_effect),
        aspects_v(&e.aspects),
        Value::Bool(e.dropped),
        Value::List(e.purged.iter().map(|(t, k, by)| Value::List(vec![Value::Tid(*t), ak_v(k), change_v(by)])).collect()),
    ])
}

fn purged_one(v: Value) -> Result<(Tid, Ak, ChangeId)> {
    let mut a = Args::new(v)?;
    let x = (a.tid()?, a.ak()?, change(a.next()?)?);
    a.end()?;
    Ok(x)
}

pub(crate) fn entry(v: Value) -> Result<CommitEntry> {
    let mut a = Args::new(v)?;
    let e = CommitEntry {
        commit: info(a.next()?)?,
        kind: ckind(&a.next()?)?,
        reverts: a.opt()?.map(change).transpose()?,
        reverted_by: a.list()?.into_iter().map(change).collect::<Result<_>>()?,
        in_effect: a.bool()?,
        aspects: aspects(a.next()?)?,
        dropped: a.bool()?,
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

/// Edge options: `[Opt(until), Opt(invite)]`.
pub(crate) fn edge_opts_v(o: &EdgeOpts) -> Value {
    Value::List(vec![opt(o.until, |w| u(w.0)), opt(o.invite, role_v)])
}

pub(crate) fn edge_opts(v: Value) -> Result<EdgeOpts> {
    let mut a = Args::new(v)?;
    let until = a.opt_wall()?;
    let invite = a.opt()?.map(|r| role(&r)).transpose()?;
    a.end()?;
    Ok(EdgeOpts { until, invite })
}

/// A share: `[0, role]` tied, `[1, role]` untied, `[2]` excluded.
pub(crate) fn share_v(s: Share) -> Value {
    Value::List(match s {
        Share::Tied(r) => vec![u(0), role_v(r)],
        Share::Untied(r) => vec![u(1), role_v(r)],
        Share::Excluded => vec![u(2)],
    })
}

pub(crate) fn share(v: Value) -> Result<Share> {
    let mut a = Args::new(v)?;
    let s = match a.uint()? {
        0 => Share::Tied(role(&a.next()?)?),
        1 => Share::Untied(role(&a.next()?)?),
        2 => Share::Excluded,
        _ => return Err(bad("share")),
    };
    a.end()?;
    Ok(s)
}

pub(crate) fn reach_v(r: &[GroupReach]) -> Value {
    Value::List(r.iter().map(|x| Value::List(vec![Value::Tid(x.group), Value::Bool(x.placed), share_v(x.share)])).collect())
}

pub(crate) fn reach(v: Value) -> Result<Vec<GroupReach>> {
    Args::of(vec![v]).list()?.into_iter().map(|x| {
        let mut a = Args::new(x)?;
        let r = GroupReach { group: a.tid()?, placed: a.bool()?, share: share(a.next()?)? };
        a.end()?;
        Ok(r)
    }).collect()
}

pub(crate) fn pairs_v(p: &[(Tid, Tid)]) -> Value {
    Value::List(p.iter().map(|(a, b)| Value::List(vec![Value::Tid(*a), Value::Tid(*b)])).collect())
}

pub(crate) fn pairs(v: Value) -> Result<Vec<(Tid, Tid)>> {
    Args::of(vec![v]).list()?.into_iter().map(|x| {
        let mut a = Args::new(x)?;
        let r = (a.tid()?, a.tid()?);
        a.end()?;
        Ok(r)
    }).collect()
}

pub(crate) fn links_v(l: &[LinkInfo]) -> Value {
    Value::List(l.iter().map(|x| Value::List(vec![Value::Tid(x.id), Value::Tid(x.target), role_v(x.role), opt(x.until, |w| u(w.0)), Value::Bool(x.single_use)])).collect())
}

pub(crate) fn links(v: Value) -> Result<Vec<LinkInfo>> {
    Args::of(vec![v]).list()?.into_iter().map(|x| {
        let mut a = Args::new(x)?;
        let r = LinkInfo { id: a.tid()?, target: a.tid()?, role: role(&a.next()?)?, until: a.opt_wall()?, single_use: a.bool()? };
        a.end()?;
        Ok(r)
    }).collect()
}

/// A sync scope: `[]` all, `[tid]` the groups holding it.
pub(crate) fn sync_scope_v(s: SyncScope) -> Value {
    Value::List(match s {
        SyncScope::All => vec![],
        SyncScope::Group(t) => vec![Value::Tid(t)],
    })
}

pub(crate) fn sync_scope(v: Value) -> Result<SyncScope> {
    let mut a = Args::new(v)?;
    let s = match a.opt_tid()? {
        None => SyncScope::All,
        Some(t) => SyncScope::Group(t),
    };
    a.end()?;
    Ok(s)
}

/// A `Demotion`: `[sync, Opt(backdate), repudiate, Opt(keep)]`, sync 0 required, 1 skip, else
/// `[ms]` try.
pub(crate) fn demotion_v(d: &crate::Demotion) -> Value {
    let sync = match d.sync {
        crate::WaitForSync::Required => u(0),
        crate::WaitForSync::Skip => u(1),
        crate::WaitForSync::Try(t) => Value::List(vec![u(u64::try_from(t.as_millis()).unwrap_or(u64::MAX))]),
    };
    Value::List(vec![sync, opt(d.backdate, |w| u(w.0)), Value::Bool(d.repudiate), opt(d.keep, Value::Bool)])
}

pub(crate) fn demotion(v: Value) -> Result<crate::Demotion> {
    let mut a = Args::new(v)?;
    let sync = match a.next()? {
        Value::List(l) => crate::WaitForSync::Try(std::time::Duration::from_millis(Args::of(l).uint()?)),
        s => match s.as_uint() {
            Some(0) => crate::WaitForSync::Required,
            Some(1) => crate::WaitForSync::Skip,
            _ => return Err(bad("demotion")),
        },
    };
    let backdate = a.opt_wall()?;
    let repudiate = a.bool()?;
    let keep = a.opt()?.map(|k| Args::of(vec![k]).bool()).transpose()?;
    a.end()?;
    Ok(crate::Demotion { sync, backdate, repudiate, keep })
}

/// A sync policy's fields.
pub(crate) fn policy_v(p: &crate::GroupPolicy) -> Vec<Value> {
    vec![opt(p.publish_reach, Value::Bool), Value::Bool(p.receipts_only)]
}

pub(crate) fn policy(a: &mut Args) -> Result<crate::GroupPolicy> {
    let publish_reach = a.opt()?.map(|k| Args::of(vec![k]).bool()).transpose()?;
    Ok(crate::GroupPolicy { publish_reach, receipts_only: a.bool()? })
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
        Error::NotUndoable { commit, reason } => (ApiCode::NOT_UNDOABLE, vec![change_v(commit), u(u64::from(*reason == DropReason::Superseded))]),
        Error::Unsynced { groups } => (ApiCode::UNSYNCED, vec![tids_v(groups)]),
        Error::Invalid(m) => (ApiCode::INVALID, vec![t(m)]),
        Error::Storage(m) => (ApiCode::STORAGE, vec![t(m)]),
        Error::Network(m) => (ApiCode::NETWORK, vec![t(m)]),
        Error::OutcomeUnknown => (ApiCode::OUTCOME_UNKNOWN, vec![]),
        Error::Unsupported(m) => (ApiCode::UNSUPPORTED, vec![t(m)]),
        Error::Closed => (ApiCode::STORAGE, vec![t("the node's database closed")]),
        Error::StillOpen { .. } => (ApiCode::INVALID, vec![t(&e.to_string())]),
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
            ApiCode::NOT_UNDOABLE => Error::NotUndoable { commit: change(a.next()?)?, reason: if a.uint()? == 1 { DropReason::Superseded } else { DropReason::Compacted } },
            ApiCode::UNSYNCED => Error::Unsynced { groups: tids(a.next()?)? },
            ApiCode::INVALID => Error::Invalid(text(&mut a)),
            ApiCode::STORAGE => Error::Storage(text(&mut a)),
            ApiCode::NETWORK => Error::Network(text(&mut a)),
            ApiCode::UNSUPPORTED => Error::Unsupported(text(&mut a)),
            ApiCode::OUTCOME_UNKNOWN => Error::OutcomeUnknown,
            _ => Error::Invalid(format!("port: error code {code}")),
        })
    })();
    r.unwrap_or_else(|e| e)
}
