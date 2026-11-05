//! The serving side of the client port (notes/client-port.md §2): requests the sync engine hands
//! out (`Action::Request`) are queued under the handle lock and run after it is released on one
//! worker thread, one at a time, each as ordinary `Osis` calls (one engine transaction each);
//! replies and Notify payloads are encoded there, never under the lock. Subscriptions are
//! ordinary dispatcher registrations whose callbacks only set dirty flags (and queue fired
//! signals and diagnostics within `SIGNAL_BYTES`); the worker materializes dirty subscriptions
//! when push room opens (`Action::Room`). Writes carry a nonce: outcomes are kept per (tier
//! identity, session), so a retry is answered once.
//!
//! **Invariant** (notes/client-port.md §3): every row of a thin client's session runs on a handle
//! acting as that client's actor, never as this node's account, and that client's authority ends
//! at revocation. `Worker::session` is the only way to a row or a send of a client session:
//! it asks the sync engine whether the session's client is live (its `clients.0^` entry there,
//! under the same secret, before its `until`) at that moment, not when the request was queued,
//! and hands out `Osis::act_as` of its actor, whose every read and write the rights of that actor
//! decide at that moment (`Reader::hidden`, `Mutation::confine`). There is no cached scope or
//! role to go stale; a call that passed `session` just before a revocation is ordered before it.

use super::codec::{self as c, Args, outcome_err, u};
use super::{HISTORY_DIRTY_BYTES, HISTORY_SEND, MAX_SCHEMA_BYTES, MAX_WAITS, SIGNAL_BYTES, STREAM_CHUNK, WRITE_NONCES, filter, method};
use osis_node::sync::MAX_CONNS_PER_CLIENT;
use crate::error::{Error, Result};
use crate::handle::{Inner, Osis, WeakOsis};
use crate::watch::{Delivery, Filter, Subscription, lock};
use osis_base::{Ak, Tid, Value};
use osis_node::sync::{Action, ConnId, Event, Tier};
use osis_proto::msg::Id;
use osis_proto::{Code, Message, Outcome, Payload};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::future::Future;
use std::io::{Read, Seek, SeekFrom};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::{Sender, channel};
use std::sync::{Arc, Mutex};

/// Whether an action is the client port's (not the network driver's).
pub(crate) fn is_port(a: &Action) -> bool {
    matches!(a, Action::Request { .. } | Action::Room { .. } | Action::Ended { .. })
}

pub(crate) enum Job {
    Act(Action),
    /// A subscription of this connection has something to send.
    Dirty(ConnId),
    /// A task's outcome may be known.
    Woke(ConnId, Id),
    /// The database's last user handle went: running tasks end, so they do not keep it open.
    Closing,
}

impl Job {
    /// The connection whose job this is.
    fn conn(&self) -> Option<ConnId> {
        match self {
            Job::Act(Action::Request { conn, .. } | Action::Room { conn, .. } | Action::Ended { conn }) => Some(*conn),
            Job::Act(_) | Job::Closing => None,
            Job::Dirty(c) | Job::Woke(c, _) => Some(*c),
        }
    }
}

/// Wakes the worker for a task (from under the handle lock: only a send).
struct Wake {
    tx: Sender<Job>,
    conn: ConnId,
    id: Id,
}

impl std::task::Wake for Wake {
    fn wake(self: Arc<Self>) {
        let _ = self.tx.send(Job::Woke(self.conn, self.id));
    }
}

thread_local! {
    static ON_WORKER: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Whether this thread is a port worker, which serves every client of its node one call at a time
/// and so never waits on another node (`crate::sources`).
pub(crate) fn on_worker() -> bool {
    ON_WORKER.get()
}

/// The port of one database: the jobs queued under the lock, the worker.
pub(crate) struct Port {
    /// A test's way to reach `Worker::panicked`: no client input is known to.
    pub panic_next: std::sync::atomic::AtomicBool,
    /// Likewise after a Call ran, before its reply: the reply is lost, the write stays applied.
    pub panic_after_call: std::sync::atomic::AtomicBool,
    /// A test's way to a pairing reply above the small allowance: bytes added to the next.
    pub pad_pair_reply: AtomicUsize,
    /// A test's way into the gap between a write's route and its lock.
    pub after_route: Mutex<Option<Box<dyn Fn() + Send>>>,
    queued: Mutex<Vec<Job>>,
    tx: Mutex<Option<Sender<Job>>>,
}

impl Port {
    pub fn new() -> Port {
        Port { panic_next: false.into(), panic_after_call: false.into(), pad_pair_reply: AtomicUsize::new(0), after_route: Mutex::new(None), queued: Mutex::new(Vec::new()), tx: Mutex::new(None) }
    }

    /// Queues actions (under the handle lock).
    pub fn queue(&self, acts: Vec<Action>) {
        lock(&self.queued).extend(acts.into_iter().map(Job::Act));
    }

    /// Hands queued jobs to the worker (after the lock is released), starting it first.
    pub fn kick(&self, inner: &Arc<Inner>) {
        let jobs = std::mem::take(&mut *lock(&self.queued));
        if jobs.is_empty() {
            return;
        }
        let mut tx = lock(&self.tx);
        if tx.is_none() {
            let (t, rx) = channel::<Job>();
            let weak = WeakOsis(Arc::downgrade(inner));
            let mine = t.clone();
            let spawned = std::thread::Builder::new().name("osis-port".into()).spawn(move || {
                ON_WORKER.set(true);
                let mut w = Worker { db: weak, tx: mine, conns: BTreeMap::new(), nonces: BTreeMap::new(), schemas: BTreeMap::new(), tick: 0 };
                while let Ok(j) = rx.recv() {
                    // a panic ends the connection it served, not the port: its session's other
                    // jobs find no session, every other client goes on. A write's nonce stays
                    // spent (`top` is set before it runs), so its retry is `OutcomeUnknown`.
                    let conn = j.conn();
                    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| w.job(j))) {
                        Ok(true) => {}
                        Ok(false) => return,
                        Err(_) => w.panicked(conn),
                    }
                }
            });
            if spawned.is_err() {
                return;
            }
            *tx = Some(t);
        }
        if let Some(t) = tx.as_ref() {
            for j in jobs {
                let _ = t.send(j);
            }
        }
    }

    /// The last user handle went: a running task holds the database, which must close.
    pub fn closing(&self) {
        if let Some(t) = lock(&self.tx).as_ref() {
            let _ = t.send(Job::Closing);
        }
    }
}

/// What a subscription callback leaves for the worker (shared with the dispatcher).
#[derive(Default)]
struct Pending {
    /// The roster or status changed since the last Notify.
    dirty: bool,
    /// Aspect or thing subscription: aspects changed, with their newest source.
    aks: BTreeMap<Ak, crate::watch::Source>,
    /// Fired signals and diagnostics, never coalesced, each with its bytes.
    queue: VecDeque<(Value, usize)>,
    /// History subscription: the commits whose entries changed (`HISTORY_DIRTY_BYTES` each).
    history: BTreeSet<osis_node::ChangeId>,
    /// A delivery did not fit `SIGNAL_BYTES`: the subscription ends.
    lapsed: bool,
}

impl Pending {
    /// Commit `id`'s entry changed. Past the connection's budget the subscription lapses: the client
    /// reads its pages again.
    fn note_history(&mut self, id: osis_node::ChangeId, held: &AtomicUsize) {
        if self.history.contains(&id) {
            return;
        }
        if held.load(Ordering::Acquire).saturating_add(HISTORY_DIRTY_BYTES) > SIGNAL_BYTES {
            self.lapsed = true;
        } else {
            held.fetch_add(HISTORY_DIRTY_BYTES, Ordering::AcqRel);
            self.history.insert(id);
        }
    }

    /// Forgets all of it, giving its queued bytes back to the connection's `held`.
    fn clear(&mut self, held: &AtomicUsize) {
        for (_, n) in self.queue.drain(..) {
            held.fetch_sub(n, Ordering::AcqRel);
        }
        held.fetch_sub(self.history.len() * HISTORY_DIRTY_BYTES, Ordering::AcqRel);
        self.history.clear();
        self.dirty = false;
        self.aks.clear();
    }
}

/// A row that waits, polled on the worker: it holds the database, so `Job::Closing` ends it.
type Task = std::pin::Pin<Box<dyn Future<Output = Result<Value>>>>;

enum Kind {
    Aspect(Tid, Ak),
    Thing(Tid),
    Roster(Tid),
    History(Tid, Ak),
    Status,
    Diagnostics,
    /// A row that waits (`filter::TASK`), until its outcome went.
    Task(Option<Task>),
}

impl Kind {
    /// The thing it watches.
    fn thing(&self) -> Option<Tid> {
        match self {
            Kind::Aspect(t, _) | Kind::Thing(t) | Kind::Roster(t) | Kind::History(t, _) => Some(*t),
            _ => None,
        }
    }
}

struct PortSub {
    max_reply: usize,
    kind: Kind,
    pending: Arc<Mutex<Pending>>,
    _sub: Option<Subscription>,
    /// A client's: its actor could read the thing at some point of this subscription. When it no
    /// longer can the subscription lapses; one it never could stays silent, as for an unknown tid.
    seen: bool,
}

struct Conn {
    tier: Tier,
    session: [u8; 16],
    subs: BTreeMap<Id, PortSub>,
    /// Bytes of queued signals and diagnostics over all its subscriptions.
    held: Arc<AtomicUsize>,
    /// Room was asked for and not yet given.
    asked: bool,
    /// `settle` calls answered once nothing is left to send.
    settles: Vec<Id>,
    /// A bundle waiting to go out in pages (`method::EXPORT_BUNDLE`), until its last one went.
    export: Vec<u8>,
    /// A bundle coming in pages (`method::BUNDLE_WRITE`).
    import: Vec<u8>,
}

impl Conn {
    /// Ends a subscription; what it still held is freed with it.
    fn end_sub(&mut self, id: Id) {
        if let Some(s) = self.subs.remove(&id) {
            lock(&s.pending).clear(&self.held);
        }
    }
}

/// Whose write outcomes: the Owner's, or a client actor's (a session id of one identity never
/// reads another's).
type Identity = Option<Tid>;

/// Write outcomes of one session: by nonce (at most `WRITE_NONCES`), the highest seen, and
/// when it was last used (least recently used sessions go first).
#[derive(Default)]
struct Nonces {
    done: BTreeMap<u64, Result<Value>>,
    top: u64,
    used: u64,
    /// This entry was born from a resend: the session's earlier state is gone, so no resent nonce
    /// that `done` does not hold may run, whatever `top` says (until the session's next new write,
    /// after which every later nonce was sent under this entry).
    lost: bool,
}

struct Worker {
    db: WeakOsis,
    tx: Sender<Job>,
    conns: BTreeMap<ConnId, Conn>,
    /// Per (identity, session).
    nonces: BTreeMap<(Identity, [u8; 16]), Nonces>,
    /// Schema sources registered through the port (by hash of file and source): their bytes,
    /// at most `MAX_SCHEMA_BYTES` in all.
    schemas: BTreeMap<[u8; 32], usize>,
    tick: u64,
}

fn unsupported(what: &str) -> Error {
    Error::Unsupported(format!("{what} through the client port"))
}

/// Polls a task, its waker queueing `Job::Woke`.
fn poll_task(tx: &Sender<Job>, conn: ConnId, id: Id, t: &mut Task) -> std::task::Poll<Result<Value>> {
    let waker = std::task::Waker::from(Arc::new(Wake { tx: tx.clone(), conn, id }));
    t.as_mut().poll(&mut std::task::Context::from_waker(&waker))
}

/// The empty result of a row.
fn nothing() -> Value {
    Value::List(vec![])
}

/// Starts a row that waits (`filter::TASK`), an Owner's. Each runs as the node's own async call,
/// polled when its waker fires.
fn task(db: &Osis, m: u64, args: Vec<Value>) -> Result<Task> {
    let mut a = Args::of(args);
    let db = Osis::internal(db.inner.clone());
    let t: Task = match m {
        method::WAIT_SYNCED => {
            let (scope, ms) = (c::sync_scope(a.next()?)?, a.uint()?);
            a.end()?;
            let p = db.wait_synced_pending(scope, std::time::Duration::from_millis(ms));
            Box::pin(async move { p.await.map(|()| nothing()) })
        }
        method::REDEEM => {
            let link: crate::ShareLink = a.text()?.parse()?;
            a.end()?;
            Box::pin(async move { Ok(Value::Tid(db.redeem(&link).await?)) })
        }
        method::DEMOTE => {
            let (target, holder) = (a.tid()?, a.tid()?);
            let to = a.opt()?.map_or(Ok(crate::Lower::Remove), |r| c::role(&r).map(crate::Lower::To))?;
            let d = c::demotion(a.next()?)?;
            a.end()?;
            Box::pin(async move { db.demote(target, holder, to, d).await.map(|()| nothing()) })
        }
        method::REVOKE_LINK => {
            let (id, d) = (a.tid()?, c::demotion(a.next()?)?);
            a.end()?;
            Box::pin(async move { db.revoke_link(id, d).await.map(|()| nothing()) })
        }
        method::REVOKE_JOINER => {
            let (id, joiner, d) = (a.tid()?, a.tid()?, c::demotion(a.next()?)?);
            a.end()?;
            Box::pin(async move { db.revoke_joiner(id, joiner, d).await.map(|()| nothing()) })
        }
        method::IMPORT_CONTACT => {
            let card: crate::ContactCard = a.text()?.parse()?;
            a.end()?;
            Box::pin(async move { Ok(Value::Tid(db.import_contact(&card).await?)) })
        }
        _ => return Err(unsupported(&format!("method {m} as a row that waits"))),
    };
    Ok(t)
}

impl Worker {
    /// Runs a job; `false` once the database is gone.
    fn job(&mut self, j: Job) -> bool {
        let Some(db) = self.db.hold() else { return false };
        assert!(!db.inner.port.panic_next.swap(false, Ordering::AcqRel), "port worker: test panic");
        match j {
            Job::Act(Action::Request { conn, tier, msg }) => self.request(&db, conn, tier, *msg),
            Job::Act(Action::Room { conn, budget }) => {
                if let Some(c) = self.conns.get_mut(&conn) {
                    c.asked = false;
                }
                if let Some(h) = self.session(&db, conn) {
                    self.flush(&h, conn, budget);
                }
            }
            Job::Act(Action::Ended { conn }) => {
                self.conns.remove(&conn);
            }
            Job::Act(_) => {}
            Job::Dirty(conn) => self.want_room(&db, conn),
            Job::Woke(conn, id) => self.woke(&db, conn, id),
            Job::Closing => self.closing(&db),
        }
        true
    }

    /// A job of `conn` panicked: that session ends at once (its client sees the connection drop
    /// and reconnects), reported as a diagnostic. Its calls do not wait out a stall timeout.
    fn panicked(&mut self, conn: Option<ConnId>) {
        let Some(db) = self.db.hold() else { return };
        if let Some(c) = conn {
            self.conns.remove(&c);
        }
        db.engine(|e| e.report(osis_node::Diagnostic { kind: osis_node::DiagnosticKind::Storage, tids: Vec::new(), commit: None, peer: None, detail: format!("client port: a request panicked (connection {conn:?} ended)") }));
        if let Some(conn) = conn {
            self.feed(&db, Event::End { conn });
        }
    }

    /// Polls a task; once its outcome is known, it is queued as the subscription's one Notify.
    fn woke(&mut self, db: &Osis, conn: ConnId, id: Id) {
        let Some(s) = self.conns.get_mut(&conn).and_then(|c| c.subs.get_mut(&id)) else { return };
        let Kind::Task(Some(t)) = &mut s.kind else { return };
        let std::task::Poll::Ready(r) = poll_task(&self.tx, conn, id, t) else { return };
        s.kind = Kind::Task(None);
        lock(&s.pending).queue.push_back((Value::List(vec![c::outcome(r).to_value()]), 0));
        self.want_room(db, conn);
    }

    /// Ends the running tasks, each told: nobody is left to close a database they would hold.
    fn closing(&mut self, db: &Osis) {
        let mut told = Vec::new();
        for (conn, cn) in &mut self.conns {
            for s in cn.subs.values_mut().filter(|s| matches!(s.kind, Kind::Task(Some(_)))) {
                s.kind = Kind::Task(None);
                lock(&s.pending).queue.push_back((Value::List(vec![c::outcome(Err(Error::Closed)).to_value()]), 0));
                told.push(*conn);
            }
        }
        for conn in told {
            self.want_room(db, conn);
        }
    }

    fn feed(&self, db: &Osis, ev: Event) {
        db.handled(|l| l.sync.handle(ev));
    }

    fn reply(&self, db: &Osis, conn: ConnId, id: Id, reply: std::result::Result<Outcome, Code>) {
        self.feed(db, Event::Reply { conn, id, reply });
    }

    fn want_room(&mut self, db: &Osis, conn: ConnId) {
        let Some(c) = self.conns.get_mut(&conn) else { return };
        if !c.asked {
            c.asked = true;
            self.feed(db, Event::WantRoom { conn });
        }
    }

    /// The handle a row or a send of session `conn` runs on (the module's invariant): the
    /// Owner's as it is, a client's acting as its actor while it is live. A client no longer live
    /// is ended here; `None` then, as for a session this worker does not hold.
    fn session(&mut self, db: &Osis, conn: ConnId) -> Option<Osis> {
        match self.conns.get(&conn)?.tier {
            Tier::Owner => Some(Osis::internal(db.inner.clone())),
            Tier::Keyed => None,
            Tier::Client(actor) => {
                let live = db.locked(|l| l.sync.client_of(conn)) == Some(actor);
                if !live {
                    self.conns.remove(&conn);
                    self.feed(db, Event::End { conn });
                    return None;
                }
                Some(db.act_as(actor))
            }
        }
    }

    fn request(&mut self, db: &Osis, conn: ConnId, tier: Tier, msg: Message) {
        match msg {
            Message::Auth { id, session, .. } => {
                let new = || Conn { tier, session, subs: BTreeMap::new(), held: Arc::default(), asked: false, settles: Vec::new(), export: Vec::new(), import: Vec::new() };
                self.conns.entry(conn).and_modify(|c| c.session = session).or_insert_with(new);
                if self.session(db, conn).is_none() {
                    return self.reply(db, conn, id, Err(Code::REFUSED));
                }
                self.reply(db, conn, id, Ok(Outcome::Ok { value: Value::List(vec![]) }));
            }
            Message::Call { id, method, args, .. } => {
                let Some(h) = self.session(db, conn) else { return self.reply(db, conn, id, Err(Code::REFUSED)) };
                let db = &h;
                if db.acting.is_some() && !method::for_client(method) {
                    return self.reply(db, conn, id, Ok(outcome_err(&unsupported(&format!("method {method} for a thin client")))));
                }
                if method == method::SETTLE {
                    db.settle();
                    if let Some(c) = self.conns.get_mut(&conn) {
                        c.settles.push(id);
                    }
                    return self.want_room(db, conn);
                }
                let r = self.call(db, conn, method, args);
                assert!(!db.inner.port.panic_after_call.swap(false, Ordering::AcqRel), "port worker: test panic");
                self.reply(db, conn, id, Ok(c::outcome(r)));
            }
            Message::Sub { id, max_reply, filter } => {
                let Some(h) = self.session(db, conn) else { return self.reply(db, conn, id, Err(Code::REFUSED)) };
                let db = &h;
                let max = usize::try_from(max_reply).unwrap_or(usize::MAX);
                let mut out = c::outcome(self.sub(db, conn, id, max, filter));
                // an initial value above max_reply ends the subscription here as in proto, which
                // answers it TooLarge and frees the id (`MAX_SUBS` counts live ones only)
                if (Message::Reply { id, outcome: out.clone() }).encode().len() > max {
                    if let Some(c) = self.conns.get_mut(&conn) {
                        c.end_sub(id);
                    }
                    out = Outcome::too_large(max);
                }
                self.reply(db, conn, id, Ok(out));
            }
            Message::Unsub { sub, .. } => {
                if let Some(c) = self.conns.get_mut(&conn) {
                    c.end_sub(sub);
                }
            }
            _ => {}
        }
    }

    /// The write outcomes of a session, kept: at most as many sessions per identity as its
    /// connection cap, the least recently used going. Whether they are new, too.
    fn nonces_of(&mut self, db: &Osis, key: (Identity, [u8; 16])) -> (&mut Nonces, bool) {
        let fresh = !self.nonces.contains_key(&key);
        if fresh {
            let cap = match key.0 {
                Some(_) => MAX_CONNS_PER_CLIENT,
                None => db.locked(|l| l.sync.config().max_clients),
            };
            let mine = || self.nonces.iter().filter(|((w, _), _)| *w == key.0);
            if mine().count() >= cap
                && let Some(old) = mine().min_by_key(|(_, n)| n.used).map(|(k, _)| *k)
            {
                self.nonces.remove(&old);
            }
        }
        self.tick += 1;
        let n = self.nonces.entry(key).or_default();
        n.used = self.tick;
        (n, fresh)
    }

    /// The outcome of a write under `nonce` of this connection's session: a remembered one
    /// again, `OutcomeUnknown` for one at or below the highest seen and no longer remembered, else
    /// `run`'s, remembered.
    ///
    /// A nonce marked as sent again (`NONCE_RESENT`) in a session whose state this node lost is
    /// unknown too, each of them: the state may have been evicted after the first send ran.
    fn once(&mut self, db: &Osis, conn: ConnId, nonce: u64, run: impl FnOnce() -> Result<Value>) -> Result<Value> {
        let resent = nonce & super::client::NONCE_RESENT != 0;
        let nonce = nonce & !super::client::NONCE_RESENT;
        let Some(c) = self.conns.get(&conn) else { return Err(Error::Invalid("no session".into())) };
        let who = if let Tier::Client(a) = c.tier { Some(a) } else { None };
        let session = c.session;
        let (n, fresh) = self.nonces_of(db, (who, session));
        n.lost |= fresh && resent;
        if let Some(r) = n.done.get(&nonce) {
            return r.clone();
        }
        if nonce == 0 || nonce <= n.top {
            return Err(Error::OutcomeUnknown);
        }
        n.top = nonce;
        if resent && n.lost {
            return Err(Error::OutcomeUnknown);
        }
        n.lost = false;
        let r = run();
        n.done.insert(nonce, r.clone());
        while n.done.len() > WRITE_NONCES {
            n.done.pop_first();
        }
        r
    }

    fn call(&mut self, db: &Osis, conn: ConnId, m: u64, args: Vec<Value>) -> Result<Value> {
        let mut a = Args::of(args);
        let b = Value::Bool;
        let v = match m {
            method::WHOAMI => Value::List(vec![Value::Tid(db.me()), Value::Tid(db.node())]),
            method::GET => {
                let (tid, ak, path) = (a.tid()?, a.ak()?, c::path(a.next()?)?);
                let key = db.key(ak.as_str())?;
                let r = if path.0.is_empty() { db.at(tid, ak).get() } else { db.at(tid, key).path(path).get() };
                c::read_v(&r)
            }
            method::ASPECTS => Value::List(db.aspects(a.tid()?)?.iter().map(c::ak_v).collect()),
            method::KNOWS => b(db.knows(a.tid()?)?),
            method::HOLDS => b(db.holds(a.tid()?)),
            method::GROUPS_OF => c::groups_v(&db.groups_of(a.tid()?)?),
            method::ROSTER => c::roster_v(&db.roster(a.tid()?)?),
            method::ROLE_ON => c::opt(db.role_on(a.tid()?)?, c::role_v),
            method::OWNER_OF => c::opt(db.owner_of(a.tid()?)?, Value::Tid),
            method::CREATED => c::opt(db.created(a.tid()?)?, |s| c::stamp_v(&s)),
            method::CHANGED => c::opt(db.changed(a.tid()?)?, |s| c::stamp_v(&s)),
            method::WRITE => {
                let nonce = a.uint()?;
                let rest = a.rest();
                return self.once(db, conn, nonce, || Ok(c::opt(db.replay(rest)?, |x| c::committed_v(&x))));
            }
            method::COMMITS => Value::List(db.commits(&c::query(a.next()?)?)?.iter().map(c::entry_v).collect()),
            method::UNDO | method::REDO => {
                let nonce = a.uint()?;
                let scope = c::scope(a.next()?)?;
                return self.once(db, conn, nonce, || Ok(c::opt(if m == method::UNDO { db.undo(&scope)? } else { db.redo(&scope)? }, |x| c::committed_v(&x))));
            }
            method::REVERT => {
                let nonce = a.uint()?;
                let ch = c::change(a.next()?)?;
                return self.once(db, conn, nonce, || Ok(c::committed_v(&db.revert(ch)?)));
            }
            method::HISTORY => {
                let (tid, ak, from) = (a.tid()?, a.ak()?, c::from(a.next()?)?);
                let (limit, bytes) = (a.uint()?, a.uint()?);
                // the Owner's handle routes: this engine's copy would be stale
                if !db.is_local(tid) {
                    return Err(unsupported("a history of a group this node reads at another node"));
                }
                c::hist_page_v(&db.history_here(tid, &ak, from, usize::try_from(limit).unwrap_or(usize::MAX), usize::try_from(bytes).unwrap_or(usize::MAX))?)
            }
            method::STATUS => c::status_v(&db.status()?),
            method::REGISTER_SCHEMA => {
                let (file, src) = (a.text()?, a.text()?);
                // registrations are process-wide and kept: counted per node, by distinct source
                // (a client registering its schemas again on each connection costs nothing)
                let h = osis_base::hash::hash(&osis_base::cbor::encode(&Value::List(vec![Value::Str(file.clone()), Value::Str(src.clone())])));
                if !self.schemas.contains_key(&h) {
                    let total: usize = self.schemas.values().sum();
                    if total.saturating_add(src.len()) > MAX_SCHEMA_BYTES {
                        return Err(Error::TooLarge { limit: MAX_SCHEMA_BYTES });
                    }
                }
                db.register_schema(&file, &src)?;
                self.schemas.insert(h, src.len());
                Value::List(vec![])
            }
            method::LEN | method::STREAM_READ => {
                let (tid, ak, path) = (a.tid()?, a.ak()?, c::path(a.next()?)?);
                let s = db.at(tid, ak).path(path).stream()?;
                if m == method::LEN {
                    c::opt(s, |s| u(s.len()))
                } else {
                    let (off, n) = (a.uint()?, usize::try_from(a.uint()?).unwrap_or(usize::MAX).min(STREAM_CHUNK));
                    let mut s = s.ok_or(Error::Invalid("no value to stream".into()))?;
                    s.seek(SeekFrom::Start(off)).map_err(|e| Error::Storage(e.to_string()))?;
                    let mut buf = Vec::new();
                    s.take(n as u64).read_to_end(&mut buf).map_err(|e| Error::Storage(e.to_string()))?;
                    Value::Bytes(buf)
                }
            }
            method::NOW => u(db.now().0),
            method::ADD_CLIENT => {
                let until = a.opt_wall()?;
                let (actor, secret) = db.add_client(until)?;
                Value::List(vec![Value::Tid(actor), Value::bytes(secret.expose())])
            }
            method::CLIENTS => Value::List(db.clients()?.iter().map(|x| Value::List(vec![Value::Tid(x.actor), c::opt(x.until, |w| Value::uint(w.0))])).collect()),
            method::REMOVE_CLIENT => b(db.remove_client(a.tid()?)?),
            method::ROTATE_CLIENT_SECRET => Value::bytes(db.rotate_client_secret(a.tid()?)?.expose()),
            method::ROTATE_CLIENT_KEY => Value::List(db.rotate_client_key()?.iter().map(|h| Value::Str(h.to_string())).collect()),
            method::KEPT => Value::List(db.kept_copies()?.into_iter().map(Value::Tid).collect()),
            method::DROP_KEPT => {
                db.drop_kept(a.tid()?)?;
                Value::List(vec![])
            }
            method::HOSTS => Value::List(db.hosts()?.iter().map(|h| Value::Str(h.to_string())).collect()),
            method::SYNC_NOW => {
                db.sync_now()?;
                Value::List(vec![])
            }
            method::SYNC => {
                let g = a.tid()?;
                let hosts = a.list()?.into_iter().map(|h| c::Args::of(vec![h]).text()?.parse()).collect::<Result<Vec<crate::HostAddr>>>()?;
                db.sync(g, &hosts)?;
                Value::List(vec![])
            }
            method::UNSYNC => {
                db.unsync(a.tid()?)?;
                Value::List(vec![])
            }
            method::GRANT | method::CHANGE_EDGE | method::SHARE => {
                let (t, h, r, o) = (a.tid()?, a.tid()?, c::role(&a.next()?)?, c::edge_opts(a.next()?)?);
                match m {
                    method::GRANT => db.grant(t, h, r, o)?,
                    method::SHARE => db.share(t, h, r, o)?,
                    _ => db.change_edge(t, h, r, o)?,
                }
                Value::List(vec![])
            }
            method::SHARE_INTO => {
                let (t, g, r) = (a.tid()?, a.tid()?, c::role(&a.next()?)?);
                let o = crate::ShareOpts { subgroup: a.bool()?, place_anyway: a.bool()? };
                c::share_v(db.share_into(t, g, r, o)?)
            }
            method::REMOVE_EDGE_OF => {
                db.remove_edge_of(a.tid()?, a.tid()?)?;
                Value::List(vec![])
            }
            method::CREATE_OWNERLESS => Value::Tid(db.create_ownerless(a.tid()?)?),
            method::DEVICES => Value::List(db.devices()?.iter().map(|x| Value::List(vec![Value::Tid(x.node), c::role_v(x.role)])).collect()),
            method::ADD_HOST | method::REMOVE_HOST => {
                let h: crate::HostAddr = a.text()?.parse()?;
                if m == method::ADD_HOST { db.add_host(&h)? } else { db.remove_host(&h)? }
                nothing()
            }
            method::HOST_KEY => c::opt(db.host_key()?, |k| Value::bytes(&k)),
            method::PAIR_OFFER => Value::Str(db.pair_offer()?.to_string()),
            method::PAIR_ACCEPT => {
                let (node, reply) = db.pair_accept(&a.text()?.parse()?)?;
                let pad = vec![0; db.inner.port.pad_pair_reply.swap(0, Ordering::AcqRel)];
                Value::List(vec![Value::Tid(node), Value::Str(reply.to_string()), Value::Bytes(pad)])
            }
            method::CONTACT_CARD => Value::Str(db.contact_card()?.to_string()),
            method::PROFILE_OF => c::opt(db.profile_of(a.tid()?)?, Value::Tid),
            method::INVITE_REQUESTS => Value::List(db.invite_requests()?.iter().map(|i| Value::bytes(i.bytes())).collect()),
            method::ACCEPT_INVITE => {
                db.accept_invite(crate::InviteId::from_bytes(&a.bytes()?)?)?;
                nothing()
            }
            method::DECLINE_INVITE => {
                db.decline_invite(crate::InviteId::from_bytes(&a.bytes()?)?)?;
                nothing()
            }
            method::GROUP_POLICY => Value::List(c::policy_v(&db.group_policy(a.tid()?)?)),
            method::SYNC_POLICY => {
                let g = a.tid()?;
                db.sync_policy(g, c::policy(&mut a)?)?;
                nothing()
            }
            method::ROTATE_REACH => {
                db.rotate_reach()?;
                nothing()
            }
            method::EXPORT_BUNDLE => {
                let mut b = Vec::new();
                db.export_bundle(&c::tids(a.next()?)?, &mut b)?;
                let n = b.len();
                self.conns.get_mut(&conn).ok_or(Error::Closed)?.export = b;
                u(n as u64)
            }
            method::BUNDLE_READ => {
                let (off, n) = (usize::try_from(a.uint()?).unwrap_or(usize::MAX), usize::try_from(a.uint()?).unwrap_or(usize::MAX).min(STREAM_CHUNK));
                let b = &mut self.conns.get_mut(&conn).ok_or(Error::Closed)?.export;
                let end = off.saturating_add(n).min(b.len());
                let page = Value::bytes(b.get(off..end).unwrap_or_default());
                if end == b.len() {
                    *b = Vec::new();
                }
                page
            }
            method::BUNDLE_WRITE => {
                let page = a.bytes()?;
                self.conns.get_mut(&conn).ok_or(Error::Closed)?.import.extend_from_slice(&page);
                nothing()
            }
            method::IMPORT_BUNDLE => {
                let want = a.uint()?;
                let b = std::mem::take(&mut self.conns.get_mut(&conn).ok_or(Error::Closed)?.import);
                if b.len() as u64 != want {
                    return Err(Error::Network("the connection to the node changed during an import: run it again".into()));
                }
                db.import_bundle(&b[..])?;
                nothing()
            }
            method::LEAVE => {
                db.leave(a.tid()?)?;
                Value::List(vec![])
            }
            method::REACH => c::reach_v(&db.reach(a.tid()?)?),
            method::HOLDER_PATH => c::pairs_v(&db.holder_path(a.tid()?, a.tid()?)?),
            method::LINKS => c::links_v(&db.links()?),
            method::MAKE_LINK => {
                let (t, r) = (a.tid()?, c::role(&a.next()?)?);
                let until = a.opt_wall()?;
                let o = crate::LinkOpts { until, single_use: a.bool()?, direct: a.bool()? };
                Value::Str(db.make_link(t, r, o)?.to_string())
            }
            _ => return Err(unsupported(&format!("method {m}"))),
        };
        Ok(v)
    }

    /// Registers a subscription: a dispatcher registration taken atomically with its initial
    /// value (the Reply's), whose callback only marks it dirty.
    fn sub(&mut self, db: &Osis, conn: ConnId, id: Id, max_reply: usize, f: Value) -> Result<Value> {
        let c = self.conns.get(&conn).ok_or(Error::Closed)?;
        let held = c.held.clone();
        let acting = db.acting;
        let mut a = Args::new(f)?;
        // the Owner's handle routes; this subscription would watch this engine's stale copy
        let thing = |t: Tid| {
            if !db.is_local(t) {
                return Err(unsupported("a watch of a group this node reads at another node"));
            }
            Ok(t)
        };
        let (kind, filter) = match a.uint()? {
            // the sharing and sync flows take no actor (`method::for_client`)
            filter::TASK if acting.is_some() => return Err(unsupported("a row that waits, for a thin client")),
            filter::TASK => {
                let (m, args) = (a.uint()?, a.list()?);
                a.end()?;
                if c.subs.values().filter(|s| matches!(s.kind, Kind::Task(Some(_)))).count() >= MAX_WAITS {
                    return Err(Error::Invalid(format!("at most {MAX_WAITS} waits at once per connection")));
                }
                // no user handle left: nothing would end it but its own deadline
                if db.inner.life.0.users_now() == 0 {
                    return Err(Error::Closed);
                }
                let t = task(db, m, args)?;
                return Ok(self.sub_task(conn, id, max_reply, t));
            }
            filter::ASPECT => {
                let (t, ak) = (thing(a.tid()?)?, a.ak()?);
                (Kind::Aspect(t, ak.clone()), Filter::Aspect(t, ak))
            }
            filter::THING => {
                let t = thing(a.tid()?)?;
                (Kind::Thing(t), Filter::Thing(t))
            }
            filter::ROSTER => {
                let t = thing(a.tid()?)?;
                (Kind::Roster(t), Filter::Roster(t))
            }
            filter::HISTORY => {
                let (t, ak) = (thing(a.tid()?)?, a.ak()?);
                (Kind::History(t, ak.clone()), Filter::History(t, ak))
            }
            filter::STATUS => (Kind::Status, Filter::Status),
            filter::DIAGNOSTICS => (Kind::Diagnostics, Filter::Diagnostics),
            _ => return Err(c::bad("filter")),
        };
        a.end()?;
        let pending: Arc<Mutex<Pending>> = Arc::default();
        let tx = self.tx.clone();
        let p = pending.clone();
        // a fired signal or diagnostic waits within the connection's byte budget, else the
        // subscription lapses
        let held2 = held.clone();
        let queue = move |g: &mut Pending, v: Value| {
            let n = osis_base::cbor::encode(&v).len();
            if held.load(Ordering::Acquire).saturating_add(n) > SIGNAL_BYTES {
                g.lapsed = true;
            } else {
                held.fetch_add(n, Ordering::AcqRel);
                g.queue.push_back((v, n));
            }
        };
        let cb: crate::watch::Callback = Box::new(move |db, d| {
            match d {
                // a client's diagnostics: those naming only what its actor reads
                Delivery::Diagnostic(x) if acting.is_some_and(|a| x.tids.is_empty() || !db.engine(|e| x.tids.iter().all(|t| e.readable_by(&a, t)))) => return,
                // a signal of what it may not read takes none of its budget (a lapse would tell)
                Delivery::Fired { tid, .. } | Delivery::History { tid, .. } if acting.is_some_and(|a| !db.engine(|e| e.readable_by(&a, &tid))) => return,
                Delivery::Aspect { ak, source, .. } => {
                    lock(&p).aks.insert(ak, source);
                }
                // a fired signal carries a fifth item: delivered even when equal to the last
                Delivery::Fired { tid, ak, source, value } => queue(&mut lock(&p), Value::List(vec![Value::Tid(tid), c::ak_v(&ak), c::read_v(&Ok(Some(value))), c::source_v(&source), Value::Bool(true)])),
                Delivery::History { id, .. } => lock(&p).note_history(id, &held2),
                Delivery::Roster | Delivery::Status(_) => lock(&p).dirty = true,
                // this node's own source for it moved: the client's subscription ends
                Delivery::Moved => lock(&p).lapsed = true,
                Delivery::Diagnostic(x) => queue(&mut lock(&p), c::diag_v(&x)),
                _ => return,
            }
            let _ = tx.send(Job::Dirty(conn));
        });
        let mut initial = Ok(Value::List(vec![]));
        let sub = db.subscribe(filter, false, |r| {
            match &kind {
                Kind::Aspect(t, ak) => initial = Ok(c::read_v(&r.value(*t, ak))),
                Kind::Thing(t) => initial = r.aspects(*t).map(|aks| Value::List(aks.iter().map(|ak| Value::List(vec![c::ak_v(ak), c::read_v(&r.value(*t, ak))])).collect())),
                Kind::Roster(t) => initial = Ok(c::roster_v(&r.roster(*t))),
                _ => {}
            }
            cb
        });
        let mut initial = initial?;
        if let Kind::Status = kind {
            initial = c::status_v(&db.status()?);
        }
        let seen = kind.thing().is_none_or(|t| db.read_local(|r| !r.hidden(t)));
        if let Some(c) = self.conns.get_mut(&conn) {
            c.subs.insert(id, PortSub { max_reply, kind, pending, _sub: Some(sub), seen });
        }
        Ok(initial)
    }

    /// A row that waits as a subscription (notes/client-port.md §2): the node's own async call (its
    /// waiters, polled under the lock after every change as a local app's are), never blocking
    /// this worker; the Reply carries the outcome when it is known at once, else the one Notify.
    fn sub_task(&mut self, conn: ConnId, id: Id, max_reply: usize, mut t: Task) -> Value {
        let (kind, initial) = match poll_task(&self.tx, conn, id, &mut t) {
            std::task::Poll::Ready(r) => (Kind::Task(None), c::opt(Some(r), |r| c::outcome(r).to_value())),
            std::task::Poll::Pending => (Kind::Task(Some(t)), Value::List(vec![])),
        };
        if let Some(c) = self.conns.get_mut(&conn) {
            c.subs.insert(id, PortSub { max_reply, kind, pending: Arc::default(), _sub: None, seen: true });
        }
        initial
    }

    /// Sends what dirty subscriptions of `conn` have, within `budget` bytes; asks for room again
    /// while something is left; answers waiting `settle` calls once nothing is.
    fn flush(&mut self, db: &Osis, conn: ConnId, budget: usize) {
        let Some(cn) = self.conns.get_mut(&conn) else { return };
        let mut notes: Vec<(Id, Payload)> = Vec::new();
        let mut used = 0usize;
        let mut left = false;
        let mut more_history = false;
        let mut gone = Vec::new();
        for (id, s) in &mut cn.subs {
            let mut g = lock(&s.pending);
            // what its actor may read now (the module's invariant): a thing it could read and no
            // longer can ends the subscription; nothing of one it cannot read is sent, its lapse
            // neither (a move's would tell the thing is there)
            if let (Some(_), Some(t)) = (db.acting, s.kind.thing()) {
                if db.read_local(|r| r.hidden(t)) {
                    if s.seen {
                        notes.push((*id, Payload::Lapsed));
                        gone.push(*id);
                    } else {
                        g.clear(&cn.held);
                    }
                    continue;
                }
                s.seen = true;
            }
            if g.lapsed {
                notes.push((*id, Payload::Lapsed));
                gone.push(*id);
                continue;
            }
            let out = due(db, &s.kind, &g);
            let queued = g.queue.len();
            let mut sent = 0;
            for (v, src) in &out {
                let (p, size) = fit(*id, s.max_reply, v, src);
                let lapse = p == Payload::Lapsed;
                if used.saturating_add(size) > budget && !notes.is_empty() {
                    left = true;
                    break;
                }
                used = used.saturating_add(size);
                notes.push((*id, p));
                sent += 1;
                if lapse {
                    gone.push(*id);
                    break;
                }
            }
            // drop what went
            for _ in 0..sent.min(queued) {
                if let Some((_, n)) = g.queue.pop_front() {
                    cn.held.fetch_sub(n, Ordering::AcqRel);
                }
            }
            if let Kind::History(..) = s.kind {
                for _ in 0..sent.saturating_sub(queued) {
                    if g.history.pop_first().is_some() {
                        cn.held.fetch_sub(HISTORY_DIRTY_BYTES, Ordering::AcqRel);
                    }
                }
                // read at the next send: no reason to hold back the other subscriptions now
                more_history |= !g.history.is_empty();
            }
            if sent == out.len() {
                g.dirty = false;
                g.aks.clear();
            } else if sent > queued {
                let done: Vec<Ak> = g.aks.keys().take(sent - queued).cloned().collect();
                for ak in done {
                    g.aks.remove(&ak);
                }
            }
            if left {
                break;
            }
        }
        for id in gone {
            cn.end_sub(id);
        }
        left |= more_history;
        let settles = if left { Vec::new() } else { std::mem::take(&mut cn.settles) };
        if !notes.is_empty() {
            self.feed(db, Event::Notify { conn, notes });
        }
        if left {
            self.want_room(db, conn);
        }
        for id in settles {
            self.reply(db, conn, id, Ok(Outcome::Ok { value: Value::List(vec![]) }));
        }
    }
}

/// What a subscription would send now, oldest first: queued deliveries, then what changed
/// (a value, with its source when it has one), read now.
fn due(db: &Osis, kind: &Kind, g: &Pending) -> Vec<(Value, Option<crate::watch::Source>)> {
    let mut out: Vec<_> = g.queue.iter().map(|(v, _)| (v.clone(), None)).collect();
    match kind {
        Kind::Aspect(t, _) | Kind::Thing(t) => {
            for (ak, src) in &g.aks {
                let v = Value::List(vec![Value::Tid(*t), c::ak_v(ak), c::read_v(&db.read_local(|r| r.value(*t, ak))), c::source_v(src)]);
                out.push((v, Some(*src)));
            }
        }
        Kind::History(t, ak) => {
            for id in g.history.iter().take(HISTORY_SEND) {
                let Ok(e) = db.history_entry_here(*t, ak, id) else { continue };
                out.push((Value::List(vec![c::change_v(id), c::opt(e.as_ref(), c::hist_entry_v)]), None));
            }
        }
        Kind::Roster(t) if g.dirty => out.push((c::roster_v(&db.read_local(|r| r.roster(*t))), None)),
        Kind::Status if g.dirty => {
            if let Ok(st) = db.status() {
                out.push((c::status_v(&st), None));
            }
        }
        _ => {}
    }
    out
}

/// A delivery as the Notify payload that fits `max_reply`, with its message's size.
fn fit(id: Id, max_reply: usize, v: &Value, src: &Option<crate::watch::Source>) -> (Payload, usize) {
    let size_of = |p: &Payload| Message::Notify { sub: id, payload: p.clone() }.encode().len();
    let p = Payload::Delivery { value: v.clone() };
    let size = size_of(&p);
    if size <= max_reply {
        return (p, size);
    }
    // above the subscription's bound: what changed, read by path or stream
    let p = Payload::TooLarge { source: c::source_v(&src.unwrap_or(crate::watch::Source::Initial)) };
    let size = size_of(&p);
    if size <= max_reply {
        return (p, size);
    }
    // not even that fits: the subscription ends here as proto would end it (`Lapsed`), so it is
    // never live at one side only
    (Payload::Lapsed, size_of(&Payload::Lapsed))
}
