//! The serving side of the client port (notes/client-port.md §2): requests the sync engine hands
//! out (`Action::Request`) are queued under the handle lock and run after it is released on one
//! worker thread, one at a time, each as ordinary `Osis` calls (one engine transaction each);
//! replies and Notify payloads are encoded there, never under the lock. Subscriptions are
//! ordinary dispatcher registrations whose callbacks only set dirty flags (and queue fired
//! ephemeral signals' entries and diagnostics within `PUSH_BYTES`); the worker materializes dirty subscriptions
//! when push room opens (`Action::Room`). Writes carry a nonce: outcomes are kept per (tier
//! identity, session), so a retry is answered once.
//!
//! **Invariant** (notes/client-port.md §3): every row of a thin client's session runs on a handle
//! acting as that client's actor, never as this node's account, and that client's authority ends
//! at revocation. `Worker::session` is the only way to a row or a send of a client session:
//! it asks the sync engine whether the session's client is live (its `clients^.0` entry there,
//! under the same secret, before its `until`) at that moment, not when the request was queued,
//! and hands out `Osis::act_as` of its actor, whose every read and write the rights of that actor
//! decide at that moment (`Reader::hidden`, `Mutation::confine`). There is no cached scope or
//! role to go stale; a call that passed `session` just before a revocation is ordered before it.

use super::codec::{self as c, Args, outcome_err, u};
use super::{COMMIT_DIRTY_BYTES, COMMIT_SEND, MAX_SCHEMA_BYTES, MAX_WAITS, PUSH_BYTES, STREAM_CHUNK, WRITE_NONCES, filter, method};
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
    /// The node's last user handle went: running tasks end, so they do not keep it open.
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

/// The port of one node: the jobs queued under the lock, the worker.
pub(crate) struct Port {
    /// A test's way to reach `Worker::panicked`: no client input is known to.
    pub panic_next: std::sync::atomic::AtomicBool,
    /// Likewise after a Call ran, before its reply: the reply is lost, the write stays applied.
    pub panic_after_call: std::sync::atomic::AtomicBool,
    /// A test's way to a pairing reply above the small allowance: bytes added to the next.
    pub pad_pair_reply: AtomicUsize,
    /// A test's way into the gap between a write's source decision and its lock.
    pub after_source: Mutex<Option<Box<dyn Fn() + Send>>>,
    queued: Mutex<Vec<Job>>,
    tx: Mutex<Option<Sender<Job>>>,
}

impl Port {
    pub fn new() -> Port {
        Port { panic_next: false.into(), panic_after_call: false.into(), pad_pair_reply: AtomicUsize::new(0), after_source: Mutex::new(None), queued: Mutex::new(Vec::new()), tx: Mutex::new(None) }
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

    /// The last user handle went: a running task holds the node, which must close.
    pub fn closing(&self) {
        if let Some(t) = lock(&self.tx).as_ref() {
            let _ = t.send(Job::Closing);
        }
    }
}

/// What a subscription callback leaves for the worker (shared with the dispatcher).
#[derive(Default)]
struct Pending {
    /// The grants or status changed since the last Notify.
    dirty: bool,
    /// Aspect or thing subscription: aspects changed, with their newest source.
    aks: BTreeMap<Ak, crate::watch::Origin>,
    /// Fired ephemeral signals' commits and diagnostics, never coalesced, each with its bytes.
    queue: VecDeque<(Value, usize)>,
    /// Commit subscription: the commits that may read otherwise (`COMMIT_DIRTY_BYTES` each).
    commits: BTreeSet<crate::CommitId>,
    /// A delivery did not fit `PUSH_BYTES`: the subscription ends.
    lapsed: bool,
}

impl Pending {
    /// Commit `id` may read otherwise. Past the connection's budget the subscription lapses: the
    /// client reads its pages again.
    fn note_commit(&mut self, id: crate::CommitId, held: &AtomicUsize) {
        if self.commits.contains(&id) {
            return;
        }
        if held.load(Ordering::Acquire).saturating_add(COMMIT_DIRTY_BYTES) > PUSH_BYTES {
            self.lapsed = true;
        } else {
            held.fetch_add(COMMIT_DIRTY_BYTES, Ordering::AcqRel);
            self.commits.insert(id);
        }
    }

    /// Forgets all of it, giving its queued bytes back to the connection's `held`.
    fn clear(&mut self, held: &AtomicUsize) {
        for (_, n) in self.queue.drain(..) {
            held.fetch_sub(n, Ordering::AcqRel);
        }
        held.fetch_sub(self.commits.len() * COMMIT_DIRTY_BYTES, Ordering::AcqRel);
        self.commits.clear();
        self.dirty = false;
        self.aks.clear();
    }
}

/// A row that waits, polled on the worker: it holds the node, so `Job::Closing` ends it.
type Task = std::pin::Pin<Box<dyn Future<Output = Result<Value>>>>;

/// A value watch's last value read for the client, set under the engine lock as it is read: a
/// change the dispatcher reads equal to it sends nothing. (Compared with what the dispatcher last
/// read instead, a send reading a newer value than the dispatcher saw, then a change back, would
/// leave the client on the newer one.)
type Sent = Arc<Mutex<Option<Option<crate::watch::Digest>>>>;

enum Kind {
    /// A value at a path inside an aspect, how it reads (`value_read`), and what the client
    /// was last sent (or the initial reply carried).
    Aspect(Tid, crate::watch::ReadAt, Sent),
    Thing(Tid),
    Grants(Tid),
    Commits(crate::commits::Address),
    /// A page of a thing's backlinks: what its actor may read of them, whoever may read the thing;
    /// the digest of the page the client was last sent. A wake that reads the same page sends
    /// nothing: a wake may come from what the actor may not read (a hidden source's reference, any
    /// roster change), and a Notify would tell it.
    Backlinks(Tid, crate::BacklinkQuery, Option<crate::watch::Digest>),
    Status,
    Diagnostics,
    /// A row that waits (`filter::TASK`), until its outcome went.
    Task(Option<Task>),
}

impl Kind {
    /// The thing it watches.
    fn thing(&self) -> Option<Tid> {
        match self {
            Kind::Aspect(t, ..) | Kind::Thing(t) | Kind::Grants(t) => Some(*t),
            Kind::Commits(a) => a.things().first().copied(),
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
    /// Bytes of queued pushes over all its subscriptions (`PUSH_BYTES`).
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

/// Whose write outcomes: the main actor's, or a client actor's (a session id of one identity never
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

/// Starts a row that waits (`filter::TASK`), a main-actor. Each runs as the node's own async call,
/// polled when its waker fires.
fn task(db: &Osis, m: u64, args: Vec<Value>) -> Result<Task> {
    let mut a = Args::of(args);
    let db = Osis::internal(db.inner.clone());
    let t: Task = match m {
        method::WAIT_SYNCED => {
            let scope = c::sync_scope(a.next()?)?;
            a.end()?;
            let p = db.wait_synced_pending(scope);
            Box::pin(async move { p.await.map(|()| nothing()) })
        }
        method::REDEEM => {
            let link: crate::ShareLink = a.text()?.parse()?;
            a.end()?;
            Box::pin(async move { Ok(Value::Tid(db.redeem(&link).await?)) })
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
    /// Runs a job; `false` once the node is gone.
    fn job(&mut self, j: Job) -> bool {
        let Some(db) = self.db.hold() else { return false };
        assert!(!db.inner.port.panic_next.swap(false, Ordering::AcqRel), "port worker: test panic");
        match j {
            Job::Act(Action::Request { conn, tier, msg }) => self.request(&db, conn, tier, *msg),
            Job::Act(Action::Room { conn, budget }) => {
                if let Some(c) = self.conns.get_mut(&conn) {
                    c.asked = false;
                }
                match self.session(&db, conn) {
                    Some(h) => self.flush(&h, conn, budget),
                    // the room goes back unused (node sync shares it with the stream)
                    None => self.feed(&db, Event::Notify { conn, notes: Vec::new() }),
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

    /// Ends the running tasks, each told: nobody is left to close a node they would hold.
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
    /// main actor's as it is, a client's acting as its actor while it is live. A client no longer live
    /// is ended here; `None` then, as for a session this worker does not hold.
    fn session(&mut self, db: &Osis, conn: ConnId) -> Option<Osis> {
        match self.conns.get(&conn)?.tier {
            Tier::Main => Some(Osis::internal(db.inner.clone())),
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
            method::WHOAMI => Value::List(vec![Value::Tid(db.me()), Value::Tid(db.node()), Value::Tid(db.home())]),
            method::GET => {
                let (tid, ak, path) = (a.tid()?, a.ak()?, c::path(a.next()?)?);
                let key = db.aspect_key(ak.as_str())?;
                let r = if path.0.is_empty() { db.at(tid, crate::DynamicAspectKey::untyped(ak)).get() } else { db.at(tid, key).path(path).get() };
                c::read_v(&r)
            }
            method::ASPECTS => Value::List(db.aspects(a.tid()?)?.iter().map(c::ak_v).collect()),
            method::HAS_CONTENT => b(db.has_content(a.tid()?)?),
            method::HOLDS => b(db.holds(a.tid()?)),
            method::GROUPS_OF => c::groups_v(&db.groups_of(a.tid()?)?),
            method::GRANTS => c::grants_v(&db.grants(a.tid()?)?),
            method::ROLE_ON => c::opt(db.role_on(a.tid()?)?, c::role_v),
            method::CREATED => c::opt(db.created(a.tid()?)?, |s| c::thing_stamp_v(&s)),
            method::CHANGED => c::opt(db.changed(a.tid()?)?, |s| c::thing_stamp_v(&s)),
            method::WRITE => {
                let nonce = a.uint()?;
                let rest = a.rest();
                return self.once(db, conn, nonce, || Ok(c::opt(db.replay(rest)?, |x| c::commit_v(&x))));
            }
            method::UNDO_TARGET => c::opt(db.undo_target(&c::scope(a.next()?)?)?.as_ref(), c::commit_v),
            method::REDO_TARGET => c::opt(db.redo_target(&c::scope(a.next()?)?)?.as_ref(), c::commit_v),
            method::UNDO | method::REDO => {
                let nonce = a.uint()?;
                let scope = c::scope(a.next()?)?;
                return self.once(db, conn, nonce, || Ok(c::opt(if m == method::UNDO { db.undo(&scope)? } else { db.redo(&scope)? }, |x| c::commit_v(&x))));
            }
            method::REVERT => {
                let nonce = a.uint()?;
                let ch = c::commit_id(a.next()?)?;
                return self.once(db, conn, nonce, || Ok(c::commit_v(&db.revert(ch)?)));
            }
            method::LISTING => {
                let (at, q, bytes) = (c::address(a.next()?)?, c::query(a.next()?)?, a.uint()?);
                // the main actor's handle routes: this engine's copy would be stale
                if at.things().iter().any(|t| !db.is_local(*t)) {
                    return Err(unsupported("commits of a group this node reads at another node"));
                }
                c::page_v(&db.listing_here(&at, &q, usize::try_from(bytes).unwrap_or(usize::MAX))?)
            }
            method::LISTED_COMMIT => {
                let (at, id) = (c::address(a.next()?)?, c::commit_id(a.next()?)?);
                if at.things().iter().any(|t| !db.is_local(*t)) {
                    return Err(unsupported("commits of a group this node reads at another node"));
                }
                c::opt(db.commit_told_here(&at, id, None)?.as_ref(), c::commit_v)
            }
            method::BACKLINKS => {
                let (t, q) = (a.tid()?, c::backlink_query(a.next()?)?);
                c::backlink_page_v(&db.backlinks(t, &q)?)
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
            method::BYTE_LEN | method::STREAM_READ => {
                let (tid, ak, path) = (a.tid()?, a.ak()?, c::path(a.next()?)?);
                let s = db.at(tid, crate::DynamicAspectKey::untyped(ak)).path(path).stream()?;
                if m == method::BYTE_LEN {
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
            method::NOW => u(db.now()?.0),
            method::ADD_CLIENT => {
                let until = a.opt_wall()?;
                let (actor, secret) = db.add_client(until)?;
                Value::List(vec![Value::Tid(actor), Value::bytes(secret.expose())])
            }
            method::CLIENTS => Value::List(db.clients()?.iter().map(|x| Value::List(vec![Value::Tid(x.actor), c::opt(x.until, |w| Value::uint(w.0))])).collect()),
            method::REMOVE_CLIENT => b(db.remove_client(a.tid()?)?),
            method::ROTATE_CLIENT_SECRET => Value::bytes(db.rotate_client_secret(a.tid()?)?.expose()),
            method::RETAINED_COPIES => Value::List(db.retained_copies()?.into_iter().map(Value::Tid).collect()),
            method::DROP_RETAINED_COPY => {
                db.drop_retained_copy(a.tid()?)?;
                Value::List(vec![])
            }
            method::SAVED_PEERS => Value::List(db.saved_peers()?.iter().map(|h| Value::Str(h.to_string())).collect()),
            method::PEERS => Value::List(db.peers(a.tid()?)?.iter().map(|h| Value::Str(h.to_string())).collect()),
            method::NUDGE_SYNC => {
                db.nudge_sync()?;
                Value::List(vec![])
            }
            method::SYNC => {
                let g = a.tid()?;
                let hosts = a.list()?.into_iter().map(|h| c::Args::of(vec![h]).text()?.parse()).collect::<Result<Vec<crate::Address>>>()?;
                db.sync(g, &hosts)?;
                Value::List(vec![])
            }
            method::GRANT => {
                db.grant(a.tid()?, a.tid()?, c::role(&a.next()?)?, c::grant_opts(a.next()?)?)?;
                Value::List(vec![])
            }
            method::REVOKE_LINK => {
                db.revoke_link(crate::share::LinkId(a.tid()?))?;
                Value::List(vec![])
            }
            method::SET_ROLE => {
                let (target, holder) = (a.tid()?, a.tid()?);
                let role = a.opt()?.map(|r| c::role(&r)).transpose()?;
                db.set_role(target, holder, role, c::set_role(a.next()?)?)?;
                Value::List(vec![])
            }
            method::ADD_WITH_GRANT => {
                db.add_with_grant(c::member(a.next()?)?, a.tid()?, c::role(&a.next()?)?)?;
                Value::List(vec![])
            }
            method::NODES => Value::List(db.nodes()?.iter().map(|x| Value::List(vec![Value::Tid(x.node), c::role_v(x.role)])).collect()),
            method::ADD_PEER | method::REMOVE_PEER => {
                let h: crate::Address = a.text()?.parse()?;
                if m == method::ADD_PEER { db.add_peer(&h)? } else { db.remove_peer(&h)? }
                nothing()
            }
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
            method::SYNC_IDS => Value::List(db.sync_ids(a.tid()?)?.iter().map(|x| Value::Str(x.to_string())).collect()),
            method::ROTATE_PEER_ADDRESS => {
                db.rotate_peer_address()?;
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
                db.leave(a.tid()?, a.tid()?)?;
                Value::List(vec![])
            }
            method::HOLDERS => c::holders_v(&db.holders(a.tid()?)?),
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
        // the main actor's handle routes; this subscription would watch this engine's stale copy
        let thing = |t: Tid| {
            if !db.is_local(t) {
                return Err(unsupported("a watch of a group this node reads at another node"));
            }
            Ok(t)
        };
        let (mut kind, filter) = match a.uint()? {
            // the sharing and sync flows take no actor (`method::for_client`)
            filter::TASK if acting.is_some() => return Err(unsupported("a row that waits, for a thin client")),
            filter::TASK => {
                let (m, args) = (a.uint()?, a.list()?);
                a.end()?;
                if c.subs.values().filter(|s| matches!(s.kind, Kind::Task(Some(_)))).count() >= MAX_WAITS {
                    return Err(Error::Invalid(format!("at most {MAX_WAITS} waits at once per connection")));
                }
                // no user handle left: nothing would tell it (`closing`) and it holds the node open
                if db.inner.life.0.users_now() == 0 {
                    return Err(Error::Closed);
                }
                let t = task(db, m, args)?;
                return Ok(self.sub_task(conn, id, max_reply, t));
            }
            filter::ASPECT => {
                let (t, ak, path) = (thing(a.tid()?)?, a.ak()?, c::path(a.next()?)?);
                let read = value_read(db, t, &ak, path)?;
                (Kind::Aspect(t, read.clone(), Sent::default()), Filter::Aspect(t, ak, read))
            }
            filter::THING => {
                let t = thing(a.tid()?)?;
                (Kind::Thing(t), Filter::Thing(t))
            }
            filter::GRANTS => {
                let t = thing(a.tid()?)?;
                (Kind::Grants(t), Filter::Grants(t))
            }
            filter::COMMITS => {
                let at = c::address(a.next()?)?;
                // a fire's versions change as the fire does: `on_fire` hears them
                if matches!(at, crate::commits::Address::Versions(..)) {
                    return Err(c::bad("filter"));
                }
                for t in at.things() {
                    thing(t)?;
                }
                (Kind::Commits(at.clone()), Filter::Commits(at))
            }
            filter::BACKLINKS => {
                let (t, q) = (thing(a.tid()?)?, c::backlink_query(a.next()?)?);
                (Kind::Backlinks(t, q, None), Filter::Due(crate::watch::Watch::Backlinks(t, acting.is_some())))
            }
            filter::STATUS => (Kind::Status, Filter::Status),
            filter::DIAGNOSTICS => (Kind::Diagnostics, Filter::Diagnostics),
            _ => return Err(c::bad("filter")),
        };
        a.end()?;
        let pending: Arc<Mutex<Pending>> = Arc::default();
        let tx = self.tx.clone();
        let p = pending.clone();
        // a fired signal's commit or a diagnostic waits within the connection's byte budget, else
        // the subscription lapses
        let held2 = held.clone();
        let queue = move |g: &mut Pending, v: Value| {
            let n = osis_base::cbor::encode(&v).len();
            if held.load(Ordering::Acquire).saturating_add(n) > PUSH_BYTES {
                g.lapsed = true;
            } else {
                held.fetch_add(n, Ordering::AcqRel);
                g.queue.push_back((v, n));
            }
        };
        let at = match &kind {
            Kind::Commits(a) => Some(a.clone()),
            _ => None,
        };
        // a value watch: a change that leaves what the client has equal sends nothing
        let sent = match &kind {
            Kind::Aspect(_, _, sent) => Some(sent.clone()),
            _ => None,
        };
        let cb: crate::watch::Callback = Box::new(move |db, d| {
            match d {
                // a client's diagnostics: those naming only what its actor reads
                Delivery::Diagnostic(x) if acting.is_some_and(|a| x.tids.is_empty() || !db.engine(|e| x.tids.iter().all(|t| e.readable_by(&a, t)))) => return,
                // a signal of what it may not read takes none of its budget (a lapse would tell)
                Delivery::Commit { tids, .. } if acting.is_some_and(|a| !db.engine(|e| tids.iter().any(|t| e.readable_by(&a, t)))) => return,
                Delivery::Aspect { ak, origin, value, .. } => {
                    if value.is_ok() && sent.as_ref().is_some_and(|s| *lock(s) == Some(crate::watch::digest(&value))) {
                        return;
                    }
                    lock(&p).aks.insert(ak, origin);
                }
                // a fired ephemeral signal is held by nobody: it goes as it arrived
                Delivery::Commit { id, fired: Some(row), .. } => {
                    let Some(at) = &at else { return };
                    let told = match acting {
                        Some(x) => db.act_as(x).commit_told_here(at, id, Some(row)),
                        None => db.commit_told_here(at, id, Some(row)),
                    };
                    let Ok(Some(e)) = told else { return };
                    queue(&mut lock(&p), Value::List(vec![c::commit_id_v(&id), c::opt(Some(&e), c::commit_v)]))
                }
                Delivery::Commit { id, fired: None, .. } => lock(&p).note_commit(id, &held2),
                Delivery::Grants | Delivery::Status(_) | Delivery::Due => lock(&p).dirty = true,
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
                Kind::Aspect(_, read, sent) => {
                    let v = read.0(r);
                    initial = Ok(c::read_v(&v));
                    *lock(sent) = Some(crate::watch::digest(&v));
                }
                Kind::Thing(t) => initial = r.aspects(*t).map(|aks| Value::List(aks.iter().map(|ak| Value::List(vec![c::ak_v(ak), c::read_v(&r.value(*t, ak))])).collect())),
                Kind::Grants(t) => initial = Ok(c::grants_v(&r.grants(*t))),
                Kind::Backlinks(t, q, _) => {
                    r.e.watch_references();
                    initial = r.backlinks(*t, q).map(|p| c::backlink_page_v(&p));
                }
                _ => {}
            }
            cb
        });
        let mut initial = initial?;
        if let Kind::Backlinks(_, _, sent) = &mut kind {
            *sent = Some(page_digest(&initial));
        }
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
        let Some(cn) = self.conns.get_mut(&conn) else {
            self.feed(db, Event::Notify { conn, notes: Vec::new() });
            return;
        };
        let mut notes: Vec<(Id, Payload)> = Vec::new();
        let mut used = 0usize;
        let mut left = false;
        let mut more_commits = false;
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
            if let Kind::Commits(..) = s.kind {
                for _ in 0..sent.saturating_sub(queued) {
                    if g.commits.pop_first().is_some() {
                        cn.held.fetch_sub(COMMIT_DIRTY_BYTES, Ordering::AcqRel);
                    }
                }
                // read at the next send: no reason to hold back the other subscriptions now
                more_commits |= !g.commits.is_empty();
            }
            if let (Kind::Backlinks(_, _, last), Some((v, _))) = (&mut s.kind, out.last())
                && sent == out.len()
            {
                *last = Some(page_digest(v));
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
        left |= more_commits;
        let settles = if left { Vec::new() } else { std::mem::take(&mut cn.settles) };
        // even none: it gives the room back
        self.feed(db, Event::Notify { conn, notes });
        if left {
            self.want_room(db, conn);
        }
        for id in settles {
            self.reply(db, conn, id, Ok(Outcome::Ok { value: Value::List(vec![]) }));
        }
    }
}

/// How a value watch at `path` of `t`'s `ak` reads, as `method::GET` does: the whole aspect
/// untyped, a path through the schema this node has for `ak`.
fn value_read(db: &Osis, t: Tid, ak: &Ak, path: osis_schema::Path) -> Result<crate::watch::ReadAt> {
    if path.0.is_empty() {
        let ak = ak.clone();
        return Ok(crate::watch::ReadAt::new(move |r| r.value(t, &ak)));
    }
    let key = db.aspect_key(ak.as_str())?;
    if let (Some(s), Some(ty)) = (osis_schema::RawKey::schema(&key), osis_schema::RawKey::ty(&key)) {
        osis_schema::type_at(s, ty, &path)?;
    }
    Ok(crate::watch::ReadAt::new(move |r| r.get_path(t, &key, &path)))
}

/// A sent backlinks page's digest (`Kind::Backlinks`).
fn page_digest(v: &Value) -> crate::watch::Digest {
    *blake3::hash(&osis_base::cbor::encode(v)).as_bytes()
}

/// What a subscription would send now, oldest first: queued deliveries, then what changed
/// (a value, with its source when it has one), read now.
fn due(db: &Osis, kind: &Kind, g: &Pending) -> Vec<(Value, Option<crate::watch::Origin>)> {
    let mut out: Vec<_> = g.queue.iter().map(|(v, _)| (v.clone(), None)).collect();
    match kind {
        Kind::Aspect(t, read, sent) => {
            for (ak, src) in &g.aks {
                let now = db.read_local(|r| {
                    let v = read.0(r);
                    *lock(sent) = Some(crate::watch::digest(&v));
                    v
                });
                let v = Value::List(vec![Value::Tid(*t), c::ak_v(ak), c::read_v(&now), c::origin_v(src)]);
                out.push((v, Some(*src)));
            }
        }
        Kind::Thing(t) => {
            for (ak, src) in &g.aks {
                let v = Value::List(vec![Value::Tid(*t), c::ak_v(ak), c::read_v(&db.read_local(|r| r.value(*t, ak))), c::origin_v(src)]);
                out.push((v, Some(*src)));
            }
        }
        Kind::Commits(at) => {
            for id in g.commits.iter().take(COMMIT_SEND) {
                let Ok(e) = db.commit_told_here(at, *id, None) else { continue };
                out.push((Value::List(vec![c::commit_id_v(id), c::opt(e.as_ref(), c::commit_v)]), None));
            }
        }
        Kind::Grants(t) if g.dirty => out.push((c::grants_v(&db.read_local(|r| r.grants(*t))), None)),
        // a page that cannot be read now goes at the next change
        Kind::Backlinks(t, q, sent) if g.dirty => {
            if let Ok(p) = db.read_local(|r| r.backlinks(*t, q)) {
                let v = c::backlink_page_v(&p);
                if *sent != Some(page_digest(&v)) {
                    out.push((v, None));
                }
            }
        }
        Kind::Status if g.dirty => {
            // a store that cannot answer: the client hears something changed and asks for itself
            out.push((db.status().map_or_else(|_| Value::List(vec![]), |st| c::status_v(&st)), None));
        }
        _ => {}
    }
    out
}

/// A delivery as the Notify payload that fits `max_reply`, with its message's size.
fn fit(id: Id, max_reply: usize, v: &Value, src: &Option<crate::watch::Origin>) -> (Payload, usize) {
    let size_of = |p: &Payload| Message::Notify { sub: id, payload: p.clone() }.encode().len();
    let p = Payload::Delivery { value: v.clone() };
    let size = size_of(&p);
    if size <= max_reply {
        return (p, size);
    }
    // above the subscription's bound: what changed, read by path or stream
    let p = Payload::TooLarge { source: c::origin_v(&src.unwrap_or(crate::watch::Origin::Initial)) };
    let size = size_of(&p);
    if size <= max_reply {
        return (p, size);
    }
    // not even that fits: the subscription ends here as proto would end it (`Lapsed`), so it is
    // never live at one side only
    (Payload::Lapsed, size_of(&Payload::Lapsed))
}
