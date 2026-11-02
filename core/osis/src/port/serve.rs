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
use super::{MAX_SCHEMA_BYTES, MAX_WAITS, SIGNAL_BYTES, STREAM_CHUNK, WRITE_NONCES, filter, method};
use osis_node::sync::MAX_CONNS_PER_CLIENT;
use crate::error::{Error, Result};
use crate::handle::{Inner, Osis, WeakOsis};
use crate::watch::{Delivery, Filter, Subscription, lock};
use osis_base::{Ak, Tid, Value};
use osis_node::sync::{Action, ConnId, Event, Tier};
use osis_proto::msg::Id;
use osis_proto::{Code, Message, Outcome, Payload};
use std::collections::{BTreeMap, VecDeque};
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
    /// A `wait_synced` subscription's outcome may be known.
    Woke(ConnId, Id),
}

impl Job {
    /// The connection whose job this is.
    fn conn(&self) -> Option<ConnId> {
        match self {
            Job::Act(Action::Request { conn, .. } | Action::Room { conn, .. } | Action::Ended { conn }) => Some(*conn),
            Job::Act(_) => None,
            Job::Dirty(c) | Job::Woke(c, _) => Some(*c),
        }
    }
}

/// Wakes the worker for a `wait_synced` subscription (from under the handle lock: only a send).
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
    /// A test's way into the gap between a write's route and its lock.
    pub after_route: Mutex<Option<Box<dyn Fn() + Send>>>,
    queued: Mutex<Vec<Job>>,
    tx: Mutex<Option<Sender<Job>>>,
}

impl Port {
    pub fn new() -> Port {
        Port { panic_next: false.into(), panic_after_call: false.into(), after_route: Mutex::new(None), queued: Mutex::new(Vec::new()), tx: Mutex::new(None) }
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
}

/// What a subscription callback leaves for the worker (shared with the dispatcher).
#[derive(Default)]
struct Pending {
    /// The value (aspect sub), roster or status changed since the last Notify: with the source
    /// of the newest change.
    dirty: Option<crate::watch::Source>,
    /// Thing subscription: aspects changed, with their newest source.
    aks: BTreeMap<Ak, crate::watch::Source>,
    /// Fired signals and diagnostics, never coalesced, each with its bytes.
    queue: VecDeque<(Value, usize)>,
    /// A delivery did not fit `SIGNAL_BYTES`: the subscription ends.
    lapsed: bool,
}

enum Kind {
    Aspect(Tid, Ak),
    Thing(Tid),
    Roster(Tid),
    Status,
    Diagnostics,
    /// One `wait_synced` at this node, until its outcome went.
    Synced(Option<crate::net::Pending<Result<()>>>),
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
    session: Option<[u8; 16]>,
    subs: BTreeMap<Id, PortSub>,
    /// Bytes of queued signals and diagnostics over all its subscriptions.
    held: Arc<AtomicUsize>,
    /// Room was asked for and not yet given.
    asked: bool,
    /// `settle` calls answered once nothing is left to send.
    settles: Vec<Id>,
}

/// Whose write outcomes: the Owner's, or a client actor's (a session id of one identity never
/// reads another's).
type Identity = Option<Tid>;

/// Write outcomes of one session: by nonce (at most `WRITE_NONCES`), the highest seen, and
/// when it was last used (least recently used sessions go first).
#[derive(Default)]
struct Nonces {
    done: BTreeMap<u64, Outcome>,
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

    /// Polls a `wait_synced` subscription's outcome; once known, it is queued as the
    /// subscription's one Notify.
    fn woke(&mut self, db: &Osis, conn: ConnId, id: Id) {
        let tx = self.tx.clone();
        let Some(s) = self.conns.get_mut(&conn).and_then(|c| c.subs.get_mut(&id)) else { return };
        let Kind::Synced(Some(p)) = &mut s.kind else { return };
        let waker = std::task::Waker::from(Arc::new(Wake { tx, conn, id }));
        let std::task::Poll::Ready(r) = std::pin::Pin::new(p).poll(&mut std::task::Context::from_waker(&waker)) else { return };
        s.kind = Kind::Synced(None);
        lock(&s.pending).queue.push_back((Value::List(vec![c::done_v(&r)]), 0));
        self.want_room(db, conn);
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
                // the sync engine sends up only an Owner's Auth and a client's it matched
                if tier == Tier::Keyed {
                    return self.reply(db, conn, id, Err(Code::REFUSED));
                }
                let c = self.conns.entry(conn).or_insert_with(|| Conn { tier, session: None, subs: BTreeMap::new(), held: Arc::default(), asked: false, settles: Vec::new() });
                c.session = Some(session);
                if self.session(db, conn).is_none() {
                    return self.reply(db, conn, id, Err(Code::REFUSED));
                }
                let seq = db.locked(|l| l.seq);
                self.reply(db, conn, id, Ok(Outcome::Ok { seq, value: Value::List(vec![]) }));
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
                let seq = db.locked(|l| l.seq);
                let out = match r {
                    Ok(value) => Outcome::Ok { seq, value },
                    Err(e) => outcome_err(&e),
                };
                self.reply(db, conn, id, Ok(out));
            }
            Message::Sub { id, max_reply, filter } => {
                let Some(h) = self.session(db, conn) else { return self.reply(db, conn, id, Err(Code::REFUSED)) };
                let db = &h;
                let max = usize::try_from(max_reply).unwrap_or(usize::MAX);
                let r = self.sub(db, conn, id, max, filter);
                let seq = db.locked(|l| l.seq);
                let mut out = match r {
                    Ok(value) => Outcome::Ok { seq, value },
                    Err(e) => outcome_err(&e),
                };
                // an initial value above max_reply ends the subscription here as in proto, which
                // answers it TooLarge and frees the id (`MAX_SUBS` counts live ones only)
                if (Message::Reply { id, outcome: out.clone() }).encode().len() > max {
                    if let Some(c) = self.conns.get_mut(&conn) {
                        c.subs.remove(&id);
                    }
                    out = Outcome::too_large(max);
                }
                self.reply(db, conn, id, Ok(out));
            }
            Message::Unsub { sub, .. } => {
                if let Some(c) = self.conns.get_mut(&conn) {
                    c.subs.remove(&sub);
                }
            }
            _ => {}
        }
    }

    /// The outcome of a write under `nonce` of this connection's session: a remembered one
    /// again, `OutcomeUnknown` for one at or below the highest seen and no longer remembered, else
    /// `run`'s, remembered.
    ///
    /// A nonce marked as sent again (`NONCE_RESENT`) in a session whose state this node lost is
    /// unknown too, each of them: the state may have been evicted after the first send ran.
    fn once(&mut self, conn: ConnId, nonce: u64, run: impl FnOnce() -> Result<Value>) -> Result<Value> {
        let resent = nonce & super::client::NONCE_RESENT != 0;
        let nonce = nonce & !super::client::NONCE_RESENT;
        let Some((who, session)) = self.conns.get(&conn).and_then(|c| Some((if let Tier::Client(a) = c.tier { Some(a) } else { None }, c.session?))) else { return Err(Error::Invalid("no session".into())) };
        self.tick += 1;
        let tick = self.tick;
        // at most as many sessions per identity as its connection cap: the least recently used
        // goes
        let key = (who, session);
        let cap = match who {
            Some(_) => MAX_CONNS_PER_CLIENT.max(1),
            None => self.db.hold().map_or(64, |db| db.locked(|l| l.sync.config().max_clients)).max(1),
        };
        if !self.nonces.contains_key(&key) && self.nonces.keys().filter(|(w, _)| *w == who).count() >= cap
            && let Some(old) = self.nonces.iter().filter(|((w, _), _)| *w == who).min_by_key(|(_, n)| n.used).map(|(k, _)| *k)
        {
            self.nonces.remove(&old);
        }
        let fresh = !self.nonces.contains_key(&key);
        let n = self.nonces.entry(key).or_default();
        n.used = tick;
        n.lost |= fresh && resent;
        if let Some(o) = n.done.get(&nonce) {
            return match o.clone() {
                Outcome::Ok { value, .. } => Ok(value),
                Outcome::Err { code, detail } => Err(c::error_of(code, detail)),
            };
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
        let o = match &r {
            Ok(v) => Outcome::Ok { seq: 0, value: v.clone() },
            Err(e) => outcome_err(e),
        };
        let n = self.nonces.entry(key).or_default();
        n.done.insert(nonce, o);
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
                let key = db.key(ak.as_str())?;
                let r = if path.0.is_empty() { db.at(tid, ak).get_value() } else { db.at(tid, key).path(path).get_value() };
                c::read_v(&r)
            }
            method::ASPECTS => Value::List(db.aspects(a.tid()?)?.iter().map(c::ak_v).collect()),
            method::KNOWS => b(db.knows(a.tid()?)),
            method::GROUPS_OF => c::groups_v(&db.groups_of(a.tid()?)),
            method::ROSTER => c::roster_v(&db.roster(a.tid()?)),
            method::ROLE_ON => c::opt(db.role_on(a.tid()?), c::role_v),
            method::OWNER_OF => c::opt(db.owner_of(a.tid()?), Value::Tid),
            method::CREATED => c::opt(db.created(a.tid()?), |s| c::stamp_v(&s)),
            method::CHANGED => c::opt(db.changed(a.tid()?), |s| c::stamp_v(&s)),
            method::SAME_THING => b(db.same_thing(a.tid()?, a.tid()?)),
            method::WRITE => {
                let nonce = a.uint()?;
                let rest = a.rest();
                return self.once(conn, nonce, || Ok(c::opt(db.replay(rest)?, |x| c::committed_v(&x))));
            }
            method::COMMITS => Value::List(db.commits(&c::query(a.next()?)?)?.iter().map(c::entry_v).collect()),
            method::UNDO | method::REDO => {
                let nonce = a.uint()?;
                let scope = c::scope(a.next()?)?;
                return self.once(conn, nonce, || Ok(c::opt(if m == method::UNDO { db.undo(&scope)? } else { db.redo(&scope)? }, |x| c::committed_v(&x))));
            }
            method::REVERT => {
                let nonce = a.uint()?;
                let ch = c::change(a.next()?)?;
                return self.once(conn, nonce, || Ok(c::committed_v(&db.revert(ch)?)));
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
                db.register_schema_source(&file, &src)?;
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
                let until = a.opt()?.map(|w| w.as_uint().map(osis_base::WallMs).ok_or_else(|| c::bad("time"))).transpose()?;
                let (actor, secret) = db.add_client(until)?;
                Value::List(vec![Value::Tid(actor), Value::bytes(secret.expose())])
            }
            method::CLIENTS => Value::List(db.clients()?.iter().map(|x| Value::List(vec![Value::Tid(x.actor), c::opt(x.until, |w| Value::uint(w.0))])).collect()),
            method::REMOVE_CLIENT => b(db.remove_client(a.tid()?)?),
            method::ROTATE_CLIENT_SECRET => Value::bytes(db.rotate_client_secret(a.tid()?)?.expose()),
            method::ROTATE_CLIENT_KEY => Value::List(db.rotate_client_key()?.iter().map(|h| Value::Str(h.to_string())).collect()),
            method::HOSTS => Value::List(db.hosts().iter().map(|h| Value::Str(h.to_string())).collect()),
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
            method::GRANT | method::CHANGE_EDGE => {
                let (t, h, r, o) = (a.tid()?, a.tid()?, c::role(&a.next()?)?, c::edge_opts(a.next()?)?);
                if m == method::GRANT { db.grant(t, h, r, o)? } else { db.change_edge(t, h, r, o)? }
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
            method::LEAVE => {
                db.leave(a.tid()?)?;
                Value::List(vec![])
            }
            method::REACH => c::reach_v(&db.reach(a.tid()?)),
            method::HOLDER_PATH => c::pairs_v(&db.holder_path(a.tid()?, a.tid()?)),
            method::LINKS => c::links_v(&db.links(a.tid()?)),
            method::MAKE_LINK => {
                let (t, r) = (a.tid()?, c::role(&a.next()?)?);
                let until = a.opt()?.map(|w| w.as_uint().map(osis_base::WallMs).ok_or_else(|| c::bad("time"))).transpose()?;
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
        let kind = match a.uint()? {
            filter::SYNCED if acting.is_some() => return Err(unsupported("wait_synced for a thin client")),
            filter::SYNCED => {
                let (scope, ms) = (c::sync_scope(a.next()?)?, a.uint()?);
                a.end()?;
                if c.subs.values().filter(|s| matches!(s.kind, Kind::Synced(Some(_)))).count() >= MAX_WAITS {
                    return Err(Error::Invalid(format!("at most {MAX_WAITS} waits at once per connection")));
                }
                return Ok(self.sub_synced(db, conn, id, max_reply, scope, ms));
            }
            filter::ASPECT => Kind::Aspect(a.tid()?, a.ak()?),
            filter::THING => Kind::Thing(a.tid()?),
            filter::ROSTER => Kind::Roster(a.tid()?),
            filter::STATUS => Kind::Status,
            filter::DIAGNOSTICS => Kind::Diagnostics,
            _ => return Err(c::bad("filter")),
        };
        a.end()?;
        // the Owner's handle routes; this subscription would watch this engine's stale copy
        if let (None, Kind::Aspect(t, _) | Kind::Thing(t) | Kind::Roster(t)) = (acting, &kind)
            && !db.is_local(*t)
        {
            return Err(unsupported("a watch of a group this node reads at another node"));
        }
        let pending: Arc<Mutex<Pending>> = Arc::default();
        let tx = self.tx.clone();
        let p = pending.clone();
        // a fired signal or diagnostic waits within the connection's byte budget, else the
        // subscription lapses
        let queue = move |v: Value| {
            let n = osis_base::cbor::encode(&v).len();
            let mut g = lock(&p);
            if held.load(Ordering::Acquire).saturating_add(n) > SIGNAL_BYTES {
                g.lapsed = true;
            } else {
                held.fetch_add(n, Ordering::AcqRel);
                g.queue.push_back((v, n));
            }
        };
        let p = pending.clone();
        let mark = move |ak: Option<Ak>, s: crate::watch::Source| {
            let mut g = lock(&p);
            match ak {
                Some(ak) => {
                    g.aks.insert(ak, s);
                }
                None => g.dirty = Some(s),
            }
        };
        let moved = pending.clone();
        let cb: crate::watch::Callback = Box::new(move |db, d| {
            match d {
                // a client's diagnostics: those naming only what its actor reads
                Delivery::Diagnostic(x) if acting.is_some_and(|a| x.tids.is_empty() || !db.engine(|e| x.tids.iter().all(|t| e.readable_by(&a, t)))) => return,
                // a signal of what it may not read takes none of its budget (a lapse would tell)
                Delivery::Fired { tid, .. } if acting.is_some_and(|a| !db.engine(|e| e.readable_by(&a, &tid))) => return,
                Delivery::Aspect { ak, source, .. } => mark(Some(ak), source),
                // a fired signal carries a fifth item: delivered even when equal to the last
                Delivery::Fired { tid, ak, source, value } => queue(Value::List(vec![Value::Tid(tid), c::ak_v(&ak), c::read_v(&Ok(Some(value))), c::source_v(&source), Value::Bool(true)])),
                Delivery::Roster | Delivery::Status(_) => mark(None, crate::watch::Source::Initial),
                // this node's own source for it moved: the client's subscription ends
                Delivery::Moved => lock(&moved).lapsed = true,
                Delivery::Diagnostic(x) => queue(c::diag_v(&x)),
                Delivery::Initial => return,
                _ => return,
            }
            let _ = tx.send(Job::Dirty(conn));
        });
        let limit = db.inner.limit;
        let mut initial = Value::List(vec![]);
        let (filter, tid) = match &kind {
            Kind::Aspect(t, ak) => {
                let t = db.read_local(|r| r.resolve(*t));
                (Filter::Aspect(t, ak.clone()), Some(t))
            }
            Kind::Thing(t) | Kind::Roster(t) => {
                let t = db.read_local(|r| r.resolve(*t));
                (if matches!(kind, Kind::Thing(_)) { Filter::Thing(t) } else { Filter::Roster(t) }, Some(t))
            }
            Kind::Status => (Filter::Status, None),
            Kind::Diagnostics => (Filter::Diagnostics, None),
            Kind::Synced(_) => return Err(c::bad("filter")),
        };
        let sub = db.subscribe(filter, false, |r| {
            initial = match &kind {
                Kind::Aspect(_, ak) => c::read_v(&r.value(tid.unwrap_or(db.me()), ak)),
                Kind::Thing(_) => {
                    let t = tid.unwrap_or(db.me());
                    Value::List(r.aspects(t).unwrap_or_default().iter().map(|ak| Value::List(vec![c::ak_v(ak), c::read_v(&r.value(t, ak))])).collect())
                }
                Kind::Roster(_) => c::roster_v(&r.roster(tid.unwrap_or(db.me()))),
                Kind::Status | Kind::Diagnostics | Kind::Synced(_) => Value::List(vec![]),
            };
            let _ = limit;
            cb
        });
        if let Kind::Status = kind {
            initial = c::status_v(&db.status()?);
        }
        let seen = tid.is_none_or(|t| db.read_local(|r| !r.hidden(t)));
        let kind = match kind {
            Kind::Aspect(_, ak) => Kind::Aspect(tid.unwrap_or(db.me()), ak),
            Kind::Thing(_) => Kind::Thing(tid.unwrap_or(db.me())),
            Kind::Roster(_) => Kind::Roster(tid.unwrap_or(db.me())),
            k => k,
        };
        if let Some(c) = self.conns.get_mut(&conn) {
            c.subs.insert(id, PortSub { max_reply, kind, pending, _sub: Some(sub), seen });
        }
        Ok(initial)
    }

    /// A `wait_synced` as a subscription (notes/client-port.md §8): the node's own wait (its
    /// waiter, polled under the lock after every change as a local app's is), never blocking
    /// this worker; the Reply carries the outcome when it is known at once, else the one Notify.
    fn sub_synced(&mut self, db: &Osis, conn: ConnId, id: Id, max_reply: usize, scope: crate::share::SyncScope, ms: u64) -> Value {
        let mut p = db.wait_synced_pending(scope, std::time::Duration::from_millis(ms));
        let waker = std::task::Waker::from(Arc::new(Wake { tx: self.tx.clone(), conn, id }));
        let now = std::pin::Pin::new(&mut p).poll(&mut std::task::Context::from_waker(&waker));
        let (kind, initial) = match now {
            std::task::Poll::Ready(r) => (Kind::Synced(None), c::opt(Some(r), |r| c::done_v(&r))),
            std::task::Poll::Pending => (Kind::Synced(Some(p)), Value::List(vec![])),
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
        let seq = db.locked(|l| l.seq);
        let mut notes: Vec<(Id, Payload)> = Vec::new();
        let mut used = 0usize;
        let mut left = false;
        let mut gone = Vec::new();
        for (id, s) in &mut cn.subs {
            let mut g = lock(&s.pending);
            if g.lapsed {
                notes.push((*id, Payload::Lapsed));
                gone.push(*id);
                continue;
            }
            // what its actor may read now (the module's invariant): a thing it could read and no
            // longer can ends the subscription; nothing of one it cannot read is sent
            if let (Some(_), Kind::Aspect(t, _) | Kind::Thing(t) | Kind::Roster(t)) = (db.acting, &s.kind) {
                if db.read_local(|r| r.hidden(*t)) {
                    if s.seen {
                        notes.push((*id, Payload::Lapsed));
                        gone.push(*id);
                    } else {
                        for (_, n) in g.queue.drain(..) {
                            cn.held.fetch_sub(n, Ordering::AcqRel);
                        }
                        g.dirty = None;
                        g.aks.clear();
                    }
                    continue;
                }
                s.seen = true;
            }
            // what this subscription would send now, oldest first
            let mut out: Vec<(Value, usize, Option<crate::watch::Source>)> = Vec::new();
            for (v, n) in &g.queue {
                out.push((v.clone(), *n, None));
            }
            let nq = out.len();
            match &s.kind {
                Kind::Aspect(t, ak) => {
                    // the callback marks by aspect (as for a thing subscription)
                    if let Some(src) = g.aks.get(ak).copied().or(g.dirty) {
                        let v = Value::List(vec![Value::Tid(*t), c::ak_v(ak), c::read_v(&db.read_local(|r| r.value(*t, ak))), c::source_v(&src)]);
                        out.push((v, 0, Some(src)));
                    }
                }
                Kind::Thing(t) => {
                    for (ak, src) in &g.aks {
                        let v = Value::List(vec![Value::Tid(*t), c::ak_v(ak), c::read_v(&db.read_local(|r| r.value(*t, ak))), c::source_v(src)]);
                        out.push((v, 0, Some(*src)));
                    }
                }
                Kind::Roster(t) if g.dirty.is_some() => out.push((c::roster_v(&db.roster(*t)), 0, None)),
                Kind::Status if g.dirty.is_some() => {
                    if let Ok(st) = db.status() {
                        out.push((c::status_v(&st), 0, None));
                    }
                }
                _ => {}
            }
            let mut sent = 0;
            for (v, _, src) in &out {
                let mut p = Payload::Delivery { seq, value: v.clone() };
                let size_of = |p: &Payload| Message::Notify { sub: *id, payload: p.clone() }.encode().len();
                let mut size = size_of(&p);
                if size > s.max_reply {
                    // above the subscription's bound: what changed, read by path or stream
                    p = Payload::TooLarge { seq, source: c::source_v(&src.unwrap_or(crate::watch::Source::Initial)) };
                    size = size_of(&p);
                }
                if size > s.max_reply {
                    // not even that fits: the subscription ends here as proto would end it
                    // (`Lapsed`), so it is never live at one side only
                    p = Payload::Lapsed;
                    size = size_of(&p);
                }
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
            let q_sent = sent.min(nq);
            for _ in 0..q_sent {
                if let Some((_, n)) = g.queue.pop_front() {
                    cn.held.fetch_sub(n, Ordering::AcqRel);
                }
            }
            if sent == out.len() {
                g.dirty = None;
                g.aks.clear();
            } else if sent > nq && matches!(s.kind, Kind::Thing(_)) {
                let done: Vec<Ak> = g.aks.keys().take(sent - nq).cloned().collect();
                for ak in done {
                    g.aks.remove(&ak);
                }
            }
            if left {
                break;
            }
        }
        for id in gone {
            // what it still held is freed with it
            if let Some(s) = cn.subs.remove(&id) {
                let freed: usize = lock(&s.pending).queue.iter().map(|(_, n)| *n).sum();
                cn.held.fetch_sub(freed, Ordering::AcqRel);
            }
        }
        let settles = if left { Vec::new() } else { std::mem::take(&mut cn.settles) };
        if !notes.is_empty() {
            self.feed(db, Event::Notify { conn, notes });
        }
        if left {
            self.want_room(db, conn);
        }
        for id in settles {
            let seq = db.locked(|l| l.seq);
            self.reply(db, conn, id, Ok(Outcome::Ok { seq, value: Value::List(vec![]) }));
        }
    }
}
