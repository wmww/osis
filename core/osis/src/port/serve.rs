//! The serving side of the client port (notes/client-port.md §2): requests the sync engine hands
//! out (`Action::Request`) are queued under the handle lock and run after it is released on one
//! worker thread, one at a time, each as ordinary `Osis` calls (one engine transaction each);
//! replies and Notify payloads are encoded there, never under the lock. Subscriptions are
//! ordinary dispatcher registrations whose callbacks only set dirty flags (and queue fired
//! signals and diagnostics within `SIGNAL_BYTES`); the worker materializes dirty subscriptions
//! when push room opens (`Action::Room`). Writes carry a nonce: outcomes are kept per (tier
//! identity, session) under the node epoch, so a retry is answered once.

use super::codec::{self as c, Args, outcome_err, u};
use super::{MAX_SCHEMA_BYTES, SIGNAL_BYTES, STREAM_CHUNK, WRITE_NONCES, filter, method};
use crate::error::{Error, Result};
use crate::handle::{Inner, Osis, WeakOsis};
use crate::watch::{Delivery, Filter, Subscription, lock};
use osis_base::{Ak, Tid, Value};
use osis_node::sync::{Action, ConnId, Event, Tier};
use osis_proto::msg::Id;
use osis_proto::{Code, Message, Outcome, Payload};
use std::collections::{BTreeMap, VecDeque};
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
}

/// The port of one database: its node epoch, the jobs queued under the lock, the worker.
pub(crate) struct Port {
    pub epoch: [u8; 16],
    queued: Mutex<Vec<Job>>,
    tx: Mutex<Option<Sender<Job>>>,
}

impl Port {
    /// A fresh node epoch: 16 random bytes per process start (never from a test seed: a node
    /// restarted with the same seed must not repeat it).
    pub fn new() -> Port {
        let mut epoch = [0u8; 16];
        {
            use osis_crypto::RngCore;
            osis_crypto::OsRng.fill_bytes(&mut epoch);
        }
        Port { epoch, queued: Mutex::new(Vec::new()), tx: Mutex::new(None) }
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
                let mut w = Worker { db: weak, tx: mine, conns: BTreeMap::new(), nonces: BTreeMap::new(), tick: 0 };
                while let Ok(j) = rx.recv() {
                    if !w.job(j) {
                        return;
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
}

struct PortSub {
    max_reply: usize,
    kind: Kind,
    pending: Arc<Mutex<Pending>>,
    _sub: Subscription,
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
    schema_bytes: usize,
}

/// Write outcomes of one session: by nonce (at most `WRITE_NONCES`), the highest seen, and
/// when it was last used (least recently used sessions go first).
#[derive(Default)]
struct Nonces {
    done: BTreeMap<u64, Outcome>,
    top: u64,
    used: u64,
}

struct Worker {
    db: WeakOsis,
    tx: Sender<Job>,
    conns: BTreeMap<ConnId, Conn>,
    /// Per (identity, session): the Owner's uid is the only identity in (b), so by session.
    nonces: BTreeMap<[u8; 16], Nonces>,
    tick: u64,
}

fn unsupported(what: &str) -> Error {
    Error::Unsupported(format!("{what} through the client port"))
}

impl Worker {
    /// Runs a job; `false` once the database is gone.
    fn job(&mut self, j: Job) -> bool {
        let Some(db) = self.db.hold() else { return false };
        match j {
            Job::Act(Action::Request { conn, tier, msg }) => self.request(&db, conn, tier, *msg),
            Job::Act(Action::Room { conn, budget }) => {
                if let Some(c) = self.conns.get_mut(&conn) {
                    c.asked = false;
                }
                self.flush(&db, conn, budget);
            }
            Job::Act(Action::Ended { conn }) => {
                self.conns.remove(&conn);
            }
            Job::Act(_) => {}
            Job::Dirty(conn) => self.want_room(&db, conn),
        }
        true
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

    fn request(&mut self, db: &Osis, conn: ConnId, tier: Tier, msg: Message) {
        match msg {
            Message::Auth { id, client_pk, session, .. } => {
                // a keyed Auth (credentials, step (c1)) and any Auth on a keyed transport: Error 1
                if tier != Tier::Owner || client_pk.is_some() {
                    return self.reply(db, conn, id, Err(Code::REFUSED));
                }
                let c = self.conns.entry(conn).or_insert_with(|| Conn { tier, session: None, subs: BTreeMap::new(), held: Arc::default(), asked: false, settles: Vec::new(), schema_bytes: 0 });
                c.session = Some(session);
                let seq = db.locked(|l| l.seq);
                self.reply(db, conn, id, Ok(Outcome::Ok { seq, value: Value::bytes(&db.inner.port.epoch) }));
            }
            Message::Call { id, method, args, .. } => {
                if !self.conns.get(&conn).is_some_and(|c| c.tier == Tier::Owner) {
                    return self.reply(db, conn, id, Err(Code::REFUSED));
                }
                if method == method::SETTLE {
                    db.settle();
                    if let Some(c) = self.conns.get_mut(&conn) {
                        c.settles.push(id);
                    }
                    return self.want_room(db, conn);
                }
                let r = self.call(db, conn, method, args);
                let seq = db.locked(|l| l.seq);
                let out = match r {
                    Ok(value) => Outcome::Ok { seq, value },
                    Err(e) => outcome_err(&e),
                };
                self.reply(db, conn, id, Ok(out));
            }
            Message::Sub { id, max_reply, filter } => {
                let r = self.sub(db, conn, id, usize::try_from(max_reply).unwrap_or(usize::MAX), filter);
                let seq = db.locked(|l| l.seq);
                let out = match r {
                    Ok(value) => Outcome::Ok { seq, value },
                    Err(e) => outcome_err(&e),
                };
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
    /// again, `Invalid("outcome unknown")` for one at or below the highest seen and no longer
    /// remembered, else `run`'s, remembered.
    fn once(&mut self, conn: ConnId, nonce: u64, run: impl FnOnce() -> Result<Value>) -> Result<Value> {
        let Some(session) = self.conns.get(&conn).and_then(|c| c.session) else { return Err(Error::Invalid("no session".into())) };
        self.tick += 1;
        let tick = self.tick;
        // at most as many sessions as the Owner's connection cap: the least recently used goes
        let cap = self.db.hold().map_or(64, |db| db.locked(|l| l.sync.config().max_clients)).max(1);
        if !self.nonces.contains_key(&session) && self.nonces.len() >= cap
            && let Some(old) = self.nonces.iter().min_by_key(|(_, n)| n.used).map(|(k, _)| *k)
        {
            self.nonces.remove(&old);
        }
        let n = self.nonces.entry(session).or_default();
        n.used = tick;
        if let Some(o) = n.done.get(&nonce) {
            return match o.clone() {
                Outcome::Ok { value, .. } => Ok(value),
                Outcome::Err { code, detail } => Err(c::error_of(code, detail)),
            };
        }
        if nonce == 0 || nonce <= n.top {
            return Err(Error::Invalid("outcome unknown".into()));
        }
        n.top = nonce;
        let r = run();
        let o = match &r {
            Ok(v) => Outcome::Ok { seq: 0, value: v.clone() },
            Err(e) => outcome_err(e),
        };
        let n = self.nonces.entry(session).or_default();
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
                let c = self.conns.get_mut(&conn).ok_or(Error::Closed)?;
                if c.schema_bytes.saturating_add(src.len()) > MAX_SCHEMA_BYTES {
                    return Err(Error::TooLarge { limit: MAX_SCHEMA_BYTES });
                }
                c.schema_bytes += src.len();
                db.register_schema_source(&file, &src)?;
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
            method::HOSTS => Value::List(db.hosts().iter().map(|h| Value::Str(h.to_string())).collect()),
            _ => return Err(unsupported(&format!("method {m}"))),
        };
        Ok(v)
    }

    /// Registers a subscription: a dispatcher registration taken atomically with its initial
    /// value (the Reply's), whose callback only marks it dirty.
    fn sub(&mut self, db: &Osis, conn: ConnId, id: Id, max_reply: usize, f: Value) -> Result<Value> {
        let c = self.conns.get(&conn).filter(|c| c.tier == Tier::Owner).ok_or(Error::Closed)?;
        let held = c.held.clone();
        let mut a = Args::new(f)?;
        let kind = match a.uint()? {
            filter::ASPECT => Kind::Aspect(a.tid()?, a.ak()?),
            filter::THING => Kind::Thing(a.tid()?),
            filter::ROSTER => Kind::Roster(a.tid()?),
            filter::STATUS => Kind::Status,
            filter::DIAGNOSTICS => Kind::Diagnostics,
            _ => return Err(c::bad("filter")),
        };
        a.end()?;
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
        let cb: crate::watch::Callback = Box::new(move |_, d| {
            match d {
                Delivery::Aspect { ak, source, .. } => mark(Some(ak), source),
                // a fired signal carries a fifth item: delivered even when equal to the last
                Delivery::Fired { tid, ak, source, value } => queue(Value::List(vec![Value::Tid(tid), c::ak_v(&ak), c::read_v(&Ok(Some(value))), c::source_v(&source), Value::Bool(true)])),
                Delivery::Roster | Delivery::Status(_) => mark(None, crate::watch::Source::Initial),
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
                let t = db.read(|r| r.resolve(*t));
                (Filter::Aspect(t, ak.clone()), Some(t))
            }
            Kind::Thing(t) | Kind::Roster(t) => {
                let t = db.read(|r| r.resolve(*t));
                (if matches!(kind, Kind::Thing(_)) { Filter::Thing(t) } else { Filter::Roster(t) }, Some(t))
            }
            Kind::Status => (Filter::Status, None),
            Kind::Diagnostics => (Filter::Diagnostics, None),
        };
        let sub = db.subscribe(filter, false, |r| {
            initial = match &kind {
                Kind::Aspect(_, ak) => c::read_v(&r.value(tid.unwrap_or(db.me()), ak)),
                Kind::Thing(_) => {
                    let t = tid.unwrap_or(db.me());
                    Value::List(r.aspects(t).unwrap_or_default().iter().map(|ak| Value::List(vec![c::ak_v(ak), c::read_v(&r.value(t, ak))])).collect())
                }
                Kind::Roster(_) => c::roster_v(&r.roster(tid.unwrap_or(db.me()))),
                Kind::Status | Kind::Diagnostics => Value::List(vec![]),
            };
            let _ = limit;
            cb
        });
        if let Kind::Status = kind {
            initial = c::status_v(&db.status()?);
        }
        let kind = match kind {
            Kind::Aspect(_, ak) => Kind::Aspect(tid.unwrap_or(db.me()), ak),
            Kind::Thing(_) => Kind::Thing(tid.unwrap_or(db.me())),
            Kind::Roster(_) => Kind::Roster(tid.unwrap_or(db.me())),
            k => k,
        };
        if let Some(c) = self.conns.get_mut(&conn) {
            c.subs.insert(id, PortSub { max_reply, kind, pending, _sub: sub });
        }
        Ok(initial)
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
        for (id, s) in &cn.subs {
            let mut g = lock(&s.pending);
            if g.lapsed {
                let freed: usize = g.queue.iter().map(|(_, n)| *n).sum();
                cn.held.fetch_sub(freed, Ordering::AcqRel);
                notes.push((*id, Payload::Lapsed));
                gone.push(*id);
                continue;
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
                        let v = Value::List(vec![Value::Tid(*t), c::ak_v(ak), c::read_v(&db.read(|r| r.value(*t, ak))), c::source_v(&src)]);
                        out.push((v, 0, Some(src)));
                    }
                }
                Kind::Thing(t) => {
                    for (ak, src) in &g.aks {
                        let v = Value::List(vec![Value::Tid(*t), c::ak_v(ak), c::read_v(&db.read(|r| r.value(*t, ak))), c::source_v(src)]);
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
                let mut size = osis_proto::Message::Notify { sub: *id, payload: p.clone() }.encode().len();
                if size > s.max_reply {
                    // above the subscription's bound: what changed, read by path or stream
                    p = Payload::TooLarge { seq, source: c::source_v(&src.unwrap_or(crate::watch::Source::Initial)) };
                    size = 64;
                }
                if used.saturating_add(size) > budget && !notes.is_empty() {
                    left = true;
                    break;
                }
                used = used.saturating_add(size);
                notes.push((*id, p));
                sent += 1;
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
            cn.subs.remove(&id);
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
