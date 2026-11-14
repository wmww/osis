//! The client port, node side (spec/wire.md §11.2 kinds 24-29, spec/sync-transport.md §6): sync
//! carries Auth, Call, Sub and Unsub on its sessions (`osis_sync::PortEvent`) and the handle
//! answers them here, off the node lock, as ordinary calls on itself or, for a client-actor
//! session, on a handle acting as the client's actor (notes/client-port.md §3). One request at a
//! time, in order: the one loop feeding the node's inputs serves them (`ReadOnly::step`).
//!
//! State, in `Locked` (memory only: a restart forgets it, and a client resending a write then
//! hears `OutcomeUnknown`): per connection, who its session acts as, its session id and its
//! subscriptions (at most `MAX_SUBS`, gone with the connection); per (identity, session id), the
//! last `WRITE_NONCES` write outcomes, as many sessions per identity as its connection cap, least
//! recently used going.

use super::codec::{self, bad, list, opt, outcome_of, read_to, tid};
use super::{MAX_CLIENTS, WRITE_NONCES, filter, method};
use crate::error::{Error, Result};
use crate::handle::{Locked, ReadOnly};
use crate::read::Reader;
use crate::watch::{Delivery, Filter, ReadAt, Subscription, digest};
use osis_base::{Tid, Value};
use osis_proto::api::{Outcome, Payload};
use osis_proto::limits::{MAX_CONNS_PER_CLIENT, MAX_SUBS};
use osis_proto::{Code, Msg};
use osis_schema::Path;
use osis_sync::{ConnId, PortEvent};
use std::collections::{BTreeMap, BTreeSet};

/// A resend's mark on a write nonce (spec/wire.md §11.2 Write nonces).
pub(crate) const RESENT: u64 = 1 << 62;

/// Who a session acts as.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Who {
    /// The node's main actor (a unix session).
    Main,
    /// A client actor, by the hash of the secret its Auth sent.
    Client { actor: Tid, hash: [u8; 32] },
}

impl Who {
    /// Whose write nonces these are: a client's sessions share its actor's.
    fn ident(self) -> Option<Tid> {
        match self {
            Who::Main => None,
            Who::Client { actor, .. } => Some(actor),
        }
    }
}

/// One connection's port session.
struct Session {
    who: Who,
    id: [u8; 16],
    subs: BTreeMap<u32, Subscription>,
}

/// One session's write outcomes (spec/wire.md §11.2 Write nonces).
#[derive(Default)]
struct Nonces {
    outcomes: BTreeMap<u64, Outcome>,
    /// The highest nonce run.
    top: u64,
    /// A resend came that this node held no outcomes for: every later resend it does not
    /// remember is unknown too, until the session's next new write.
    forgot: bool,
    /// When it was last used, for the cap's least recently used.
    used: u64,
}

/// The client port's sessions on this node's connections.
#[derive(Default)]
pub(crate) struct Port {
    /// Connections over the unix transport (`Osis::step`).
    main: BTreeSet<ConnId>,
    sessions: BTreeMap<ConnId, Session>,
    nonces: BTreeMap<(Option<Tid>, [u8; 16]), Nonces>,
    uses: u64,
}

impl std::fmt::Debug for Port {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Port({} sessions)", self.sessions.len())
    }
}

impl Port {
    /// `conn` runs over the unix transport: its Auth without a secret makes a main session.
    pub fn main(&mut self, conn: ConnId) {
        self.main.insert(conn);
    }

    /// `conn` ended: its session and subscriptions go (its write outcomes stay, for a resend
    /// on the next connection).
    fn closed(&mut self, conn: ConnId) -> Option<Session> {
        self.main.remove(&conn);
        self.sessions.remove(&conn)
    }

    /// The write outcomes of `who`'s session `id`, made if `make`; the identity's least recently
    /// used session goes past its cap.
    fn nonces(&mut self, who: Who, id: [u8; 16], make: bool) -> Option<&mut Nonces> {
        let key = (who.ident(), id);
        self.uses += 1;
        if !self.nonces.contains_key(&key) {
            if !make {
                return None;
            }
            let cap = if who == Who::Main { MAX_CLIENTS } else { MAX_CONNS_PER_CLIENT };
            let mine: Vec<_> = self.nonces.iter().filter(|(k, _)| k.0 == key.0).map(|(k, n)| (n.used, *k)).collect();
            if mine.len() >= cap
                && let Some((_, old)) = mine.into_iter().min()
            {
                self.nonces.remove(&old);
            }
        }
        let n = self.nonces.entry(key).or_default();
        n.used = self.uses;
        Some(n)
    }
}

/// Serves the client port's events one step took from sync, in order (`ReadOnly::step`): the
/// requests served as the node's main handle, whatever handle stepped; the answers to this
/// process's own requests handed to its client connections (`client`).
pub(crate) fn serve(inner: &std::sync::Arc<crate::handle::Inner>, events: Vec<PortEvent>) {
    if events.is_empty() {
        return;
    }
    let db = crate::Osis::internal(inner.clone());
    for ev in events {
        match ev {
            PortEvent::Closed(conn) => {
                let gone = db.locked(|l| l.port.closed(conn));
                drop(gone);
                super::client::closed(&db, conn);
            }
            PortEvent::Request(conn, id, m) => request(&db, conn, id, *m),
            PortEvent::Up(conn) => super::client::up(&db, conn),
            PortEvent::Reply(conn, id, m) => super::client::reply(&db, conn, id, *m),
            PortEvent::Notify(conn, m) => super::client::notify(&db, conn, *m),
        }
    }
}

fn error(code: Code) -> Msg {
    Msg::Error { id: 0, code }
}

fn reply(outcome: Outcome) -> Msg {
    Msg::Reply { id: 0, outcome }
}

/// Sends `m` as the answer to request `id` on `conn`.
fn answer(l: &mut Locked, conn: ConnId, id: osis_sync::session::RequestId, m: Msg) {
    let o = l.node.port_answer(conn, id, m);
    l.out.extend(o);
}

/// Answers request `id` on `conn`.
fn request(db: &ReadOnly, conn: ConnId, id: osis_sync::session::RequestId, m: Msg) {
    // a Sub registers and answers under one hold: no Notify of it goes before its Reply
    if let Msg::Sub { max_reply, filter, .. } = m {
        return sub(db, conn, id, max_reply, filter, &mut |l, m| answer(l, conn, id, m));
    }
    let a = match m {
        Msg::Auth { secret, session_id, .. } => auth(db, conn, secret.as_ref().map(|s| *s.expose()), session_id),
        Msg::Call { max_reply, method, args, .. } => call(db, conn, max_reply, method, args),
        Msg::Unsub { sub_id, .. } => {
            let gone = db.locked(|l| l.port.sessions.get_mut(&conn).and_then(|s| s.subs.remove(&sub_id)));
            drop(gone);
            Msg::Ok { id: 0 }
        }
        _ => error(Code::UNSUPPORTED),
    };
    db.locked(|l| answer(l, conn, id, a));
}

/// Auth (spec/wire.md §11.2): a main session on the unix transport without a secret; a
/// client-actor session elsewhere with its bearer secret, once; at most `MAX_CONNS_PER_CLIENT`
/// sessions of one client and `MAX_CLIENTS` of all.
fn auth(db: &ReadOnly, conn: ConnId, secret: Option<[u8; 32]>, id: [u8; 16]) -> Msg {
    let (main, had) = db.locked(|l| (l.port.main.contains(&conn), l.port.sessions.get(&conn).map(|s| s.who)));
    let who = match (secret, main) {
        (None, true) => Who::Main,
        (Some(s), false) if !matches!(had, Some(Who::Client { .. })) => {
            let hash = osis_base::hash::hash(&s);
            let Some(actor) = client_of(db, &hash) else { return error(Code::REFUSED) };
            let (mine, all) = db.locked(|l| {
                let clients = || l.port.sessions.iter().filter(|(c, _)| **c != conn).filter_map(|(_, s)| s.who.ident());
                (clients().filter(|a| *a == actor).count(), clients().count())
            });
            if mine >= MAX_CONNS_PER_CLIENT || all >= MAX_CLIENTS {
                return error(Code::RATE_LIMITED);
            }
            Who::Client { actor, hash }
        }
        _ => return error(Code::REFUSED),
    };
    db.locked(|l| l.port.sessions.insert(conn, Session { who, id, subs: BTreeMap::new() }));
    reply(Outcome::Ok { value: Value::List(Vec::new()) })
}

/// The client actor of the `clients^.0` entry whose secret hash is `hash`, its `until` not
/// passed (compared in constant time).
fn client_of(db: &ReadOnly, hash: &[u8; 32]) -> Option<Tid> {
    let now = db.inner.clock.now_wall_ms();
    let entries = db.read_local(|r| r.get(db.inner.node, &osis_schema::core_types::CLIENTS)).ok()??;
    entries.into_iter().find(|(_, c)| same(&c.secret_hash, hash) && c.until.is_none_or(|u| u.0 > now.0)).map(|(a, _)| a)
}

fn same(a: &[u8; 32], b: &[u8; 32]) -> bool {
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// The session on `conn`, checked now: a client-actor session ends when its entry goes, its
/// secret hash changes or its `until` passes (spec/wire.md §11.2 End of a client-actor session).
fn session(db: &ReadOnly, conn: ConnId) -> Option<(Who, [u8; 16])> {
    let (who, id) = db.locked(|l| l.port.sessions.get(&conn).map(|s| (s.who, s.id)))?;
    if let Who::Client { actor, hash } = who
        && client_of(db, &hash) != Some(actor)
    {
        let gone = db.locked(|l| l.port.sessions.remove(&conn));
        drop(gone);
        return None;
    }
    Some((who, id))
}

/// The handle a session's rows run on.
fn handle(db: &ReadOnly, who: Who) -> crate::Osis {
    match who {
        Who::Main => crate::Osis::internal(db.inner.clone()),
        Who::Client { actor, .. } => crate::Osis::internal(db.inner.clone()).act_as(actor),
    }
}

/// A Call: run as the session's actor, its reply within `max_reply`.
fn call(db: &ReadOnly, conn: ConnId, max_reply: u64, method: u64, args: Vec<Value>) -> Msg {
    let Some((who, id)) = session(db, conn) else { return error(Code::REFUSED) };
    let h = handle(db, who);
    let outcome = if method == method::WRITE {
        write(db, &h, who, id, args)
    } else {
        match run(&h, method, args) {
            Ok(v) => Outcome::Ok { value: v },
            Err(e) => outcome_of(&e),
        }
    };
    let limit = usize::try_from(max_reply).unwrap_or(usize::MAX);
    if reply(outcome.clone()).encode().len() > limit {
        return reply(Outcome::too_large(limit));
    }
    reply(outcome)
}

/// A thing a row names: one this node reads at another node is no answer of its own (the port
/// never waits on another node, notes/client-port.md §8): a main session's row is
/// `Unsupported`; a client actor reads it as unknown (`readable_by` denies it).
fn here(h: &crate::Osis, t: Tid) -> Result<Tid> {
    match h.source(t)? {
        crate::sources::Source::Node(_) if h.acting.is_none() => Err(Error::Unsupported("a thing this node reads at another node: not through its port".into())),
        _ => Ok(t),
    }
}

/// `[tid, ak, path]`.
fn place(args: Vec<Value>) -> Result<(Tid, crate::DynamicAspectKey, Path)> {
    let [t, a, p] = <[Value; 3]>::try_from(args).map_err(|_| bad("arguments"))?;
    Ok((tid(&t)?, crate::DynamicAspectKey::untyped(codec::ak(&a)?), codec::path_from(p)?))
}

fn one_tid(args: &[Value]) -> Result<Tid> {
    match args {
        [t] => tid(t),
        _ => Err(bad("arguments")),
    }
}

/// Runs method `method` on `h`.
fn run(h: &crate::Osis, method: u64, args: Vec<Value>) -> Result<Value> {
    match method {
        method::WHOAMI => Ok(Value::List(vec![Value::Tid(h.me()), Value::Tid(h.node()), Value::Tid(h.home())])),
        method::GET => {
            let (t, k, p) = place(args)?;
            here(h, t)?;
            Ok(read_to(&h.read_local(|r| r.get_path(t, &k, &p))))
        }
        method::ASPECTS => {
            let t = here(h, one_tid(&args)?)?;
            Ok(Value::List(h.read_local(|r| r.aspects(t))?.iter().map(codec::ak_to).collect()))
        }
        method::HAS_CONTENT => {
            let t = here(h, one_tid(&args)?)?;
            Ok(Value::Bool(h.read_local(|r| r.knows(t))?))
        }
        method::HOLDS => {
            let t = here(h, one_tid(&args)?)?;
            Ok(Value::Bool(h.read_local(|r| r.holds(t))))
        }
        method::NOW => Ok(Value::uint(h.now()?.0)),
        method::SETTLE => {
            // every Notify for what changed before this goes before its Reply
            h.settle_here();
            Ok(Value::List(Vec::new()))
        }
        m => Err(Error::Unsupported(format!("unknown method {m}"))),
    }
}

/// A write by nonce (spec/wire.md §11.2 Write nonces): a remembered nonce gets its first
/// outcome; a resend this node cannot tell from a repeat is `OutcomeUnknown` and does not run.
fn write(db: &ReadOnly, h: &crate::Osis, who: Who, id: [u8; 16], mut args: Vec<Value>) -> Outcome {
    let Some(nonce) = args.first().and_then(Value::as_uint) else { return outcome_of(&bad("write")) };
    args.remove(0);
    let (n, resent) = (nonce & !RESENT, nonce & RESENT != 0);
    if n == 0 || n >= RESENT {
        return outcome_of(&bad("write nonce"));
    }
    let known = db.locked(|l| -> std::result::Result<(), Outcome> {
        let unknown = || outcome_of(&Error::OutcomeUnknown);
        let Some(s) = l.port.nonces(who, id, !resent) else {
            // a resend of a session this node holds nothing of
            if let Some(s) = l.port.nonces(who, id, true) {
                s.forgot = true;
            }
            return Err(unknown());
        };
        if let Some(o) = s.outcomes.get(&n) {
            return Err(o.clone());
        }
        if resent && (s.forgot || n <= s.top) {
            return Err(unknown());
        }
        if !resent {
            s.forgot = false;
        }
        // set before it runs: a write that never answers is unknown to its resend
        s.top = s.top.max(n);
        Ok(())
    });
    if let Err(o) = known {
        return o;
    }
    let r = crate::write::Write::from_wire(h, args).and_then(|w| {
        w.things().into_iter().try_for_each(|t| here(h, t).map(drop))?;
        w.commit()
    });
    let o = match r {
        Ok(c) => Outcome::Ok { value: opt(c.as_ref().map(codec::commit_to)) },
        Err(e) => outcome_of(&e),
    };
    db.locked(|l| {
        if let Some(s) = l.port.nonces(who, id, true) {
            s.outcomes.insert(n, o.clone());
            while s.outcomes.len() > WRITE_NONCES {
                s.outcomes.pop_first();
            }
        }
    });
    o
}

/// A Sub: the filter's value now in its Reply and a Notify each time it reads otherwise, read
/// as the session's actor at each send (notes/client-port.md §2 Subscriptions as pushes).
fn sub(db: &ReadOnly, conn: ConnId, id: osis_sync::session::RequestId, max_reply: u64, f: Value, answer: &mut dyn FnMut(&mut Locked, Msg)) {
    let mut refuse = |m: Msg| db.locked(|l| answer(l, m));
    let Some((who, _)) = session(db, conn) else { return refuse(error(Code::REFUSED)) };
    let parsed = list(f, "filter").and_then(|mut f| match f.first().and_then(Value::as_uint) {
        Some(filter::VALUE) => place(f.split_off(1)),
        _ => Err(Error::Unsupported("no such filter".into())),
    });
    let (t, k, p) = match parsed {
        Ok(x) => x,
        Err(e) => return refuse(reply(outcome_of(&e))),
    };
    let h = handle(db, who);
    if let Err(e) = here(&h, t) {
        return refuse(reply(outcome_of(&e)));
    }
    let acting = h.acting;
    let ak = k.ak.clone();
    let read = ReadAt::new(move |r| {
        let a = std::mem::replace(&mut r.actor, acting);
        let v = r.get_path(t, &k, &p);
        r.actor = a;
        v
    });
    let limit = usize::try_from(max_reply).unwrap_or(usize::MAX);
    db.locked(|l| {
        let Some(s) = l.port.sessions.get(&conn) else { return answer(l, error(Code::REFUSED)) };
        if s.subs.contains_key(&id) {
            // a Sub reusing a live subscription's id (spec/wire.md §11.1)
            return answer(l, error(Code::MALFORMED));
        }
        if s.subs.len() >= MAX_SUBS {
            return answer(l, error(Code::RATE_LIMITED));
        }
        let first = read.0(&mut Reader { e: l.engine(), limit: db.inner.limit, actor: acting });
        let initial = reply(Outcome::Ok { value: read_to(&first) });
        if initial.encode().len() > limit {
            return answer(l, reply(Outcome::too_large(limit)));
        }
        let mut last = digest(&first);
        let cb = Box::new(move |db: &crate::Osis, d: Delivery| {
            let Delivery::Aspect { value, origin, .. } = d else { return };
            let now = digest(&value);
            if value.is_ok() && now == last {
                return;
            }
            last = now;
            // the session is checked at every send: an ended one hears nothing more
            if session(db, conn).is_none() {
                return;
            }
            let delivery = Payload::Delivery { value: Value::List(vec![read_to(&value), codec::origin_to(&origin)]) };
            let mut m = Msg::Notify { sub_id: id, payload: delivery };
            if m.encode().len() > limit {
                m = Msg::Notify { sub_id: id, payload: Payload::TooLarge { source: Value::uint(limit as u64) } };
            }
            db.locked(|l| match l.node.port_push(conn, m, false) {
                Some(o) => l.out.extend(o),
                // no room: it lapses, and the client subscribes again
                None => {
                    let gone = l.port.sessions.get_mut(&conn).and_then(|s| s.subs.remove(&id));
                    let o = l.node.port_push(conn, Msg::Notify { sub_id: id, payload: Payload::Lapsed }, true).unwrap_or_default();
                    l.out.extend(o);
                    drop(gone);
                }
            });
        });
        let sub = db.subscribe_in(l, Filter::Aspect(t, ak, read.clone()), false, cb);
        if let Some(s) = l.port.sessions.get_mut(&conn) {
            s.subs.insert(id, sub);
        }
        answer(l, initial);
    });
}

/// Tests: answers `msgs` as the port does on one connection (`main`: over the unix transport),
/// without a transport; the replies in order.
pub(crate) fn answer_all(db: &ReadOnly, conn: ConnId, main: bool, msgs: Vec<Msg>) -> Vec<Msg> {
    if main {
        db.locked(|l| l.port.main(conn));
    }
    msgs.into_iter()
        .map(|m| match m {
            Msg::Auth { secret, session_id, .. } => auth(db, conn, secret.as_ref().map(|s| *s.expose()), session_id),
            Msg::Call { max_reply, method, args, .. } => call(db, conn, max_reply, method, args),
            Msg::Sub { id, max_reply, filter } => {
                let mut got = None;
                sub(db, conn, id, max_reply, filter, &mut |_, m| got = Some(m));
                got.unwrap_or_else(|| error(Code::UNSUPPORTED))
            }
            _ => error(Code::UNSUPPORTED),
        })
        .collect()
}
