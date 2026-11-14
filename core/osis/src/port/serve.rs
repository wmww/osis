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
//! recently used going. Each Auth first drops the sessions that ended and the outcomes of every
//! client that can no longer authenticate, so the whole is bounded by the clients that can.

use super::codec::{self, bad, list, opt, outcome_of, read_to, tid};
use super::{MAX_CLIENTS, WRITE_NONCES, filter, method};
use crate::error::{Error, Result};
use crate::handle::{Locked, ReadOnly};
use crate::read::Reader;
use crate::watch::{Delivery, Digest, Filter, ReadAt, Subscription, digest};
use osis_base::{Ak, Tid, Value};
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

    /// Drops the sessions that ended (`current`: the clients that authenticate now, by actor)
    /// and the write outcomes of every client not among them; returns the sessions, to drop off
    /// the lock (their subscriptions).
    fn prune(&mut self, current: &BTreeMap<Tid, [u8; 32]>) -> Vec<Session> {
        let live = |w: Who| match w {
            Who::Main => true,
            Who::Client { actor, hash } => current.get(&actor) == Some(&hash),
        };
        let ended: Vec<ConnId> = self.sessions.iter().filter(|(_, s)| !live(s.who)).map(|(c, _)| *c).collect();
        self.nonces.retain(|(ident, _), _| ident.is_none_or(|a| current.contains_key(&a)));
        ended.into_iter().filter_map(|c| self.sessions.remove(&c)).collect()
    }

    /// Tests: the sessions and the nonce sessions held.
    pub fn held(&self) -> (usize, usize) {
        (self.sessions.len(), self.nonces.len())
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
/// sessions of one client and `MAX_CLIENTS` of all. Ended sessions go first: they hold no slot,
/// and a client that can no longer authenticate keeps no write outcomes, so what the port holds
/// is bounded by the clients that can (no timer needed: every later request of an ended
/// session is checked when it runs).
fn auth(db: &ReadOnly, conn: ConnId, secret: Option<[u8; 32]>, id: [u8; 16]) -> Msg {
    let current = clients(db);
    let gone = db.locked(|l| l.port.prune(&current));
    drop(gone);
    let (main, had) = db.locked(|l| (l.port.main.contains(&conn), l.port.sessions.get(&conn).map(|s| s.who)));
    let who = match (secret, main) {
        (None, true) => Who::Main,
        (Some(s), false) if !matches!(had, Some(Who::Client { .. })) => {
            let hash = osis_base::hash::hash(&s);
            let Some(actor) = holder(&current, &hash) else { return error(Code::REFUSED) };
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

/// The `clients^.0` entries that authenticate now (`until` not passed): actor to secret hash.
fn clients(db: &ReadOnly) -> BTreeMap<Tid, [u8; 32]> {
    let now = db.inner.clock.now_wall_ms();
    let entries = db.read_local(|r| r.get(db.inner.node, &osis_schema::core_types::CLIENTS)).ok().flatten().unwrap_or_default();
    entries.into_iter().filter(|(_, c)| c.until.is_none_or(|u| u.0 > now.0)).map(|(a, c)| (a, c.secret_hash)).collect()
}

/// The client actor of `current` whose secret hash is `hash` (compared in constant time).
fn holder(current: &BTreeMap<Tid, [u8; 32]>, hash: &[u8; 32]) -> Option<Tid> {
    current.iter().find(|(_, h)| same(h, hash)).map(|(a, _)| *a)
}

/// The client actor of the `clients^.0` entry whose secret hash is `hash`, its `until` not
/// passed.
fn client_of(db: &ReadOnly, hash: &[u8; 32]) -> Option<Tid> {
    holder(&clients(db), hash)
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
        method::GROUPS_OF => {
            let t = here(h, one_tid(&args)?)?;
            Ok(codec::groups_of_to(&h.read_local(|r| r.groups_of(t))))
        }
        method::GRANTS => {
            let t = here(h, one_tid(&args)?)?;
            Ok(codec::grants_to(&h.read_local(|r| r.grants(t))))
        }
        method::ROLE_ON => {
            let t = here(h, one_tid(&args)?)?;
            Ok(opt(h.read_local(|r| r.role_on(t))?.map(codec::role_to)))
        }
        method::HOLDERS => {
            let t = here(h, one_tid(&args)?)?;
            Ok(codec::holders_to(&h.read_local(|r| crate::share::holders_in(r, t))))
        }
        method::CREATED => {
            let t = here(h, one_tid(&args)?)?;
            Ok(codec::thing_stamp_to(h.read_local(|r| r.created(t))))
        }
        method::CHANGED => {
            let t = here(h, one_tid(&args)?)?;
            Ok(codec::thing_stamp_to(h.read_local(|r| r.changed(t))))
        }
        method::STATUS => Ok(codec::status_to(&h.locked(|l| crate::syncing::status_in(l, h.acting))?)),
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

/// What a Sub watches (its filter, notes/client-port.md §2).
enum Watched {
    Value(Tid, crate::DynamicAspectKey, Path),
    Thing(Tid),
    Grants(Tid),
    Status,
}

fn watched(f: Value) -> Result<Watched> {
    let mut f = list(f, "filter")?;
    let kind = f.first().and_then(Value::as_uint);
    let rest = f.split_off(f.len().min(1));
    match kind {
        Some(filter::VALUE) => place(rest).map(|(t, k, p)| Watched::Value(t, k, p)),
        Some(filter::THING) => one_tid(&rest).map(Watched::Thing),
        Some(filter::GRANTS) => one_tid(&rest).map(Watched::Grants),
        Some(filter::STATUS) if rest.is_empty() => Ok(Watched::Status),
        Some(filter::STATUS) => Err(bad("filter")),
        _ => Err(Error::Unsupported("no such filter".into())),
    }
}

/// What a subscription's callback makes of a delivery: the Notifies to push, each its value and
/// the `source` it goes as above `max_reply`.
type Tell = Box<dyn FnMut(&crate::Osis, Delivery) -> Vec<(Value, Value)> + Send>;

/// Reads with `f` as `actor` (a callback's handle is the node's own).
fn read_as<R>(db: &ReadOnly, actor: Option<Tid>, f: impl FnOnce(&mut Reader<'_>) -> R) -> R {
    let limit = db.inner.limit;
    db.locked(|l| f(&mut Reader { e: l.engine(), limit, actor }))
}

/// `t`'s `ak` read as `actor`, as a Notify of a thing filter when it reads otherwise than `last`
/// (absent when never told: a thing the actor may not read tells nothing).
fn aspect_told(db: &ReadOnly, actor: Option<Tid>, last: &mut BTreeMap<Ak, Option<Digest>>, t: Tid, ak: Ak, origin: &crate::Origin, limit: Value) -> Option<(Value, Value)> {
    let value = read_as(db, actor, |r| r.value(t, &ak));
    let now = digest(&value);
    if value.is_ok() && last.get(&ak).copied().unwrap_or(digest(&Ok(None))) == now {
        return None;
    }
    last.insert(ak.clone(), now);
    Some((Value::List(vec![codec::ak_to(&ak), read_to(&value), codec::origin_to(origin)]), Value::List(vec![codec::ak_to(&ak), limit])))
}

/// The value a Sub's Reply carries and how it goes on: each kind read as `actor`, so a thing it
/// may not read answers and tells exactly what a never known one does.
fn watch(l: &mut Locked, read_limit: usize, actor: Option<Tid>, w: Watched, limit: usize) -> Result<(Value, Filter, Tell)> {
    let mut r = Reader { e: l.engine(), limit: read_limit, actor };
    let source = Value::uint(limit as u64);
    Ok(match w {
        Watched::Value(t, k, p) => {
            let ak = k.ak.clone();
            let read = ReadAt::new(move |r| {
                let a = std::mem::replace(&mut r.actor, actor);
                let v = r.get_path(t, &k, &p);
                r.actor = a;
                v
            });
            let first = read.0(&mut r);
            let mut last = digest(&first);
            let tell: Tell = Box::new(move |_, d| {
                let Delivery::Aspect { value, origin, .. } = d else { return Vec::new() };
                let now = digest(&value);
                if value.is_ok() && now == last {
                    return Vec::new();
                }
                last = now;
                vec![(Value::List(vec![read_to(&value), codec::origin_to(&origin)]), source.clone())]
            });
            (read_to(&first), Filter::Aspect(t, ak, read), tell)
        }
        Watched::Thing(t) => {
            let mut last = BTreeMap::new();
            let mut first = Vec::new();
            for ak in r.aspects(t)? {
                let v = r.value(t, &ak);
                last.insert(ak.clone(), digest(&v));
                first.push(Value::List(vec![codec::ak_to(&ak), read_to(&v)]));
            }
            let tell: Tell = Box::new(move |db, d| match d {
                Delivery::Aspect { ak, origin, .. } => aspect_told(db, actor, &mut last, t, ak, &origin, source.clone()).into_iter().collect(),
                // every aspect it told or holds now, read again
                Delivery::Reread => {
                    let mut aks: std::collections::BTreeSet<Ak> = last.keys().cloned().collect();
                    aks.extend(read_as(db, actor, |r| r.aspects(t)).unwrap_or_default());
                    let origin = crate::Origin::Derived(crate::DerivedFrom::Recovered);
                    aks.into_iter().filter_map(|ak| aspect_told(db, actor, &mut last, t, ak, &origin, source.clone())).collect()
                }
                _ => Vec::new(),
            });
            (Value::List(first), Filter::Thing(t), tell)
        }
        Watched::Grants(t) => {
            let first = codec::grants_to(&r.grants(t));
            let mut last = first.clone();
            let tell: Tell = Box::new(move |db, d| {
                if !matches!(d, Delivery::Grants) {
                    return Vec::new();
                }
                let now = codec::grants_to(&read_as(db, actor, |r| r.grants(t)));
                if now == last {
                    return Vec::new();
                }
                last = now.clone();
                vec![(now, source.clone())]
            });
            (first, Filter::Grants(t), tell)
        }
        Watched::Status => {
            let first = codec::status_to(&crate::syncing::status_in(l, actor)?);
            let mut last = first.clone();
            let tell: Tell = Box::new(move |db, d| {
                if !matches!(d, Delivery::Due) {
                    return Vec::new();
                }
                let Ok(now) = db.locked(|l| crate::syncing::status_in(l, actor)) else { return Vec::new() };
                let now = codec::status_to(&now);
                if now == last {
                    return Vec::new();
                }
                last = now.clone();
                vec![(now, source.clone())]
            });
            (first, Filter::Status, tell)
        }
    })
}

/// Pushes a delivery of subscription `id` on `conn`; one with no room lapses it (the client
/// subscribes again): `false`.
fn push(db: &ReadOnly, conn: ConnId, id: osis_sync::session::RequestId, limit: usize, value: Value, source: Value) -> bool {
    let mut m = Msg::Notify { sub_id: id, payload: Payload::Delivery { value } };
    if m.encode().len() > limit {
        m = Msg::Notify { sub_id: id, payload: Payload::TooLarge { source } };
    }
    db.locked(|l| match l.node.port_push(conn, m, false) {
        Some(o) => {
            l.out.extend(o);
            true
        }
        None => {
            let gone = l.port.sessions.get_mut(&conn).and_then(|s| s.subs.remove(&id));
            let o = l.node.port_push(conn, Msg::Notify { sub_id: id, payload: Payload::Lapsed }, true).unwrap_or_default();
            l.out.extend(o);
            drop(gone);
            false
        }
    })
}

/// A Sub: the filter's value now in its Reply and a Notify each time it reads otherwise, read
/// as the session's actor at each send (notes/client-port.md §2 Subscriptions as pushes).
fn sub(db: &ReadOnly, conn: ConnId, id: osis_sync::session::RequestId, max_reply: u64, f: Value, answer: &mut dyn FnMut(&mut Locked, Msg)) {
    let mut refuse = |m: Msg| db.locked(|l| answer(l, m));
    let Some((who, _)) = session(db, conn) else { return refuse(error(Code::REFUSED)) };
    let w = match watched(f) {
        Ok(w) => w,
        Err(e) => return refuse(reply(outcome_of(&e))),
    };
    let h = handle(db, who);
    if let Watched::Value(t, ..) | Watched::Thing(t) | Watched::Grants(t) = &w
        && let Err(e) = here(&h, *t)
    {
        return refuse(reply(outcome_of(&e)));
    }
    let acting = h.acting;
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
        let (first, filter, mut tell) = match watch(l, db.inner.limit, acting, w, limit) {
            Ok(x) => x,
            Err(e) => return answer(l, reply(outcome_of(&e))),
        };
        let initial = reply(Outcome::Ok { value: first });
        if initial.encode().len() > limit {
            return answer(l, reply(Outcome::too_large(limit)));
        }
        let cb = Box::new(move |db: &crate::Osis, d: Delivery| {
            let out = tell(db, d);
            // the session is checked at every send: an ended one hears nothing more
            if out.is_empty() || session(db, conn).is_none() {
                return;
            }
            for (value, source) in out {
                if !push(db, conn, id, limit, value, source) {
                    return;
                }
            }
        });
        let sub = db.subscribe_in(l, filter, false, cb);
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
