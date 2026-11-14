//! The client port, node side (spec/wire.md §11.2 kinds 24-29, spec/sync-transport.md §6): sync
//! carries Auth, Call, Sub and Unsub on its sessions (`osis_sync::PortEvent`) and the handle
//! answers them here, off the node lock, as ordinary calls on itself or, for a client-actor
//! session, on a handle acting as the client's actor (notes/client-port.md §3).
//!
//! Built: Auth (main sessions over the unix transport; client actors by bearer secret, at most
//! `MAX_CONNS_PER_CLIENT` sessions each), the end of a client-actor session checked at every
//! request, and the method table's `GET`. Not built: every other method of the table (answered
//! as unknown, `[1, 11, text]`), subscriptions (a Sub is answered `[1, 11, text]`), write nonces
//! (no method writes), `max_clients`, thin clients (`Osis::connect`).

use crate::error::{Error, Result};
use crate::handle::ReadOnly;
use crate::watch::lock;
use osis_base::{Tid, Value};
use osis_proto::api::{ApiCode, Outcome};
use osis_proto::{Code, Msg};
use osis_sync::{ConnId, PortEvent};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::Ordering;

/// The method table (notes/client-port.md §2), as far as it is built.
pub mod method {
    /// `GET [tid, ak] -> Opt(value)`: an aspect's whole value, untyped.
    pub const GET: u64 = 1;
}

/// Who a session acts as.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Who {
    /// The node's main actor (a unix session).
    Main,
    /// A client actor, by the hash of the secret its Auth sent.
    Client { actor: Tid, hash: [u8; 32] },
}

/// The client port's sessions on this node's connections.
#[derive(Debug, Default)]
pub(crate) struct Port {
    /// Connections over the unix transport (`Osis::step`).
    main: BTreeSet<ConnId>,
    sessions: BTreeMap<ConnId, Who>,
}

impl Port {
    /// `conn` runs over the unix transport: its Auth without a secret makes a main session.
    pub fn main(&mut self, conn: ConnId) {
        self.main.insert(conn);
    }

    fn closed(&mut self, conn: ConnId) {
        self.main.remove(&conn);
        self.sessions.remove(&conn);
    }
}

/// Serves the client port's requests taken from sync, in order, on one thread at a time (a
/// call made while serving queues its own for this loop).
pub(crate) fn serve(db: &ReadOnly) {
    let inner = &db.inner;
    loop {
        if inner.port_busy.swap(true, Ordering::AcqRel) {
            return;
        }
        while let Some(ev) = lock(&inner.port_in).pop_front() {
            match ev {
                PortEvent::Closed(conn) => db.locked(|l| l.port.closed(conn)),
                PortEvent::Request(conn, id, m) => {
                    let answer = request(db, conn, *m);
                    db.locked(|l| {
                        let o = l.node.port_answer(conn, id, answer);
                        l.out.extend(o);
                    });
                }
            }
        }
        inner.port_busy.store(false, Ordering::Release);
        // a request queued after the last pop and before the flag fell is served now
        if lock(&inner.port_in).is_empty() {
            return;
        }
    }
}

fn error(code: Code) -> Msg {
    Msg::Error { id: 0, code }
}

fn reply(outcome: Outcome) -> Msg {
    Msg::Reply { id: 0, outcome }
}

/// The answer to one request on `conn`.
fn request(db: &ReadOnly, conn: ConnId, m: Msg) -> Msg {
    match m {
        Msg::Auth { secret, .. } => auth(db, conn, secret.as_ref().map(|s| *s.expose())),
        Msg::Call { max_reply, method, args, .. } => {
            let Some(who) = session(db, conn) else { return error(Code::REFUSED) };
            let h = match who {
                Who::Main => crate::Osis::internal(db.inner.clone()),
                Who::Client { actor, .. } => crate::Osis::internal(db.inner.clone()).act_as(actor),
            };
            let outcome = match call(&h, method, args) {
                Ok(v) => Outcome::Ok { value: v },
                Err(e) => outcome_of(&e),
            };
            let limit = usize::try_from(max_reply).unwrap_or(usize::MAX);
            if reply(outcome.clone()).encode().len() > limit {
                return reply(Outcome::too_large(limit));
            }
            reply(outcome)
        }
        Msg::Sub { .. } => match session(db, conn) {
            None => error(Code::REFUSED),
            Some(_) => reply(Outcome::Err { code: ApiCode::UNSUPPORTED, detail: vec![Value::Str("no subscription filter is served".into())] }),
        },
        Msg::Unsub { .. } => Msg::Ok { id: 0 },
        _ => error(Code::UNSUPPORTED),
    }
}

/// Auth (spec/wire.md §11.2): a main session on the unix transport without a secret; a
/// client-actor session elsewhere with its bearer secret, once.
fn auth(db: &ReadOnly, conn: ConnId, secret: Option<[u8; 32]>) -> Msg {
    let (main, had) = db.locked(|l| (l.port.main.contains(&conn), l.port.sessions.get(&conn).copied()));
    let who = match (secret, main) {
        (None, true) => Who::Main,
        (Some(s), false) if !matches!(had, Some(Who::Client { .. })) => {
            let hash = osis_base::hash::hash(&s);
            let Some(actor) = client_of(db, &hash) else { return error(Code::REFUSED) };
            let n = db.locked(|l| l.port.sessions.iter().filter(|(c, w)| **c != conn && matches!(w, Who::Client { actor: a, .. } if *a == actor)).count());
            if n >= osis_proto::limits::MAX_CONNS_PER_CLIENT {
                return error(Code::RATE_LIMITED);
            }
            Who::Client { actor, hash }
        }
        _ => return error(Code::REFUSED),
    };
    db.locked(|l| l.port.sessions.insert(conn, who));
    reply(Outcome::Ok { value: Value::List(Vec::new()) })
}

/// The client actor of the `clients^.0` entry whose secret hash is `hash`, its `until` not
/// passed (compared in constant time).
fn client_of(db: &ReadOnly, hash: &[u8; 32]) -> Option<Tid> {
    let now = db.inner.clock.now_wall_ms();
    let entries = db.at(db.inner.node, osis_schema::core_types::CLIENTS).get().ok()??;
    entries.into_iter().find(|(_, c)| same(&c.secret_hash, hash) && c.until.is_none_or(|u| u.0 > now.0)).map(|(a, _)| a)
}

fn same(a: &[u8; 32], b: &[u8; 32]) -> bool {
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// The session on `conn`, checked now: a client-actor session ends when its entry goes, its
/// secret hash changes or its `until` passes (spec/wire.md §11.2 End of a client-actor session).
fn session(db: &ReadOnly, conn: ConnId) -> Option<Who> {
    let who = db.locked(|l| l.port.sessions.get(&conn).copied())?;
    if let Who::Client { actor, hash } = who
        && client_of(db, &hash) != Some(actor)
    {
        db.locked(|l| l.port.sessions.remove(&conn));
        return None;
    }
    Some(who)
}

/// Runs method `method` on `h`.
fn call(h: &crate::Osis, method: u64, args: Vec<Value>) -> Result<Value> {
    let bad = || Error::Invalid("malformed arguments".into());
    match method {
        method::GET => {
            let [Value::Tid(t), Value::Str(ak)] = args.as_slice() else { return Err(bad()) };
            let ak = osis_base::Ak::new(ak).map_err(|_| bad())?;
            let v = h.at(*t, crate::DynamicAspectKey::untyped(ak)).get()?;
            Ok(Value::List(v.into_iter().collect()))
        }
        m => Err(Error::Unsupported(format!("unknown method {m}"))),
    }
}

/// An API error as a Reply's outcome (spec/wire.md §11.2 Outcome error codes).
fn outcome_of(e: &Error) -> Outcome {
    let text = |s: &str| vec![Value::Str(s.to_string())];
    let (code, detail) = match e {
        Error::UnknownThing { tid } => (ApiCode::UNKNOWN_THING, vec![Value::Tid(*tid)]),
        Error::UnknownActor { tid } => (ApiCode::UNKNOWN_ACTOR, vec![Value::Tid(*tid)]),
        Error::Permission { tid, needs } => (ApiCode::PERMISSION, vec![Value::Tid(*tid), Value::uint(*needs as u64)]),
        Error::TooLarge { limit } => (ApiCode::TOO_LARGE, vec![Value::uint(*limit as u64)]),
        Error::Invalid(m) => (ApiCode::INVALID, text(m)),
        Error::Storage(m) => (ApiCode::STORAGE, text(m)),
        Error::Network(m) => (ApiCode::NETWORK, text(m)),
        Error::Unsupported(m) => (ApiCode::UNSUPPORTED, text(m)),
        Error::Closed => (ApiCode::CLOSED, Vec::new()),
        Error::InUse => (ApiCode::IN_USE, Vec::new()),
        e => (ApiCode::INVALID, text(&e.to_string())),
    };
    Outcome::Err { code, detail }
}

/// Tests: answers `msgs` as the port does on one connection (`main`: over the unix transport),
/// without a transport.
pub(crate) fn answer_all(db: &ReadOnly, conn: ConnId, main: bool, msgs: Vec<Msg>) -> Vec<Msg> {
    if main {
        db.locked(|l| l.port.main(conn));
    }
    msgs.into_iter().map(|m| request(db, conn, m)).collect()
}
