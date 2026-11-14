//! The client port end to end (spec/wire.md §11.2 kinds 24-29, spec/sync-transport.md §6,
//! spec/sync-set.md §5): thin clients (`Osis::connect`, `connect_socket`) and group sources
//! (`connect_node`, `group_source`) against nodes on one in-process test network
//! (`internals::ManualNet`), one manual clock. A call on the test network runs it until quiet.

use crate::common::{ak, cfg, clock};
use osis::internals::{ManualClock, ManualNet};
use osis::{AppConfig, ClientSecret, DynamicAspectKey, Error, GroupSource, MemStore, NodeLogin, Origin, Osis, Role, Tid, Value};
use std::sync::mpsc::{Receiver, channel};
use std::sync::Arc;

/// Node `seed` on `net`, listening.
fn node(net: &ManualNet, seed: u64, c: &Arc<ManualClock>) -> (Osis, osis::Address) {
    let mut o = cfg(seed, MemStore::new(), c);
    o.app.internals.net = Some(net.clone());
    let db = osis::internals::create(o).unwrap();
    let addr = db.listen(&["peer://127.0.0.1:1".parse().unwrap()]).unwrap().remove(0);
    (db, addr)
}

fn app(net: &ManualNet, c: &Arc<ManualClock>) -> AppConfig {
    let mut a = AppConfig::default();
    a.internals.net = Some(net.clone());
    a.internals.clock = Some(c.clone());
    a.internals.seed = Some(900);
    a
}

/// Polls `f` once: on the test network a connection is made within one poll.
fn ready<T>(f: impl std::future::Future<Output = T>) -> T {
    let mut f = std::pin::pin!(f);
    match f.as_mut().poll(&mut std::task::Context::from_waker(std::task::Waker::noop())) {
        std::task::Poll::Ready(v) => v,
        std::task::Poll::Pending => panic!("not ready on the test network"),
    }
}

fn connect(net: &ManualNet, c: &Arc<ManualClock>, addr: &osis::Address, secret: &ClientSecret) -> osis::Result<Osis> {
    ready(Osis::connect(&[NodeLogin { addr: addr.clone(), secret: secret.clone() }], app(net, c)))
}

fn v() -> DynamicAspectKey {
    DynamicAspectKey::untyped(ak("x:v.0"))
}

/// A node holding thing `t` (`x:v.0` = 5), a client registered, granted `role` on `t`, and the
/// client connected.
struct World {
    net: ManualNet,
    c: Arc<ManualClock>,
    a: Osis,
    addr: osis::Address,
    t: Tid,
    actor: Tid,
    secret: ClientSecret,
}

fn world(role: Option<Role>) -> World {
    let c = clock();
    let net = ManualNet::new(c.clone());
    let (a, addr) = node(&net, 1, &c);
    let mut w = a.write();
    let t = w.create().unwrap();
    w.at(t, v()).set(&Value::Int(5)).unwrap();
    w.commit().unwrap();
    let (actor, secret) = a.add_client(None).unwrap();
    if let Some(r) = role {
        a.grant(t, actor, r, osis::GrantOpts::default()).unwrap();
    }
    World { net, c, a, addr, t, actor, secret }
}

fn changes(db: &Osis, t: Tid) -> (osis::Subscription, Receiver<osis::Change<Value>>) {
    let (tx, rx) = channel();
    let s = db.at(t, v()).on_change(move |_, ch| tx.send(ch).unwrap()).unwrap();
    (s, rx)
}

// spec/sync-transport.md §6 (Client-actor session): a thin client acts as its client actor:
// `me()` is that actor, it reads and writes by the actor's rights, and the node signs.
#[test]
fn a_thin_client_reads_and_writes_as_its_actor_spec_sync_transport_6() {
    let w = world(Some(Role::Write));
    let cl = connect(&w.net, &w.c, &w.addr, &w.secret).unwrap();
    assert!(!cl.has_store());
    assert_eq!((cl.me(), cl.home(), cl.node()), (w.actor, w.actor, w.a.node()));
    assert_eq!(cl.at(w.t, v()).get().unwrap(), Some(Value::Int(5)));
    assert!(cl.has_content(w.t).unwrap());
    assert!(cl.aspects(w.t).unwrap().contains(&ak("x:v.0")));
    let mut x = cl.write();
    x.at(w.t, v()).set(&Value::Int(6)).unwrap();
    let made = x.commit().unwrap().expect("a commit");
    assert_eq!(made.stamp.actor, w.actor);
    assert_eq!(w.a.at(w.t, v()).get().unwrap(), Some(Value::Int(6)));
    assert_eq!(cl.now().unwrap(), w.a.now().unwrap());
}

// spec/wire.md §11.2 (A client actor's rights): a thing the actor may not read answers every
// method as a thing the node does not know, writes included.
#[test]
fn a_hidden_thing_reads_as_unknown_through_a_thin_client_spec_wire_11() {
    let w = world(None);
    let cl = connect(&w.net, &w.c, &w.addr, &w.secret).unwrap();
    let never = Tid::from_bytes([9; 15]);
    for t in [w.t, never] {
        assert_eq!(cl.at(t, v()).get().unwrap(), None);
        assert!(!cl.has_content(t).unwrap());
        assert!(cl.aspects(t).unwrap().is_empty());
        let mut x = cl.write();
        x.at(t, v()).set(&Value::Int(1)).unwrap();
        assert_eq!(x.commit().unwrap_err(), Error::UnknownThing { tid: t }, "as never known");
    }
    assert_eq!(w.a.at(w.t, v()).get().unwrap(), Some(Value::Int(5)));
}

// spec/wire.md §11.2 (A client actor's rights): a write the actor may not make is code 3.
#[test]
fn a_reader_writes_nothing_spec_wire_11() {
    let w = world(Some(Role::Read));
    let cl = connect(&w.net, &w.c, &w.addr, &w.secret).unwrap();
    assert_eq!(cl.at(w.t, v()).get().unwrap(), Some(Value::Int(5)));
    let mut x = cl.write();
    x.at(w.t, v()).set(&Value::Int(6)).unwrap();
    assert!(matches!(x.commit(), Err(Error::Permission { tid, .. }) if tid == w.t));
    assert_eq!(w.a.at(w.t, v()).get().unwrap(), Some(Value::Int(5)));
}

// notes/client-port.md §3: a client's actor goes with the client, so what it makes names a
// first admin that stays (`create_with_admin`); `create()` is `Invalid`.
#[test]
fn a_thin_client_creates_under_a_thing_it_writes_notes_client_port() {
    let w = world(Some(Role::Admin));
    let cl = connect(&w.net, &w.c, &w.addr, &w.secret).unwrap();
    let mut x = cl.write();
    x.create().unwrap();
    assert!(matches!(x.commit(), Err(Error::Invalid(_))));
    let mut x = cl.write();
    let n = x.create_with_admin(w.t).unwrap();
    x.at(n, v()).set(&Value::Int(1)).unwrap();
    x.commit().unwrap();
    assert_eq!(w.a.at(n, v()).get().unwrap(), Some(Value::Int(1)));
    assert_eq!(cl.at(n, v()).get().unwrap(), Some(Value::Int(1)));
}

// notes/client-port.md, Decoder limits: a write through a node carries at most `MAX_WRITE_OPS`
// (1024) ops.
#[test]
fn a_write_through_a_node_is_bounded_notes_client_port() {
    let w = world(Some(Role::Write));
    let cl = connect(&w.net, &w.c, &w.addr, &w.secret).unwrap();
    let mut x = cl.write();
    for i in 0..1025 {
        x.at(w.t, v()).set(&Value::Int(i)).unwrap();
    }
    assert!(matches!(x.commit(), Err(Error::Invalid(_))));
    let mut x = cl.write();
    for i in 0..1024 {
        x.at(w.t, v()).set(&Value::Int(i)).unwrap();
    }
    x.commit().unwrap();
    assert_eq!(w.a.at(w.t, v()).get().unwrap(), Some(Value::Int(1023)));
}

// spec/sync-transport.md §6, notes/client-port.md §1: a watch at the node hears the value at
// once, then each change wherever made; once dropped it hears nothing and the node's
// subscription goes at its next change.
#[test]
fn a_watch_through_a_thin_client_spec_sync_transport_6() {
    use osis::internals::Internals as _;
    let w = world(Some(Role::Write));
    let cl = connect(&w.net, &w.c, &w.addr, &w.secret).unwrap();
    let before = w.a.watches();
    let (sub, rx) = changes(&cl, w.t);
    cl.settle();
    let first = rx.try_recv().unwrap();
    assert_eq!((first.value, first.origin), (Ok(Some(Value::Int(5))), Origin::Initial));
    crate::common::commit_with(&w.a, |x| x.at(w.t, v()).set(&Value::Int(6)));
    cl.settle();
    let ch = rx.try_recv().unwrap();
    assert_eq!(ch.value, Ok(Some(Value::Int(6))));
    assert!(matches!(ch.origin, Origin::Local(s) if s.actor == w.a.me()), "{:?}", ch.origin);
    let mut x = cl.write();
    x.at(w.t, v()).set(&Value::Int(7)).unwrap();
    x.commit().unwrap();
    cl.settle();
    let ch = rx.try_recv().unwrap();
    assert!(matches!(ch.origin, Origin::Local(s) if s.actor == w.actor), "{:?}", ch.origin);
    assert!(rx.try_recv().is_err(), "an unchanged value is not told again");
    assert_eq!(w.a.watches(), before + 1);
    drop(sub);
    crate::common::commit_with(&w.a, |x| x.at(w.t, v()).set(&Value::Int(8)));
    cl.settle();
    assert!(rx.try_recv().is_err());
    cl.settle();
    assert_eq!(w.a.watches(), before, "unsubscribed at the node");
}

// spec/wire.md §11.2 (End of a client-actor session): removing the client ends its session:
// every later call is refused, and its watches hear nothing more.
#[test]
fn a_removed_client_is_refused_spec_wire_11() {
    let w = world(Some(Role::Write));
    let cl = connect(&w.net, &w.c, &w.addr, &w.secret).unwrap();
    let (_sub, rx) = changes(&cl, w.t);
    cl.settle();
    rx.try_recv().unwrap();
    assert!(w.a.remove_client(w.actor).unwrap());
    // no request in between: the Notify's own check ends it
    crate::common::commit_with(&w.a, |x| x.at(w.t, v()).set(&Value::Int(6)));
    w.a.settle();
    w.net.run();
    cl.settle();
    assert!(rx.try_recv().is_err(), "an ended session hears nothing");
    assert!(matches!(cl.at(w.t, v()).get(), Err(Error::Refused(_))));
    assert!(matches!(connect(&w.net, &w.c, &w.addr, &w.secret), Err(Error::Refused(_))));
}

// notes/client-port.md §1: a thin client carries only what the port carries; every other call
// says `Unsupported`, never an answer of its own.
#[test]
fn a_thin_client_answers_nothing_of_its_own_notes_client_port() {
    let w = world(Some(Role::Admin));
    let cl = connect(&w.net, &w.c, &w.addr, &w.secret).unwrap();
    let u = |r: Result<(), Error>| assert!(matches!(r, Err(Error::Unsupported(_))), "{r:?}");
    let t = w.t;
    u(cl.add_client(None).map(drop));
    u(cl.clients().map(drop));
    u(cl.grant(t, w.actor, Role::Read, osis::GrantOpts::default()));
    u(cl.writes(&osis::Scope::Thing(t), &osis::CommitQuery::default()).map(drop));
    u(cl.undo(&osis::Scope::Thing(t)).map(drop));
    u(cl.on_diagnostic(|_, _| {}).map(drop));
    u(cl.contact_card().map(drop));
    u(cl.profile().map(drop));
    u(cl.nodes().map(drop));
    u(cl.links().map(drop));
    u(cl.pair_offer().map(drop));
    u(cl.listen(&[]).map(drop));
    u(cl.at(t, v()).path(osis::p![]).edit_text().map(drop));
    u(ready(cl.connect_node(&NodeLogin { addr: w.addr.clone(), secret: w.secret.clone() })));
    u(ready(cl.group_source(t, GroupSource::Local)));
}

// ---- the node side, request by request ----

use osis::internals::proto::Msg;
use osis::internals::proto::api::{ApiCode, Outcome};

fn auth_as(secret: Option<&ClientSecret>, session: u8) -> Msg {
    Msg::Auth { id: 1, secret: secret.map(|s| osis::internals::Secret32::from_bytes(*s.expose())), session_id: [session; 16] }
}

/// A WRITE of nonce `nonce` overwriting `t`'s `x:v.0` with `n` (an overwrite always writes).
fn write_call(nonce: u64, actor: Tid, t: Tid, n: i64) -> Msg {
    let op = Value::List(vec![Value::uint(2), Value::Tid(t), Value::uint(0), Value::List(vec![Value::List(vec![]), Value::List(vec![Value::uint(1), Value::Int(n)])])]);
    let args = vec![Value::uint(nonce), Value::Tid(actor), Value::List(vec![Value::Str("x:v.0".into())]), Value::List(vec![op]), Value::List(vec![])];
    Msg::Call { id: 3, max_reply: 1 << 20, method: osis::internals::port_method::WRITE, args }
}

const RESENT: u64 = 1 << 62;

fn outcome(m: &Msg) -> &Outcome {
    match m {
        Msg::Reply { outcome, .. } => outcome,
        m => panic!("not a reply: {m:?}"),
    }
}

fn unknown(m: &Msg) -> bool {
    matches!(outcome(m), Outcome::Err { code, .. } if *code == ApiCode::OUTCOME_UNKNOWN)
}

fn error_code(m: &Msg) -> Option<u64> {
    match m {
        Msg::Error { code, .. } => Some(code.0),
        _ => None,
    }
}

// spec/wire.md §11.2 (Write nonces), spec/sync-transport.md §6: a resend (bit 62) of a write
// the node remembers gets its first outcome and does not run again, on any connection of the
// session; a node holding nothing of the session answers resends code 12 and runs none until
// the session's next new write; a resend at or below the highest nonce run and not remembered
// is code 12; above it, it runs.
#[test]
fn write_nonces_spec_wire_11() {
    let w = world(None);
    let (a, t, me) = (&w.a, w.t, w.a.me());
    let r = osis::internals::port_answers(a, 1, true, vec![auth_as(None, 1), write_call(1, me, t, 10), write_call(1 | RESENT, me, t, 11)]);
    assert!(matches!(outcome(&r[1]), Outcome::Ok { .. }));
    assert_eq!(r[1], r[2], "the first outcome, not run again");
    assert_eq!(a.at(t, v()).get().unwrap(), Some(Value::Int(10)));
    // the same session on a new connection
    let r = osis::internals::port_answers(a, 2, true, vec![auth_as(None, 1), write_call(1 | RESENT, me, t, 12)]);
    assert!(matches!(outcome(&r[1]), Outcome::Ok { .. }));
    assert_eq!(a.at(t, v()).get().unwrap(), Some(Value::Int(10)));
    // a session the node holds nothing of
    let r = osis::internals::port_answers(a, 3, true, vec![auth_as(None, 2), write_call(5 | RESENT, me, t, 13), write_call(6 | RESENT, me, t, 14), write_call(7, me, t, 15), write_call(6 | RESENT, me, t, 16), write_call(9 | RESENT, me, t, 17)]);
    assert!(unknown(&r[1]) && unknown(&r[2]), "{r:?}");
    assert!(matches!(outcome(&r[3]), Outcome::Ok { .. }));
    assert!(unknown(&r[4]), "at or below the highest run");
    assert!(matches!(outcome(&r[5]), Outcome::Ok { .. }), "above it: never received");
    assert_eq!(a.at(t, v()).get().unwrap(), Some(Value::Int(17)));
}

/// `m` encoded, each `from` tid's bytes made `to`'s.
fn bytes_as(m: &Msg, from: Tid, to: Tid) -> Vec<u8> {
    let (mut b, f, t) = (m.encode(), *from.as_bytes(), *to.as_bytes());
    let mut i = 0;
    while i + f.len() <= b.len() {
        if b[i..i + f.len()] == f[..] {
            b[i..i + f.len()].copy_from_slice(&t);
            i += f.len();
        } else {
            i += 1;
        }
    }
    b
}

// spec/wire.md §11.2 (A client actor's rights): a thing the actor may not read answers every
// method as a thing the node does not know: byte for byte the answers of every row, a write and
// a subscription included, are a never-known thing's.
#[test]
fn a_hidden_thing_answers_as_a_never_known_one_spec_wire_11() {
    let w = world(None);
    shared_in_home(&w.a, w.t);
    let never = Tid::from_bytes([9; 15]);
    let call = |method: u64, args: Vec<Value>| Msg::Call { id: 3, max_reply: 1 << 20, method, args };
    let m = osis::internals::port_method::GET;
    let rows = |t: Tid, session: u8| {
        let (tv, ak) = (Value::Tid(t), Value::Str("x:v.0".into()));
        let at = |path: Vec<Value>| vec![tv.clone(), ak.clone(), Value::List(path)];
        let index = Value::List(vec![Value::uint(3), Value::uint(0)]);
        vec![
            auth_as(Some(&w.secret), session),
            call(osis::internals::port_method::WHOAMI, vec![]),
            call(m, at(vec![])),
            call(m, at(vec![index.clone()])),
            call(m, vec![tv.clone(), Value::Str("created.0".into()), Value::List(vec![])]),
            call(m, vec![tv.clone(), Value::Str("group.0".into()), Value::List(vec![])]),
            call(osis::internals::port_method::ASPECTS, vec![tv.clone()]),
            call(osis::internals::port_method::HAS_CONTENT, vec![tv.clone()]),
            call(osis::internals::port_method::HOLDS, vec![tv.clone()]),
            call(osis::internals::port_method::GROUPS_OF, vec![tv.clone()]),
            call(osis::internals::port_method::GRANTS, vec![tv.clone()]),
            call(osis::internals::port_method::ROLE_ON, vec![tv.clone()]),
            call(osis::internals::port_method::HOLDERS, vec![tv.clone()]),
            call(osis::internals::port_method::CREATED, vec![tv.clone()]),
            call(osis::internals::port_method::CHANGED, vec![tv.clone()]),
            call(osis::internals::port_method::STATUS, vec![]),
            write_call(1, w.actor, t, 7),
            write_call(2 | RESENT, w.actor, t, 7),
            Msg::Sub { id: 4, max_reply: 1 << 16, filter: Value::List(vec![Value::uint(0), tv.clone(), ak.clone(), Value::List(vec![])]) },
            Msg::Sub { id: 5, max_reply: 1 << 16, filter: Value::List(vec![Value::uint(0), tv.clone(), ak, Value::List(vec![index])]) },
            Msg::Sub { id: 6, max_reply: 1 << 16, filter: Value::List(vec![Value::uint(1), tv.clone()]) },
            Msg::Sub { id: 7, max_reply: 1 << 16, filter: Value::List(vec![Value::uint(2), tv]) },
            Msg::Sub { id: 8, max_reply: 1 << 16, filter: Value::List(vec![Value::uint(3)]) },
        ]
    };
    let hidden = osis::internals::port_answers(&w.a, 1, false, rows(w.t, 1));
    let unknown = osis::internals::port_answers(&w.a, 2, false, rows(never, 2));
    assert!(matches!(&hidden[0], Msg::Reply { .. }), "{hidden:?}");
    for (h, u) in hidden.iter().zip(&unknown) {
        assert_eq!(bytes_as(h, w.t, never), u.encode(), "{h:?} / {u:?}");
    }
    assert_eq!(w.a.at(w.t, v()).get().unwrap(), Some(Value::Int(5)));
    // the node itself, whose `clients^.0` holds every client's secret hash, is such a thing
    let node = osis::internals::port_answers(&w.a, 3, false, vec![auth_as(Some(&w.secret), 3), call(m, vec![Value::Tid(w.a.node()), Value::Str("clients^.0".into()), Value::List(vec![])])]);
    assert_eq!(bytes_as(&node[1], w.a.node(), never), unknown[2].encode(), "{node:?}");
}

// spec/wire.md §11.2 (A client actor's rights): a watch on a thing the actor may not read hears
// what a watch on a never-known thing hears, nothing when the thing changes; one on a thing it
// reads hears the change.
#[test]
fn a_hidden_thing_notifies_nothing_spec_wire_11() {
    let w = world(None);
    let mut x = w.a.write();
    let seen = x.create().unwrap();
    x.at(seen, v()).set(&Value::Int(1)).unwrap();
    x.commit().unwrap();
    w.a.grant(seen, w.actor, Role::Read, osis::GrantOpts::default()).unwrap();
    let cl = connect(&w.net, &w.c, &w.addr, &w.secret).unwrap();
    let never = Tid::from_bytes([9; 15]);
    let (_a, hidden) = changes(&cl, w.t);
    let (_b, unknown) = changes(&cl, never);
    let (_c, read) = changes(&cl, seen);
    cl.settle();
    for rx in [&hidden, &unknown] {
        let first = rx.try_recv().unwrap();
        assert_eq!((first.value, first.origin), (Ok(None), Origin::Initial));
    }
    read.try_recv().unwrap();
    for n in 6..9 {
        crate::common::commit_with(&w.a, |x| {
            x.at(w.t, v()).set(&Value::Int(n))?;
            x.at(seen, v()).set(&Value::Int(n))
        });
        cl.settle();
        assert_eq!(read.try_recv().unwrap().value, Ok(Some(Value::Int(n))));
    }
    assert!(hidden.try_recv().is_err() && unknown.try_recv().is_err());
}

// spec/wire.md §11.2 (an ended session (below) counts toward neither): an ended session is no
// authenticated one, so it holds no place under `max_clients`; a client that can no longer
// authenticate (removed, or past its `until`) keeps no write outcomes at the node.
#[test]
fn ended_sessions_hold_nothing_spec_wire_11() {
    let w = world(Some(Role::Write));
    let until = osis::Time(w.a.now().unwrap().0 + 60_000);
    let mut clients: Vec<(Tid, ClientSecret)> = (0..7).map(|_| w.a.add_client(None).unwrap()).collect();
    clients.push(w.a.add_client(Some(until)).unwrap());
    for (actor, _) in &clients {
        w.a.grant(w.t, *actor, Role::Write, osis::GrantOpts::default()).unwrap();
    }
    let mut conn = 100;
    for (i, (actor, s)) in clients.iter().enumerate() {
        for k in 0..8u8 {
            conn += 1;
            let r = osis::internals::port_answers(&w.a, conn, false, vec![auth_as(Some(s), k), write_call(1, *actor, w.t, (i * 8) as i64 + k as i64)]);
            assert!(matches!(outcome(&r[1]), Outcome::Ok { .. }), "{r:?}");
        }
    }
    assert_eq!(osis::internals::port_held(&w.a), (64, 64));
    let late = w.a.add_client(None).unwrap().1;
    let r = osis::internals::port_answers(&w.a, conn + 1, false, vec![auth_as(Some(&late), 1)]);
    assert_eq!(error_code(&r[0]), Some(4), "full");
    assert!(w.a.remove_client(clients[0].0).unwrap());
    w.c.advance(60_000);
    let r = osis::internals::port_answers(&w.a, conn + 2, false, vec![auth_as(Some(&late), 1)]);
    assert!(matches!(&r[0], Msg::Reply { .. }), "{r:?}");
    assert_eq!(osis::internals::port_held(&w.a), (49, 48), "the removed and the expired client's sessions and outcomes went");
}

// spec/wire.md §11.2 (Auth): past `max_clients` (64) authenticated client-actor sessions of all
// clients, Error 4.
#[test]
fn clients_together_are_bounded_spec_wire_11() {
    let w = world(None);
    let secrets: Vec<ClientSecret> = (0..9).map(|_| w.a.add_client(None).unwrap().1).collect();
    let mut conn = 100;
    for s in &secrets[..8] {
        for _ in 0..8 {
            conn += 1;
            let r = osis::internals::port_answers(&w.a, conn, false, vec![auth_as(Some(s), 1)]);
            assert!(matches!(&r[0], Msg::Reply { .. }), "{r:?}");
        }
    }
    let r = osis::internals::port_answers(&w.a, conn + 1, false, vec![auth_as(Some(&secrets[8]), 1)]);
    assert_eq!(error_code(&r[0]), Some(4));
}

// spec/wire.md §11.2 (Subscriptions): at most `MAX_SUBS` (4096) live subscriptions per
// connection, Error 4 past it; a Sub reusing a live subscription's id is Error 2
// (spec/wire.md §11.1).
#[test]
fn subscriptions_per_connection_are_bounded_spec_wire_11() {
    let w = world(None);
    let filter = Value::List(vec![Value::uint(0), Value::Tid(w.t), Value::Str("x:v.0".into()), Value::List(vec![])]);
    let sub = |id: u32| Msg::Sub { id, max_reply: 1 << 16, filter: filter.clone() };
    let mut msgs = vec![auth_as(None, 1)];
    msgs.extend((1..=4096).map(sub));
    msgs.push(sub(1));
    msgs.push(sub(5000));
    let r = osis::internals::port_answers(&w.a, 1, true, msgs);
    assert!(r[1..=4096].iter().all(|m| matches!(outcome(m), Outcome::Ok { .. })));
    assert_eq!(error_code(&r[4097]), Some(2), "a live id reused");
    assert_eq!(error_code(&r[4098]), Some(4), "past the cap");
}

/// A directory of its own, removed at the end.
struct Dir(std::path::PathBuf);

impl Dir {
    fn new(name: &str) -> Dir {
        use std::hash::{BuildHasher, Hasher};
        let mut h = std::collections::hash_map::RandomState::new().build_hasher();
        h.write_u8(0);
        let d = std::env::temp_dir().join(format!("osis-{name}-{}-{:x}", std::process::id(), h.finish()));
        std::fs::create_dir_all(&d).unwrap();
        Dir(d)
    }
}

impl Drop for Dir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

// spec/sync-transport.md §6 (`unix:///path`): a session on the node's socket is a main session,
// acting as the node's main actor: its `me`, its reads, its writes.
#[test]
fn a_socket_client_is_the_main_actor_spec_sync_transport_6() {
    let dir = Dir::new("port-socket");
    let c = clock();
    let net = ManualNet::new(c.clone());
    let mut o = osis::internals::Opening::at(osis::Store::Dir(dir.0.clone()));
    o.app.internals.seed = Some(1);
    o.app.internals.clock = Some(c.clone());
    o.app.internals.net = Some(net.clone());
    let a = osis::internals::create(o).unwrap();
    a.listen_socket().unwrap();
    let t = crate::common::commit_with(&a, |x| {
        let t = x.create()?;
        x.at(t, v()).set(&Value::Int(5))
    });
    let t = t.parts().next().unwrap().0;
    let cl = ready(Osis::connect_socket(&dir.0, app(&net, &c))).unwrap();
    assert_eq!((cl.me(), cl.home(), cl.node()), (a.me(), a.home(), a.node()));
    assert_eq!(cl.at(t, v()).get().unwrap(), Some(Value::Int(5)));
    let mut x = cl.write();
    x.at(t, v()).set(&Value::Int(6)).unwrap();
    assert_eq!(x.commit().unwrap().unwrap().stamp.actor, a.me());
    assert_eq!(a.at(t, v()).get().unwrap(), Some(Value::Int(6)));
}

// spec/sync-transport.md §6 (Client-actor session): a client's secret goes over a keyed
// transport only: `connect` refuses a socket address.
#[test]
fn a_secret_never_goes_to_a_socket_spec_sync_transport_6() {
    let w = world(None);
    let sock: osis::Address = format!("unix:///tmp/x.sock#{}", w.addr.to_string().split('#').nth(1).unwrap()).parse().unwrap();
    assert!(matches!(connect(&w.net, &w.c, &sock, &w.secret), Err(Error::Invalid(_))));
}

// spec/sync-transport.md §6 (Client-actor session), as notes/client-port.md Reconnect has it: a
// lost connection is `Network` to calls and to watches; once the node is back, a call dials
// again, and the watch hears the value again.
#[test]
fn a_lost_connection_comes_back_spec_sync_transport_6() {
    let w = world(Some(Role::Write));
    let cl = connect(&w.net, &w.c, &w.addr, &w.secret).unwrap();
    let (_sub, rx) = changes(&cl, w.t);
    cl.settle();
    assert_eq!(rx.try_recv().unwrap().value, Ok(Some(Value::Int(5))));
    w.net.set_online(0, false);
    w.net.run();
    cl.settle();
    assert!(matches!(rx.try_recv().unwrap().value, Err(Error::Network(_))));
    assert!(matches!(cl.at(w.t, v()).get(), Err(Error::Network(_))));
    w.net.set_online(0, true);
    w.net.run();
    // the call finding it down dials again, failing at once; the next finds it up
    assert!(matches!(cl.at(w.t, v()).get(), Err(Error::Network(_))));
    w.net.run();
    assert_eq!(cl.at(w.t, v()).get().unwrap(), Some(Value::Int(5)));
    crate::common::commit_with(&w.a, |x| x.at(w.t, v()).set(&Value::Int(6)));
    cl.settle();
    let got: Vec<_> = rx.try_iter().map(|c| c.value).collect();
    assert_eq!(got, vec![Ok(Some(Value::Int(5))), Ok(Some(Value::Int(6)))]);
}

// ---- group sources ----

fn login(w: &World) -> NodeLogin {
    NodeLogin { addr: w.addr.clone(), secret: w.secret.clone() }
}

// spec/sync-set.md §5: a group sourced at another node is read and written there as this
// node's client actor; this node's own identity and process-wide calls stay its own; a read
// this port does not carry is `Unsupported`; moved home, it reads this node's copy again.
#[test]
fn a_group_read_at_another_node_spec_sync_set_5() {
    let w = world(Some(Role::Write));
    let (b, _) = node(&w.net, 2, &w.c);
    assert!(matches!(ready(b.group_source(w.t, GroupSource::Node(w.addr.clone()))), Err(Error::Invalid(_))), "not connected");
    ready(b.connect_node(&login(&w))).unwrap();
    assert_eq!(b.at(w.t, v()).get().unwrap(), None, "not sourced yet: this node's own answer");
    ready(b.group_source(w.t, GroupSource::Node(w.addr.clone()))).unwrap();
    assert_eq!(b.group_sources().into_iter().collect::<Vec<_>>(), vec![(w.t, w.addr.clone())]);
    assert_eq!(b.at(w.t, v()).get().unwrap(), Some(Value::Int(5)));
    let mut x = b.write();
    x.at(w.t, v()).set(&Value::Int(6)).unwrap();
    assert_eq!(x.commit().unwrap().unwrap().stamp.actor, w.actor);
    assert_eq!(w.a.at(w.t, v()).get().unwrap(), Some(Value::Int(6)));
    assert_eq!(b.grants(w.t).unwrap(), w.a.grants(w.t).unwrap(), "read at the source");
    assert!(matches!(b.undo(&osis::Scope::Thing(w.t)), Err(Error::Unsupported(_))));
    assert!(b.has_store());
    b.status().unwrap();
    ready(b.group_source(w.t, GroupSource::Local)).unwrap();
    assert_eq!(b.at(w.t, v()).get().unwrap(), None);
    assert!(b.disconnect_node(&w.addr).unwrap());
    assert!(!b.disconnect_node(&w.addr).unwrap());
}

// spec/sync-set.md §5: a write on a thing sourced at another node is refused while a group
// carrying it syncs here.
#[test]
fn a_split_thing_refuses_writes_spec_sync_set_5() {
    let w = world(Some(Role::Write));
    let (b, _) = node(&w.net, 2, &w.c);
    let home = b.home();
    let mut x = b.write();
    let (t, g) = (x.create().unwrap(), x.create().unwrap());
    x.group(home).add(osis::Member::Subgroup(g)).unwrap();
    x.group(g).add(osis::Member::Item(t)).unwrap();
    x.group(home).add(osis::Member::Item(t)).unwrap();
    x.commit().unwrap();
    ready(b.connect_node(&login(&w))).unwrap();
    ready(b.group_source(g, GroupSource::Node(w.addr.clone()))).unwrap();
    let mut x = b.write();
    x.at(t, v()).set(&Value::Int(1)).unwrap();
    assert!(matches!(x.commit(), Err(Error::Invalid(_))));
}

// notes/client-port.md, Moving: group sources outlive the process; until the node is
// connected again, the group's calls fail `Network`, never this node's copy.
#[test]
fn group_sources_are_kept_notes_client_port() {
    let w = world(Some(Role::Write));
    let store = MemStore::new();
    let open = |create: bool| {
        let mut o = cfg(2, store.clone(), &w.c);
        o.app.internals.net = Some(w.net.clone());
        if create { osis::internals::create(o).unwrap() } else { osis::internals::open(o).unwrap() }
    };
    let b = open(true);
    ready(b.connect_node(&login(&w))).unwrap();
    ready(b.group_source(w.t, GroupSource::Node(w.addr.clone()))).unwrap();
    assert_eq!(b.close().unwrap(), osis::Close::Closed);
    let b = open(false);
    assert_eq!(b.group_sources().into_iter().collect::<Vec<_>>(), vec![(w.t, w.addr.clone())]);
    assert!(matches!(b.at(w.t, v()).get(), Err(Error::Network(_))));
    ready(b.connect_node(&login(&w))).unwrap();
    assert_eq!(b.at(w.t, v()).get().unwrap(), Some(Value::Int(5)));
}

// spec/sync-transport.md §6 (Client-actor session), spec/wire.md §11.2 (Write nonces): a write
// whose answer was lost is sent again, marked, once the connection is back, and the node
// answers it with its first outcome: it applied once.
#[test]
fn a_write_whose_answer_was_lost_applies_once_spec_sync_transport_6() {
    let w = world(Some(Role::Write));
    let cl = connect(&w.net, &w.c, &w.addr, &w.secret).unwrap();
    let before = w.a.writes(&osis::Scope::Thing(w.t), &osis::CommitQuery::default()).unwrap().commits.len();
    w.net.lose_next_bytes_to(1);
    let mut x = cl.write();
    x.at(w.t, v()).overwrite(&Value::Int(6)).unwrap();
    let made = x.commit().unwrap().unwrap();
    let after = w.a.writes(&osis::Scope::Thing(w.t), &osis::CommitQuery::default()).unwrap().commits;
    assert_eq!(after.len(), before + 1, "applied once");
    assert_eq!(after[0].stamp.id, made.stamp.id);
}

// spec/sync-transport.md §6 (`unix:///path`), over the product's transports: a socket client
// of a node on its own runtime reads, writes and watches as the main actor, and a watch hears
// a change made at the node.
#[test]
fn a_socket_client_over_a_real_socket_spec_sync_transport_6() {
    let dir = Dir::new("port-real-socket");
    let mut o = osis::internals::Opening::at(osis::Store::Dir(dir.0.clone()));
    o.runtime = osis::Runtime::Own;
    o.direct_sync = false;
    let a = osis::internals::create(o).unwrap();
    a.listen_socket().unwrap();
    let t = crate::common::commit_with(&a, |x| {
        let t = x.create()?;
        x.at(t, v()).set(&Value::Int(5))
    })
    .parts()
    .next()
    .unwrap()
    .0;
    let cl = crate::common::block_on(Osis::connect_socket(&dir.0, AppConfig::default())).unwrap();
    assert_eq!(cl.me(), a.me());
    assert_eq!(cl.at(t, v()).get().unwrap(), Some(Value::Int(5)));
    let (_sub, rx) = changes(&cl, t);
    assert_eq!(rx.recv_timeout(std::time::Duration::from_secs(60)).unwrap().value, Ok(Some(Value::Int(5))));
    crate::common::commit_with(&a, |x| x.at(t, v()).set(&Value::Int(6)));
    assert_eq!(rx.recv_timeout(std::time::Duration::from_secs(60)).unwrap().value, Ok(Some(Value::Int(6))));
    let mut x = cl.write();
    x.at(t, v()).set(&Value::Int(7)).unwrap();
    x.commit().unwrap();
    assert_eq!(a.at(t, v()).get().unwrap(), Some(Value::Int(7)));
    drop(cl);
}

/// One write of every kind of op on `t` (and a creation under it), through `db`.
fn every_op(db: &Osis, t: Tid) -> Tid {
    let k = |a: &str| db.aspect_key(a).unwrap();
    let mut x = db.write();
    let n = x.create_with_admin(t).unwrap();
    x.at(n, k("x:v.0")).set(&Value::Int(1)).unwrap();
    x.at(t, k("x:m.0")).path(osis::p!["b"]).set(&Value::Int(2)).unwrap();
    x.at(t, k("x:o.0")).overwrite(&Value::Str("o".into())).unwrap();
    x.at(t, k("x:l.0")).set(&Value::List(vec![Value::Int(1), Value::Int(2), Value::Int(3)])).unwrap();
    x.at(t, k("x:s.0")).path(osis::p![]).add(&Value::Int(4)).unwrap();
    x.at(t, k("x:gone.0")).set(&Value::Int(0)).unwrap();
    x.commit().unwrap();
    let mut x = db.write();
    x.at(t, k("x:l.0")).path(osis::p![]).splice(1..2, &[Value::Int(9), Value::Int(8)]).unwrap();
    x.at(t, k("x:l.0")).path(osis::p![]).move_range(0..1, 3).unwrap();
    x.at(t, k("x:m.0")).edit(&Value::Map(Default::default()), &Value::Map([(Value::Str("c".into()), Value::Bool(true))].into_iter().collect())).unwrap();
    x.at(t, k("x:gone.0")).remove().unwrap();
    x.at(t, k("x:o.0")).retention(osis::Retention::default()).set(&Value::Str("p".into())).unwrap();
    x.commit().unwrap();
    n
}

// notes/client-port.md, Wire: a write's ops cross the port as they were recorded, the node
// typing each aspect by its own schemas: the same ops through a thin client and on the node
// itself read alike, on the node and through the client.
#[test]
fn every_op_reads_alike_through_a_thin_client_notes_client_port() {
    let w = world(Some(Role::Admin));
    w.a.register_schema("t.osis", "revision 1;\naspect x:l.0: list<int>;\n").unwrap();
    let here = crate::common::commit_with(&w.a, |x| x.create_with_admin(w.t).map(drop)).parts().next().unwrap().0;
    w.a.grant(here, w.actor, Role::Admin, osis::GrantOpts::default()).unwrap();
    let cl = connect(&w.net, &w.c, &w.addr, &w.secret).unwrap();
    let n_here = every_op(&w.a, here);
    let n_there = every_op(&cl, w.t);
    for a in ["x:m.0", "x:o.0", "x:l.0", "x:s.0", "x:gone.0"] {
        let k = DynamicAspectKey::untyped(ak(a));
        let local = w.a.at(here, k.clone()).get().unwrap();
        assert_eq!(w.a.at(w.t, k.clone()).get().unwrap(), local, "{a}");
        assert_eq!(cl.at(w.t, k).get().unwrap(), local, "{a} through the client");
    }
    assert_eq!(w.a.at(n_there, v()).get().unwrap(), w.a.at(n_here, v()).get().unwrap());
}

fn get_call(t: Tid) -> Msg {
    Msg::Call { id: 2, max_reply: 1 << 16, method: osis::internals::port_method::GET, args: vec![Value::Tid(t), Value::Str("x:v.0".into()), Value::List(vec![])] }
}

// notes/client-port.md, Catching up (the port never waits on another node): a node's own
// clients get nothing it reads at another node: its copy may be behind. A client actor reads
// such a thing as unknown and cannot write it; a main session's row is `Unsupported`; no
// write goes on to the other node.
#[test]
fn a_nodes_clients_get_nothing_it_reads_elsewhere_notes_client_port() {
    let w = world(Some(Role::Write));
    let (b, _) = node(&w.net, 2, &w.c);
    let mut x = b.write();
    let (t, g) = (x.create().unwrap(), x.create().unwrap());
    x.group(g).add(osis::Member::Item(t)).unwrap();
    x.at(t, v()).set(&Value::Int(3)).unwrap();
    x.commit().unwrap();
    let (actor, secret) = b.add_client(None).unwrap();
    b.grant(t, actor, Role::Write, osis::GrantOpts::default()).unwrap();
    let read = |main: bool, conn: u64| {
        let a = if main { auth_as(None, conn as u8) } else { auth_as(Some(&secret), conn as u8) };
        osis::internals::port_answers(&b, conn, main, vec![a, get_call(t), write_call(1, if main { b.me() } else { actor }, t, 9)])
    };
    let r = read(false, 1);
    assert_eq!(outcome(&r[1]), &Outcome::Ok { value: Value::List(vec![Value::uint(0), Value::List(vec![Value::Int(3)])]) }, "readable here first");
    ready(b.connect_node(&login(&w))).unwrap();
    ready(b.group_source(g, GroupSource::Node(w.addr.clone()))).unwrap();
    let r = read(false, 2);
    assert_eq!(outcome(&r[1]), &Outcome::Ok { value: Value::List(vec![Value::uint(0), Value::List(vec![])]) }, "as unknown");
    assert!(matches!(outcome(&r[2]), Outcome::Err { code, .. } if *code == ApiCode::UNKNOWN_THING), "{r:?}");
    let r = read(true, 3);
    assert!(matches!(outcome(&r[1]), Outcome::Err { code, .. } if *code == ApiCode::UNSUPPORTED), "{r:?}");
    assert!(matches!(outcome(&r[2]), Outcome::Err { code, .. } if *code == ApiCode::UNSUPPORTED), "{r:?}");
    assert_eq!(w.a.at(t, v()).get().unwrap(), None, "nothing went on to the other node");
}

// spec/wire.md §11.2 (Write nonces), notes/client-port.md Writes: a node keeps the last
// `WRITE_NONCES` (64) outcomes of a session, and per identity as many sessions as its
// connection cap (the main actor's: `max_clients`, 64), least recently used going; a resend of
// what it forgot is code 12, never run again.
#[test]
fn write_outcomes_are_bounded_spec_wire_11() {
    let w = world(None);
    let (a, t, me) = (&w.a, w.t, w.a.me());
    let mut msgs = vec![auth_as(None, 1)];
    msgs.extend((1..=65).map(|n| write_call(n, me, t, n as i64)));
    msgs.push(write_call(2 | RESENT, me, t, 0));
    msgs.push(write_call(1 | RESENT, me, t, 0));
    let r = osis::internals::port_answers(a, 1, true, msgs);
    assert!(matches!(outcome(&r[66]), Outcome::Ok { .. }), "the 64th last is kept");
    assert!(unknown(&r[67]), "the 65th last is not");
    // 64 more sessions: the first, least recently used, goes
    for s in 2..=65u8 {
        let r = osis::internals::port_answers(a, u64::from(s), true, vec![auth_as(None, s), write_call(1, me, t, 100 + i64::from(s))]);
        assert!(matches!(outcome(&r[1]), Outcome::Ok { .. }));
    }
    let r = osis::internals::port_answers(a, 100, true, vec![auth_as(None, 1), write_call(65 | RESENT, me, t, 0), write_call(1 | RESENT, me, t, 0)]);
    assert!(unknown(&r[1]), "session 1 forgotten");
    let r = osis::internals::port_answers(a, 101, true, vec![auth_as(None, 65), write_call(1 | RESENT, me, t, 0)]);
    assert!(matches!(outcome(&r[1]), Outcome::Ok { .. }), "session 65 kept");
    assert_eq!(a.at(t, v()).get().unwrap(), Some(Value::Int(165)), "no resend ran");
}

// ---- sharing, stamps, status and their watches through a connection ----

/// Puts `t` in `a`'s home and grants it to another actor, so it has grants, a group and a sync
/// ID of its own (in `a`'s status).
fn shared_in_home(a: &Osis, t: Tid) {
    crate::common::commit_with(a, |x| x.group(a.home()).add(osis::Member::Item(t)).map(drop));
    let other = a.add_client(None).unwrap().0;
    a.grant(t, other, Role::Read, osis::GrantOpts::default()).unwrap();
    assert!(a.status().unwrap().groups.contains_key(&t), "{:?}", a.status());
}

// notes/client-port.md §2 (method table), spec/wire.md §11.2 (A client actor's rights): a thin
// client reads groups, grants, roles, holders and stamps at its node, as its actor: a group it
// may not read is not listed.
#[test]
fn sharing_reads_through_a_thin_client_spec_wire_11() {
    let w = world(Some(Role::Write));
    shared_in_home(&w.a, w.t);
    let cl = connect(&w.net, &w.c, &w.addr, &w.secret).unwrap();
    assert_eq!(cl.grants(w.t).unwrap(), w.a.grants(w.t).unwrap());
    assert_eq!(cl.role_on(w.t).unwrap(), Some(Role::Write));
    assert_eq!(w.a.role_on(w.t).unwrap(), Some(Role::Admin));
    let (there, all) = (cl.holders(w.t).unwrap(), w.a.holders(w.t).unwrap());
    assert!(there.iter().any(|h| h.actor == w.actor && h.role == Role::Write && h.through.is_empty()), "{there:?}");
    assert!(there.iter().all(|h| all.contains(h)), "{there:?}");
    assert!(all.iter().filter(|h| !there.contains(h)).all(|h| !h.through.is_empty()), "only what is behind an actor it may not read goes");
    assert_eq!(cl.created(w.t).unwrap(), w.a.created(w.t).unwrap());
    assert!(cl.created(w.t).unwrap().is_some());
    assert_eq!(cl.changed(w.t).unwrap(), w.a.changed(w.t).unwrap());
    assert!(w.a.groups_of(w.t).unwrap().item_of.contains(&w.a.home()));
    assert_eq!(cl.groups_of(w.t).unwrap(), osis::GroupsOf::default(), "home is no group the client reads");
}

// spec/wire.md §11.2 (Status): a client actor's status shows the things it may read and counts
// the connections with one of them open; a thing it may not read is not there, as a never-known
// one is not.
#[test]
fn status_shows_a_client_what_it_reads_spec_wire_11() {
    let w = world(Some(Role::Read));
    let mut x = w.a.write();
    let hidden = x.create().unwrap();
    x.at(hidden, v()).set(&Value::Int(1)).unwrap();
    x.commit().unwrap();
    shared_in_home(&w.a, w.t);
    shared_in_home(&w.a, hidden);
    let cl = connect(&w.net, &w.c, &w.addr, &w.secret).unwrap();
    let s = cl.status().unwrap();
    assert!(s.groups.contains_key(&w.t) && !s.groups.contains_key(&hidden), "{s:?}");
    assert!(s.groups.keys().all(|t| *t == w.t || *t == w.actor), "its own actor's sync ID beside it: {s:?}");
    assert_eq!(s.groups[&w.t], w.a.status().unwrap().groups[&w.t]);
    assert_eq!(s.connected, 0, "no connection has what it reads open");
    assert!(w.a.status().unwrap().connected > 0, "the client's own connection is the node's");
}

// notes/client-port.md §1 (Watches), spec/wire.md §11.2: `on_status_change` through a thin
// client hears the status at once and again when what its actor may read changes it; a lost
// connection shows as nothing connected, each thing `NotConnected` (here no change), and
// `status` fails `Network`.
#[test]
fn a_status_watch_through_a_thin_client_spec_wire_11() {
    let w = world(None);
    shared_in_home(&w.a, w.t);
    let cl = connect(&w.net, &w.c, &w.addr, &w.secret).unwrap();
    let (tx, rx) = channel();
    let _s = cl.on_status_change(move |_, s| tx.send(s).unwrap()).unwrap();
    cl.settle();
    assert!(!rx.try_recv().unwrap().groups.contains_key(&w.t));
    osis::internals::costs::take();
    let hidden = crate::common::commit_with(&w.a, |x| x.create().map(drop)).parts().next().unwrap().0;
    shared_in_home(&w.a, hidden);
    w.a.settle();
    w.net.run();
    cl.settle();
    assert_eq!(notifies(), 0, "a thing it may not read entering the node's status tells nothing");
    assert!(rx.try_recv().is_err());
    w.a.grant(w.t, w.actor, Role::Read, osis::GrantOpts::default()).unwrap();
    w.a.settle();
    w.net.run();
    cl.settle();
    let s = rx.try_iter().last().expect("told");
    assert!(s.groups.contains_key(&w.t), "{s:?}");
    w.net.set_online(0, false);
    w.net.run();
    cl.settle();
    // it showed nothing connected already: nothing new to tell; a call fails
    assert!(rx.try_recv().is_err());
    assert!(matches!(cl.status(), Err(Error::Network(_))));
}

/// The Notifies this thread's thin clients heard since the last `costs::take`.
fn notifies() -> u64 {
    osis::internals::costs::take().into_iter().find(|(k, ..)| *k == "port: notify").map_or(0, |(.., n)| n)
}

/// `on_thing_change` of `t` through `db`, into a channel.
fn thing_changes(db: &Osis, t: Tid) -> (osis::Subscription, Receiver<osis::Change<Value>>) {
    let (tx, rx) = channel();
    let s = db.on_thing_change(t, move |_, ch| tx.send(ch).unwrap()).unwrap();
    (s, rx)
}

// notes/client-port.md §1 (Watches), spec/wire.md §11.2 (A client actor's rights):
// `on_thing_change` through a thin client hears each aspect, then each change; one on a thing
// the actor may not read hears what one on a never-known thing hears: nothing.
#[test]
fn a_thing_watch_through_a_thin_client_spec_wire_11() {
    let w = world(None);
    let mut x = w.a.write();
    let seen = x.create().unwrap();
    x.at(seen, v()).set(&Value::Int(1)).unwrap();
    x.commit().unwrap();
    w.a.grant(seen, w.actor, Role::Read, osis::GrantOpts::default()).unwrap();
    let cl = connect(&w.net, &w.c, &w.addr, &w.secret).unwrap();
    let (_a, hidden) = thing_changes(&cl, w.t);
    let (_b, unknown) = thing_changes(&cl, Tid::from_bytes([9; 15]));
    let (_c, read) = thing_changes(&cl, seen);
    cl.settle();
    let first: Vec<_> = read.try_iter().collect();
    assert!(first.iter().any(|c| c.ak == ak("x:v.0") && c.value == Ok(Some(Value::Int(1))) && c.origin == Origin::Initial), "{first:?}");
    osis::internals::costs::take();
    for n in 6..9 {
        crate::common::commit_with(&w.a, |x| {
            x.at(w.t, v()).set(&Value::Int(n))?;
            x.at(seen, v()).set(&Value::Int(n))
        });
        cl.settle();
        let c = read.try_recv().unwrap();
        assert_eq!((c.ak, c.value), (ak("x:v.0"), Ok(Some(Value::Int(n)))));
        assert!(matches!(c.origin, Origin::Local(s) if s.actor == w.a.me()), "{:?}", c.origin);
    }
    assert!(hidden.try_recv().is_err() && unknown.try_recv().is_err());
    assert_eq!(notifies(), 3, "one per change of the thing it reads, none of the hidden one");
    w.net.set_online(0, false);
    w.net.run();
    cl.settle();
    assert!(read.try_iter().all(|c| matches!(c.value, Err(Error::Network(_)))));
    assert!(hidden.try_recv().is_err() && unknown.try_recv().is_err(), "nothing told, nothing lost");
}

// notes/client-port.md §1 (Watches), spec/wire.md §11.2 (A client actor's rights):
// `on_grants_change` through a thin client hears the grants, then each change; one on a thing
// the actor may not read hears what one on a never-known thing hears: the empty grants, once.
#[test]
fn a_grants_watch_through_a_thin_client_spec_wire_11() {
    let w = world(Some(Role::Read));
    let mut x = w.a.write();
    let hidden = x.create().unwrap();
    x.at(hidden, v()).set(&Value::Int(1)).unwrap();
    x.commit().unwrap();
    let cl = connect(&w.net, &w.c, &w.addr, &w.secret).unwrap();
    let grants = |t: Tid| {
        let (tx, rx) = channel();
        (cl.on_grants_change(t, move |_, g| tx.send(g).unwrap()).unwrap(), rx)
    };
    let (_a, seen) = grants(w.t);
    let (_b, hid) = grants(hidden);
    let (_c, unknown) = grants(Tid::from_bytes([9; 15]));
    cl.settle();
    assert_eq!(seen.try_recv().unwrap().unwrap(), w.a.grants(w.t).unwrap());
    let other = w.a.add_client(None).unwrap().0;
    osis::internals::costs::take();
    w.a.grant(hidden, other, Role::Read, osis::GrantOpts::default()).unwrap();
    cl.settle();
    assert_eq!(notifies(), 0, "a hidden thing's grants change tells nothing on the wire");
    w.a.grant(w.t, other, Role::Read, osis::GrantOpts::default()).unwrap();
    cl.settle();
    assert_eq!(notifies(), 1);
    let now = seen.try_recv().unwrap().unwrap();
    assert!(now.contains_key(&other));
    assert_eq!(now, w.a.grants(w.t).unwrap());
    for rx in [&hid, &unknown] {
        assert_eq!(rx.try_recv().unwrap().unwrap(), osis::Grants::new());
        assert!(rx.try_recv().is_err());
    }
}
