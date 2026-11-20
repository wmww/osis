//! The client port end to end (spec/wire.md §11.2 kinds 24-29, spec/sync-transport.md §6,
//! spec/sync-set.md §5): thin clients (`Osis::connect`, `connect_socket`) and sync unit sources
//! (`connect_node`, `unit_source`) against nodes on one in-process test network
//! (`internals::ManualNet`), one manual clock. A call on the test network runs it until quiet.

use crate::common::Held as _;
use crate::common::TestWrites as _;
use crate::common::{ak, cfg, clock};
use osis::internals::{ManualClock, ManualNet};
use osis::{AppConfig, ClientSecret, DynamicAspectKey, Error, UnitSource, MemStore, NodeLogin, Origin, Osis, Role, Tid, Value};
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
    let t = w.create_held().unwrap();
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
// mint admin that stays; one under its own actor is `Invalid`.
#[test]
fn a_thin_client_creates_under_a_thing_it_writes_notes_client_port() {
    let w = world(Some(Role::Admin));
    let cl = connect(&w.net, &w.c, &w.addr, &w.secret).unwrap();
    let mut x = cl.write();
    x.create(cl.me(), None).unwrap();
    assert!(matches!(x.commit(), Err(Error::Invalid(_))));
    let mut x = cl.write();
    let n = x.create_held_with_admin(w.t).unwrap();
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
    assert!(matches!(ch.origin, Origin::Local(s) if s.author == w.a.me()), "{:?}", ch.origin);
    let mut x = cl.write();
    x.at(w.t, v()).set(&Value::Int(7)).unwrap();
    x.commit().unwrap();
    cl.settle();
    let ch = rx.try_recv().unwrap();
    assert!(matches!(ch.origin, Origin::Local(s) if s.author == w.actor), "{:?}", ch.origin);
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
    u(cl.on_diagnostic(|_, _| {}).map(drop));
    u(cl.contact_card().map(drop));
    u(cl.profile().map(drop));
    u(cl.nodes().map(drop));
    u(cl.links().map(drop));
    u(cl.pair_offer().map(drop));
    u(cl.listen(&[]).map(drop));
    u(cl.at(t, v()).path(osis::p![]).edit_text().map(drop));
    u(ready(cl.connect_node(&NodeLogin { addr: w.addr.clone(), secret: w.secret.clone() })));
    u(ready(cl.unit_source(t, UnitSource::Local)));
}

// ---- the node side, request by request ----

use osis::internals::proto::Msg;
use osis::internals::proto::api::{ApiCode, Outcome};

fn auth_as(secret: Option<&ClientSecret>, session: u8) -> Msg {
    Msg::Auth { id: 1, secret: secret.map(|s| osis::internals::Secret32::from_bytes(*s.expose())), session_id: [session; 16] }
}

/// A WRITE of nonce `nonce` overwriting `t`'s `x:v.0` with `n` (an overwrite always writes).
fn write_call(nonce: u64, actor: Tid, t: Tid, n: i64) -> Msg {
    let op = Value::List(vec![Value::uint(2), Value::bytes(t.as_bytes()), Value::uint(0), Value::List(vec![Value::List(vec![]), Value::List(vec![Value::uint(1), Value::Int(n)])])]);
    let args = vec![Value::uint(nonce), Value::bytes(actor.as_bytes()), Value::List(vec![Value::Str("x:v.0".into())]), Value::List(vec![op]), Value::List(vec![])];
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

/// The commit id in a WRITE's `Opt(commit)` (a commit's stamp first, its id first).
fn made_id(m: &Msg) -> [u8; 32] {
    match outcome(m) {
        Outcome::Ok { value: Value::List(c) } => match c.as_slice() {
            [Value::List(c)] => match c.first() {
                Some(Value::List(stamp)) => <[u8; 32]>::try_from(stamp[0].as_bytes().unwrap()).unwrap(),
                o => panic!("{o:?}"),
            },
            o => panic!("{o:?}"),
        },
        o => panic!("{o:?}"),
    }
}

// spec/wire.md §11.2 (A client actor's rights): a watch on a thing the actor may not read hears
// what a watch on a never-known thing hears, nothing when the thing changes; one on a thing it
// reads hears the change.
#[test]
fn a_hidden_thing_notifies_nothing_spec_wire_11() {
    let w = world(None);
    let mut x = w.a.write();
    let seen = x.create_held().unwrap();
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
    let filter = Value::List(vec![Value::uint(0), Value::bytes(w.t.as_bytes()), Value::Str("x:v.0".into()), Value::List(vec![])]);
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

// ---- sync unit sources ----

fn login(w: &World) -> NodeLogin {
    NodeLogin { addr: w.addr.clone(), secret: w.secret.clone() }
}

// spec/sync-set.md §5: a sync unit sourced at another node is read and written there as this
// node's client actor; this node's own identity and process-wide calls stay its own; a read
// this port does not carry is `Unsupported`; moved back, it reads this node's copy again.
#[test]
fn a_group_read_at_another_node_spec_sync_set_5() {
    let w = world(Some(Role::Write));
    let (b, _) = node(&w.net, 2, &w.c);
    assert!(matches!(ready(b.unit_source(w.t, UnitSource::Node(w.addr.clone()))), Err(Error::Invalid(_))), "not connected");
    ready(b.connect_node(&login(&w))).unwrap();
    assert_eq!(b.at(w.t, v()).get().unwrap(), None, "not sourced yet: this node's own answer");
    ready(b.unit_source(w.t, UnitSource::Node(w.addr.clone()))).unwrap();
    assert_eq!(b.unit_sources().into_iter().collect::<Vec<_>>(), vec![(w.t, w.addr.clone())]);
    assert_eq!(b.at(w.t, v()).get().unwrap(), Some(Value::Int(5)));
    let mut x = b.write();
    x.at(w.t, v()).set(&Value::Int(6)).unwrap();
    assert_eq!(x.commit().unwrap().unwrap().stamp.author, w.actor);
    assert_eq!(w.a.at(w.t, v()).get().unwrap(), Some(Value::Int(6)));
    assert_eq!(b.grants(w.t).unwrap(), w.a.grants(w.t).unwrap(), "read at the source");
    {
        use osis::internals::Internals as _;
        let q = osis::CommitQuery::default();
        assert_eq!(b.writes(&osis::Scope::Thing(w.t), &q), w.a.acting_as(w.actor).writes(&osis::Scope::Thing(w.t), &q), "listed at the source");
    }
    assert!(b.has_store());
    b.status().unwrap();
    ready(b.unit_source(w.t, UnitSource::Local)).unwrap();
    assert_eq!(b.at(w.t, v()).get().unwrap(), None);
    assert!(b.disconnect_node(&w.addr).unwrap());
    assert!(!b.disconnect_node(&w.addr).unwrap());
}

// notes/client-port.md, Moving: sync unit sources outlive the process; until the node is
// connected again, the sync unit's calls fail `Network`, never this node's copy.
#[test]
fn unit_sources_are_kept_notes_client_port() {
    let w = world(Some(Role::Write));
    let store = MemStore::new();
    let open = |create: bool| {
        let mut o = cfg(2, store.clone(), &w.c);
        o.app.internals.net = Some(w.net.clone());
        if create { osis::internals::create(o).unwrap() } else { osis::internals::open(o).unwrap() }
    };
    let b = open(true);
    ready(b.connect_node(&login(&w))).unwrap();
    ready(b.unit_source(w.t, UnitSource::Node(w.addr.clone()))).unwrap();
    assert_eq!(b.close().unwrap(), osis::Close::Closed);
    let b = open(false);
    assert_eq!(b.unit_sources().into_iter().collect::<Vec<_>>(), vec![(w.t, w.addr.clone())]);
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
    let listed = || w.a.writes(&osis::Scope::Thing(w.t), &osis::CommitQuery::default()).unwrap().commits.into_iter().map(|c| c.stamp.id).collect::<Vec<_>>();
    let before = listed();
    w.net.lose_next_bytes_to(1);
    let mut x = cl.write();
    x.at(w.t, v()).overwrite(&Value::Int(6)).unwrap();
    let made = x.commit().unwrap().unwrap();
    let after = listed();
    assert_eq!(after.iter().filter(|c| !before.contains(c)).collect::<Vec<_>>(), vec![&made.stamp.id], "applied once");
    assert_eq!(after[0], made.stamp.id);
}

// spec/sync-transport.md §6 (`unix:///path`), over the product's transports: a socket client
// of a node on its own runtime reads, writes and watches as the main actor, and a watch hears
// a change made at the node.
#[test]
fn a_socket_client_over_a_real_socket_spec_sync_transport_6() {
    let dir = Dir::new("port-real-socket");
    let mut o = osis::internals::Opening::at(osis::Store::Dir(dir.0.clone()));
    o.runtime = osis::Runtime::Own;
    o.app.internals.no_listen = true;
    let a = osis::internals::create(o).unwrap();
    a.listen_socket().unwrap();
    let t = a.commit_with(|x| {
        let t = x.create_held()?;
        x.at(t, v()).set(&Value::Int(5))?;
        Ok(t)
    })
    .unwrap();
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
    let n = x.create_held_with_admin(t).unwrap();
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
    let here = w.a.commit_with(|x| x.create_held_with_admin(w.t)).unwrap();
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

// notes/client-port.md §3 (Revert and undo), spec/wire.md §11.2 (Write nonces): undo, redo and
// revert through a thin client run at the node as its actor, each a write row under a nonce;
// what it would undo reads alike; a commit it did not make is not its to undo.
#[test]
fn undo_through_a_thin_client_spec_wire_11() {
    let w = world(Some(Role::Write));
    let cl = connect(&w.net, &w.c, &w.addr, &w.secret).unwrap();
    crate::common::keep_day(&w.a, w.t, &["x:v.0"]);
    let scope = osis::Scope::Thing(w.t);
    assert_eq!(cl.undo(&scope).unwrap(), None, "the node's own write is no undo of the client's");
    let mut x = cl.write();
    x.at(w.t, v()).set(&Value::Int(6)).unwrap();
    let made = x.commit().unwrap().unwrap();
    assert_eq!(cl.undo_target(&scope).unwrap().map(|c| c.stamp.id), Some(made.stamp.id));
    let undone = cl.undo(&scope).unwrap().expect("undone");
    assert_eq!(undone.stamp.author, w.actor);
    assert_eq!(cl.at(w.t, v()).get().unwrap(), Some(Value::Int(5)));
    assert_eq!(cl.redo_target(&scope).unwrap().map(|c| c.stamp.id), Some(undone.stamp.id));
    cl.redo(&scope).unwrap().expect("redone");
    assert_eq!(w.a.at(w.t, v()).get().unwrap(), Some(Value::Int(6)));
    let back = cl.revert(made.stamp.id).unwrap();
    assert_eq!(back.reverts, Some(made.stamp.id));
    assert_eq!(w.a.at(w.t, v()).get().unwrap(), Some(Value::Int(5)));
}

// spec/wire.md §11.2 (Write nonces): undo, redo and revert are write rows: a resend gets the
// first outcome and runs nothing again (a second undo would undo the next commit back).
#[test]
fn undo_resends_run_once_spec_wire_11() {
    let w = world(Some(Role::Write));
    crate::common::keep_day(&w.a, w.t, &["x:v.0"]);
    let scope = Value::List(vec![Value::uint(0), Value::bytes(w.t.as_bytes())]);
    let row = |nonce: u64, method: u64, arg: Value| Msg::Call { id: 3, max_reply: 1 << 20, method, args: vec![Value::uint(nonce), arg] };
    let (undo, redo, revert) = (osis::internals::port_method::UNDO, osis::internals::port_method::REDO, osis::internals::port_method::REVERT);
    let r = osis::internals::port_answers(&w.a, 1, false, vec![auth_as(Some(&w.secret), 1), write_call(1, w.actor, w.t, 6), write_call(2, w.actor, w.t, 7)]);
    let six = made_id(&r[1]);
    let r = osis::internals::port_answers(&w.a, 1, false, vec![auth_as(Some(&w.secret), 1), row(3, undo, scope.clone()), row(3 | RESENT, undo, scope.clone())]);
    assert!(matches!(outcome(&r[1]), Outcome::Ok { value: Value::List(c) } if c.len() == 1), "{r:?}");
    assert_eq!(r[1], r[2], "the first outcome");
    assert_eq!(w.a.at(w.t, v()).get().unwrap(), Some(Value::Int(6)), "undone once");
    let r = osis::internals::port_answers(&w.a, 1, false, vec![auth_as(Some(&w.secret), 1), row(4, redo, scope.clone()), row(4 | RESENT, redo, scope)]);
    assert_eq!(r[1], r[2]);
    assert_eq!(w.a.at(w.t, v()).get().unwrap(), Some(Value::Int(7)), "redone once");
    let r = osis::internals::port_answers(&w.a, 1, false, vec![auth_as(Some(&w.secret), 1), row(5, revert, Value::Bytes(six.to_vec())), row(5 | RESENT, revert, Value::Bytes(six.to_vec()))]);
    assert!(matches!(outcome(&r[1]), Outcome::Ok { .. }), "{r:?}");
    assert_eq!(r[1], r[2]);
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
    let seen = x.create_held().unwrap();
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
        assert!(matches!(c.origin, Origin::Local(s) if s.author == w.a.me()), "{:?}", c.origin);
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
    let hidden = x.create_held().unwrap();
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

// ---- the API's rows that are one call each (notes/client-port.md §2) ----

/// A node on a store directory, at `net`'s `peer://` address and on its own socket, and a client
/// of it over the socket (the node's main actor, as the CLI beside `osis serve`).
fn daemon(net: &ManualNet, c: &Arc<ManualClock>, seed: u64, name: &str) -> (Dir, Osis, Osis) {
    let dir = Dir::new(name);
    let mut o = osis::internals::Opening::at(osis::Store::Dir(dir.0.clone()));
    o.app.internals.seed = Some(seed);
    o.app.internals.clock = Some(c.clone());
    o.app.internals.net = Some(net.clone());
    let a = osis::internals::create(o).unwrap();
    a.listen(&["peer://127.0.0.1:1".parse().unwrap()]).unwrap();
    a.listen_socket().unwrap();
    let cl = ready(Osis::connect_socket(&dir.0, app(net, c))).unwrap();
    (dir, a, cl)
}

fn signal() -> DynamicAspectKey {
    DynamicAspectKey::untyped(ak("x:log~0"))
}

fn text(x: &str) -> Value {
    Value::Str(x.into())
}

/// A thing keeping its signal's fires and `x:v.0`'s writes for good: `x:v.0` set twice, the
/// signal fired twice and its first fire replaced; the first fire's id.
fn history(db: &Osis) -> (Tid, osis::CommitId) {
    let keep = crate::common::setting(&[("x:log~0", osis::History::FOREVER), ("x:v.0", osis::History::FOREVER)]);
    let t = db
        .commit_with(|w| {
            let t = w.create_held()?;
            w.at(t, osis::core::RETENTION).set(&keep)?;
            w.at(t, v()).set(&Value::Int(1))?;
            Ok(t)
        })
        .unwrap();
    crate::common::commit_with(db, |w| w.at(t, v()).set(&Value::Int(2)));
    let o = crate::common::commit_with(db, |w| w.at(t, signal()).fire(&text("one"))).stamp.id;
    crate::common::commit_with(db, |w| w.at(t, signal()).fire(&text("other")));
    crate::common::commit_with(db, |w| w.at(t, signal()).replace(o, &text("two")).map(drop));
    (t, o)
}

// notes/client-port.md §2: a page through a connection is cut to what one Reply carries,
// saying `more`; read on from its last commit, the pages together are the node's.
#[test]
fn a_listing_page_fits_a_reply_notes_client_port() {
    let c = clock();
    let net = ManualNet::new(c.clone());
    let (_dir, a, cl) = daemon(&net, &c, 1, "port-page");
    let (t, _) = history(&a);
    // past one Reply's bound (`REPLY_BUDGET`) in all, and the bodies a node reads for one page
    // (up to that bound, then one more) too
    let big = "x".repeat(3 << 20);
    for i in 0..4 {
        crate::common::commit_with(&a, |w| w.at(t, v()).set(&text(&format!("{i}{big}"))));
    }
    let all = |db: &Osis| {
        let (mut got, mut from, mut pages) = (Vec::new(), osis::CommitFrom::Newest, 0);
        loop {
            let p = db.at(t, v()).writes(&osis::CommitQuery { from, ..Default::default() }).unwrap();
            pages += 1;
            got.extend(p.commits.iter().map(|c| c.stamp.id));
            match p.commits.last() {
                Some(l) if p.more => from = osis::CommitFrom::Before(l.pos()),
                _ => return (got, pages),
            }
        }
    };
    let (here, one) = all(&a);
    let (there, several) = all(&cl);
    assert_eq!(there, here);
    assert_eq!(one, 1);
    assert!(several > 1, "{several} pages");
}

/// What a commit listener heard since the last call, as (id, the part's body on `t`'s `k`).
fn events(db: &Osis, rx: &Receiver<osis::CommitEvent>, t: Tid, k: &str) -> Vec<(osis::CommitId, Option<osis::Body<Value>>)> {
    db.settle();
    rx.try_iter()
        .map(|e| match e {
            osis::CommitEvent::Commit { id, commit } => (id, commit.map(|c| crate::common::part(&c, t, &ak(k)).body)),
            e => panic!("{e:?}"),
        })
        .collect()
}

// notes/client-port.md §2 (Commits): `on_fire` and `on_write` through a socket client hear each
// commit made at the node, as the node's own listeners do; one dropped hears no more.
#[test]
fn commit_listeners_through_a_socket_notes_client_port() {
    let c = clock();
    let net = ManualNet::new(c.clone());
    let (_dir, a, cl) = daemon(&net, &c, 1, "port-listen");
    let (t, _) = history(&a);
    let (txf, fires) = channel();
    let (txw, writes) = channel();
    let f = cl.at(t, signal()).on_fire(move |_, e| txf.send(e).unwrap()).unwrap();
    let _w = cl.at(t, v()).on_write(move |_, e| txw.send(e).unwrap()).unwrap();
    let (txh, here) = channel();
    let _h = a.at(t, signal()).on_fire(move |_, e| txh.send(e).unwrap()).unwrap();
    let fired = crate::common::commit_with(&a, |w| w.at(t, signal()).fire(&text("new"))).stamp.id;
    let set = crate::common::commit_with(&cl, |w| w.at(t, v()).set(&Value::Int(3))).stamp.id;
    let heard = events(&cl, &fires, t, "x:log~0");
    assert_eq!(heard, vec![(fired, Some(osis::Body::Held(Some(text("new")))))]);
    assert_eq!(heard, events(&a, &here, t, "x:log~0"));
    assert_eq!(events(&cl, &writes, t, "x:v.0"), vec![(set, Some(osis::Body::Held(Some(Value::Int(3)))))]);
    drop(f);
    crate::common::commit_with(&a, |w| w.at(t, signal()).fire(&text("later")));
    // a dropped listener goes at its next Notify, which it does not pass on
    assert_eq!(events(&cl, &fires, t, "x:log~0"), vec![]);
}

// notes/client-port.md §2 (Rows that wait): dropping a wait's future ends it at the node, as
// dropping it locally does.
#[test]
fn a_dropped_wait_ends_at_the_node_notes_client_port() {
    let c = clock();
    let net = ManualNet::new(c.clone());
    let (_dir, a, cl) = daemon(&net, &c, 1, "port-drop-wait");
    // a thing never known there: its wait runs on
    let t = a.write().create_held().unwrap();
    {
        let mut f = std::pin::pin!(cl.wait_synced(osis::SyncScope::Thing(t)));
        for _ in 0..3 {
            assert!(f.as_mut().poll(&mut std::task::Context::from_waker(std::task::Waker::noop())).is_pending(), "never known there");
            net.run();
        }
        assert_eq!(osis::internals::port_waits(&a), 1);
    }
    net.run();
    assert_eq!(osis::internals::port_waits(&a), 0);
}

// notes/client-port.md §2: `on_diagnostic` through a socket client hears the node's
// diagnostics (here: a callback of the node's that panicked).
#[test]
fn diagnostics_through_a_socket_notes_client_port() {
    let c = clock();
    let net = ManualNet::new(c.clone());
    let (_dir, a, cl) = daemon(&net, &c, 1, "port-diag");
    let (tx, rx) = channel();
    let _d = cl.on_diagnostic(move |_, d| tx.send(d).unwrap()).unwrap();
    let t = a.commit_with(|w| w.create_held()).unwrap();
    let _p = a.at(t, v()).on_change(|_, ch| assert!(ch.value != Ok(Some(Value::Int(9))), "a callback that panics")).unwrap();
    crate::common::commit_with(&a, |w| w.at(t, v()).set(&Value::Int(9)));
    a.settle();
    cl.settle();
    let got: Vec<_> = rx.try_iter().collect();
    assert!(got.iter().any(|d| matches!(d, osis::Diagnostic::Callback { .. })), "{got:?}");
}
