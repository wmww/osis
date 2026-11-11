//! Client-port plumbing in the sync engine (notes/client-port.md §0, §2, §5): every listener
//! serves it, through the node's hub; the tier is the transport type's (`Peer::Unix` is main, a
//! key never is), requests go up as actions only after Auth, an authenticated client is exempt
//! from the bound on sessions sharing nothing, a ported session's end is reported.

use crate::net::local_nodes;
use crate::net::*;
use osis_base::{Tid, Value};
use osis_crdt::{Op, PathOp, PathSeg};
use osis_crypto::Secret32;
use osis_node::Mutation;
use osis_node::sync::{Action, ConnId, Event, SyncConfig, Tier};
use osis_schema::Codec;
use osis_schema::core_types as ct;
use osis_proto::{ClientConfig, ClientInput, ClientOutput, ClientSession, Command, Message, Outcome};
use osis_transport::Peer;

const LOCAL: [u8; 32] = [0x42; 32];

/// A client's session on node `n`'s hub: the served session (the engine's ID), the hub's
/// connection and the client's end.
struct Cl {
    conn: ConnId,
    hc: ConnId,
    cs: ClientSession,
}

/// Node `n` carries out `acts`, the client's frames go in, the node's come back; the node's
/// client-port actions meanwhile.
fn feed(net: &mut Net, n: usize, c: &mut Cl, outs: Vec<ClientOutput>, acts: Vec<Action>) -> Vec<Action> {
    net.hand_exchange(n, c.hc, &mut c.cs, acts, outs, false);
    net.take_port(n)
}

/// Node `n` handles `ev`: its actions, carried out (closes reach the hand connections).
fn step(net: &mut Net, n: usize, ev: Event) -> Vec<Action> {
    let acts = net.sync(n).handle(ev);
    net.actions(n, acts.clone());
    acts.into_iter().chain(net.take_port(n)).collect()
}

fn client_on(net: &mut Net, n: usize, key: [u8; 32], peer: Peer) -> Cl {
    let (hc, sent) = net.hand_accept(n, key, peer);
    let mut c = Cl { conn: 0, hc, cs: ClientSession::new(ClientConfig { peer_static_key: key, challenge: [7; 32] }) };
    let now = net.now();
    let mut outs = c.cs.handle(now, ClientInput::Start);
    for f in sent {
        outs.extend(c.cs.handle(now, ClientInput::Bytes(f)));
    }
    feed(net, n, &mut c, outs, Vec::new());
    c.conn = net.served(n, hc);
    c
}

fn client(net: &mut Net, n: usize, peer: Peer) -> Cl {
    client_on(net, n, LOCAL, peer)
}

fn auth(net: &mut Net, n: usize, c: &mut Cl) -> Vec<Action> {
    let now = net.now();
    let outs = c.cs.handle(now, ClientInput::Command(Command::Auth { token: 1, session: [3; 16], secret: None }));
    feed(net, n, c, outs, Vec::new())
}

/// Frames to the hub, one input: what it answered.
fn raw(net: &mut Net, n: usize, c: &Cl, m: &Message) -> Vec<Message> {
    net.hand_input(n, c.hc, osis_proto::encode_frame(&m.encode())).iter().filter_map(|b| Message::decode(&b[4..]).ok()).collect()
}

// spec/sync.md §10 (client port), notes/client-port.md §0, §5: main only from Peer::Unix; a keyed peer's Auth is refused by the sync engine (Error 1) whatever its key, never handed up
#[test]
fn tier_is_the_transport_types() {
    let (mut net, [a]) = local_nodes::<1>();
    let uid = osis_transport::unix::own_uid().unwrap();
    let mut c = client(&mut net, a, Peer::Unix { uid });
    let got = auth(&mut net, a, &mut c);
    assert!(got.iter().any(|x| matches!(x, Action::Request { conn, tier: Tier::Main, msg } if *conn == c.conn && matches!(**msg, Message::Auth { .. }))), "{got:?}");
    // a unix peer of another uid (whatever listener let it in) is never main
    let mut o = client(&mut net, a, Peer::Unix { uid: uid.wrapping_add(1) });
    let got = auth(&mut net, a, &mut o);
    assert!(!got.iter().any(|x| matches!(x, Action::Request { .. })), "{got:?}");
    // a keyed peer presenting the very key a unix peer stands for is still keyed
    let mut k = client(&mut net, a, Peer::Key(osis_transport::unix::uid_key(uid)));
    let got = auth(&mut net, a, &mut k);
    assert!(!got.iter().any(|x| matches!(x, Action::Request { .. })), "{got:?}");
}

// spec/wire.md §11.2, notes/client-port.md §3: Auths pipelined by a keyed peer, one per input, are each refused (Error 1) by the sync engine; none reaches the port worker
#[test]
fn keyed_auth_flood_never_goes_up() {
    let (mut net, [a]) = local_nodes::<1>();
    let k = client(&mut net, a, Peer::Key([9; 32]));
    let mut refused = 0;
    for id in 1..=20_000u32 {
        for m in raw(&mut net, a, &k, &Message::Auth { id, secret: None, session: [0; 16] }) {
            if m == (Message::Error { id, code: osis_proto::Code::REFUSED }) {
                refused += 1;
            }
        }
    }
    assert_eq!(refused, 20_000);
    assert!(net.take_port(a).is_empty());
    assert!(!net.hand_closed(a, k.hc));
}

// spec/sync.md §10 (client port), notes/client-port.md §3: a client acts on the node's one key (the listener of its dialable key, which serves sync too) only after Auth: a Call before it is Error 1 and goes nowhere, a bearer Auth binds the session to its client actor, and its Calls then go up as that actor's; a sync kind on the same session is answered as on any connection
#[test]
fn a_client_acts_on_the_dialable_key_only_after_auth() {
    let mut net = Net::new();
    let a = net.node(1, &[]);
    let key = net.sync(a).dialable_key();
    let actor = Tid::from_bytes([5; 15]);
    set_entry(&mut net, a, actor, Some(entry(&SECRET, None)));
    let mut c = client_on(&mut net, a, key, Peer::Key([9; 32]));
    let call = Message::Call { id: 3, max_reply: osis_proto::client::SMALL_REPLY as u64, method: 0, args: vec![] };
    assert_eq!(raw(&mut net, a, &c, &call), vec![Message::Error { id: 3, code: osis_proto::Code::REFUSED }]);
    assert!(net.take_port(a).is_empty(), "nothing goes up before Auth");
    let (got, code) = bearer(&mut net, a, &mut c, Some(SECRET));
    assert_eq!(code, None);
    let Some((Tier::Client(x), Message::Auth { id, .. })) = request(&got) else { panic!("{got:?}") };
    assert_eq!(x, actor);
    let id = *id;
    let acts = net.sync(a).handle(Event::Reply { conn: c.conn, id, reply: Ok(Outcome::Ok { value: Value::Bytes(vec![0; 16]) }) });
    feed(&mut net, a, &mut c, Vec::new(), acts);
    raw(&mut net, a, &c, &call);
    let got = net.take_port(a);
    assert!(matches!(request(&got), Some((Tier::Client(x), Message::Call { id: 3, .. })) if x == actor), "{got:?}");
    let sub = Message::Subscribe { id: 9, labels: vec![osis_base::LabelId([1; 16])] };
    let r = raw(&mut net, a, &c, &sub);
    assert!(!r.iter().any(|m| matches!(m, Message::Error { code, .. } if *code == osis_proto::Code::UNSUPPORTED)), "{r:?}");
}

// spec/sync.md §5, notes/client-port.md §3: an authenticated client's end is reported
#[test]
fn an_authenticated_clients_end_is_reported() {
    let mut net = Net::new();
    let a = net.add_node(1, SyncConfig::default());
    let uid = osis_transport::unix::own_uid().unwrap();
    let mut c = client(&mut net, a, Peer::Unix { uid });
    let got = auth(&mut net, a, &mut c);
    let Some((_, Message::Auth { id, .. })) = request(&got) else { panic!("{got:?}") };
    let id = *id;
    let acts = net.sync(a).handle(Event::Reply { conn: c.conn, id, reply: Ok(Outcome::Ok { value: Value::Bytes(vec![0; 16]) }) });
    feed(&mut net, a, &mut c, Vec::new(), acts);
    assert!(!net.hand_closed(a, c.hc));
    net.hand_close(a, c.hc);
    assert!(net.take_port(a).contains(&Action::Ended { conn: c.conn }));
}

const SECRET: [u8; 32] = [0x77; 32];

/// Sets (or removes) this node's `clients^.0` entry of `actor` and lets the sync engine see it.
fn set_entry(net: &mut Net, n: usize, actor: Tid, entry: Option<ct::Client>) -> Vec<Action> {
    let me = net.sync(n).engine().tid();
    let mut m = Mutation::new();
    let op = match entry {
        Some(e) => PathOp { path: vec![PathSeg::Key(Value::Tid(actor))], op: Op::Set(e.to_value()) },
        None => PathOp { path: Vec::new(), op: Op::Remove(Value::Tid(actor)) },
    };
    m.op(me, &ct::CLIENTS, op).unwrap();
    net.sync(n).engine_mut().commit(m).unwrap();
    step(net, n, Event::Local)
}

fn entry(secret: &[u8; 32], until: Option<u64>) -> ct::Client {
    ct::Client { secret_hash: osis_base::hash::hash(secret), until: until.map(osis_base::WallMs) }
}

/// A bearer Auth over a keyed session: the client-port actions, and the code the node answered with.
fn bearer(net: &mut Net, n: usize, c: &mut Cl, secret: Option<[u8; 32]>) -> (Vec<Action>, Option<osis_proto::Code>) {
    let now = net.now();
    let outs = c.cs.handle(now, ClientInput::Command(Command::Auth { token: 1, session: [3; 16], secret: secret.map(Secret32::from_bytes) }));
    let mut code = None;
    for o in outs {
        if let ClientOutput::Send(bytes) = o {
            for f in net.hand_input(n, c.hc, bytes) {
                if let Ok(Message::Error { code: x, .. }) = Message::decode(&f[4..]) {
                    code = Some(x);
                }
                let now = net.now();
                c.cs.handle(now, ClientInput::Bytes(f));
            }
        }
    }
    (net.take_port(n), code)
}

fn request(acts: &[Action]) -> Option<(Tier, &Message)> {
    acts.iter().find_map(|a| match a {
        Action::Request { tier, msg, .. } => Some((*tier, &**msg)),
        _ => None,
    })
}

// spec/wire.md §11.2 (Auth), spec/sync.md §10, notes/client-port.md §3: a keyed session's Auth goes up only when its secret's hash is a current entry, bound to that entry's actor with the secret stripped; an unknown secret, no secret, and an entry past its until are Error 1 and never reach the worker; a second Auth on a bound session is Error 1; a main session's Auth with a secret is Error 1
#[test]
fn bearer_auth_gated_in_the_sync_engine() {
    let (mut net, [a]) = local_nodes::<1>();
    let actor = Tid::from_bytes([5; 15]);
    set_entry(&mut net, a, actor, Some(entry(&SECRET, None)));
    for bad in [Some([1u8; 32]), None] {
        let mut k = client(&mut net, a, Peer::Key([9; 32]));
        let (acts, code) = bearer(&mut net, a, &mut k, bad);
        assert_eq!(code, Some(osis_proto::Code::REFUSED));
        assert!(request(&acts).is_none(), "{acts:?}");
    }
    let mut k = client(&mut net, a, Peer::Key([9; 32]));
    let (acts, code) = bearer(&mut net, a, &mut k, Some(SECRET));
    assert_eq!(code, None);
    let (tier, msg) = request(&acts).unwrap();
    assert_eq!(tier, Tier::Client(actor));
    assert!(matches!(msg, Message::Auth { secret: None, .. }), "the worker never sees the secret");
    assert_eq!(net.sync(a).client_of(k.conn), Some(actor));
    let (acts, code) = bearer(&mut net, a, &mut k, Some(SECRET));
    assert_eq!(code, Some(osis_proto::Code::REFUSED));
    assert!(request(&acts).is_none());
    let uid = osis_transport::unix::own_uid().unwrap();
    let mut o = client(&mut net, a, Peer::Unix { uid });
    let (acts, code) = bearer(&mut net, a, &mut o, Some(SECRET));
    assert_eq!(code, Some(osis_proto::Code::REFUSED));
    assert!(request(&acts).is_none());
    assert_eq!(net.sync(a).client_of(o.conn), None, "the main session is no client");
    // expired: past its until at Auth
    let now = net.now();
    let late = Tid::from_bytes([6; 15]);
    set_entry(&mut net, a, late, Some(entry(&[2; 32], Some(now))));
    let mut k2 = client(&mut net, a, Peer::Key([9; 32]));
    let (acts, code) = bearer(&mut net, a, &mut k2, Some([2; 32]));
    assert_eq!(code, Some(osis_proto::Code::REFUSED));
    assert!(request(&acts).is_none());
}

// spec/data-model.md §9, spec/sync.md §10, notes/client-port.md §3: a session ends when its entry goes, when its secret rotates, and at its until by the timer alone (a wake is asked for it, with no other change); an extended until moves the timer; client_of agrees before any of that reaches the session's connection
#[test]
fn bound_sessions_end_with_their_entry() {
    let (mut net, [a]) = local_nodes::<1>();
    let actor = Tid::from_bytes([5; 15]);
    let until = net.now() + 10_000;
    set_entry(&mut net, a, actor, Some(entry(&SECRET, Some(until))));
    let mut k = client(&mut net, a, Peer::Key([9; 32]));
    bearer(&mut net, a, &mut k, Some(SECRET));
    let acts = step(&mut net, a, Event::Tick);
    assert!(acts.iter().any(|x| matches!(x, Action::Wake { at } if *at <= until)), "a wake for its until: {acts:?}");
    // extended: the old end passes without closing
    set_entry(&mut net, a, actor, Some(entry(&SECRET, Some(until + 10_000))));
    net.clock.advance(10_001);
    step(&mut net, a, Event::Tick);
    assert!(!net.hand_closed(a, k.hc));
    // its until passes: client_of says so before a tick does anything
    net.clock.advance(10_000);
    assert_eq!(net.sync(a).client_of(k.conn), None);
    let acts = step(&mut net, a, Event::Tick);
    assert!(net.hand_closed(a, k.hc));
    assert!(acts.contains(&Action::Ended { conn: k.conn }), "{acts:?}");
    // rotated: the old secret's session closes, the old secret is refused, the new one binds
    set_entry(&mut net, a, actor, Some(entry(&SECRET, None)));
    let mut k = client(&mut net, a, Peer::Key([9; 32]));
    bearer(&mut net, a, &mut k, Some(SECRET));
    // the entry written, not yet seen by a step: client_of reads it, so a queued request cannot pass
    let me = net.sync(a).engine().tid();
    let mut m = Mutation::new();
    m.op(me, &ct::CLIENTS, PathOp { path: vec![PathSeg::Key(Value::Tid(actor))], op: Op::Set(entry(&[8; 32], None).to_value()) }).unwrap();
    net.sync(a).engine_mut().commit(m).unwrap();
    assert_eq!(net.sync(a).client_of(k.conn), None, "another secret's hash");
    step(&mut net, a, Event::Local);
    assert!(net.hand_closed(a, k.hc));
    let mut k = client(&mut net, a, Peer::Key([9; 32]));
    assert_eq!(bearer(&mut net, a, &mut k, Some(SECRET)).1, Some(osis_proto::Code::REFUSED));
    assert_eq!(bearer(&mut net, a, &mut k, Some([8; 32])).1, None);
    // removed
    set_entry(&mut net, a, actor, None);
    assert!(net.hand_closed(a, k.hc));
}

// spec/wire.md §11.2, notes/client-port.md §3 and Picked numbers: past MAX_CONNS_PER_CLIENT authenticated connections of one client a further Auth is Error 4 and goes nowhere; another client is unaffected; one ending frees a slot; max_clients bounds all clients together whatever the per-client cap (0 serves none)
#[test]
fn client_connection_caps() {
    let mut net = Net::new();
    let cfg = SyncConfig { max_clients: osis_node::sync::MAX_CONNS_PER_CLIENT + 1, ..SyncConfig::default() };
    let a = net.add_node(1, cfg);
    let (x, y) = (Tid::from_bytes([5; 15]), Tid::from_bytes([6; 15]));
    set_entry(&mut net, a, x, Some(entry(&SECRET, None)));
    set_entry(&mut net, a, y, Some(entry(&[8; 32], None)));
    let mut conns = Vec::new();
    for _ in 0..osis_node::sync::MAX_CONNS_PER_CLIENT {
        let mut k = client(&mut net, a, Peer::Key([9; 32]));
        assert_eq!(bearer(&mut net, a, &mut k, Some(SECRET)).1, None);
        conns.push(k);
    }
    let mut over = client(&mut net, a, Peer::Key([9; 32]));
    let (acts, code) = bearer(&mut net, a, &mut over, Some(SECRET));
    assert_eq!(code, Some(osis_proto::Code::RATE_LIMITED));
    assert!(request(&acts).is_none());
    // another client: the last slot of max_clients
    assert_eq!(bearer(&mut net, a, &mut over, Some([8; 32])).1, None);
    // the pool is full now: the first client's freed slot is what lets it back in
    let mut more = client(&mut net, a, Peer::Key([9; 32]));
    assert_eq!(bearer(&mut net, a, &mut more, Some(SECRET)).1, Some(osis_proto::Code::RATE_LIMITED));
    net.hand_close(a, conns[0].hc);
    assert_eq!(bearer(&mut net, a, &mut more, Some(SECRET)).1, None);
    // max_clients 0: no client is served
    let mut net = Net::new();
    let a = net.add_node(2, SyncConfig { max_clients: 0, ..SyncConfig::default() });
    set_entry(&mut net, a, x, Some(entry(&SECRET, None)));
    let mut k = client(&mut net, a, Peer::Key([9; 32]));
    assert_eq!(bearer(&mut net, a, &mut k, Some(SECRET)).1, Some(osis_proto::Code::RATE_LIMITED));
}

// spec/data-model.md §9, notes/client-port.md §3 (a crash between minting the actor and writing the entry): both are one engine transaction: a failure in the second leaves no commit, no thing and nothing in the index; on success both are there
#[test]
fn minting_a_client_is_all_or_nothing() {
    let mut net = Net::bare();
    let a = net.node(1, &[]);
    let (p, _) = net.sync(a).engine_mut().create_account(&[]).unwrap();
    let me = p.account;
    let node = net.sync(a).engine().tid();
    let before = net.sync(a).engine_mut().commit_ids().len();
    let mut seen = None;
    let r = net.sync(a).engine_mut().mint_actor(&me, |t| {
        seen = Some(t);
        Err(osis_node::Error::Misuse("the entry failed"))
    });
    assert!(r.is_err());
    let t = seen.unwrap();
    assert!(!net.sync(a).engine().knows(&t));
    assert_eq!(net.sync(a).engine_mut().commit_ids().len(), before);
    assert_eq!(net.sync(a).engine_mut().get_typed(&node, &ct::CLIENTS).unwrap(), None);
    let (t, _) = net
        .sync(a)
        .engine_mut()
        .mint_actor(&me, |t| {
            let mut m = Mutation::new();
            m.op(node, &ct::CLIENTS, PathOp { path: vec![PathSeg::Key(Value::Tid(t))], op: Op::Set(entry(&SECRET, None).to_value()) })?;
            Ok(m)
        })
        .unwrap();
    assert!(net.sync(a).engine().knows(&t));
    assert!(net.sync(a).engine_mut().epochs(&t).is_some(), "secrets of its own");
    assert!(net.sync(a).engine_mut().get_typed(&node, &ct::CLIENTS).unwrap().unwrap().contains_key(&t));
}

