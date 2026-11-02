//! Client-port plumbing in the sync engine (notes/client-port.md §0, §2, §5): the tier is the
//! transport type's (`Peer::Unix` is Owner, a key never is), requests go up as actions, clients
//! have their own pool, an authenticated client is exempt from the idle bound, a ported
//! session's end is reported.

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

/// Feeds the client's frames to the node; returns the node's actions for `conn` other than
/// sends (answered back into the client).
fn feed(net: &mut Net, n: usize, conn: ConnId, cs: &mut ClientSession, outs: Vec<ClientOutput>, mut acts: Vec<Action>) -> Vec<Action> {
    let mut got = Vec::new();
    let mut outs = outs;
    loop {
        let mut moved = false;
        for o in std::mem::take(&mut outs) {
            if let ClientOutput::Send(b) = o {
                acts.extend(net.sync(n).handle(Event::Bytes { conn, bytes: b }));
                moved = true;
            }
        }
        for a in std::mem::take(&mut acts) {
            match a {
                Action::Send { conn: c, bytes } if c == conn => {
                    let now = net.now();
                    outs.extend(cs.handle(now, ClientInput::Bytes(bytes)));
                    moved = true;
                }
                a => got.push(a),
            }
        }
        if !moved {
            return got;
        }
    }
}

fn client(net: &mut Net, n: usize, peer: Peer) -> (ConnId, ClientSession, Vec<Action>) {
    let (conn, acts) = net.sync(n).accept_peer(LOCAL, peer);
    let mut cs = ClientSession::new(ClientConfig { peer_static_key: LOCAL, challenge: [7; 32] });
    let now = net.now();
    let outs = cs.handle(now, ClientInput::Start);
    let got = feed(net, n, conn, &mut cs, outs, acts);
    (conn, cs, got)
}

fn auth(net: &mut Net, n: usize, conn: ConnId, cs: &mut ClientSession) -> Vec<Action> {
    let now = net.now();
    let outs = cs.handle(now, ClientInput::Command(Command::Auth { token: 1, session: [3; 16], secret: None }));
    feed(net, n, conn, cs, outs, Vec::new())
}

// spec/sync.md §10 (client port), notes/client-port.md §0, §5: Owner only from Peer::Unix; a keyed peer's Auth is refused by the sync engine (Error 1) whatever its key, never handed up
#[test]
fn tier_is_the_transport_types() {
    let mut net = Net::new();
    let a = net.node(1, &[]);
    let uid = osis_transport::unix::own_uid().unwrap();
    let (c, mut cs, _) = client(&mut net, a, Peer::Unix { uid });
    let got = auth(&mut net, a, c, &mut cs);
    assert!(got.iter().any(|x| matches!(x, Action::Request { conn, tier: Tier::Owner, msg } if *conn == c && matches!(**msg, Message::Auth { .. }))), "{got:?}");
    // a unix peer of another uid (whatever listener let it in) is never Owner
    let (o, mut os, _) = client(&mut net, a, Peer::Unix { uid: uid.wrapping_add(1) });
    let got = auth(&mut net, a, o, &mut os);
    assert!(!got.iter().any(|x| matches!(x, Action::Request { .. })), "{got:?}");
    // a keyed peer presenting the very key a unix peer stands for is still keyed
    let (k, mut ks, _) = client(&mut net, a, Peer::Key(osis_transport::unix::uid_key(uid)));
    let got = auth(&mut net, a, k, &mut ks);
    assert!(!got.iter().any(|x| matches!(x, Action::Request { .. })), "{got:?}");
}

// spec/wire.md §11.2, notes/client-port.md §3: Auths pipelined by a keyed peer, one per input, are each refused (Error 1) by the sync engine; none reaches the port worker
#[test]
fn keyed_auth_flood_never_goes_up() {
    let mut net = Net::new();
    let a = net.node(1, &[]);
    let (k, _, _) = client(&mut net, a, Peer::Key([9; 32]));
    let mut refused = 0;
    for id in 1..=20_000u32 {
        let bytes = osis_proto::encode_frame(&Message::Auth { id, secret: None, session: [0; 16] }.encode());
        for x in net.sync(a).handle(Event::Bytes { conn: k, bytes }) {
            match x {
                Action::Request { .. } | Action::Close { .. } => panic!("{x:?}"),
                Action::Send { bytes, .. } if Message::decode(&bytes[4..]).is_ok_and(|m| m == Message::Error { id, code: osis_proto::Code::REFUSED }) => refused += 1,
                _ => {}
            }
        }
    }
    assert_eq!(refused, 20_000);
}

// spec/sync.md §10 (client port), notes/client-port.md §3: clients have their own pool (max_clients): a newcomer evicts the oldest unauthenticated client, never a keyed session; with every client authenticated the newcomer is refused; an authenticated client outlives serve_idle_ms; its end is reported
#[test]
fn client_pool_idle_and_end() {
    let mut net = Net::new();
    let cfg = SyncConfig { max_clients: 1, max_served: 1, serve_idle_ms: 1_000, serve_open_ms: 1_000_000, ..SyncConfig::default() };
    let a = net.add_node(1, cfg);
    let uid = osis_transport::unix::own_uid().unwrap();
    let (keyed, _, _) = client(&mut net, a, Peer::Key([9; 32]));
    let (c1, _, _) = client(&mut net, a, Peer::Unix { uid });
    let (c2, _, got) = client(&mut net, a, Peer::Unix { uid });
    assert!(got.contains(&Action::Close { conn: c1 }) && !got.contains(&Action::Close { conn: keyed }), "{got:?}");
    let acts = net.sync(a).accept_peer(LOCAL, Peer::Unix { uid }).1;
    assert!(acts.contains(&Action::Close { conn: c2 }), "{acts:?}");
    let (c3, mut cs3, _) = client(&mut net, a, Peer::Unix { uid });
    let got = auth(&mut net, a, c3, &mut cs3);
    let Some(Action::Request { msg, .. }) = got.into_iter().find(|x| matches!(x, Action::Request { .. })) else { panic!() };
    let Message::Auth { id, .. } = *msg else { panic!() };
    let acts = net.sync(a).handle(Event::Reply { conn: c3, id, reply: Ok(Outcome::Ok { value: Value::Bytes(vec![0; 16]) }) });
    feed(&mut net, a, c3, &mut cs3, Vec::new(), acts);
    let (c4, acts) = net.sync(a).accept_peer(LOCAL, Peer::Unix { uid });
    assert!(acts.contains(&Action::Close { conn: c4 }) && !acts.contains(&Action::Close { conn: c3 }), "{acts:?}");
    net.clock.advance(5_000);
    let acts = net.sync(a).handle(Event::Tick);
    assert!(!acts.contains(&Action::Close { conn: c3 }), "authenticated: no idle close");
    assert!(acts.contains(&Action::Close { conn: keyed }), "the keyed one idles out: {acts:?}");
    let acts = net.sync(a).handle(Event::Down { conn: c3 });
    assert!(acts.contains(&Action::Ended { conn: c3 }));
}

const SECRET: [u8; 32] = [0x77; 32];

/// Sets (or removes) this node's `clients.0^` entry of `actor` and lets the sync engine see it.
fn set_entry(net: &mut Net, n: usize, actor: Tid, entry: Option<ct::Client>) -> Vec<Action> {
    let me = net.sync(n).engine().tid();
    let mut m = Mutation::new();
    let op = match entry {
        Some(e) => PathOp { path: vec![PathSeg::Key(Value::Tid(actor))], op: Op::Set(e.to_value()) },
        None => PathOp { path: Vec::new(), op: Op::Remove(Value::Tid(actor)) },
    };
    m.op(me, &ct::CLIENTS, op).unwrap();
    net.sync(n).engine_mut().commit(m).unwrap();
    net.sync(n).handle(Event::Local)
}

fn entry(secret: &[u8; 32], until: Option<u64>) -> ct::Client {
    ct::Client { secret_hash: osis_base::hash::hash(secret), until: until.map(osis_base::WallMs) }
}

/// A bearer Auth over a keyed session: the actions, and the codes the node answered with.
fn bearer(net: &mut Net, n: usize, conn: ConnId, cs: &mut ClientSession, secret: Option<[u8; 32]>) -> (Vec<Action>, Option<osis_proto::Code>) {
    let now = net.now();
    let outs = cs.handle(now, ClientInput::Command(Command::Auth { token: 1, session: [3; 16], secret: secret.map(Secret32::from_bytes) }));
    let mut acts = Vec::new();
    let mut code = None;
    for o in outs {
        if let ClientOutput::Send(bytes) = o {
            acts.extend(net.sync(n).handle(Event::Bytes { conn, bytes }));
        }
    }
    let mut rest = Vec::new();
    for a in acts {
        match a {
            Action::Send { conn: c, bytes } if c == conn => {
                if let Ok(Message::Error { code: x, .. }) = Message::decode(&bytes[4..]) {
                    code = Some(x);
                }
                let now = net.now();
                cs.handle(now, ClientInput::Bytes(bytes));
            }
            a => rest.push(a),
        }
    }
    (rest, code)
}

fn request(acts: &[Action]) -> Option<(Tier, &Message)> {
    acts.iter().find_map(|a| match a {
        Action::Request { tier, msg, .. } => Some((*tier, &**msg)),
        _ => None,
    })
}

// spec/wire.md §11.2 (Auth), spec/sync.md §10, notes/client-port.md §3: a keyed session's Auth goes up only when its secret's hash is a current entry, bound to that entry's actor with the secret stripped; an unknown secret, no secret, and an entry past its until are Error 1 and never reach the worker; a second Auth on a bound session is Error 1; an Owner session's Auth with a secret is Error 1
#[test]
fn bearer_auth_gated_in_the_sync_engine() {
    let mut net = Net::new();
    let a = net.node(1, &[]);
    let actor = Tid::from_bytes([5; 15]);
    set_entry(&mut net, a, actor, Some(entry(&SECRET, None)));
    for bad in [Some([1u8; 32]), None] {
        let (k, mut ks, _) = client(&mut net, a, Peer::Key([9; 32]));
        let (acts, code) = bearer(&mut net, a, k, &mut ks, bad);
        assert_eq!(code, Some(osis_proto::Code::REFUSED));
        assert!(request(&acts).is_none(), "{acts:?}");
    }
    let (k, mut ks, _) = client(&mut net, a, Peer::Key([9; 32]));
    let (acts, code) = bearer(&mut net, a, k, &mut ks, Some(SECRET));
    assert_eq!(code, None);
    let (tier, msg) = request(&acts).unwrap();
    assert_eq!(tier, Tier::Client(actor));
    assert!(matches!(msg, Message::Auth { secret: None, .. }), "the worker never sees the secret");
    assert_eq!(net.sync(a).client_of(k), Some(actor));
    let (acts, code) = bearer(&mut net, a, k, &mut ks, Some(SECRET));
    assert_eq!(code, Some(osis_proto::Code::REFUSED));
    assert!(request(&acts).is_none());
    let uid = osis_transport::unix::own_uid().unwrap();
    let (o, mut os, _) = client(&mut net, a, Peer::Unix { uid });
    let (acts, code) = bearer(&mut net, a, o, &mut os, Some(SECRET));
    assert_eq!(code, Some(osis_proto::Code::REFUSED));
    assert!(request(&acts).is_none());
    assert_eq!(net.sync(a).client_of(o), None, "the Owner session is no client");
    // expired: past its until at Auth
    let now = net.now();
    let late = Tid::from_bytes([6; 15]);
    set_entry(&mut net, a, late, Some(entry(&[2; 32], Some(now))));
    let (k2, mut ks2, _) = client(&mut net, a, Peer::Key([9; 32]));
    let (acts, code) = bearer(&mut net, a, k2, &mut ks2, Some([2; 32]));
    assert_eq!(code, Some(osis_proto::Code::REFUSED));
    assert!(request(&acts).is_none());
}

// spec/data-model.md §9, spec/sync.md §10, notes/client-port.md §3: a session ends when its entry goes, when its secret rotates, and at its until by the timer alone (a wake is asked for it, with no other change); an extended until moves the timer; client_of agrees before any of that reaches the session's connection
#[test]
fn bound_sessions_end_with_their_entry() {
    let mut net = Net::new();
    let a = net.node(1, &[]);
    let actor = Tid::from_bytes([5; 15]);
    let until = net.now() + 10_000;
    set_entry(&mut net, a, actor, Some(entry(&SECRET, Some(until))));
    let (k, mut ks, _) = client(&mut net, a, Peer::Key([9; 32]));
    bearer(&mut net, a, k, &mut ks, Some(SECRET));
    let acts = net.sync(a).handle(Event::Tick);
    assert!(acts.iter().any(|x| matches!(x, Action::Wake { at } if *at <= until)), "a wake for its until: {acts:?}");
    // extended: the old end passes without closing
    set_entry(&mut net, a, actor, Some(entry(&SECRET, Some(until + 10_000))));
    net.clock.advance(10_001);
    let acts = net.sync(a).handle(Event::Tick);
    assert!(!acts.contains(&Action::Close { conn: k }), "{acts:?}");
    // its until passes: client_of says so before a tick does anything
    net.clock.advance(10_000);
    assert_eq!(net.sync(a).client_of(k), None);
    let acts = net.sync(a).handle(Event::Tick);
    assert!(acts.contains(&Action::Close { conn: k }), "{acts:?}");
    assert!(acts.contains(&Action::Ended { conn: k }), "{acts:?}");
    // rotated: the old secret's session closes, the old secret is refused, the new one binds
    set_entry(&mut net, a, actor, Some(entry(&SECRET, None)));
    let (k, mut ks, _) = client(&mut net, a, Peer::Key([9; 32]));
    bearer(&mut net, a, k, &mut ks, Some(SECRET));
    // the entry written, not yet seen by a step: client_of reads it, so a queued request cannot pass
    let me = net.sync(a).engine().tid();
    let mut m = Mutation::new();
    m.op(me, &ct::CLIENTS, PathOp { path: vec![PathSeg::Key(Value::Tid(actor))], op: Op::Set(entry(&[8; 32], None).to_value()) }).unwrap();
    net.sync(a).engine_mut().commit(m).unwrap();
    assert_eq!(net.sync(a).client_of(k), None, "another secret's hash");
    let acts = net.sync(a).handle(Event::Local);
    assert!(acts.contains(&Action::Close { conn: k }), "{acts:?}");
    let (k, mut ks, _) = client(&mut net, a, Peer::Key([9; 32]));
    assert_eq!(bearer(&mut net, a, k, &mut ks, Some(SECRET)).1, Some(osis_proto::Code::REFUSED));
    assert_eq!(bearer(&mut net, a, k, &mut ks, Some([8; 32])).1, None);
    // removed
    let acts = set_entry(&mut net, a, actor, None);
    assert!(acts.contains(&Action::Close { conn: k }), "{acts:?}");
}

// spec/wire.md §11.2, notes/client-port.md §3 and Picked numbers: past MAX_CONNS_PER_CLIENT authenticated connections of one client a further Auth is Error 4 and goes nowhere; another client is unaffected; one ending frees a slot; max_clients bounds all clients together whatever the per-client cap (0 serves none); neither counts against max_served or the Owner's pool
#[test]
fn client_connection_caps() {
    let mut net = Net::new();
    let cfg = SyncConfig { max_clients: osis_node::sync::MAX_CONNS_PER_CLIENT + 1, max_served: 1, ..SyncConfig::default() };
    let a = net.add_node(1, cfg);
    let (x, y) = (Tid::from_bytes([5; 15]), Tid::from_bytes([6; 15]));
    set_entry(&mut net, a, x, Some(entry(&SECRET, None)));
    set_entry(&mut net, a, y, Some(entry(&[8; 32], None)));
    let mut conns = Vec::new();
    for _ in 0..osis_node::sync::MAX_CONNS_PER_CLIENT {
        let (k, mut ks, _) = client(&mut net, a, Peer::Key([9; 32]));
        assert_eq!(bearer(&mut net, a, k, &mut ks, Some(SECRET)).1, None);
        conns.push(k);
    }
    let (over, mut os, _) = client(&mut net, a, Peer::Key([9; 32]));
    let (acts, code) = bearer(&mut net, a, over, &mut os, Some(SECRET));
    assert_eq!(code, Some(osis_proto::Code::RATE_LIMITED));
    assert!(request(&acts).is_none());
    // another client: the last slot of max_clients
    assert_eq!(bearer(&mut net, a, over, &mut os, Some([8; 32])).1, None);
    // the pool is full now: the first client's freed slot is what lets it back in
    let (more, mut ms, _) = client(&mut net, a, Peer::Key([9; 32]));
    assert_eq!(bearer(&mut net, a, more, &mut ms, Some(SECRET)).1, Some(osis_proto::Code::RATE_LIMITED));
    net.sync(a).handle(Event::Down { conn: conns[0] });
    assert_eq!(bearer(&mut net, a, more, &mut ms, Some(SECRET)).1, None);
    // max_clients 0: no client is served
    let mut net = Net::new();
    let a = net.add_node(2, SyncConfig { max_clients: 0, ..SyncConfig::default() });
    set_entry(&mut net, a, x, Some(entry(&SECRET, None)));
    let (k, mut ks, _) = client(&mut net, a, Peer::Key([9; 32]));
    assert_eq!(bearer(&mut net, a, k, &mut ks, Some(SECRET)).1, Some(osis_proto::Code::RATE_LIMITED));
}

// spec/data-model.md §9, notes/client-port.md §3 (a crash between minting the actor and writing the entry): both are one engine transaction: a failure in the second leaves no commit, no thing and nothing in the index; on success both are there
#[test]
fn minting_a_client_is_all_or_nothing() {
    let mut net = Net::new();
    let a = net.node(1, &[]);
    let (p, _) = net.sync(a).engine_mut().create_person(&[]).unwrap();
    let me = p.person;
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

// spec/sync.md §10, notes/client-port.md §5: unauthenticated sessions on the client listener are a pool of their own: a flood there evicts its own oldest, never a co-reader's session on another listener, and a session of another listener's flood never takes a client listener's place; `Authed` tells the driver a session left the pool; the key is random, kept, rotated, shredded
#[test]
fn client_listener_sessions_are_a_pool_of_their_own() {
    let mut net = Net::new();
    let cfg = SyncConfig { max_served: 1, client_pending: 2, serve_open_ms: 1_000_000, ..SyncConfig::default() };
    let a = net.add_node(1, cfg);
    let secret = net.sync(a).client_listen_secret(false);
    let key = net.sync(a).client_listen_key().unwrap();
    assert_eq!(*net.sync(a).client_listen_secret(false).expose(), *secret.expose());
    assert_ne!(key, LOCAL);
    let (peer, _) = net.sync(a).accept_peer(LOCAL, Peer::Key([1; 32]));
    let (p1, _) = net.sync(a).accept_peer(key, Peer::Key([2; 32]));
    let (_p2, _) = net.sync(a).accept_peer(key, Peer::Key([3; 32]));
    // the flood's third: its own oldest goes, no co-reader
    let (_p3, acts) = net.sync(a).accept_peer(key, Peer::Key([4; 32]));
    assert!(acts.contains(&Action::Close { conn: p1 }), "{acts:?}");
    assert!(!acts.contains(&Action::Close { conn: peer }), "{acts:?}");
    // the other way: a second peer session evicts the first peer, no client listener session
    let (_peer2, acts) = net.sync(a).accept_peer(LOCAL, Peer::Key([5; 32]));
    assert!(acts.contains(&Action::Close { conn: peer }), "{acts:?}");
    assert!(!acts.contains(&Action::Close { conn: _p2 }), "{acts:?}");
    // an Auth that matches: Authed for the driver, then out of the pool
    let (actor, bytes) = (Tid::from_bytes([3; 15]), [7u8; 32]);
    set_entry(&mut net, a, actor, Some(entry(&bytes, None)));
    let cs_key = key;
    let (conn, acts) = net.sync(a).accept_peer(cs_key, Peer::Key([6; 32]));
    let mut cs = ClientSession::new(ClientConfig { peer_static_key: cs_key, challenge: [0; 32] });
    let o = cs.handle(0, ClientInput::Start);
    feed(&mut net, a, conn, &mut cs, o, acts);
    let (got, code) = bearer(&mut net, a, conn, &mut cs, Some(bytes));
    assert_eq!(code, None);
    assert!(got.contains(&Action::Authed { conn }), "{got:?}");
    // a bad Auth tells nothing
    let (c2, acts) = net.sync(a).accept_peer(cs_key, Peer::Key([7; 32]));
    let mut cs2 = ClientSession::new(ClientConfig { peer_static_key: cs_key, challenge: [0; 32] });
    let o = cs2.handle(0, ClientInput::Start);
    feed(&mut net, a, c2, &mut cs2, o, acts);
    let (got, code) = bearer(&mut net, a, c2, &mut cs2, Some([8; 32]));
    assert!(code.is_some() && !got.contains(&Action::Authed { conn: c2 }), "{got:?}");
    // a client listener serves the client port alone: a sync kind is Error 11, before Auth and after
    let open = Message::Subscribe { id: 9, labels: vec![osis_base::LabelId([1; 16])] };
    let frame = |m: &Message| { let e = m.encode(); let mut f = (e.len() as u32).to_be_bytes().to_vec(); f.extend(e); f };
    let reply = |acts: Vec<Action>| acts.into_iter().find_map(|a| if let Action::Send { bytes, .. } = a { Message::decode(&bytes[4..]).ok() } else { None });
    for c in [c2, conn] {
        let r = reply(net.sync(a).handle(Event::Bytes { conn: c, bytes: frame(&open) }));
        assert!(matches!(r, Some(Message::Error { id: 9, code }) if code == osis_proto::Code::UNSUPPORTED), "{r:?}");
    }
    // rotation and shredding
    let rotated = net.sync(a).client_listen_secret(true);
    assert_ne!(*rotated.expose(), *secret.expose());
    assert_ne!(net.sync(a).client_listen_key(), Some(key));
    net.sync(a).drop_client_listen_secret();
    assert_eq!(net.sync(a).client_listen_key(), None);
}
