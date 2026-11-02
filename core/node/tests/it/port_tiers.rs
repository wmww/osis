//! Client-port plumbing in the sync engine (notes/client-port.md §0, §2, §5): the tier is the
//! transport type's (`Peer::Unix` is Owner, a key never is), requests go up as actions, clients
//! have their own pool, an authenticated client is exempt from the idle bound, a ported
//! session's end is reported.

use crate::net::*;
use osis_base::Value;
use osis_node::sync::{Action, ConnId, Event, SyncConfig, Tier};
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
    let outs = cs.handle(now, ClientInput::Command(Command::Auth { token: 1, session: [3; 16] }));
    feed(net, n, conn, cs, outs, Vec::new())
}

// spec/sync.md §10 (client port), notes/client-port.md §0, §5: Owner only from Peer::Unix; a keyed peer's Auth is refused by the sync engine (Error 1) whatever its key, never handed up
#[test]
fn tier_is_the_transport_types() {
    let mut net = Net::new();
    let a = net.node(1, &[]);
    let uid = 1000;
    let (c, mut cs, _) = client(&mut net, a, Peer::Unix { uid });
    let got = auth(&mut net, a, c, &mut cs);
    assert!(got.iter().any(|x| matches!(x, Action::Request { conn, tier: Tier::Owner, msg } if *conn == c && matches!(**msg, Message::Auth { .. }))), "{got:?}");
    // a keyed peer presenting the very key a unix peer stands for is still keyed
    let (k, mut ks, _) = client(&mut net, a, Peer::Key(osis_transport::unix::uid_key(uid)));
    let got = auth(&mut net, a, k, &mut ks);
    assert!(!got.iter().any(|x| matches!(x, Action::Request { .. })), "{got:?}");
}

// spec/wire.md §11.2, notes/client-port.md §8 (b): Auths pipelined by a keyed peer, one per input, are each refused (Error 1) by the sync engine; none reaches the port worker
#[test]
fn keyed_auth_flood_never_goes_up() {
    let mut net = Net::new();
    let a = net.node(1, &[]);
    let (k, _, _) = client(&mut net, a, Peer::Key([9; 32]));
    let mut refused = 0;
    for id in 1..=20_000u32 {
        let bytes = osis_proto::encode_frame(&Message::Auth { id, client_pk: None, session: [0; 16], sig: None }.encode());
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

// spec/sync.md §10 (client port), notes/client-port.md §8 (b): clients have their own pool (max_clients): a newcomer evicts the oldest unauthenticated client, never a keyed session; with every client authenticated the newcomer is refused; an authenticated client outlives serve_idle_ms; its end is reported
#[test]
fn client_pool_idle_and_end() {
    let mut net = Net::new();
    let cfg = SyncConfig { max_clients: 1, max_served: 1, serve_idle_ms: 1_000, serve_open_ms: 1_000_000, ..SyncConfig::default() };
    let a = net.add_node(1, cfg);
    let (keyed, _, _) = client(&mut net, a, Peer::Key([9; 32]));
    let (c1, _, _) = client(&mut net, a, Peer::Unix { uid: 7 });
    let (c2, _, got) = client(&mut net, a, Peer::Unix { uid: 7 });
    assert!(got.contains(&Action::Close { conn: c1 }) && !got.contains(&Action::Close { conn: keyed }), "{got:?}");
    let acts = net.sync(a).accept_peer(LOCAL, Peer::Unix { uid: 7 }).1;
    assert!(acts.contains(&Action::Close { conn: c2 }), "{acts:?}");
    let (c3, mut cs3, _) = client(&mut net, a, Peer::Unix { uid: 7 });
    let got = auth(&mut net, a, c3, &mut cs3);
    let Some(Action::Request { msg, .. }) = got.into_iter().find(|x| matches!(x, Action::Request { .. })) else { panic!() };
    let Message::Auth { id, .. } = *msg else { panic!() };
    let acts = net.sync(a).handle(Event::Reply { conn: c3, id, reply: Ok(Outcome::Ok { seq: 0, value: Value::Bytes(vec![0; 16]) }) });
    feed(&mut net, a, c3, &mut cs3, Vec::new(), acts);
    let (c4, acts) = net.sync(a).accept_peer(LOCAL, Peer::Unix { uid: 7 });
    assert!(acts.contains(&Action::Close { conn: c4 }) && !acts.contains(&Action::Close { conn: c3 }), "{acts:?}");
    net.clock.advance(5_000);
    let acts = net.sync(a).handle(Event::Tick);
    assert!(!acts.contains(&Action::Close { conn: c3 }), "authenticated: no idle close");
    assert!(acts.contains(&Action::Close { conn: keyed }), "the keyed one idles out: {acts:?}");
    let acts = net.sync(a).handle(Event::Down { conn: c3 });
    assert!(acts.contains(&Action::Ended { conn: c3 }));
}
