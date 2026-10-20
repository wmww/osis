#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
//! Member-peer serving limits and LAN routes (spec/sync.md §5, §10): tombstones, budgets,
//! session caps, refused strangers and removed members, LAN candidates, co-reader caps.

mod net;
use net::*;
use osis_core::{LabelId, Role};
use osis_crypto::{Secret32, SigningSecret};
use osis_label::Address;
use osis_node::sync::{Action, ConnId, EntryKind, Event, SyncConfig};
use osis_proto::{ClientConfig, ClientEvent, ClientInput, ClientOutput, ClientSession, Code, Command, LabelStore, OpenKey};

const LOCAL: [u8; 32] = [0x42; 32];

/// A hand-driven peer session into node `n`.
struct Dialer {
    conn: ConnId,
    cs: ClientSession,
}

fn exchange(net: &mut Net, n: usize, p: &mut Dialer, mut acts: Vec<Action>, mut outs: Vec<ClientOutput>) -> Vec<ClientEvent> {
    let mut evs = Vec::new();
    loop {
        let mut moved = false;
        for o in std::mem::take(&mut outs) {
            match o {
                ClientOutput::Send(b) => {
                    acts.extend(net.sync(n).handle(Event::Bytes { conn: p.conn, bytes: b }));
                    moved = true;
                }
                ClientOutput::Event(e) => evs.push(e),
                _ => {}
            }
        }
        for a in std::mem::take(&mut acts) {
            match a {
                Action::Send { conn, bytes } if conn == p.conn => {
                    let now = net.now();
                    outs.extend(p.cs.handle(now, ClientInput::Bytes(bytes)));
                    moved = true;
                }
                Action::Close { conn } if conn == p.conn => {}
                a => net.actions(n, vec![a]),
            }
        }
        net.settle(100_000);
        if !moved {
            return evs;
        }
    }
}

fn dial_in(net: &mut Net, n: usize) -> (Dialer, Vec<ClientEvent>) {
    let (conn, acts) = net.sync(n).accept(LOCAL, [0x43; 32]);
    let mut p = Dialer { conn, cs: ClientSession::new(ClientConfig { peer_static_key: LOCAL, challenge: [7; 32] }) };
    let now = net.now();
    let outs = p.cs.handle(now, ClientInput::Start);
    let evs = exchange(net, n, &mut p, acts, outs);
    (p, evs)
}

fn command(net: &mut Net, n: usize, p: &mut Dialer, cmd: Command) -> Vec<ClientEvent> {
    let now = net.now();
    let outs = p.cs.handle(now, ClientInput::Command(cmd));
    exchange(net, n, p, Vec::new(), outs)
}

fn reach(net: &mut Net, n: usize, key: u8) {
    let acts = net.sync(n).publish_reach([key; 32], vec![]).unwrap();
    net.actions(n, acts);
}

fn upload_codes(evs: &[ClientEvent]) -> Vec<Code> {
    evs.iter().filter_map(|e| if let ClientEvent::EntryStatus { codes, .. } = e { Some(codes.clone()) } else { None }).flatten().collect()
}

// spec/sync.md §5 (tombstones, member peer): a body a server deleted is refused when a peer
// uploads it again (code 6), and never goes back to the server.
#[test]
fn dropped_entry_refused_from_peer_spec_sync_5() {
    let mut net = Net::new();
    let sv = net.add_server();
    let a = net.node(1, &[sv]);
    let b = net.node(2, &[sv]);
    let g = net.group(a, &[(b, Role::Write)], &[sv]);
    let t = net.item(a, g, g, "one");
    net.run();
    let c = net.write(a, t, "two");
    net.run();
    let l = net.label(b);
    let x = net.sync(b).entries(&l).into_iter().find(|(_, k)| matches!(k, EntryKind::Commit { commit, .. } if *commit == c)).unwrap().0;
    let meta = net.servers[sv].hub.store().entry(&l, &x).unwrap().unwrap();
    let blob = net.servers[sv].hub.store().blob(&x).unwrap().unwrap();
    let now = net.now();
    assert_eq!(net.servers[sv].hub.store_mut().delete(&l, &x, now).unwrap(), Code::OK);
    let acts = net.sync(b).sync_now();
    net.actions(b, acts);
    net.settle(100_000);
    assert!(!net.sync(b).entries(&l).iter().any(|(id, _)| *id == x), "the server's deletion reached b");
    let (mut p, _) = dial_in(&mut net, b);
    let evs = command(&mut net, b, &mut p, Command::Upload { label: l, entries: vec![osis_proto::Entry { blob, wrap: meta.wrap, stamp: meta.stamp.unwrap() }] });
    assert_eq!(upload_codes(&evs), vec![Code::TOMBSTONED]);
    net.run();
    assert!(!net.sync(b).entries(&l).iter().any(|(id, _)| *id == x));
    assert!(!net.server_ids(sv, &l).contains(&x), "never re-uploaded");
}

// spec/sync.md §5 (servers cap storage per label; member peer applies the same rule): a peer's
// uploads past its byte budget get code 12 and are not kept.
#[test]
fn peer_budget_refuses_spec_sync_5() {
    let mut net = Net::new();
    let a = net.node(1, &[]);
    let cfg = SyncConfig { peers: false, peer_bytes: 64, ..SyncConfig::default() };
    let b = net.add_node(2, cfg);
    reach(&mut net, a, 0xa1);
    reach(&mut net, b, 0xb1);
    let g = net.group_at(a, &[(b, Role::Write)], vec![]);
    let t = net.item(a, g, g, "too big for the budget");
    net.run();
    assert_eq!(net.read(b, t), None, "b dials nobody and refuses a's uploads past 64 bytes");
    assert!(net.sync(a).take_diagnostics().iter().any(|d| d.contains("code 12")));
}

// spec/sync.md §5: served sessions are capped and idle ones closed.
#[test]
fn served_sessions_capped_and_idle_closed_spec_sync_5() {
    let mut net = Net::new();
    let cfg = SyncConfig { max_served: 1, serve_idle_ms: 1_000, ..SyncConfig::default() };
    let b = net.add_node(2, cfg);
    let (c1, a1) = net.sync(b).accept(LOCAL, [1; 32]);
    assert!(!a1.contains(&Action::Close { conn: c1 }));
    let (c2, a2) = net.sync(b).accept(LOCAL, [2; 32]);
    assert!(a2.contains(&Action::Close { conn: c2 }), "over the cap");
    net.clock.advance(1_001);
    let acts = net.sync(b).handle(Event::Tick);
    assert!(acts.contains(&Action::Close { conn: c1 }), "idle");
    assert!(net.sync(b).served_opened().is_empty());
}

// spec/sync.md §5: a stranger without the label's sync key opens nothing.
// spec/sync.md §5 (member peer)
#[test]
fn stranger_refused_spec_sync_5() {
    let mut net = Net::new();
    let a = net.node(1, &[]);
    let b = net.node(2, &[]);
    reach(&mut net, a, 0xa1);
    reach(&mut net, b, 0xb1);
    net.group_at(a, &[(b, Role::Write)], vec![]);
    net.run();
    let l: LabelId = net.label(b);
    let (mut p, _) = dial_in(&mut net, b);
    let key = SigningSecret::from_seed(&Secret32::from_bytes([0x99; 32]));
    let evs = command(&mut net, b, &mut p, Command::Open { label: l, key: OpenKey::Sync(key) });
    assert!(evs.iter().any(|e| matches!(e, ClientEvent::Refused { .. })), "{evs:?}");
    assert!(!evs.iter().any(|e| matches!(e, ClientEvent::Opened { .. })));
    assert!(net.sync(b).served_opened()[&p.conn].is_empty());
}

// spec/sync.md §5, spec/permissions.md §3: a removed member's node is not dialed (its old
// `/reach` is held, it may not read now) and, once the label has a new step, opens nothing
// served.
// spec/sync.md §5 (member peer)
#[test]
fn removed_member_not_dialed_nor_served_spec_sync_5() {
    let mut net = Net::new();
    let sv = net.add_server();
    let a = net.node(1, &[sv]);
    let r = net.node(2, &[]);
    reach(&mut net, a, 0xa1);
    reach(&mut net, r, 0xb1);
    let g = net.group(a, &[(r, Role::Read)], &[sv]);
    let t = net.item(a, g, g, "before");
    net.run();
    assert_eq!(net.read(r, t), Some(s("before")));
    assert!(net.sync(a).peers().contains_key(&[0xb1; 32]));
    let (ta, tr) = (net.tid(a), net.tid(r));
    let e = net.engine(a);
    let rec = recipients_of(e, &[(ta, Role::Admin)]);
    remove_member(e, g, tr, &rec, 77);
    net.set_online(r, false);
    net.run();
    let la = net.label(a);
    assert!(net.server_path(sv, &la).len() >= 2, "a registered a new step");
    assert!(!net.sync(a).peers().contains_key(&[0xb1; 32]), "not dialed");
    net.write(a, t, "after");
    net.set_online(r, true);
    net.advance(61_000);
    let served = net.sync(a).served_opened();
    assert!(!served.is_empty(), "r dialed a");
    assert!(served.values().all(|o| o.is_empty()), "served nothing");
    assert_eq!(net.read(r, t), Some(s("before")));
}

fn reach_ed(net: &mut Net, n: usize) -> [u8; 32] {
    let secret = net.sync(n).dialable_secret();
    let k = SigningSecret::from_seed(&secret).verifying_key().to_bytes();
    let acts = net.sync(n).publish_reach(k, vec![]).unwrap();
    net.actions(n, acts);
    k
}

fn dials(acts: &[Action]) -> Vec<Address> {
    acts.iter().filter_map(|x| if let Action::Dial { address, .. } = x { Some(address.clone()) } else { None }).collect()
}

const IP: &str = "192.168.7.7";

// spec/sync.md §10: a LAN address is only a candidate; one whose connection fails before coming
// up is backed off without pausing the peer, which is reached by its `peer://` route at once,
// and a repeat of its announcement is not dialed while backed off.
#[test]
fn lan_candidate_failure_keeps_route_spec_sync_10() {
    let mut net = Net::new();
    let a = net.node(1, &[]);
    let b = net.node(2, &[]);
    reach_ed(&mut net, a);
    let kb = reach_ed(&mut net, b);
    net.blocked_peers.insert((a, b));
    let g = net.group_at(a, &[(b, Role::Write)], vec![]);
    net.run();
    net.blocked_peers.clear();
    net.clock.advance(60_001);
    // b announces a key nobody listens with
    let ann = net.sync(b).lan_announcement([0x77; 32], 9).unwrap();
    let (hit, acts) = net.sync(a).lan_seen(&ann, IP.parse().unwrap());
    assert_eq!(hit, Some(kb));
    let bogus = Address { url: format!("peer://{IP}:9"), key: [0x77; 32] };
    assert_eq!(dials(&acts), vec![bogus.clone()]);
    net.actions(a, acts);
    net.settle(100_000);
    let t = net.item(a, g, g, "via peer route");
    net.run();
    assert_eq!(net.read(b, t), Some(s("via peer route")));
    let (_, acts) = net.sync(a).lan_seen(&ann, IP.parse().unwrap());
    assert!(dials(&acts).is_empty());
}

// spec/sync.md §10: a connection through a LAN address that comes up proves the route (the
// signature bound the key to the node): it is dialed first from then on; a newer candidate
// does not displace a running connection.
#[test]
fn lan_route_proven_by_up_spec_sync_10() {
    let mut net = Net::new();
    let a = net.node(1, &[]);
    let b = net.node(2, &[]);
    reach_ed(&mut net, a);
    reach_ed(&mut net, b);
    net.blocked_peers.insert((a, b));
    let g = net.group_at(a, &[(b, Role::Write)], vec![]);
    net.run();
    net.blocked_peers.clear();
    net.clock.advance(60_001);
    // b listens on the LAN with a fresh key
    let lk = SigningSecret::from_seed(&net.sync(b).lan_secret()).verifying_key().to_bytes();
    net.lan_keys.insert(lk, b);
    let ann = net.sync(b).lan_announcement(lk, 5000).unwrap();
    let (_, acts) = net.sync(a).lan_seen(&ann, IP.parse().unwrap());
    let route = Address { url: format!("peer://{IP}:5000"), key: lk };
    assert_eq!(dials(&acts), vec![route.clone()]);
    net.actions(a, acts);
    net.settle(100_000);
    let t = net.item(a, g, g, "over the LAN");
    net.run();
    assert_eq!(net.read(b, t), Some(s("over the LAN")));
    // another address while connected: no dial
    let (_, acts) = net.sync(a).lan_seen(&ann, "192.168.7.8".parse().unwrap());
    assert!(dials(&acts).is_empty(), "{acts:?}");
    // the connection drops: after the pause the proven route is dialed, not the candidate
    net.set_online(b, false);
    net.set_online(b, true);
    net.advance(61_000);
    let acts = net.sync(a).handle(Event::Tick);
    assert!(dials(&acts).iter().all(|d| *d != Address { url: "peer://192.168.7.8:5000".into(), key: lk }), "{acts:?}");
}

// spec/sync.md §5 (member peer): a peer authenticated with the dialable key of a node that
// currently reads the label opens it whatever its proof; another key is refused.
#[test]
fn member_node_opens_without_proof_spec_sync_5() {
    let mut net = Net::new();
    let a = net.node(1, &[]);
    let b = net.node(2, &[]);
    reach_ed(&mut net, a);
    let kb = reach_ed(&mut net, b);
    net.group_at(a, &[(b, Role::Read)], vec![]);
    net.run();
    let l: LabelId = net.label(a);
    let key = || SigningSecret::from_seed(&Secret32::from_bytes([0x99; 32]));
    let (conn, acts) = net.sync(a).accept(LOCAL, kb);
    let mut p = Dialer { conn, cs: ClientSession::new(ClientConfig { peer_static_key: LOCAL, challenge: [7; 32] }) };
    let now = net.now();
    let outs = p.cs.handle(now, ClientInput::Start);
    exchange(&mut net, a, &mut p, acts, outs);
    let evs = command(&mut net, a, &mut p, Command::Open { label: l, key: OpenKey::Sync(key()) });
    assert!(evs.iter().any(|e| matches!(e, ClientEvent::Opened { entry_box: None, .. })), "{evs:?}");
    let (mut q, _) = dial_in(&mut net, a);
    let evs = command(&mut net, a, &mut q, Command::Open { label: l, key: OpenKey::Sync(key()) });
    assert!(evs.iter().any(|e| matches!(e, ClientEvent::Refused { .. })), "{evs:?}");
}

// spec/sync.md §5: a served session that opens nothing is closed after `serve_open_ms`, even
// while it keeps sending.
#[test]
fn silent_session_closed_spec_sync_5() {
    let mut net = Net::new();
    let cfg = SyncConfig { serve_open_ms: 1_000, ..SyncConfig::default() };
    let b = net.add_node(2, cfg);
    let (mut p, _) = dial_in(&mut net, b);
    net.clock.advance(1_001);
    let now = net.now();
    let outs = p.cs.handle(now, ClientInput::Command(Command::Open { label: LabelId([1; 16]), key: OpenKey::Sync(SigningSecret::from_seed(&Secret32::from_bytes([3; 32]))) }));
    exchange(&mut net, b, &mut p, Vec::new(), outs);
    let acts = net.sync(b).handle(Event::Tick);
    assert!(acts.contains(&Action::Close { conn: p.conn }), "{acts:?}");
}

// spec/permissions.md §3: a complete pass also waits for every co-reader the node received the
// label from and can reach: with that peer's replies held back, the server's pass alone is not
// enough.
#[test]
fn complete_pass_counts_peers_spec_permissions_3() {
    let mut net = Net::new();
    let sv = net.add_server();
    let a = net.node(1, &[sv]);
    let b = net.node(2, &[sv]);
    let c = net.node(3, &[sv]);
    reach_ed(&mut net, a);
    reach_ed(&mut net, b);
    let g = net.group(a, &[(b, Role::Admin), (c, Role::Read)], &[sv]);
    net.item(b, g, g, "from b");
    net.run();
    assert!(net.sync(a).complete_pass(&g));
    net.held.insert((b, a));
    let (tb, tc) = (net.tid(b), net.tid(c));
    let e = net.engine(b);
    let rec = recipients_of(e, &[(tb, Role::Admin)]);
    remove_member(e, g, tc, &rec, 78);
    net.run();
    assert!(!net.sync(a).complete_pass(&g), "b's pass is held back");
    net.release();
    net.run();
    assert!(net.sync(a).complete_pass(&g));
}

// spec/permissions.md §4: `/reach` goes under every label except those of groups the app
// excludes (open audiences): a co-reader learns the dialable key only through the others.
#[test]
fn reach_excluded_per_label_spec_permissions_4() {
    for excluded in [false, true] {
        let mut net = Net::new();
        let sv = net.add_server();
        let a = net.node(1, &[sv]);
        let b = net.node(2, &[sv]);
        let g = net.group(a, &[(b, Role::Read)], &[sv]);
        net.sync(a).set_no_reach(g, excluded);
        let ka = reach_ed(&mut net, a);
        net.run();
        assert_eq!(net.sync(b).peers().contains_key(&ka), !excluded, "excluded: {excluded}");
    }
}

// spec/sync.md §5: co-readers dialed per label are capped.
#[test]
fn co_readers_capped_spec_sync_5() {
    let mut net = Net::new();
    let cfg = SyncConfig { max_peers_per_label: 1, ..SyncConfig::default() };
    let a = net.add_node(1, cfg);
    let b = net.node(2, &[]);
    let c = net.node(3, &[]);
    reach(&mut net, a, 0xa1);
    reach(&mut net, b, 0xb1);
    reach(&mut net, c, 0xc1);
    net.group_at(a, &[(b, Role::Read), (c, Role::Read)], vec![]);
    assert_eq!(net.sync(a).peers().len(), 1);
}
