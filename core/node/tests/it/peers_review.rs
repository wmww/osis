#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
//! Member-peer serving limits and LAN routes (spec/sync.md §5, §10): tombstones, budgets,
//! session caps, refused strangers and removed members, LAN candidates, co-reader caps.

use crate::net;
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

// spec/sync.md §5: served sessions are capped: a new one evicts the oldest that has opened
// nothing (so silent sessions cannot starve members), and is refused when every running one
// opened a label; idle ones are closed.
#[test]
fn served_sessions_capped_and_idle_closed_spec_sync_5() {
    let mut net = Net::new();
    let a = net.node(1, &[]);
    let cfg = SyncConfig { max_served: 2, serve_idle_ms: 1_000, ..SyncConfig::default() };
    let b = net.add_node(2, cfg);
    reach_ed(&mut net, a);
    reach_ed(&mut net, b);
    net.blocked_peers.insert((a, b));
    net.group_at(a, &[(b, Role::Read)], vec![]);
    net.run();
    let l = net.label(b);
    let da = SigningSecret::from_seed(&net.sync(a).dialable_secret());
    let (c1, a1) = net.sync(b).accept(LOCAL, [1; 32]);
    assert!(!a1.iter().any(|x| matches!(x, Action::Close { .. })));
    let (mut m, _) = dial_in(&mut net, b);
    let evs = command(&mut net, b, &mut m, Command::Open { label: l, key: OpenKey::Member(da) });
    assert!(evs.iter().any(|e| matches!(e, ClientEvent::Opened { .. })), "{evs:?}");
    let (c3, a3) = net.sync(b).accept(LOCAL, [3; 32]);
    assert!(a3.contains(&Action::Close { conn: c1 }), "the silent session makes room: {a3:?}");
    assert!(!a3.contains(&Action::Close { conn: c3 }));
    net.actions(b, a3);
    let (_, a4) = net.sync(b).accept(LOCAL, [4; 32]);
    assert!(a4.contains(&Action::Close { conn: c3 }), "the next silent one goes: {a4:?}");
    assert!(!a4.contains(&Action::Close { conn: m.conn }), "the member stays");
    net.clock.advance(1_001);
    let acts = net.sync(b).handle(Event::Tick);
    assert!(acts.contains(&Action::Close { conn: m.conn }), "idle");
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

fn net_label(net: &mut Net, n: usize, g: osis_core::Tid) -> LabelId {
    net.engine(n).group_labels(&g).unwrap()[0].id
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

/// A LAN source at `ip`.
fn src(ip: &str) -> std::net::SocketAddr {
    (ip.parse::<std::net::IpAddr>().unwrap(), 47380).into()
}

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
    let (hit, acts) = net.sync(a).lan_seen(&ann, src(IP));
    assert_eq!(hit, Some(kb));
    let bogus = Address { url: format!("peer://{IP}:9"), key: [0x77; 32] };
    assert_eq!(dials(&acts), vec![bogus.clone()]);
    net.actions(a, acts);
    net.settle(100_000);
    let t = net.item(a, g, g, "via peer route");
    net.run();
    assert_eq!(net.read(b, t), Some(s("via peer route")));
    let (_, acts) = net.sync(a).lan_seen(&ann, src(IP));
    assert!(dials(&acts).is_empty());
}

// spec/sync.md §10: a candidate that fails falls back to the most heard verified source, so a
// replay from a spoofed source that won the candidate costs one failed dial.
#[test]
fn lan_candidate_falls_back_to_most_heard_spec_sync_10() {
    let mut net = Net::new();
    let a = net.node(1, &[]);
    let b = net.node(2, &[]);
    reach_ed(&mut net, a);
    reach_ed(&mut net, b);
    net.blocked_peers.insert((a, b));
    net.group_at(a, &[(b, Role::Write)], vec![]);
    net.run();
    let lk = SigningSecret::from_seed(&net.sync(b).lan_secret()).verifying_key().to_bytes();
    net.lan_keys.insert(lk, b);
    let ann = net.sync(b).lan_announcement(lk, 5000).unwrap();
    // the peer:// route failed (paused): the first real announcement cuts the pause and is
    // dialed; repeats and the spoofed one meanwhile dial nothing
    net.clock.advance(60_001);
    net.feed(a, Event::Tick);
    net.settle(100_000);
    let real = IP;
    let spoof = "192.168.7.66";
    let (_, first) = net.sync(a).lan_seen(&ann, src(real));
    let real_addr = Address { url: format!("peer://{real}:5000"), key: lk };
    assert_eq!(dials(&first), vec![real_addr.clone()]);
    for _ in 0..2 {
        assert!(dials(&net.sync(a).lan_seen(&ann, src(real)).1).is_empty());
    }
    net.clock.advance(osis_node::sync::peers::LAN_CHANGE_MS);
    assert!(dials(&net.sync(a).lan_seen(&ann, src(spoof)).1).is_empty());
    // that first dial got nowhere; the spoofed candidate is dialed after the pause and fails:
    // the real one takes over
    let conn = first.iter().find_map(|x| if let Action::Dial { conn, .. } = x { Some(*conn) } else { None }).unwrap();
    net.sync(a).handle(Event::Down { conn });
    let spoofed = Address { url: format!("peer://{spoof}:5000"), key: lk };
    net.blocked_peers.clear();
    net.clock.advance(61_000);
    let acts = net.sync(a).handle(Event::Tick);
    assert_eq!(dials(&acts), vec![spoofed.clone()]);
    let conn = acts.iter().find_map(|x| if let Action::Dial { conn, .. } = x { Some(*conn) } else { None }).unwrap();
    let acts = net.sync(a).handle(Event::Down { conn });
    assert_eq!(dials(&acts), vec![real_addr]);
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
    let (_, acts) = net.sync(a).lan_seen(&ann, src(IP));
    let route = Address { url: format!("peer://{IP}:5000"), key: lk };
    assert_eq!(dials(&acts), vec![route.clone()]);
    net.actions(a, acts);
    net.settle(100_000);
    let t = net.item(a, g, g, "over the LAN");
    net.run();
    assert_eq!(net.read(b, t), Some(s("over the LAN")));
    // another address while connected: no dial
    let (_, acts) = net.sync(a).lan_seen(&ann, src("192.168.7.8"));
    assert!(dials(&acts).is_empty(), "{acts:?}");
    // the connection drops: after the pause the proven route is dialed, not the candidate
    net.set_online(b, false);
    net.set_online(b, true);
    net.advance(61_000);
    let acts = net.sync(a).handle(Event::Tick);
    assert!(dials(&acts).iter().all(|d| *d != Address { url: "peer://192.168.7.8:5000".into(), key: lk }), "{acts:?}");
}

// spec/sync.md §5 (member peer), spec/wire.md §11.2 (proof 3): a member proof under the dialable
// key of a node that currently reads the label opens it over an ephemeral transport key; a
// proof by another key or a sync key nobody registered is refused, and once the node is removed
// from the group its proof is refused too and its open session closed.
#[test]
fn member_node_opens_with_proof_spec_sync_5() {
    let mut net = Net::new();
    let a = net.node(1, &[]);
    let b = net.node(2, &[]);
    reach_ed(&mut net, a);
    reach_ed(&mut net, b);
    let g = net.group_at(a, &[(b, Role::Read)], vec![]);
    net.run();
    let l: LabelId = net.label(a);
    let db = SigningSecret::from_seed(&net.sync(b).dialable_secret());
    let stranger = SigningSecret::from_seed(&Secret32::from_bytes([0x99; 32]));
    let (mut p, _) = dial_in(&mut net, a);
    let evs = command(&mut net, a, &mut p, Command::Open { label: l, key: OpenKey::Member(db.clone()) });
    assert!(evs.iter().any(|e| matches!(e, ClientEvent::Opened { entry_box: None, .. })), "{evs:?}");
    let (mut q, _) = dial_in(&mut net, a);
    for key in [OpenKey::Member(stranger.clone()), OpenKey::Sync(stranger)] {
        let evs = command(&mut net, a, &mut q, Command::Open { label: l, key });
        assert!(evs.iter().any(|e| matches!(e, ClientEvent::Refused { .. })), "{evs:?}");
    }
    // b removed from g
    let (ta, tb) = (net.tid(a), net.tid(b));
    let e = net.engine(a);
    let rec = recipients_of(e, &[(ta, Role::Admin)]);
    remove_member(e, g, tb, &rec, 79);
    let acts = net.sync(a).handle(Event::Local);
    assert!(acts.contains(&Action::Close { conn: p.conn }), "the member session closes: {acts:?}");
    net.actions(a, acts);
    let (mut r, _) = dial_in(&mut net, a);
    let evs = command(&mut net, a, &mut r, Command::Open { label: l, key: OpenKey::Member(db) });
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
// enough; a node that is no co-reader is never waited for.
#[test]
fn complete_pass_counts_peers_spec_permissions_3() {
    let mut net = Net::new();
    let sv = net.add_server();
    let a = net.node(1, &[sv]);
    let b = net.node(2, &[sv]);
    let c = net.node(3, &[sv]);
    let x = net.node(4, &[sv]);
    reach_ed(&mut net, a);
    reach_ed(&mut net, b);
    reach_ed(&mut net, x);
    let g = net.group(a, &[(b, Role::Admin), (c, Role::Read)], &[sv]);
    net.item(b, g, g, "from b");
    net.run();
    assert!(net.sync(a).complete_pass(&g));
    // x shares nothing with a: its replies held back change nothing
    net.held.insert((x, a));
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

// spec/permissions.md §3: a co-reader removed from G while still sharing another label with the
// node no longer holds G's complete pass, even with its replies held back; nor does one that
// stays silent past `peer_pass_wait_ms`.
#[test]
fn complete_pass_drops_removed_coreader_spec_permissions_3() {
    let mut net = Net::new();
    let sv = net.add_server();
    let a = net.node(1, &[sv]);
    let x = net.node(2, &[sv]);
    let b = net.node(3, &[sv]);
    reach_ed(&mut net, a);
    reach_ed(&mut net, x);
    let g = net.group(a, &[(x, Role::Write), (b, Role::Read)], &[sv]);
    let g2 = net.group_seeded(a, &[(x, Role::Read)], vec![net.address(sv)], 2);
    net.item(x, g, g, "from x");
    net.run();
    assert!(net.sync(a).complete_pass(&g) && net.sync(a).complete_pass(&g2));
    net.held.insert((x, a));
    let (ta, tx) = (net.tid(a), net.tid(x));
    let e = net.engine(a);
    let rec = recipients_of(e, &[(ta, Role::Admin)]);
    remove_member(e, g, tx, &rec, 81);
    // a membership change of g from elsewhere: b's grant
    let tb = net.tid(b);
    let e = net.engine(a);
    set_edge(e, g, tb, Role::Write);
    net.run();
    assert!(net.sync(a).peers().get(&net.sync(x).own_reach().unwrap().dialable).is_some_and(|p| !p.labels.contains(&net_label(&mut net, a, g))), "x still shares g2 only");
    assert!(net.sync(a).complete_pass(&g), "x no longer counts for g");
}

// spec/permissions.md §4: `/reach` goes under a group's labels unless its policy excludes it
// (open audiences): a co-reader then neither learns the dialable key there nor is dialed for it.
#[test]
fn reach_excluded_per_label_spec_permissions_4() {
    for excluded in [false, true] {
        let mut net = Net::new();
        let sv = net.add_server();
        let a = net.node(1, &[sv]);
        let b = net.node(2, &[sv]);
        let g = net.group(a, &[(b, Role::Read)], &[sv]);
        let acts = net.sync(a).set_reach_policy(g, Some(!excluded));
        net.actions(a, acts);
        let ka = reach_ed(&mut net, a);
        let kb = reach_ed(&mut net, b);
        net.run();
        assert_eq!(net.sync(b).peers().contains_key(&ka), !excluded, "excluded: {excluded}");
        assert_eq!(net.sync(a).peers().contains_key(&kb), !excluded, "a dials b: {excluded}");
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
