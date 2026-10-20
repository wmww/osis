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

// spec/sync.md §10: a LAN announcement only proposes an address; a candidate that fails is
// backed off without pausing the peer, which is reached by its `peer://` route at once.
#[test]
fn lan_candidate_failure_keeps_route_spec_sync_10() {
    let mut net = Net::new();
    let a = net.node(1, &[]);
    let b = net.node(2, &[]);
    reach(&mut net, a, 0xa1);
    reach(&mut net, b, 0xb1);
    net.blocked_peers.insert((a, b));
    let g = net.group_at(a, &[(b, Role::Write)], vec![]);
    net.run();
    net.blocked_peers.clear();
    let lan = net.sync(b).own_reach().unwrap().lan_secret;
    let now = net.now();
    let bogus = Address { url: "mem://nowhere".into(), key: [0x77; 32] };
    let (hit, acts) = net.sync(a).lan_seen(osis_node::sync::peers::lan_tag(&lan, now), bogus.clone());
    assert_eq!(hit, Some([0xb1; 32]));
    assert!(acts.iter().any(|x| matches!(x, Action::Dial { address, .. } if *address == bogus)));
    net.actions(a, acts);
    net.settle(100_000);
    // the candidate failed: the peer:// route is dialed without waiting for the peer pause
    let t = net.item(a, g, g, "via peer route");
    net.run();
    assert_eq!(net.read(b, t), Some(s("via peer route")));
    // the failed address is not dialed again while backed off
    let (_, acts) = net.sync(a).lan_seen(osis_node::sync::peers::lan_tag(&lan, now), bogus.clone());
    assert!(!acts.iter().any(|x| matches!(x, Action::Dial { address, .. } if *address == bogus)));
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
