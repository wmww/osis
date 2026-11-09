#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
//! Co-reader nodes syncing labels peer to peer, in process (spec/sync.md §5, §10;
//! spec/data-model.md §9).

use crate::net;
use net::*;
use osis_base::Role;
use osis_label::Address;
use osis_crypto::{Domain, Secret32, SigningSecret};
use osis_node::sync::peers::{lan_tag, LAN_WINDOW_MS};
use osis_node::sync::Action;
use osis_transport::lan::Announce;
use std::net::SocketAddr;

fn reach(net: &mut Net, n: usize, key: u8) {
    let acts = net.sync(n).publish_reach([key; 32], vec!["https://relay.example".into()]).unwrap();
    net.actions(n, acts);
}

// spec/sync.md §5 (co-reader peer), §10: two holders of a group whose label names no host sync
// it directly: each dials the other by the dialable key in its `reach.0` and is served the label
// through the host engine over the other's label state; writes flow both ways.
#[test]
fn co_readers_sync_without_host_spec_sync_5() {
    let mut net = Net::new();
    let a = net.node(1, &[]);
    let b = net.node(2, &[]);
    reach(&mut net, a, 0xa1);
    reach(&mut net, b, 0xb1);
    let g = net.group_at(a, &[(b, Role::Write)], vec![]);
    let t = net.item(a, g, g, "direct");
    net.run();
    assert_eq!(net.read(b, t), Some(s("direct")));
    net.write(b, t, "back");
    net.run();
    assert_eq!(net.read(a, t), Some(s("back")));
    assert!(net.sync(a).is_idle() && net.sync(b).is_idle());
}

// spec/sync.md §5, §10: a reader node with only a co-reader peer reachable gets the writer's
// content; the peer relays nothing it may not originate.
#[test]
fn reader_served_by_co_reader_peer_spec_sync_5() {
    let mut net = Net::new();
    let a = net.node(1, &[]);
    let r = net.node(2, &[]);
    reach(&mut net, a, 0xa2);
    reach(&mut net, r, 0xb2);
    let g = net.group_at(a, &[(r, Role::Read)], vec![]);
    let t = net.item(a, g, g, "for the reader");
    net.run();
    assert_eq!(net.read(r, t), Some(s("for the reader")));
}

// spec/sync.md §5, §10: co-readers are the nodes with a `reach.0` this node holds that may read
// a label it syncs; a node with `reach.0` that is no holder is not dialed, and nothing is dialed
// while it is the only one known.
#[test]
fn co_reader_selection_spec_sync_5() {
    let mut net = Net::new();
    let a = net.node(1, &[]);
    let b = net.node(2, &[]);
    let c = net.node(3, &[]);
    reach(&mut net, a, 0xa3);
    reach(&mut net, b, 0xb3);
    reach(&mut net, c, 0xc3);
    net.pair(c, a);
    let g = net.group_at(a, &[(b, Role::Read)], vec![]);
    let l = net.label(a);
    let peers = net.sync(a).peers();
    assert_eq!(peers.keys().copied().collect::<Vec<_>>(), vec![[0xb3; 32]]);
    assert!(peers[&[0xb3; 32]].labels.contains(&l));
    assert_eq!(peers[&[0xb3; 32]].node, net.tid(b));
    // a link's sharer node (first contact): no co-reader
    let tc = net.tid(c);
    net.sync(a).follow_link_peer(g, tc, vec![Address { url: osis_transport::peer_url(&[]), key: [0x5e; 32] }]);
    // the co-reader's dial goes to the peer scheme with the relays from its `reach.0`
    let d = dials(&net.sync(a).handle(osis_node::sync::Event::Local));
    assert_eq!(d.len(), 2, "{d:?}");
    assert!(d.iter().all(|d| d.key == [0x5e; 32] || d.key == [0xb3; 32] && d.url == "peer://https://relay.example"), "{d:?}");
}

// spec/sync.md §10: LAN tags are the kdf of the lan secret and the 10-minute window: equal
// within a window, different across windows and across secrets.
#[test]
fn lan_tag_windows_spec_sync_10() {
    let s1 = [1u8; 32];
    let t0 = 1_700_000_000_000 / LAN_WINDOW_MS * LAN_WINDOW_MS;
    assert_eq!(lan_tag(&s1, t0), lan_tag(&s1, t0 + LAN_WINDOW_MS - 1));
    assert_ne!(lan_tag(&s1, t0), lan_tag(&s1, t0 + LAN_WINDOW_MS));
    assert_ne!(lan_tag(&s1, t0), lan_tag(&[2u8; 32], t0));
    let want = osis_crypto::kdf::kdf("lan tag", &s1, &(t0 / LAN_WINDOW_MS).to_le_bytes());
    assert_eq!(&lan_tag(&s1, t0)[..], &want.expose()[..16]);
}

/// Publishes `reach.0` with the Ed25519 key of node `n`'s dialable secret (what a transport
/// listening with it presents); returns the key.
pub fn reach_ed(net: &mut Net, n: usize) -> [u8; 32] {
    let secret = net.sync(n).dialable_secret();
    let k = SigningSecret::from_seed(&secret).verifying_key().to_bytes();
    let acts = net.sync(n).publish_reach(k, vec![]).unwrap();
    net.actions(n, acts);
    k
}

/// An announcement with node `of`'s tag at `ms`, signed by node `n`'s dialable secret and sealed
/// under `of`'s lan secret.
fn signed(net: &mut Net, n: usize, of: usize, ms: u64, key: [u8; 32], port: u16) -> Announce {
    let sk = SigningSecret::from_seed(&net.sync(n).dialable_secret());
    let lan = net.sync(of).own_reach().unwrap().lan_secret;
    let tag = lan_tag(&lan, ms);
    let sig = osis_crypto::seal_lan_sig(&sk, &Secret32::from_bytes(lan), ms / LAN_WINDOW_MS, &tag, &key, port);
    Announce { tag, key, port, sig }
}

fn dials(acts: &[Action]) -> Vec<Address> {
    acts.iter().filter_map(|x| if let Action::Dial { address, .. } = x { Some(address.clone()) } else { None }).collect()
}

// notes/api.md Sync configuration: `peers` is a read: it names a co-reader by its lasting address,
// not by the LAN route of the moment, whose key is another and which only dialing expires.
#[test]
fn group_peers_names_a_co_reader_not_its_lan_route() {
    let mut net = Net::new();
    let a = net.node(1, &[]);
    let b = net.node(2, &[]);
    reach_ed(&mut net, a);
    let kb = reach_ed(&mut net, b);
    net.blocked_peers.insert((a, b));
    let g = net.group_at(a, &[(b, Role::Write)], vec![]);
    net.run();
    let lasting = vec![Address { url: osis_transport::peer_url(&[]), key: kb }];
    assert_eq!(net.sync(a).group_peers(&g), lasting);
    let own = net.sync(b).lan_announcement([0x77; 32], 4433).unwrap();
    let (hit, _) = net.sync(a).lan_seen(&own, "192.168.1.5:47380".parse().unwrap());
    assert_eq!(hit, Some(kb));
    assert_eq!(net.sync(a).group_peers(&g), lasting, "a LAN route known");
}

// notes/api.md Sync configuration: a source is a node with the label open, not one connected on
// the way to asking.
#[test]
fn a_node_is_a_source_only_once_the_label_is_open() {
    let mut net = Net::new();
    let a = net.node(1, &[]);
    let b = net.node(2, &[]);
    reach(&mut net, a, 0xa7);
    reach(&mut net, b, 0xb7);
    let g = net.group_at(a, &[(b, Role::Write)], vec![]);
    let mut told = false;
    net.feed(a, osis_node::sync::Event::Local);
    net.feed(b, osis_node::sync::Event::Local);
    for _ in 0..50 {
        net.round();
        let st = net.sync(a).label_status();
        let Some(s) = st.iter().find(|s| s.group == g) else { continue };
        if s.sources > 0 {
            let opened = |net: &mut Net, x: usize| net.sync(x).served_opened().values().any(|o| o.contains(&s.label));
            assert!(opened(&mut net, a) || opened(&mut net, b), "connected before anyone opened it");
            told = true;
        }
    }
    assert!(told, "never connected");
}

// spec/sync.md §10: a co-reader's signed announcement matches for the current and adjacent
// windows, and the node then dials the announced transport key at the source address and port
// (not the dialable key), even inside its retry pause (once per pause length); a stranger's tag,
// one two windows off, a signature by another key, one not sealed under the lan secret, a
// changed port, a source that cannot be on the LAN, or a repeat changes nothing; a second new
// address within `LAN_CHANGE_MS` is ignored.
#[test]
fn lan_match_dials_announced_key_spec_sync_10() {
    let mut net = Net::new();
    let a = net.node(1, &[]);
    let b = net.node(2, &[]);
    reach_ed(&mut net, a);
    let kb = reach_ed(&mut net, b);
    net.blocked_peers.insert((a, b));
    net.group_at(a, &[(b, Role::Write)], vec![]);
    net.run();
    let lan = net.sync(b).own_reach().unwrap().lan_secret;
    let now = net.now();
    let ip: SocketAddr = "192.168.1.5:47380".parse().unwrap();
    let own = net.sync(b).lan_announcement([0x77; 32], 4433).unwrap();
    assert_eq!(own.tag, lan_tag(&lan, now));
    let mut stranger = own;
    stranger.tag = [9; 16];
    assert_eq!(net.sync(a).lan_seen(&stranger, ip).0, None);
    let far = signed(&mut net, b, b, now + 2 * LAN_WINDOW_MS, [0x77; 32], 4433);
    assert_eq!(net.sync(a).lan_seen(&far, ip).0, None);
    let forged = signed(&mut net, a, b, now, [0x77; 32], 4433);
    assert_eq!(net.sync(a).lan_seen(&forged, ip).0, None, "signed by another key");
    let sk = SigningSecret::from_seed(&net.sync(b).dialable_secret());
    let plain = Announce { sig: sk.sign(Domain::LanAnnounce, &osis_crypto::lan_digest(&own.tag, &own.key, own.port)).0, ..own };
    assert_eq!(net.sync(a).lan_seen(&plain, ip).0, None, "not sealed");
    let mut moved = own;
    moved.port = 4434;
    assert_eq!(net.sync(a).lan_seen(&moved, ip).0, None, "port not signed");
    assert_eq!(net.sync(a).lan_seen(&own, "8.8.8.8:47380".parse().unwrap()).0, None, "not on the LAN");
    let prev = signed(&mut net, b, b, now.saturating_sub(LAN_WINDOW_MS), [0x77; 32], 4433);
    let (hit, acts) = net.sync(a).lan_seen(&prev, ip);
    assert_eq!(hit, Some(kb));
    assert_eq!(dials(&acts), vec![Address { url: "peer://192.168.1.5:4433".into(), key: [0x77; 32] }]);
    let (hit, again) = net.sync(a).lan_seen(&own, ip);
    assert_eq!((hit, again), (Some(kb), Vec::new()), "a repeat runs nothing");
    // the candidate fails (nobody listens with its key), so does the peer:// route: a new
    // candidate waits for the pause
    net.actions(a, acts);
    net.settle(100_000);
    // b rejoins elsewhere (a fresh key)
    let other: SocketAddr = "192.168.1.6:47380".parse().unwrap();
    let rejoined = net.sync(b).lan_announcement([0x78; 32], 4433).unwrap();
    let (hit, acts) = net.sync(a).lan_seen(&rejoined, other);
    assert_eq!((hit, acts), (Some(kb), Vec::new()), "within LAN_CHANGE_MS");
    net.clock.advance(osis_node::sync::peers::LAN_CHANGE_MS);
    let (hit, acts) = net.sync(a).lan_seen(&rejoined, other);
    assert_eq!(hit, Some(kb));
    assert!(dials(&acts).is_empty(), "the pause holds: {acts:?}");
    net.clock.advance(60_001);
    let acts = net.sync(a).handle(osis_node::sync::Event::Tick);
    assert_eq!(dials(&acts), vec![Address { url: "peer://192.168.1.6:4433".into(), key: [0x78; 32] }]);
}

// spec/sync.md §10 (lan replay): an announcement counts only from the first
// source it was verified from, so a LAN attacker replaying a co-reader's datagram from spoofed
// sources never draws a dial (which would show it who reads that co-reader); nor does one of an
// earlier window than the newest verified, whatever its source.
#[test]
fn lan_replay_from_other_source_ignored_spec_sync_10() {
    let mut net = Net::new();
    let a = net.node(1, &[]);
    let b = net.node(2, &[]);
    reach_ed(&mut net, a);
    let kb = reach_ed(&mut net, b);
    net.blocked_peers.insert((a, b));
    net.group_at(a, &[(b, Role::Write)], vec![]);
    net.run();
    net.clock.advance(60_001);
    let now = net.now();
    let own = net.sync(b).lan_announcement([0x77; 32], 4433).unwrap();
    let real: SocketAddr = "192.168.1.5:47380".parse().unwrap();
    let (hit, acts) = net.sync(a).lan_seen(&own, real);
    assert_eq!(hit, Some(kb));
    let route = Address { url: "peer://192.168.1.5:4433".into(), key: [0x77; 32] };
    assert_eq!(dials(&acts), vec![route.clone()]);
    net.actions(a, acts);
    net.settle(100_000);
    // replays from many spoofed sources, past LAN_CHANGE_MS and the retry pause
    let prev = signed(&mut net, b, b, now.saturating_sub(LAN_WINDOW_MS), [0x76; 32], 4433);
    for i in 0..20u8 {
        net.clock.advance(osis_node::sync::peers::LAN_CHANGE_MS);
        let spoof: SocketAddr = format!("192.168.1.{}:47380", 100 + i).parse().unwrap();
        let (hit, acts) = net.sync(a).lan_seen(&own, spoof);
        assert_eq!((hit, dials(&acts)), (Some(kb), vec![]), "replay from {spoof}");
        let v6: SocketAddr = format!("[fe80::{i}%1]:47380").parse().unwrap();
        assert!(dials(&net.sync(a).lan_seen(&own, v6).1).is_empty(), "replay from {v6}");
        assert!(dials(&net.sync(a).lan_seen(&prev, spoof).1).is_empty(), "earlier window from {spoof}");
    }
    net.clock.advance(60_001);
    let acts = net.sync(a).handle(osis_node::sync::Event::Tick);
    // spoofed sources were 192.168.1.100.. and fe80::
    assert!(dials(&acts).iter().all(|d| !d.url.starts_with("peer://192.168.1.1") && !d.url.contains("fe80")), "{acts:?}");
}

// spec/sync.md §10: the announcement is signed under the dialable key only when that key is
// the dialable secret's Ed25519 key.
#[test]
fn lan_announcement_needs_own_key_spec_sync_10() {
    let mut net = Net::new();
    let a = net.node(1, &[]);
    assert!(net.sync(a).lan_announcement([1; 32], 1).is_none(), "no reach.0 yet");
    reach(&mut net, a, 0xa5);
    assert!(net.sync(a).lan_announcement([1; 32], 1).is_none(), "not the secret's key");
    reach_ed(&mut net, a);
    assert!(net.sync(a).lan_announcement([1; 32], 1).is_some());
}

// spec/sync.md §10 (a proven route first): a co-reader reached through its `peer://` route that
// is then heard on the LAN is dialed there beside the running connection; once that comes up
// the other connection closes and the label goes on over the LAN.
#[test]
fn lan_replaces_relay_route_spec_sync_10() {
    let mut net = Net::new();
    let a = net.node(1, &[]);
    let b = net.node(2, &[]);
    reach_ed(&mut net, a);
    let kb = reach_ed(&mut net, b);
    let g = net.group_at(a, &[(b, Role::Write)], vec![]);
    let t = net.item(a, g, g, "over the relay");
    net.run();
    assert_eq!(net.read(b, t), Some(s("over the relay")));
    let routes = net.sync(a).peer_routes();
    assert!(matches!(routes.as_slice(), [(k, x, true)] if *k == kb && x.key == kb), "{routes:?}");
    // b joins a LAN a is on
    let lk = SigningSecret::from_seed(&net.sync(b).lan_secret()).verifying_key().to_bytes();
    net.lan_keys.insert(lk, b);
    let ann = net.sync(b).lan_announcement(lk, 5000).unwrap();
    let (hit, acts) = net.sync(a).lan_seen(&ann, "192.168.3.4:47380".parse().unwrap());
    assert_eq!(hit, Some(kb));
    let lan = Address { url: "peer://192.168.3.4:5000".into(), key: lk };
    assert_eq!(dials(&acts), vec![lan.clone()], "dialed beside the running connection");
    net.actions(a, acts);
    net.settle(100_000);
    assert_eq!(net.sync(a).peer_routes(), vec![(kb, lan.clone(), true)], "the relay connection closed");
    let u = net.item(a, g, g, "over the LAN");
    net.run();
    assert_eq!(net.read(b, u), Some(s("over the LAN")));
    assert_eq!(net.sync(a).peer_routes(), vec![(kb, lan, true)]);
    // a repeat of the announcement dials nothing more
    let (_, acts) = net.sync(a).lan_seen(&ann, "192.168.3.4:47380".parse().unwrap());
    assert!(dials(&acts).is_empty());
}

// spec/permissions.md §4 (`reach.0` under every label), spec/sync.md §10 (IP consent): a node's
// `reach.0` reaches the readers of every group it syncs, other accounts' nodes included; a
// rotation (`Osis::rotate_peer_address`) renews the dialable key and lan secret, tells the driver
// to listen again, and the new `reach.0` reaches them too.
#[test]
fn reach_under_every_label_and_rotation_spec_permissions_4() {
    let mut net = Net::new();
    let a = net.node(1, &[]);
    let b = net.node(2, &[]);
    let c = net.node(3, &[]);
    reach_ed(&mut net, a);
    reach_ed(&mut net, b);
    reach_ed(&mut net, c);
    let g = net.group_at(a, &[(b, Role::Write), (c, Role::Write)], vec![]);
    net.run();
    let ta = net.tid(a);
    let reach_at = |net: &mut Net, n: usize| net.engine(n).get_typed(&ta, &osis_schema::core_types::REACH).unwrap();
    let old = net.sync(a).own_reach().unwrap();
    assert_eq!(reach_at(&mut net, b), Some(old.clone()));
    assert_eq!(reach_at(&mut net, c), Some(old.clone()));
    let acts = net.sync(a).rotate_reach();
    assert!(acts.iter().any(|x| matches!(x, Action::Reach)), "{acts:?}");
    net.actions(a, acts);
    let new = net.sync(a).own_reach().unwrap();
    assert_ne!(new.dialable, old.dialable);
    assert_ne!(new.lan_secret, old.lan_secret);
    assert_eq!(new.dialable, SigningSecret::from_seed(&net.sync(a).dialable_secret()).verifying_key().to_bytes());
    let t = net.item(a, g, g, "after the rotation");
    net.run();
    net.advance(61_000);
    assert_eq!(reach_at(&mut net, b), Some(new.clone()));
    assert_eq!(reach_at(&mut net, c), Some(new));
    assert_eq!(net.read(c, t), Some(s("after the rotation")));
}

// spec/sync.md §10 (a candidate never replaces a working route before it is up): a LAN address
// whose dial fails beside a running relay connection leaves that connection in place.
#[test]
fn failed_lan_route_keeps_relay_spec_sync_10() {
    let mut net = Net::new();
    let a = net.node(1, &[]);
    let b = net.node(2, &[]);
    reach_ed(&mut net, a);
    let kb = reach_ed(&mut net, b);
    let g = net.group_at(a, &[(b, Role::Write)], vec![]);
    net.run();
    let relay = net.sync(a).peer_routes();
    assert!(matches!(relay.as_slice(), [(k, _, true)] if *k == kb));
    // a signed announcement of a key nobody listens with
    let ann = net.sync(b).lan_announcement([0x66; 32], 5000).unwrap();
    let (_, acts) = net.sync(a).lan_seen(&ann, "192.168.3.9:47380".parse().unwrap());
    assert_eq!(dials(&acts), vec![Address { url: "peer://192.168.3.9:5000".into(), key: [0x66; 32] }]);
    net.actions(a, acts);
    net.settle(100_000);
    assert_eq!(net.sync(a).peer_routes(), relay, "the relay connection stays");
    let t = net.item(a, g, g, "still over the relay");
    net.run();
    assert_eq!(net.read(b, t), Some(s("still over the relay")));
}

/// The connection of the dial to `key` among `acts`.
fn dial_to(acts: &[Action], key: [u8; 32]) -> Option<osis_node::sync::ConnId> {
    acts.iter().find_map(|x| if let Action::Dial { conn, address, .. } = x { (address.key == key).then_some(*conn) } else { None })
}

// spec: none (notes/peers.md, redial): a co-reader whose connection was up is redialed at once
// (a P2P dial that punched through ends its relayed connection; the redial takes the direct
// one), at most once per `peer_retry_ms`; a dial that never came up waits the pause.
#[test]
fn co_reader_redialed_at_once_after_up() {
    use osis_node::sync::Event;
    let mut net = Net::new();
    let a = net.node(1, &[]);
    let b = net.node(2, &[]);
    reach(&mut net, a, 0xa4);
    reach(&mut net, b, 0xb4);
    let _g = net.group_at(a, &[(b, Role::Read)], vec![]);
    let kb = [0xb4; 32];
    let conn = dial_to(&net.sync(a).handle(Event::Local), kb).expect("dialed");
    net.sync(a).handle(Event::Up { conn });
    let conn = dial_to(&net.sync(a).handle(Event::Down { conn }), kb).expect("redialed at once");
    // again within the pause: it waits
    net.sync(a).handle(Event::Up { conn });
    assert_eq!(dial_to(&net.sync(a).handle(Event::Down { conn }), kb), None);
    net.clock.advance(60_001);
    let conn = dial_to(&net.sync(a).handle(Event::Tick), kb).expect("dialed after the pause");
    // never up: it waits
    assert_eq!(dial_to(&net.sync(a).handle(Event::Down { conn }), kb), None);
}
