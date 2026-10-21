#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
//! Co-reader nodes syncing labels peer to peer, in process (spec/sync.md §5, §10;
//! spec/data-model.md §9).

mod net;
use net::*;
use osis_core::Role;
use osis_label::Address;
use osis_crypto::{Domain, Secret32, SigningSecret};
use osis_node::sync::peers::{lan_tag, LAN_WINDOW_MS};
use osis_node::sync::Action;
use osis_transport::lan::Announce;
use std::net::IpAddr;

fn reach(net: &mut Net, n: usize, key: u8) {
    let acts = net.sync(n).publish_reach([key; 32], vec!["https://relay.example".into()]).unwrap();
    net.actions(n, acts);
}

// spec/sync.md §5 (member peer), §10: two members of a group whose label names no server sync
// it directly: each dials the other by the dialable key in its `/reach` and is served the label
// through the server engine over the other's label state; writes flow both ways.
#[test]
fn co_readers_sync_without_server_spec_sync_5() {
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

// spec/sync.md §5, §10: a reader node with only a member peer reachable gets the writer's
// content; the peer relays nothing it may not originate.
#[test]
fn reader_served_by_member_peer_spec_sync_5() {
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

// spec/sync.md §5, §10: co-readers are the nodes with a `/reach` this node holds that may read
// a label it syncs; a node with `/reach` that is no member is not dialed, and nothing is dialed
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
    let _ = g;
    // the dial goes to the peer scheme with the relays from its `/reach`
    let acts = net.sync(a).handle(osis_node::sync::Event::Local);
    let dials: Vec<Address> = acts.iter().filter_map(|x| if let osis_node::sync::Action::Dial { address, .. } = x { Some(address.clone()) } else { None }).collect();
    assert!(dials.iter().all(|d| d.key == [0xb3; 32] && d.url == "peer://https://relay.example"), "{dials:?}");
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

/// Publishes `/reach` with the Ed25519 key of node `n`'s dialable secret (what a transport
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
    let ip: IpAddr = "192.168.1.5".parse().unwrap();
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
    assert_eq!(net.sync(a).lan_seen(&own, "8.8.8.8".parse().unwrap()).0, None, "not on the LAN");
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
    let other: IpAddr = "192.168.1.6".parse().unwrap();
    let (hit, acts) = net.sync(a).lan_seen(&own, other);
    assert_eq!((hit, acts), (Some(kb), Vec::new()), "within LAN_CHANGE_MS");
    net.clock.advance(osis_node::sync::peers::LAN_CHANGE_MS);
    let (hit, acts) = net.sync(a).lan_seen(&own, other);
    assert_eq!(hit, Some(kb));
    assert!(dials(&acts).is_empty(), "the pause holds: {acts:?}");
    net.clock.advance(60_001);
    let acts = net.sync(a).handle(osis_node::sync::Event::Tick);
    assert_eq!(dials(&acts), vec![Address { url: "peer://192.168.1.6:4433".into(), key: [0x77; 32] }]);
}

// spec/sync.md §10: the announcement is signed under the dialable key only when that key is
// the dialable secret's Ed25519 key.
#[test]
fn lan_announcement_needs_own_key_spec_sync_10() {
    let mut net = Net::new();
    let a = net.node(1, &[]);
    assert!(net.sync(a).lan_announcement([1; 32], 1).is_none(), "no /reach yet");
    reach(&mut net, a, 0xa5);
    assert!(net.sync(a).lan_announcement([1; 32], 1).is_none(), "not the secret's key");
    reach_ed(&mut net, a);
    assert!(net.sync(a).lan_announcement([1; 32], 1).is_some());
}
