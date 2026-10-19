#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
//! Co-reader nodes syncing labels peer to peer, in process (spec/sync.md §5, §10;
//! spec/data-model.md §9).

mod net;
use net::*;
use osis_core::Role;
use osis_label::Address;
use osis_node::sync::peers::{lan_tag, LAN_WINDOW_MS};

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

// spec/sync.md §10: a co-reader's announcement matches for the current and adjacent windows,
// and the node then dials the announced transport key (not the dialable key); a stranger's tag
// or one two windows off matches nothing.
#[test]
fn lan_match_dials_announced_key_spec_sync_10() {
    let mut net = Net::new();
    let a = net.node(1, &[]);
    let b = net.node(2, &[]);
    reach(&mut net, a, 0xa4);
    reach(&mut net, b, 0xb4);
    net.blocked_peers.insert((a, b));
    net.group_at(a, &[(b, Role::Write)], vec![]);
    net.run();
    let lan = net.sync(b).own_reach().unwrap().lan_secret;
    let now = net.now();
    let addr = Address { url: "mem://lan-b".into(), key: [0x77; 32] };
    assert_eq!(net.sync(a).lan_seen([9; 16], addr.clone()).0, None);
    assert_eq!(net.sync(a).lan_seen(lan_tag(&lan, now + 2 * LAN_WINDOW_MS), addr.clone()).0, None);
    let (hit, acts) = net.sync(a).lan_seen(lan_tag(&lan, now.saturating_sub(LAN_WINDOW_MS)), addr.clone());
    assert_eq!(hit, Some([0xb4; 32]));
    assert!(acts.iter().any(|x| matches!(x, osis_node::sync::Action::Dial { address, .. } if *address == addr)), "{acts:?}");
}
