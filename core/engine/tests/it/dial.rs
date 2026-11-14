//! Whom a node dials (`Engine::dial_peers`, spec/sync-opens.md §1 Whom to dial) and what it
//! publishes of itself (`Engine::publish_reach`, spec/sync-set.md §1, spec/sync-transport.md §5),
//! over `LocalPeer` (commits and inbox blobs carried by hand).

use crate::flows::{account_two_nodes, edge_of, people, spread, thing_of};
use osis_base::{Address, Role, SyncId, Tid, peer_url};
use osis_engine::flows::Demotion;
use osis_engine::local_peer::LocalPeer;
use osis_engine::Engine;
use osis_engine::Mutation;
use osis_schema::core_types as ct;

/// Peer `i`'s dialable key and `reach.0` items.
fn key(i: usize) -> [u8; 32] {
    [0x40 + i as u8; 32]
}

fn items(i: usize) -> Vec<String> {
    vec![format!("203.0.113.{}:4040", 10 + i)]
}

/// Peer `i` publishes where it is dialed.
fn publish(lp: &mut LocalPeer, i: usize) {
    lp.peers[i].engine.publish_reach(key(i), items(i)).unwrap();
}

/// Peer `i`'s address as others dial it.
fn addr(i: usize) -> Address {
    Address { url: peer_url(&items(i)), key: key(i) }
}

/// `t` filed as an item of group `g`.
fn file(e: &mut Engine, g: Tid, t: Tid) {
    let mut grp = e.get_typed(&g, &ct::GROUP).unwrap().unwrap_or_default();
    grp.items.insert(t);
    let mut m = Mutation::new();
    m.set(g, &ct::GROUP, &grp).unwrap();
    e.commit(m).unwrap().unwrap();
}

/// A new thing of peer `i`'s account with secrets of its own, filed in group `g`; its sync ID.
fn synced_thing(lp: &mut LocalPeer, i: usize, g: Tid) -> (Tid, SyncId) {
    let a = lp.peers[i].engine.account().unwrap().unwrap().0;
    let t = thing_of(lp, i, a);
    let e = &mut lp.peers[i].engine;
    e.give_own_secrets(&t).unwrap();
    file(e, g, t);
    (t, e.home_sync_id(&t).unwrap().unwrap())
}

fn peers(lp: &mut LocalPeer, i: usize, s: &SyncId) -> Vec<Address> {
    lp.peers[i].engine.dial_peers(s).unwrap().to_vec()
}

// spec/sync-opens.md §1 (whom to dial: its own nodes while their sync sets intersect; where:
// `reach.0` under home): two nodes of one account dial each other for home; a thing only node
// 0's synced group lists is no reason to dial node 1 (its sync set is home's closure) until D
// lists it too. A node never dials its own key.
#[test]
fn own_nodes_while_their_sync_sets_intersect_spec_sync_opens_1() {
    let (mut lp, d) = account_two_nodes();
    publish(&mut lp, 0);
    publish(&mut lp, 1);
    spread(&mut lp);
    let home = lp.peers[0].engine.home_sync_id(&d).unwrap().unwrap();
    assert_eq!(peers(&mut lp, 0, &home), vec![addr(1)]);
    assert_eq!(peers(&mut lp, 1, &home), vec![addr(0)]);
    let me = lp.peers[0].engine.tid();
    let g0 = *lp.peers[0].engine.get_typed(&d, &ct::SYNCED).unwrap().unwrap().get(&me).expect("node 0's synced group");
    let (t, s) = synced_thing(&mut lp, 0, g0);
    spread(&mut lp);
    assert!(peers(&mut lp, 0, &s).is_empty(), "node 1 does not sync it");
    file(&mut lp.peers[0].engine, d, t);
    spread(&mut lp);
    assert_eq!(peers(&mut lp, 0, &s), vec![addr(1)], "now it does");
}

// spec/sync-opens.md §1 (whom to dial: the nodes of accounts holding sync or above on a sync ID
// it syncs; where: their profile's `dial^.0`): node 0 dials node 1 for a thing once node 1's
// account holds a role on it, and no longer once it is removed.
#[test]
fn accounts_holding_a_role_by_their_dial_list_spec_sync_opens_1() {
    let (mut lp, ps) = people(2);
    publish(&mut lp, 0);
    publish(&mut lp, 1);
    spread(&mut lp);
    let d0 = lp.peers[0].engine.account().unwrap().unwrap().1;
    let (t, s) = synced_thing(&mut lp, 0, d0);
    assert!(peers(&mut lp, 0, &s).is_empty(), "nobody else holds it");
    lp.peers[0].engine.grant(&t, &ps[1], &edge_of(Role::Read)).unwrap();
    assert_eq!(peers(&mut lp, 0, &s), vec![addr(1)]);
    lp.peers[0].engine.demote(&t, &Demotion { holder: ps[1], new: None, retain: None }).unwrap();
    assert!(peers(&mut lp, 0, &s).is_empty(), "removed");
}

// spec/sync-opens.md §1 (whom to dial: the granters of what it keeps unread; where: the grant's
// inbox blob hint, spec/sync-inbox.md §2): a node keeping a thing unread dials the node that
// granted it, by the hint its sync record keeps (durable: it is there after a restart).
#[test]
fn the_granter_of_what_it_keeps_unread_spec_sync_opens_1() {
    let (mut lp, ps) = people(2);
    publish(&mut lp, 0);
    let d0 = lp.peers[0].engine.account().unwrap().unwrap().1;
    let (t, s) = synced_thing(&mut lp, 0, d0);
    let done = lp.peers[0].engine.grant(&t, &ps[1], &edge_of(Role::Sync)).unwrap();
    let blob = lp.inbox_blobs(0, &done).unwrap().into_iter().find(|(h, _)| *h == ps[1]).expect("an inbox blob to peer 1").1;
    lp.peers[1].engine.take_inbox_blob(&blob, true).unwrap().expect("opens");
    let d1 = lp.peers[1].engine.account().unwrap().unwrap().1;
    file(&mut lp.peers[1].engine, d1, t);
    assert_eq!(lp.peers[1].engine.sync_holder(&s).unwrap(), Some((t, osis_engine::sync::Holding::Unread)));
    assert_eq!(peers(&mut lp, 1, &s), vec![addr(0)]);
    lp.peers[1].restart(7).unwrap();
    assert_eq!(peers(&mut lp, 1, &s), vec![addr(0)], "after a restart");
}

// spec/sync-set.md §1 (dial list: each node keeping its own entry), spec/sync-transport.md §5
// (key change: the node writes its `reach.0` and its `dial^.0` entry for the new key): a new key
// replaces the node's entry; publishing again unchanged writes nothing.
#[test]
fn a_new_key_replaces_the_nodes_entry_spec_sync_transport_5() {
    let (mut lp, ps) = people(1);
    let e = &mut lp.peers[0].engine;
    let profile = e.profile_of(&ps[0]).expect("the profile, created with the account");
    e.publish_reach(key(0), items(0)).unwrap();
    let n = e.commit_ids().len();
    e.publish_reach(key(0), items(0)).unwrap();
    assert_eq!(e.commit_ids().len(), n, "nothing changed, nothing written");
    e.publish_reach(key(1), items(0)).unwrap();
    let list = e.get_typed(&profile, &ct::DIAL).unwrap().unwrap();
    assert_eq!(list.keys().cloned().collect::<Vec<_>>(), vec![key(1).to_vec()]);
    assert_eq!(list[&key(1).to_vec()], vec![peer_url(&items(0))]);
    let me = e.tid();
    assert_eq!(e.get_typed(&me, &ct::REACH).unwrap().map(|r| r.dialable), Some(key(1)));
}

// spec/sync-set.md §1 (dial list: written by the account; `dial^.0` admin-only,
// spec/data-model.md §1 `^`): a co-writer of P's profile cannot write its dial list (a delta
// it forged anyway is invalid by spec/permissions.md §5.2): P's contact dials P's own nodes only.
#[test]
fn a_co_writer_cannot_plant_a_dial_list_spec_sync_set_1() {
    let (mut lp, ps) = people(3);
    publish(&mut lp, 0);
    spread(&mut lp);
    let profile = lp.peers[0].engine.profile_of(&ps[0]).expect("P's profile");
    lp.peers[0].engine.grant(&profile, &ps[1], &edge_of(Role::Write)).unwrap();
    lp.peers[0].engine.grant(&profile, &ps[2], &edge_of(Role::Read)).unwrap();
    spread(&mut lp);
    let mut list = ct::DialList::new();
    list.insert(vec![0x66; 32], vec!["peer://198.51.100.1:4040".to_string()]);
    let e1 = &mut lp.peers[1].engine;
    let mut m = Mutation::new();
    m.set(profile, &ct::DIAL, &list).unwrap();
    assert!(matches!(e1.commit(m), Err(osis_engine::Error::Permission { .. })), "admin-only");
    spread(&mut lp);
    let e2 = &mut lp.peers[2].engine;
    let held = e2.get_typed(&profile, &ct::DIAL).unwrap().unwrap_or_default();
    assert_eq!(held.keys().cloned().collect::<Vec<_>>(), vec![key(0).to_vec()], "P's own entry only");
    let d2 = e2.account().unwrap().unwrap().1;
    let (_, s) = synced_thing(&mut lp, 2, d2);
    let t = lp.peers[2].engine.sync_owner(&s).unwrap().unwrap();
    lp.peers[2].engine.grant(&t, &ps[0], &edge_of(Role::Read)).unwrap();
    assert_eq!(peers(&mut lp, 2, &s), vec![addr(0)]);
}
