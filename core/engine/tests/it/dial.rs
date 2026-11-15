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
// inbox blob hint, spec/sync-inbox.md §2: dialed while the blob is held and its sync IDs are
// kept): a node keeping a thing unread it accepted dials the node that granted it (also after a
// restart).
#[test]
fn the_granter_of_what_it_keeps_unread_spec_sync_opens_1() {
    let (mut lp, ps) = people(2);
    publish(&mut lp, 0);
    let d0 = lp.peers[0].engine.account().unwrap().unwrap().1;
    let (t, s) = synced_thing(&mut lp, 0, d0);
    let done = lp.peers[0].engine.grant(&t, &ps[1], &edge_of(Role::Sync)).unwrap();
    let blob = lp.inbox_blobs(0, &done).unwrap().into_iter().find(|(h, _)| *h == ps[1]).expect("an inbox blob to peer 1").1;
    lp.peers[1].engine.take_inbox_blob(&blob, false).unwrap().expect("opens");
    crate::facade::accept(&mut lp, 1, t);
    assert_eq!(lp.peers[1].engine.sync_holder(&s).unwrap(), Some((t, osis_engine::sync::Holding::Unread)));
    assert_eq!(peers(&mut lp, 1, &s), vec![addr(0)]);
    lp.peers[1].restart(7).unwrap();
    assert_eq!(peers(&mut lp, 1, &s), vec![addr(0)], "after a restart");
}

// spec/sync-status.md §3 (held by no other node), by the rosters, known address or not: a thing
// of a one-node account is held by no other node, until another account holds a role on it
// (with no address known), and again once removed; the accepter of a thing it keeps unread
// waits for its granter; two nodes of one account each hold home for the other. Per peer
// (`may_hold`): by the proven actors a holder is named by.
#[test]
fn roster_holders_by_the_rosters_spec_sync_status_3() {
    let (mut lp, ps) = people(2);
    let d0 = lp.peers[0].engine.account().unwrap().unwrap().1;
    let home = lp.peers[0].engine.home_sync_id(&d0).unwrap().unwrap();
    let (t, s) = synced_thing(&mut lp, 0, d0);
    let held = |lp: &mut LocalPeer, i: usize, s: &SyncId| lp.peers[i].engine.roster_holders(s).unwrap().any();
    assert!(!held(&mut lp, 0, &home) && !held(&mut lp, 0, &s), "a one-node account");
    let done = lp.peers[0].engine.grant(&t, &ps[1], &edge_of(Role::Sync)).unwrap();
    assert!(peers(&mut lp, 0, &s).is_empty() && held(&mut lp, 0, &s), "no address known, held all the same");
    let r = lp.peers[0].engine.roster_holders(&s).unwrap();
    assert!(r.may_hold(&[ps[1]]) && !r.may_hold(&[ps[0]]), "per peer: the grantee's account, never this one");
    let blob = lp.inbox_blobs(0, &done).unwrap().into_iter().find(|(h, _)| *h == ps[1]).expect("an inbox blob to peer 1").1;
    lp.peers[1].engine.take_inbox_blob(&blob, false).unwrap().expect("opens");
    crate::facade::accept(&mut lp, 1, t);
    assert!(held(&mut lp, 1, &s), "kept unread: its granter");
    lp.peers[0].engine.demote(&t, &Demotion { holder: ps[1], new: None, retain: None }).unwrap();
    assert!(!held(&mut lp, 0, &s), "removed");
    let (mut lp, d) = account_two_nodes();
    spread(&mut lp);
    let home = lp.peers[0].engine.home_sync_id(&d).unwrap().unwrap();
    assert!(held(&mut lp, 0, &home) && held(&mut lp, 1, &home));
    let n1 = lp.peers[1].engine.tid();
    assert!(lp.peers[0].engine.roster_holders(&home).unwrap().may_hold(&[n1]), "per peer: the other node");
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

// spec/sync-set.md §1 (dial list: a node removed from D has no entry): the node removing another
// takes its entry out of the profile's dial list in the removal's transaction, and an entry of
// the removed node's key written there again (whoever writes it) goes again at once; the node
// paired again is listed again (also after a restart).
#[test]
fn a_removed_nodes_entry_leaves_the_dial_list_spec_sync_set_1() {
    let (mut lp, d) = account_two_nodes();
    publish(&mut lp, 0);
    publish(&mut lp, 1);
    spread(&mut lp);
    let p = lp.peers[0].engine.account().unwrap().unwrap().0;
    let profile = lp.peers[0].engine.profile_of(&p).expect("P's profile");
    let keys = |lp: &mut LocalPeer| lp.peers[0].engine.get_typed(&profile, &ct::DIAL).unwrap().unwrap_or_default().into_keys().collect::<Vec<_>>();
    assert_eq!(keys(&mut lp), vec![key(0).to_vec(), key(1).to_vec()]);
    let n1 = lp.peers[1].engine.tid();
    lp.peers[0].engine.demote(&d, &Demotion { holder: n1, new: None, retain: None }).unwrap();
    assert_eq!(keys(&mut lp), vec![key(0).to_vec()], "the removal's transaction drops it");
    let mut m = Mutation::new();
    m.op(profile, &ct::DIAL, osis_crdt::PathOp { path: vec![osis_crdt::PathSeg::Key(osis_base::Value::bytes(&key(1)))], op: osis_crdt::Op::Set(osis_base::Value::List(vec![osis_base::Value::Str(peer_url(&items(1)))])) }).unwrap();
    lp.peers[0].engine.commit(m).unwrap();
    assert_eq!(keys(&mut lp), vec![key(0).to_vec()], "written again: dropped again");
    // paired again: a node of D, its entry stays
    let (_, again) = lp.peers[0].engine.pair(&n1).unwrap();
    crate::flows::send(&mut lp, 0, 1, &again);
    lp.peers[1].engine.paired(&p).unwrap();
    spread(&mut lp);
    publish(&mut lp, 1);
    spread(&mut lp);
    lp.peers[0].restart(3).unwrap();
    publish(&mut lp, 0);
    assert_eq!(keys(&mut lp), vec![key(0).to_vec(), key(1).to_vec()], "back on D: listed");
}

// spec/sync-set.md §1 (dial list: a removed node's entry goes, unless a node on D's `reach.0`
// names that key too): a node that named another node's dialable key in its own `reach.0`
// before it was removed takes nothing out of the dial list with it.
#[test]
fn a_removed_node_naming_anothers_key_drops_no_entry_spec_sync_set_1() {
    let (mut lp, d) = account_two_nodes();
    publish(&mut lp, 0);
    publish(&mut lp, 1);
    spread(&mut lp);
    let p = lp.peers[0].engine.account().unwrap().unwrap().0;
    let n1 = lp.peers[1].engine.tid();
    let mut m = Mutation::new();
    m.set(n1, &ct::REACH, &ct::Reach { dialable: key(0), items: items(1), account: Some(p) }).unwrap();
    lp.peers[1].engine.commit(m).unwrap();
    spread(&mut lp);
    let profile = lp.peers[0].engine.profile_of(&p).expect("P's profile");
    lp.peers[0].engine.demote(&d, &Demotion { holder: n1, new: None, retain: None }).unwrap();
    let keys = lp.peers[0].engine.get_typed(&profile, &ct::DIAL).unwrap().unwrap_or_default().into_keys().collect::<Vec<_>>();
    assert_eq!(keys, vec![key(0).to_vec(), key(1).to_vec()], "node 0's entry stays; node 1's own key is not one its reach.0 names");
}

// spec/sync-set.md §1 (dial list: a removed node's entry goes whenever it is held): the removed
// node rewrites its entry beside its removal, not having seen it (counted here or not); once
// both meet, the entry is gone and stays gone, and nothing more is written (no node writes it
// back to drop it again).
#[test]
fn an_entry_written_beside_the_removal_goes_once_spec_sync_set_1() {
    let (mut lp, d) = account_two_nodes();
    publish(&mut lp, 0);
    publish(&mut lp, 1);
    spread(&mut lp);
    let p = lp.peers[0].engine.account().unwrap().unwrap().0;
    let profile = lp.peers[0].engine.profile_of(&p).expect("P's profile");
    let n1 = lp.peers[1].engine.tid();
    lp.peers[0].engine.demote(&d, &Demotion { holder: n1, new: None, retain: None }).unwrap();
    lp.peers[1].engine.publish_reach(key(1), items(5)).unwrap();
    spread(&mut lp);
    let keys = |lp: &mut LocalPeer| lp.peers[0].engine.get_typed(&profile, &ct::DIAL).unwrap().unwrap_or_default().into_keys().collect::<Vec<_>>();
    assert_eq!(keys(&mut lp), vec![key(0).to_vec()]);
    let held = lp.peers[0].engine.commit_ids().len();
    spread(&mut lp);
    spread(&mut lp);
    assert_eq!(keys(&mut lp), vec![key(0).to_vec()]);
    assert_eq!(lp.peers[0].engine.commit_ids().len(), held, "settled: no more writes");
}
