//! Whom a node dials (`Engine::dial_peers`, spec/sync-opens.md §1 Whom to dial) and what it
//! publishes of itself (`Engine::publish_reach`, spec/sync-set.md §1, spec/sync-transport.md §5),
//! over `LocalPeer` (commits and sealed fires carried by hand).

use crate::flows::{account_two_nodes, people, spread};
use osis_base::peer_url;
use osis_engine::flows::Demotion;
use osis_engine::local_peer::LocalPeer;
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

// spec/sync-set.md §1 (dial list: a node removed from D has no entry): the node removing another
// takes its entry out of the profile's dial list in the removal's transaction, and an entry of
// the removed node's key written there again (whoever writes it) goes again at once; the node
// paired again is listed again (also after a restart).
#[test]
fn a_removed_nodes_entry_leaves_the_dial_list_spec_sync_set_1() {
    let (mut lp, d) = account_two_nodes();
    publish(&mut lp, 0);
    // a node paired a moment ago lists itself once it holds the profile
    spread(&mut lp);
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
    lp.peers[1].engine.joining(&p).unwrap();
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
    // a node paired a moment ago lists itself once it holds the profile
    spread(&mut lp);
    publish(&mut lp, 1);
    spread(&mut lp);
    let p = lp.peers[0].engine.account().unwrap().unwrap().0;
    let n1 = lp.peers[1].engine.tid();
    let mut m = Mutation::new();
    m.set(n1, &ct::REACH, &ct::Reach { dialable: key(0), items: items(1), account: Some(osis_base::Weak(p)) }).unwrap();
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
    // a node paired a moment ago lists itself once it holds the profile
    spread(&mut lp);
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
