//! Pairing and removing a node of an account (spec/permissions.md §8): the ordinary grant handed
//! over a channel as an offer, the ordinary removal with A's rotation; notes/account-membership-design.md
//! §2's stolen node.

use crate::common::{s, REG, T0};
use osis_base::{Role, Tid};
use osis_engine::local_peer::{LocalPeer, Peer};
use osis_engine::Mutation;
use osis_schema::core_types as ct;

/// Peer `i` writes `REG` = `v` on `t`: its commit, if valid there.
fn write(lp: &mut LocalPeer, i: usize, t: Tid, v: &str) -> osis_base::CommitId {
    let mut m = Mutation::new();
    m.set(t, &REG, &s(v)).unwrap();
    lp.peers[i].commit(m).unwrap().unwrap()
}

// spec/permissions.md §8 Pairing, spec/sync-set.md §2 First entry: the new node strongs A from its root
// and names it in `settings^.0`; it enters A, its inbox and profile by sync, reads A at the role
// granted, and the two nodes see each other's writes on A.
#[test]
fn a_paired_node_holds_and_writes_the_account_spec_permissions_8() {
    let mut lp = crate::common::net_one(2);
    let a = crate::common::account_of(&mut lp);
    let n1 = lp.peers[1].engine.tid();
    let e1 = &mut lp.peers[1].engine;
    assert_eq!(e1.settings_thing().unwrap(), Some(a));
    assert_eq!(e1.role_on(&a), Some(Role::Admin));
    assert!(e1.closure_holds(&a));
    let inbox = e1.inbox_of(&a).unwrap().unwrap();
    assert!(e1.closure_holds(&inbox), "A's inbox comes with A's sync unit");
    assert_eq!(lp.peers[0].engine.roster(&a).get(&n1).map(|x| x.role), Some(Role::Admin));
    write(&mut lp, 1, a, "from 1");
    lp.sync_all().unwrap();
    assert_eq!(lp.peers[0].engine.get_typed(&a, &REG).unwrap(), Some(s("from 1")));
    write(&mut lp, 0, a, "from 0");
    lp.sync_all().unwrap();
    assert_eq!(lp.peers[1].engine.get_typed(&a, &REG).unwrap(), Some(s("from 0")));
    lp.peers[1].engine.check_closure();
}

// spec/permissions.md §8 Pairing: only a node holding admin on A pairs. A node paired at write
// is refused, and nothing is granted.
#[test]
fn only_an_admin_of_the_account_pairs_spec_permissions_8() {
    let mut lp = LocalPeer::apart(vec![Peer::new(0, T0).unwrap()], 0);
    osis_engine::local_peer::make_account(&mut lp.peers[0].engine).unwrap();
    let a = crate::common::account_of(&mut lp);
    let mut w = Peer::new(1, T0).unwrap();
    let (node, keys) = (w.engine.tid(), w.engine.node_keys().unwrap());
    lp.peers[0].engine.pair(&a, &node, &keys, Role::Write).unwrap();
    w.engine.take_pairing(&a).unwrap();
    lp.peers.push(w);
    lp.sync_all().unwrap();
    assert_eq!(lp.peers[1].engine.role_on(&a), Some(Role::Write));
    let mut fresh = Peer::new(2, T0).unwrap();
    let (n2, k2) = (fresh.engine.tid(), fresh.engine.node_keys().unwrap());
    let r = lp.peers[1].engine.pair(&a, &n2, &k2, Role::Admin);
    assert!(matches!(r, Err(osis_engine::Error::Permission { .. })), "{r:?}");
    assert!(!lp.peers[1].engine.roster(&a).contains_key(&n2));
}

// spec/permissions.md §8 Removing: the remover removes the node's grant on A with A's rotation
// (erase), its `dial.0` entries on A and its `caps^.0` entry. The removed node loses A once the
// removal reaches it, and opens nothing written on A after.
#[test]
fn removing_a_node_rotates_the_account_and_drops_its_entries_spec_permissions_8() {
    let mut lp = crate::common::net_one(2);
    let a = crate::common::account_of(&mut lp);
    let n1 = lp.peers[1].engine.tid();
    lp.peers[1].engine.publish_reach([7; 32], vec!["udp:1.2.3.4:5".into()], &[a]).unwrap();
    lp.peers[0].engine.publish_reach([9; 32], vec!["udp:1.2.3.4:6".into()], &[a]).unwrap();
    let mut caps = std::collections::BTreeMap::new();
    caps.insert(osis_base::Weak(n1), ct::Caps::default());
    let mut m = Mutation::new();
    m.set(a, &ct::CAPS, &caps).unwrap();
    lp.peers[0].commit(m).unwrap();
    lp.sync_all().unwrap();
    let before = lp.peers[0].engine.epochs(&a).unwrap().role(Role::Read).current();
    lp.peers[0].engine.remove_node(&a, &n1, false, &[]).unwrap();
    let e0 = &mut lp.peers[0].engine;
    assert!(!e0.roster(&a).contains_key(&n1));
    assert_ne!(e0.epochs(&a).unwrap().role(Role::Read).current(), before, "A rotated");
    let dial = e0.get_typed(&a, &ct::DIAL).unwrap().unwrap_or_default();
    let n0 = e0.tid();
    assert!(!dial.contains_key(&osis_base::Weak(n1)) && dial.contains_key(&osis_base::Weak(n0)), "the removed node's entry alone goes: {dial:?}");
    assert!(e0.get_typed(&a, &ct::CAPS).unwrap().unwrap_or_default().is_empty());
    write(&mut lp, 0, a, "after");
    lp.sync_all().unwrap();
    lp.settle_needs().unwrap();
    let e1 = &mut lp.peers[1].engine;
    assert_eq!(e1.role_on(&a), None, "removed: {:?}", e1.roster(&a).get(&n1));
    let now = lp.peers[0].engine.epochs(&a).unwrap().role(Role::Read).current();
    let e1 = &mut lp.peers[1].engine;
    assert!(e1.epochs(&a).is_none_or(|ep| now.iter().all(|x| ep.role(Role::Read).secret(x).is_none())), "the removed node holds no epoch of A made at its removal");
    // its loss carried out (sync's trigger, after a complete pass: spec/permissions.md §3 Lost
    // access)
    assert!(e1.drop_lost_secrets().unwrap().contains(&a));
    lp.settle_needs().unwrap();
    let e1 = &mut lp.peers[1].engine;
    assert!(!e1.closure_holds(&a), "the removed node drops A");
}

// notes/account-membership-design.md §2 Stolen node, steps 1, 2 and 6: H removes stolen X. X's
// writes after, on A and on a thing A writes, and its rotation of A boxing itself, are invalid
// wherever the removal is held; X opens no epoch of A made after it.
#[test]
fn a_stolen_node_removed_writes_nothing_valid_after_spec_permissions_8() {
    let mut lp = crate::common::net_one(2);
    let a = crate::common::account_of(&mut lp);
    let x = lp.peers[1].engine.tid();
    let t = {
        let e = &mut lp.peers[0].engine;
        let mut m = Mutation::new();
        let t = e.new_thing(&mut m, a);
        m.set(t, &REG, &s("t")).unwrap();
        e.commit(m).unwrap();
        t
    };
    lp.sync_all().unwrap();
    // the thief holds X as it was: a copy cut off from H
    let mut thief = LocalPeer::apart(vec![lp.peers[1].copy().unwrap()], 1);
    lp.peers[0].engine.remove_node(&a, &x, false, &[]).unwrap();
    let new_read = lp.peers[0].engine.epochs(&a).unwrap().role(Role::Read).current();
    // X writes on A and on T after the removal (honestly stamped, later)
    thief.advance(1000);
    let on_a = write(&mut thief, 0, a, "thief a");
    let on_t = write(&mut thief, 0, t, "thief t");
    let pks: Vec<_> = [on_a, on_t].iter().map(|c| thief.peers[0].engine.package(c).unwrap().unwrap()).collect();
    lp.advance(2000);
    for pk in &pks {
        lp.peers[0].receive(&pk.bytes, pk.blobs.clone()).unwrap();
    }
    let e0 = &mut lp.peers[0].engine;
    assert_ne!(e0.get_typed(&a, &REG).unwrap(), Some(s("thief a")));
    assert_ne!(e0.get_typed(&t, &REG).unwrap(), Some(s("thief t")));
    // A's epochs after the removal are boxed to H's node thing alone
    let boxed = e0.roster(&a).into_keys().collect::<Vec<_>>();
    assert!(!boxed.contains(&x), "{boxed:?}");
    let ep = thief.peers[0].engine.epochs(&a).unwrap();
    assert!(new_read.iter().all(|e| ep.role(Role::Read).secret(e).is_none()), "X holds no epoch of A made after its removal");
}

// spec/crypto.md §4 Exception (security; roles-model `leave`, control `-rotating`): node 0 makes
// account A leave T while it may rotate T (it writes T directly, a node thing's write grant);
// its leave holds back its encrypting there, so it rotates T before writing, and A's other node,
// holding T through A alone, opens nothing written after the leave.
#[test]
fn a_node_that_may_rotate_rotates_before_writing_after_its_account_leaves_spec_crypto_4() {
    let mut lp = crate::common::net_one(2);
    let a = crate::common::account_of(&mut lp);
    let (_, b) = lp.add_account(2).unwrap();
    let n0 = lp.peers[0].engine.tid();
    let t = crate::flows::thing_of(&mut lp, 2, b.thing);
    for h in [a, n0] {
        lp.peers[2].engine.grant(&t, &h, &crate::flows::grant_of(Role::Write)).unwrap();
    }
    lp.sync_all().unwrap();
    let before = lp.peers[0].engine.epochs(&t).unwrap().role(Role::Read).current();
    let c = lp.peers[0].engine.demote(&t, &osis_engine::flows::Demotion { holder: a, new: None, retain: Some(false) }).unwrap().commits[0];
    assert!(lp.peers[0].engine.waiting_removals().contains(&c), "the leave waits to be held elsewhere");
    assert!(lp.peers[0].engine.encrypt_blocked(&t).unwrap(), "its leave holds back its encrypting under T");
    let (done, still) = lp.peers[0].engine.ensure_rotated(&t).unwrap();
    assert!(still.is_empty() && !done.commits.is_empty(), "{done:?} {still:?}");
    assert!(!lp.peers[0].engine.encrypt_blocked(&t).unwrap());
    let now = lp.peers[0].engine.epochs(&t).unwrap().role(Role::Read).current();
    assert_ne!(now, before, "rotated");
    lp.sync_all().unwrap();
    let e1 = &mut lp.peers[1].engine;
    assert!(e1.epochs(&t).is_none_or(|ep| now.iter().all(|x| ep.role(Role::Read).secret(x).is_none())), "A's other node opens no epoch made after the leave");
}
