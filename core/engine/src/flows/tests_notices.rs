//! Notices (spec/permissions.md §4 Notices): what a departed holder is told.

#![allow(clippy::unwrap_used)]
use crate::rotation::tests::{edge, independent_thing, synced};
use osis_base::Role;

// spec/sync-hostile.md (a peer judged departed is served only the notices of its removals),
// spec/sync-opens.md §6, spec/permissions.md §4 (Notices): peer 1 reads X through G alone. Peer 1
// leaves G, so it reads X no more; later G is removed from X. That removal is past peer 1's
// departure: a departed peer proving peer 1 is told nothing of it. Control: G removed while peer
// 1 still reads through it, told. Fails with the removal of anything a proven thing ever held a
// role on told, whenever made.
#[test]
fn a_departed_peer_is_told_no_removal_past_its_own_spec_sync_opens_6() {
    for late in [false, true] {
        let mut lp = synced(2);
        let n = lp.peers[1].engine.tid();
        let x = independent_thing(&mut lp, 0);
        let g = independent_thing(&mut lp, 0);
        lp.peers[0].engine.grant(&x, &g, &edge(Role::Read)).unwrap();
        lp.peers[0].engine.grant(&g, &n, &edge(Role::Read)).unwrap();
        lp.sync_all().unwrap();
        if late {
            lp.peers[0].engine.demote(&g, &super::Demotion { holder: n, new: None, retain: None }).unwrap();
            lp.sync_all().unwrap();
        }
        lp.peers[0].engine.demote(&x, &super::Demotion { holder: g, new: None, retain: None }).unwrap();
        lp.sync_all().unwrap();
        let e = &mut lp.peers[0].engine;
        let s = e.sync_id_of(&x).unwrap().expect("X's sync ID");
        let told: Vec<_> = e.notices_for(&s, &[n].into()).unwrap().into_iter().filter(|x| x.holder == g && x.departs).collect();
        assert_eq!(told.is_empty(), late, "late {late}: peer 1 told G's removal only while it read X through G");
        assert!(e.notices_for(&s, &[g].into()).unwrap().iter().any(|x| x.holder == g && x.departs), "late {late}: G is told");
    }
}

// spec/permissions.md §4 (Notices: boxes), spec/sync-opens.md §5 (ByRole): peer 1 is granted read
// on X, then X rotates twice. A peer proving peer 1 is told its grant alone: the rotations box it
// under epochs the grant gives, so they open by their wraps. Peer 1, holding nothing of X but
// following its locator (as a signal or pairing has it), opens the notice by its own KEM key and
// holds the grant's epoch. Fails with the grant's notice not given or not taken by a node holding
// nothing of X.
#[test]
fn a_grantee_is_told_its_grant_alone_spec_permissions_4() {
    let mut lp = synced(2);
    let n = lp.peers[1].engine.tid();
    let x = independent_thing(&mut lp, 0);
    let g = lp.peers[0].engine.grant(&x, &n, &edge(Role::Read)).unwrap().commits[0];
    for _ in 0..2 {
        lp.peers[0].engine.run(|tx| crate::rotation::rotate_now(tx, tx.core.tid(), x, &[Role::Read].into())).unwrap();
    }
    let e = &mut lp.peers[0].engine;
    let s = e.sync_id_of(&x).unwrap().expect("X's sync ID");
    let told = e.notices_for(&s, &[n].into()).unwrap();
    assert_eq!(told.iter().map(|t| (t.commit, t.holder, t.departs)).collect::<Vec<_>>(), [(g, n, false)], "the grant alone");
    let mut rng = osis_crypto::SeededRng::from_u64(7);
    let bytes = e.seal_notice(&told[0], &mut rng).unwrap().expect("sealed");
    let loc = e.locator(&x, vec![]).unwrap().expect("X's locator");
    let p1 = &mut lp.peers[1].engine;
    assert!(p1.epochs(&x).is_none_or(|ep| ep.read.held().next().is_none()), "peer 1 holds no epoch of X before");
    p1.follow_public(&loc);
    assert!(p1.take_notice(&s, &told[0].holder, &told[0].epoch, &bytes).unwrap(), "peer 1 takes it");
    assert!(lp.peers[1].engine.epochs(&x).is_some_and(|ep| ep.read.held().next().is_some()), "and holds X's epoch its grant gives");
}

// spec/permissions.md §4 (Notices), spec/sync-set.md §2 (First entry): a notice is no reference
// and no signal. Peer 1 follows X's locator, takes the notice of its grant on X, then stops
// following it, with no reference to X and no signal held: once its needs settle it holds nothing
// of X and syncs nothing for it. Control: the same with peer 1 holding a strong to X keeps it.
// Fails with a taken notice founding a hold (grant-driven holding).
#[test]
fn a_notice_alone_holds_nothing_spec_permissions_4() {
    for referenced in [false, true] {
        let mut lp = synced(2);
        let n = lp.peers[1].engine.tid();
        let me = lp.peers[0].engine.tid();
        let mut m = crate::engine::Mutation::new();
        let x = lp.peers[0].engine.new_thing(&mut m, me);
        lp.peers[0].commit(m).unwrap();
        lp.peers[0].engine.make_independent(&x).unwrap();
        lp.hold_at(0, x);
        if referenced {
            lp.hold_at(1, x);
        }
        lp.peers[0].engine.grant(&x, &n, &edge(Role::Read)).unwrap();
        let e = &mut lp.peers[0].engine;
        let s = e.sync_id_of(&x).unwrap().expect("X's sync ID");
        let told = e.notices_for(&s, &[n].into()).unwrap();
        let mut rng = osis_crypto::SeededRng::from_u64(7);
        let bytes = e.seal_notice(&told[0], &mut rng).unwrap().expect("sealed");
        let loc = e.locator(&x, vec![]).unwrap().expect("X's locator");
        let p1 = &mut lp.peers[1].engine;
        p1.follow_public(&loc);
        assert!(p1.take_notice(&s, &told[0].holder, &told[0].epoch, &bytes).unwrap(), "referenced {referenced}: peer 1 takes it");
        p1.unfollow_link(&x);
        lp.settle_needs().unwrap();
        let p1 = &mut lp.peers[1].engine;
        assert_eq!(p1.sync_set().unwrap().ids.contains_key(&s), referenced, "referenced {referenced}: peer 1 syncs X only by its reference");
        assert_eq!(p1.knows(&x), referenced, "referenced {referenced}: peer 1 holds X only by its reference");
    }
}

// spec/wire.md §11.2 (Notice: names its holder and epoch), spec/permissions.md §4 (Notices),
// notes/principles.md (Check scaling): taking a notice costs at most one decapsulation, whatever
// the receiver holds. Peer 1 follows X and holds k read epochs of its own node thing; a notice
// to it whose box opens nowhere (a peer's junk) costs one decapsulation at k = 2 and at k = 20,
// and none under a sync ID peer 1 neither holds nor follows. A notice naming another holder or
// epoch than it is sealed to opens nothing. Fails with each held epoch (or holder) tried.
#[test]
fn a_notice_costs_one_decapsulation_whatever_is_held_spec_wire_11_2() {
    let cost = |k: usize| {
        let mut lp = synced(2);
        let n = lp.peers[1].engine.tid();
        let x = independent_thing(&mut lp, 0);
        lp.peers[0].engine.grant(&x, &n, &edge(Role::Read)).unwrap();
        for _ in 0..k {
            lp.peers[1].engine.run(|tx| crate::rotation::rotate_now(tx, tx.core.tid(), n, &[Role::Read].into())).unwrap();
        }
        assert!(lp.peers[1].engine.epochs(&n).unwrap().read.held().count() > k, "k {k}: peer 1 holds its epochs");
        let e = &mut lp.peers[0].engine;
        let s = e.sync_id_of(&x).unwrap().expect("X's sync ID");
        let told = e.notices_for(&s, &[n].into()).unwrap().remove(0);
        let mut rng = osis_crypto::SeededRng::from_u64(7);
        let mut junk = e.seal_notice(&told, &mut rng).unwrap().expect("sealed");
        let at = osis_blob::Prefix::parse(&junk).unwrap().len() + 10;
        junk[at] ^= 1;
        let loc = e.locator(&x, vec![]).unwrap().expect("X's locator");
        let p1 = &mut lp.peers[1].engine;
        p1.follow_public(&loc);
        osis_base::costs::take();
        assert!(!p1.take_notice(&s, &n, &told.epoch, &junk).unwrap(), "k {k}: junk gives nothing");
        assert!(!p1.take_notice(&osis_base::SyncId([9; 16]), &n, &told.epoch, &junk).unwrap(), "k {k}: nor under a sync ID not followed");
        let c = osis_base::costs::take();
        c.iter().find(|x| x.0 == "notices: decapsulations").map_or(0, |x| x.2)
    };
    assert_eq!((cost(2), cost(20)), (1, 1), "one decapsulation, whatever is held");
}

// spec/wire.md §11.2 (Notice), spec/permissions.md §4 (Notices): a notice named for another holder
// or epoch than its box is sealed to opens nothing, and the one named rightly is taken. Fails with
// the named holder or epoch not bound to the box.
#[test]
fn a_notice_opens_only_as_named_spec_wire_11_2() {
    let mut lp = synced(2);
    let n = lp.peers[1].engine.tid();
    let x = independent_thing(&mut lp, 0);
    lp.peers[0].engine.grant(&x, &n, &edge(Role::Read)).unwrap();
    lp.peers[1].engine.run(|tx| crate::rotation::rotate_now(tx, tx.core.tid(), n, &[Role::Read].into())).unwrap();
    let e = &mut lp.peers[0].engine;
    let s = e.sync_id_of(&x).unwrap().expect("X's sync ID");
    let told = e.notices_for(&s, &[n].into()).unwrap().remove(0);
    let mut rng = osis_crypto::SeededRng::from_u64(7);
    let bytes = e.seal_notice(&told, &mut rng).unwrap().expect("sealed");
    let loc = e.locator(&x, vec![]).unwrap().expect("X's locator");
    let p1 = &mut lp.peers[1].engine;
    p1.follow_public(&loc);
    let other = p1.epochs(&n).unwrap().read.held().map(|(e, _)| e).find(|e| *e != told.epoch).expect("another epoch held");
    assert!(!p1.take_notice(&s, &n, &other, &bytes).unwrap(), "named at another epoch: nothing");
    assert!(p1.take_notice(&s, &n, &told.epoch, &bytes).unwrap(), "named rightly: taken");
}
