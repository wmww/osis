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
// under epochs the grant gives, so they open by their wraps. Peer 1, holding nothing of X, opens the
// notice by its own KEM key and holds the grant's epoch. Fails with the grant's notice not given or
// not taken by a node holding nothing of X.
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
    assert!(lp.peers[1].engine.epochs(&x).is_none_or(|ep| ep.read.held().next().is_none()), "peer 1 holds no epoch of X before");
    assert!(lp.peers[1].engine.take_notice(&s, &bytes).unwrap(), "peer 1 takes it");
    assert!(lp.peers[1].engine.epochs(&x).is_some_and(|ep| ep.read.held().next().is_some()), "and holds X's epoch its grant gives");
}
