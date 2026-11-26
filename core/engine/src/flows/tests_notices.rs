//! Notices (spec/permissions.md §4 Notices): what a departed holder is told.

#![allow(clippy::unwrap_used)]
use crate::rotation::tests::{edge, independent_thing, synced};
use crate::sync::Opened;
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
        let mut rng = osis_crypto::SeededRng::from_u64(7);
        let carried: Vec<[u8; 32]> = e.notices_carried(&s).unwrap().into_keys().collect();
        assert!(!carried.is_empty(), "late {late}: G's removal has a notice");
        for k in carried {
            e.seal_notice(&s, &k, &mut rng).unwrap().expect("sealed");
        }
        let told = e.told(&s, &[n].into()).unwrap();
        assert_eq!(told.is_empty(), late, "late {late}: peer 1 told G's removal only while it read X through G");
    }
}

// spec/permissions.md §4 (Notices), spec/sync-hostile.md: peer 1 is removed from X; later G is
// removed. A reader of X (peer 0, hostile) seals a notice of G's removal naming peer 1 as its
// holder, its key truly sealed to peer 1: peer 2, reading X, opens it by the wrap and holds the
// copy (a valid commit), yet tells peer 1 nothing of G's removal (made past its departure), nor
// counts it toward peer 1's `until`. Fails with the holder a notice names taken on its word.
#[test]
fn a_notice_naming_another_holder_tells_that_holder_nothing_spec_permissions_4() {
    let mut lp = synced(3);
    let (n1, n2) = (lp.peers[1].engine.tid(), lp.peers[2].engine.tid());
    let x = independent_thing(&mut lp, 0);
    let g = independent_thing(&mut lp, 0);
    for h in [n1, n2, g] {
        lp.peers[0].engine.grant(&x, &h, &edge(Role::Read)).unwrap();
    }
    lp.sync_all().unwrap();
    lp.peers[0].engine.demote(&x, &super::Demotion { holder: n1, new: None, retain: None }).unwrap();
    lp.sync_all().unwrap();
    let c = lp.peers[0].engine.demote(&x, &super::Demotion { holder: g, new: None, retain: None }).unwrap().commits[0];
    lp.sync_all().unwrap();
    let e = &mut lp.peers[0].engine;
    let s = e.sync_id_of(&x).unwrap().expect("X's sync ID");
    let (epoch, kem) = e.read(|tx| crate::rotation::members::notice_keyset(tx, &x, &n1)).unwrap().expect("peer 1's notice keyset");
    let forged = crate::sync::notices::Notice { thing: x, commit: c, holder: n1, epoch };
    let key = osis_crypto::Secret32::from_bytes([3; 32]);
    let bytes = e.sealed_notice(&forged, &kem, &key).unwrap().expect("sealed");
    let id = osis_blob::blob_id(&bytes);
    let w = e.wrap_secret(&x, None).unwrap().expect("an epoch to wrap under");
    let wrap = osis_crypto::wrap(&w, &id, &key, 0).unwrap();
    let r = &mut lp.peers[2].engine;
    assert!(matches!(r.open_entry(&s, &id, &wrap, &bytes, u64::MAX).unwrap(), Opened::Notice(..)), "peer 2 opens it");
    assert!(r.notice_rows(&s).contains_key(&id), "and keeps its row");
    assert!(!r.told(&s, &[n1].into()).unwrap().contains(&c), "G's removal is not told to peer 1");
}
