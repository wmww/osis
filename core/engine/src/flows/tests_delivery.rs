//! Edge pieces delivered from outside their holder (spec/permissions.md §4 Delivering an edge
//! piece): a rotation as a sealed copy under the holder's own sync ID (spec/sync-inbox.md §2), a
//! grant as an offer (§5); one value, `EdgePiece`, taken only as judged.

#![allow(clippy::unwrap_used)]
use super::inbox::{EdgePiece, Fire, FireId, OwedFire, save};
use crate::local_peer::LocalPeer;
use crate::rotation::tests::{edge, independent_thing, synced};
use crate::sync::Opened;
use osis_base::{CommitId, Role, Tid};
use std::collections::BTreeSet;

/// Peer 2's independent T holds sync on G, an independent thing of peer 0's; everyone synced.
/// (lp, G, T)
fn sync_holder() -> (LocalPeer, Tid, Tid) {
    let (lp, (g, t)) = LocalPeer::cached("flows::tests_delivery::sync_holder", || {
        let mut lp = synced(3);
        let t = independent_thing(&mut lp, 2);
        lp.sync_all().unwrap();
        let g = independent_thing(&mut lp, 0);
        lp.peers[0].engine.grant(&g, &t, &edge(Role::Sync)).unwrap();
        lp.sync_all().unwrap();
        (lp, (g, t))
    });
    (lp, g, t)
}

/// Peer 1 reads T (granted by peer 2): it opens what is sealed to T.
fn reads_t(lp: &mut LocalPeer, t: Tid) {
    let me = lp.peers[1].engine.me();
    lp.peers[2].engine.grant(&t, &me, &edge(Role::Read)).unwrap();
    lp.sync_all().unwrap();
}

fn new_owed(lp: &LocalPeer, i: usize, before: &[FireId]) -> Vec<FireId> {
    lp.peers[i].engine.fires_owed().into_iter().filter(|f| !before.contains(f)).collect()
}

fn open(lp: &mut LocalPeer, i: usize, out: &super::inbox::SealedFireOut) -> Opened {
    lp.peers[i].engine.open_entry(&out.sync_id, &osis_blob::blob_id(&out.blob), &[0; 57], &out.blob, u64::MAX).unwrap()
}

fn sync_current(lp: &LocalPeer, i: usize, g: &Tid) -> BTreeSet<osis_crypto::Epoch> {
    lp.peers[i].engine.epochs(g).map(|e| e.role(Role::Sync).current().into_iter().collect()).unwrap_or_default()
}

// spec/permissions.md §4 (Delivering an edge piece: a rotation boxing a holder of sync alone goes
// as a sealed copy), spec/sync-inbox.md §2 (Sealed copy: under H's own sync ID, taken as a sealed
// fire's commit is): peer 0 rotates G's sync role. T holds sync alone, so no box at the epoch
// the commit is wrapped under, and peer 0 may not write T: it owes one sealed copy to T, no fire
// on an inbox. Peer 2 opens it as the rotation commit itself and holds G's new sync epoch.
// Fails with the rotation sent as a `grant@~0` fire, or not sent.
#[test]
fn a_rotation_reaches_a_holder_of_sync_alone_as_a_sealed_copy_spec_permissions_4() {
    let (mut lp, g, t) = sync_holder();
    let before = lp.peers[0].engine.fires_owed();
    let was = sync_current(&lp, 2, &g);
    let rot = lp.peers[0].engine.rotate_leaving_out(&g, &[Role::Sync], &[]).unwrap().unwrap();
    let owed = new_owed(&lp, 0, &before);
    assert_eq!(owed.len(), 1, "one delivery owed");
    let o = lp.peers[0].engine.core.ix.fires.get(&owed[0]).cloned().unwrap();
    assert!(o.thing == t && o.ak.is_none() && o.what == Fire::Copy { commit: rot, target: g }, "a sealed copy to T itself: {o:?}");
    let out = lp.peers[0].engine.sealed_fire(&owed[0]).unwrap().expect("sealed to T's read key");
    assert_eq!(Some(out.sync_id), lp.peers[2].engine.sync_id_of(&t).unwrap(), "under T's own sync ID");
    assert!(matches!(open(&mut lp, 2, &out), Opened::Commit(c, _) if c == rot), "opened as the rotation");
    let now = sync_current(&lp, 2, &g);
    assert!(!now.is_empty() && now != was, "G's new sync epoch held: {was:?} -> {now:?}");
}

/// Peer 2 forges a rotation-shaped role commit on G (it holds no admin there: the writer rules
/// skipped) and owes it as a sealed copy to T. (the forged commit, the sealed copy)
fn forged_copy(lp: &mut LocalPeer, g: Tid, t: Tid) -> (CommitId, super::inbox::SealedFireOut) {
    let e2 = &mut lp.peers[2].engine;
    let before = e2.fires_owed();
    let c = e2
        .run(|tx| {
            let mut m = crate::Mutation::new();
            crate::flows::put_edge(&mut m, g, t, &edge(Role::Admin))?;
            m.unchecked();
            tx.core.skip_writer_rules = true;
            let c = crate::engine::Engine::commit_tx(tx, m);
            tx.core.skip_writer_rules = false;
            let c = c?.expect("built");
            save(tx, OwedFire { thing: t, ak: None, what: Fire::Copy { commit: c, target: g }, to: BTreeSet::new(), commit: None, pages: Default::default() })?;
            Ok(c)
        })
        .unwrap();
    let id = *new_owed(lp, 2, &before).first().expect("owed");
    (c, lp.peers[2].engine.sealed_fire(&id).unwrap().expect("sealed"))
}

// spec/sync-inbox.md §2 (Sealed copy: taken whole or not at all), §4 (A sealed fire: none of one
// that applies invalid): anyone holding T's public key record may send a sealed copy to T. Peer
// 2 sends one of a role commit on G it may not write (making T an admin of G); peer 1, a reader
// of T, opens it: refused, nothing of it held, T no admin of G. Fails if a sealed copy's commit is
// taken unjudged or kept when it applies invalid.
#[test]
fn a_sealed_copy_that_applies_invalid_leaves_nothing_spec_sync_inbox_2() {
    let (mut lp, g, t) = sync_holder();
    reads_t(&mut lp, t);
    let (c, out) = forged_copy(&mut lp, g, t);
    assert!(matches!(open(&mut lp, 1, &out), Opened::Bad), "refused");
    assert!(lp.peers[1].engine.header(&c).is_none(), "nothing of the forged commit is held");
    assert_ne!(lp.peers[1].engine.core.role_now(&t, &g), Some(Role::Admin), "T is no admin of G");
}

// spec/wire.md §9 (Payload: form 1 a certificate copy), spec/sync-inbox.md §2 (Sealed copy: a
// certificate copy on another thing): a sealed copy of a content commit, or of a role commit on
// the thing it is sealed to, is bad input: nothing taken. Fails without the copy's form check.
#[test]
fn a_sealed_copy_of_no_certificate_copy_is_bad_spec_wire_9() {
    let (mut lp, g, t) = sync_holder();
    reads_t(&mut lp, t);
    // a content write on G, and a role commit on T itself, each sent as a sealed copy to T
    let mut m = crate::Mutation::new();
    m.set(g, &osis_base::Ak::new("t:reg.0").unwrap(), &osis_base::Value::Str("x".into())).unwrap();
    let content = lp.peers[0].commit(m).unwrap().unwrap();
    let on_t = lp.peers[2].engine.grant(&t, &g, &edge(Role::Sync)).unwrap();
    let on_t = *on_t.commits.last().unwrap();
    for (from, c, target) in [(0, content, g), (2, on_t, t)] {
        let before = lp.peers[from].engine.fires_owed();
        lp.peers[from].engine.run(|tx| save(tx, OwedFire { thing: t, ak: None, what: Fire::Copy { commit: c, target }, to: BTreeSet::new(), commit: None, pages: Default::default() })).unwrap();
        let id = *new_owed(&lp, from, &before).first().unwrap();
        let Some(out) = lp.peers[from].engine.sealed_fire(&id).unwrap() else { continue };
        assert!(matches!(open(&mut lp, 1, &out), Opened::Bad), "commit {c:?} on {target:?}: bad");
    }
}

// spec/sync-inbox.md §5 (Grant from outside: an offer's boxes held only as its copy and evidence
// judge it), spec/crypto.md §4 (Reading-only secrets): an offer anyone holding a card of T may
// fire. Peer 2 fires a grant fire on T carrying the forged commit's piece; peer 1 takes the fire
// and T holds no role on G from it, and no secret of G that it did not hold. Fails if a piece is
// taken unjudged.
#[test]
fn a_forged_offer_gives_no_role_spec_sync_inbox_5() {
    let (mut lp, g, t) = sync_holder();
    reads_t(&mut lp, t);
    let (c, _) = forged_copy(&mut lp, g, t);
    let p = lp.peers[2].engine.edge_piece(&c, &g).unwrap().expect("the forger's piece");
    let piece = EdgePiece::from_value(&p.to_value()).expect("round-trips");
    assert_eq!(piece, p);
    let taken = lp.peers[1].engine.take_edge_piece(&piece, None).unwrap();
    assert_eq!(taken, Some((c, g)), "a copy on G");
    assert!(lp.peers[1].engine.header(&c).is_none(), "the forged commit is not kept");
    assert_ne!(lp.peers[1].engine.core.role_now(&t, &g), Some(Role::Admin), "T is no admin of G");
}
