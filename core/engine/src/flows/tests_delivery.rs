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

/// The sync secrets of `g` peer `i` holds.
fn sync_held(lp: &LocalPeer, i: usize, g: &Tid) -> BTreeSet<osis_crypto::Epoch> {
    lp.peers[i].engine.epochs(g).map(|e| e.role(Role::Sync).held().map(|x| x.0).collect()).unwrap_or_default()
}

// spec/permissions.md §4 (Delivering an edge piece: a rotation boxing a holder of sync alone goes
// as a sealed copy), spec/sync-inbox.md §2 (Sealed copy: under H's own sync ID, taken as a sealed
// fire's commit is): peer 0 rotates G's sync role. T holds sync alone, so no box at the epoch
// the commit is wrapped under, and peer 0 may not write T: it owes one sealed copy to T, no fire
// on an inbox. Peer 2 opens it as the rotation commit itself and holds G's new sync secret (it
// establishes the epoch by G's steps, spec/crypto.md §4 Established: the copy carries no
// `keys.0`, spec/permissions.md §4 Copies). Fails with the rotation sent as a `grant@~0` fire,
// or not sent.
#[test]
fn a_rotation_reaches_a_holder_of_sync_alone_as_a_sealed_copy_spec_permissions_4() {
    let (mut lp, g, t) = sync_holder();
    let before = lp.peers[0].engine.fires_owed();
    let was = sync_held(&lp, 2, &g);
    let rot = lp.peers[0].engine.rotate_leaving_out(&g, &[Role::Sync], &[]).unwrap().unwrap();
    let owed = new_owed(&lp, 0, &before);
    assert_eq!(owed.len(), 1, "one delivery owed");
    let o = lp.peers[0].engine.core.ix.fires.get(&owed[0]).cloned().unwrap();
    assert!(o.thing == t && o.ak.is_none() && o.what == Fire::Copy { commit: rot, target: g }, "a sealed copy to T itself: {o:?}");
    let out = lp.peers[0].engine.sealed_fire(&owed[0]).unwrap().expect("sealed to T's read key");
    assert_eq!(Some(out.sync_id), lp.peers[2].engine.sync_id_of(&t).unwrap(), "under T's own sync ID");
    assert!(matches!(open(&mut lp, 2, &out), Opened::Commit(c, _) if c == rot), "opened as the rotation");
    let now = sync_held(&lp, 2, &g);
    assert!(now.len() > was.len() && now.is_superset(&was), "G's new sync secret held: {was:?} -> {now:?}");
}

/// Peer 2 forges a role commit on G making T an admin (it holds write there, no admin: the writer
/// rules skipped), and owes it as a sealed copy to T. A writer of G, so its commit has a chain
/// and applies, invalid, wherever it is taken: not one that pends unjudged. (the forged commit,
/// the sealed copy)
fn forged_copy(lp: &mut LocalPeer, g: Tid, t: Tid) -> (CommitId, super::inbox::SealedFireOut) {
    let w = lp.peers[2].engine.me();
    lp.peers[0].engine.grant(&g, &w, &edge(Role::Write)).unwrap();
    lp.sync_all().unwrap();
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
    let p = lp.peers[2].engine.edge_piece(&c, &g, Some(t)).unwrap().expect("the forger's piece");
    let piece = EdgePiece::from_value(&p.to_value()).expect("round-trips");
    assert_eq!(piece, p);
    let taken = lp.peers[1].engine.take_edge_piece(&piece, None).unwrap();
    assert_eq!(taken, Some((c, g)), "a copy on G");
    assert!(lp.peers[1].engine.header(&c).is_none(), "the forged commit is not kept");
    assert_ne!(lp.peers[1].engine.core.role_now(&t, &g), Some(Role::Admin), "T is no admin of G");
}

// spec/sync-inbox.md §2 (Sealed copy: taken as a sealed fire's commit is), spec/permissions.md §2:
// a role is by the target's grants. A sealed copy is bytes anyone who once read T may send
// again, sealed to a keyset of T it held. After G removes T, an old rotation's copy (the very
// blob, kept) is offered to peer 2 again: it is the old commit it was, held already, and changes
// nothing: T holds no role on G, and G's sync epochs at peer 2 stay as they were. Fails if a
// replayed copy reinstates the role or the epochs it gave.
#[test]
fn a_replayed_rotation_copy_gives_back_nothing_spec_sync_inbox_2() {
    let (mut lp, g, t) = sync_holder();
    let before = lp.peers[0].engine.fires_owed();
    let rot = lp.peers[0].engine.rotate_leaving_out(&g, &[Role::Sync], &[]).unwrap().unwrap();
    let owed = new_owed(&lp, 0, &before);
    let out = lp.peers[0].engine.sealed_fire(&owed[0]).unwrap().expect("sealed to T's read key");
    assert!(matches!(open(&mut lp, 2, &out), Opened::Commit(c, _) if c == rot), "taken once");
    lp.peers[0].engine.remove_holders(&g, &t, &[]).unwrap();
    lp.sync_all().unwrap();
    let role = lp.peers[2].engine.core.role_now(&t, &g);
    assert_eq!(role, None, "peer 2 learns T's removal from G");
    let epochs = sync_held(&lp, 2, &g);
    open(&mut lp, 2, &out);
    assert_eq!(lp.peers[2].engine.core.role_now(&t, &g), None, "T holds no role on G");
    assert_eq!(sync_held(&lp, 2, &g), epochs, "G's sync epochs at peer 2 unchanged");
}

// spec/sync-inbox.md §2 (Sealed copy: never promoted, H's writers log what it carries in H's key
// part as their own certificate copies), spec/permissions.md §4 (Key part: each commit boxing H
// in a thing's `secrets.0`): peer 2, T's writer, takes the rotation's sealed copy; the rotation
// is then in T's key part at peer 2, which it logs under T's sync ID by the rule for any piece
// it holds. Fails if a taken sealed copy is not held as the role commit it is (kept as an entry
// alone, or dropped for want of a held thing needing it).
#[test]
fn a_taken_sealed_copy_is_in_the_holders_key_part_spec_sync_inbox_2() {
    let (mut lp, g, t) = sync_holder();
    let before = lp.peers[0].engine.fires_owed();
    let rot = lp.peers[0].engine.rotate_leaving_out(&g, &[Role::Sync], &[]).unwrap().unwrap();
    let owed = new_owed(&lp, 0, &before);
    let out = lp.peers[0].engine.sealed_fire(&owed[0]).unwrap().expect("sealed to T's read key");
    assert!(!lp.peers[2].engine.key_part(&t).contains(&(rot, g)), "not before");
    assert!(matches!(open(&mut lp, 2, &out), Opened::Commit(c, _) if c == rot), "peer 2 takes it");
    assert!(lp.peers[2].engine.key_part(&t).contains(&(rot, g)), "in T's key part at T's writer");
}

// spec/wire.md §9 (Payload: every blob its commits' deltas link travels with it, a blob none
// links bad input), spec/sync-inbox.md §5 (Carried commits): a piece's evidence is taken with
// the pages its own deltas link, whatever commit carries them. Peer 2 writes a content commit on
// T whose delta pages, peer 0 rotates G; peer 1, a reader of T, has neither. A piece of the
// rotation carrying the
// content commit as evidence with its pages: both taken, the paged value read whole. The same
// piece with a blob no delta of it links: nothing taken. Fails if a piece's pages go to its copy
// alone (the evidence waits for its pages, the copy is refused for pages it does not link), or
// a stray blob is kept or ignored.
#[test]
fn a_pieces_evidence_takes_its_own_pages_spec_wire_9() {
    let (mut lp, g, t) = sync_holder();
    reads_t(&mut lp, t);
    let ak = osis_base::Ak::new("t:big.0").unwrap();
    let big = osis_base::Value::Map((0..2500).map(|i| (osis_base::Value::Int(i), osis_base::Value::Str(format!("value-{i:08}-padding-padding")))).collect());
    let mut m = crate::Mutation::new();
    m.set(t, &ak, &big).unwrap();
    let content = lp.peers[2].commit(m).unwrap().unwrap();
    let rot = lp.peers[0].engine.rotate_leaving_out(&g, &[Role::Sync], &[]).unwrap().unwrap();
    let mut p = lp.peers[0].engine.edge_piece(&rot, &g, Some(t)).unwrap().unwrap();
    let c = lp.peers[2].engine.read(|tx| tx.get_commit(&content)).unwrap().unwrap().encode();
    let pages = lp.peers[2].engine.run(|tx| super::inbox::held_pages(tx, &[c.as_slice()])).unwrap();
    assert!(!pages.is_empty(), "the content commit pages");
    p.evidence.push(c);
    p.pages.extend(pages);
    let mut stray = p.clone();
    stray.pages.push(b"no page of the piece".to_vec());
    assert_eq!(lp.peers[1].engine.take_edge_piece(&stray, None).unwrap(), None, "a stray blob: nothing taken");
    assert!(lp.peers[1].engine.header(&rot).is_none() && lp.peers[1].engine.header(&content).is_none(), "nothing of it held");
    assert_eq!(lp.peers[1].engine.take_edge_piece(&p, None).unwrap(), Some((rot, g)));
    assert!(lp.peers[1].engine.header(&rot).is_some(), "the rotation taken");
    assert_eq!(lp.peers[1].engine.get(&t, &ak).unwrap(), Some(big), "the paged evidence taken whole");
}
