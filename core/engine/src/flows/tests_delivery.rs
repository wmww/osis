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

/// The sync secrets of `g` peer `i` holds: by role commits applied, or kept unread by its sync
/// copies (`sync_ids::unread`).
fn sync_held(lp: &LocalPeer, i: usize, g: &Tid) -> BTreeSet<osis_crypto::Epoch> {
    let e = &lp.peers[i].engine;
    let mut out: BTreeSet<osis_crypto::Epoch> = e.epochs(g).map(|e| e.role(Role::Sync).held().map(|x| x.0).collect()).unwrap_or_default();
    out.extend(e.core.unread(g).secrets.keys().copied());
    out
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
    assert!(matches!(open(&mut lp, 2, &out), Opened::SyncCopy), "opened as the rotation's sync copy");
    // its box opens, but no step bears the secret yet: kept for nothing (spec/sync.md §3)
    let copies = lp.peers[2].engine.sync_copies_of(&g);
    assert!(copies.len() == 1 && copies[0].1.holder == t && !copies[0].2, "taken as T's, not counted: {copies:?}");
    assert_eq!(sync_held(&lp, 2, &g), was, "no step bears it yet");
    // G's admin issues the step: the secret is kept and the copy counts
    let s = lp.peers[0].engine.sync_id_of(&g).unwrap().unwrap();
    lp.peers[0].engine.issue_step(&g, &s, false).unwrap().expect("a step due");
    lp.sync_all().unwrap();
    let now = sync_held(&lp, 2, &g);
    assert!(now.len() > was.len() && now.is_superset(&was), "G's new sync secret held: {was:?} -> {now:?}");
    assert!(lp.peers[2].engine.sync_copies_of(&g).iter().all(|c| c.2), "counted once a step bears it");
}

/// Peer 2 forges a role commit on G making T an admin (it holds write there, no admin: the writer
/// rules skipped), and owes it as a sealed copy to T. A writer of G, so its commit has a chain
/// and applies, invalid, wherever it is taken: not one that pends unjudged. (the forged commit,
/// the sealed copy)
fn forged_copy(lp: &mut LocalPeer, g: Tid, t: Tid) -> (CommitId, super::inbox::SealedFireOut) {
    let w = lp.peers[2].engine.me();
    lp.peers[0].engine.grant(&g, &w, &edge(Role::Write)).unwrap();
    // T reads G: a sealed copy to it is a certificate copy (form 1), not a sync copy
    lp.peers[0].engine.grant(&g, &t, &edge(Role::Read)).unwrap();
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
    let p = lp.peers[2].engine.edge_piece(&c, &g, crate::sync_ids::Cut::EdgePiece(t)).unwrap().expect("the forger's piece");
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
    lp.peers[0].engine.rotate_leaving_out(&g, &[Role::Sync], &[]).unwrap().unwrap();
    let owed = new_owed(&lp, 0, &before);
    let out = lp.peers[0].engine.sealed_fire(&owed[0]).unwrap().expect("sealed to T's read key");
    assert!(matches!(open(&mut lp, 2, &out), Opened::SyncCopy), "taken once");
    lp.sync_all().unwrap();
    lp.peers[0].engine.remove_holders(&g, &t, &[]).unwrap();
    lp.sync_all().unwrap();
    let role = lp.peers[2].engine.core.role_now(&t, &g);
    assert_eq!(role, None, "peer 2 learns T's removal from G");
    let epochs = sync_held(&lp, 2, &g);
    open(&mut lp, 2, &out);
    assert_eq!(lp.peers[2].engine.core.role_now(&t, &g), None, "T holds no role on G");
    assert_eq!(sync_held(&lp, 2, &g), epochs, "G's sync epochs at peer 2 unchanged");
}

// spec/wire.md §4 (sync copy: no header), §9 (Payload: form 2 a sealed sync copy), spec/sync-ids.md §2 (What a sync holder
// learns: no signer, path or other holder's box key): peer 0 rotates G's sync role, boxing T
// (sync alone) and peer 1 (granted read on G). What reaches T's readers is T's sync copy alone:
// its payload is form 2, and no byte of it names the rotator or the other holder, nor carries
// the commit's header. Fails with the copy sent as a certificate copy (form 1: header, signer,
// records).
#[test]
fn a_sync_alone_holder_gets_no_header_spec_sync_ids_2() {
    let (mut lp, g, t) = sync_holder();
    let other = lp.peers[1].engine.me();
    lp.peers[0].engine.grant(&g, &other, &edge(Role::Read)).unwrap();
    lp.sync_all().unwrap();
    let before = lp.peers[0].engine.fires_owed();
    let rot = lp.peers[0].engine.rotate_leaving_out(&g, &[Role::Sync], &[]).unwrap().unwrap();
    let owed = new_owed(&lp, 0, &before);
    let out = lp.peers[0].engine.sealed_fire(&owed[0]).unwrap().expect("sealed to T's read key");
    let e2 = &lp.peers[2].engine;
    let (prefix, sealed) = e2.read_epochs(&t, &[]).into_iter().find_map(|(e, x)| osis_blob::open_fire(&out.blob, &t, &e, x.kem()).ok()).expect("opens at T's reader");
    let osis_blob::Sealed::SyncCopy(plain) = sealed else { panic!("form 2") };
    let h = lp.peers[0].engine.header(&rot).unwrap();
    let names = |b: &[u8], x: &[u8]| b.windows(x.len()).any(|w| w == x);
    for (what, x) in [("the rotator", h.signer.as_bytes().to_vec()), ("the other holder", other.as_bytes().to_vec()), ("the header (its blind)", h.blind.to_vec())] {
        assert!(!names(&plain, &x) && !names(&prefix.to_bytes(), &x), "{what} in the bytes T's readers get");
    }
    let copy = osis_commit::SyncCopy::decode(&plain).unwrap();
    assert!(copy.commit == rot && copy.thing == g && copy.piece.is_some(), "T's piece of the rotation");
}

// spec/wire.md §4 (sync copy: one whose piece holds a record keyed with another holder is bad
// input), spec/permissions.md §4 (Logging certificates: counts once its box opens to a secret a
// step bears): T's sync copy of a rotation, sealed by anyone holding a keyset of another
// independent thing U to U, is refused at U's reader: nothing taken. And a copy whose secret no
// step bears is taken but keeps nothing: a holder of sync alone takes no secret on a box's word.
// Fails without the holder check, or with a box kept unborne.
#[test]
fn a_sync_copy_of_another_holder_is_refused_spec_wire_4() {
    let (mut lp, g, t) = sync_holder();
    let u = crate::rotation::tests::independent_thing(&mut lp, 1);
    lp.sync_all().unwrap();
    let rot = lp.peers[0].engine.rotate_leaving_out(&g, &[Role::Sync], &[]).unwrap().unwrap();
    let (copy, _) = lp.peers[0].engine.sync_copy(&rot, &g, &t).unwrap().expect("T's sync copy");
    let plain = copy.encode();
    let b = osis_base::BlobId([9; 32]);
    assert!(!lp.peers[1].engine.take_sync_copy(&u, &b, &plain).unwrap(), "T's piece is no copy of U's");
    assert!(lp.peers[1].engine.sync_copies_of(&g).is_empty(), "nothing taken");
    let was = sync_held(&lp, 2, &g);
    assert!(lp.peers[2].engine.take_sync_copy(&t, &b, &plain).unwrap(), "T's own");
    assert_eq!(sync_held(&lp, 2, &g), was, "no step bears it: kept for nothing");
}

// spec/wire.md §4 (sync copy: a delta that does not decode is bad input), spec/permissions.md §4
// (Logging certificates: one of two sync copies counts): a copy logged under T's
// sync ID with garbage for its piece is refused and not held; the real copy taken again under
// another blob moves nothing; G's sync ID at T's reader stays G's own. Fails if garbage is held
// or takes the real copy's place.
#[test]
fn garbage_does_not_take_the_real_copys_place_spec_sync_3() {
    let (mut lp, g, t) = sync_holder();
    let before = lp.peers[2].engine.sync_id_of(&g).unwrap();
    let rot = lp.peers[0].engine.rotate_leaving_out(&g, &[Role::Sync], &[]).unwrap().unwrap();
    let (copy, _) = lp.peers[0].engine.sync_copy(&rot, &g, &t).unwrap().expect("T's sync copy");
    let junk = osis_commit::SyncCopy { piece: Some(vec![0x81, 0x01]), ..copy.clone() };
    assert!(!lp.peers[2].engine.take_sync_copy(&t, &osis_base::BlobId([1; 32]), &junk.encode()).unwrap(), "garbage: bad input");
    let other = lp.peers[0].engine.sync_copy(&rot, &g, &t).unwrap().unwrap().0;
    lp.peers[2].engine.take_sync_copy(&t, &osis_base::BlobId([2; 32]), &other.encode()).unwrap();
    lp.sync_all().unwrap();
    assert_eq!(lp.peers[2].engine.sync_id_of(&g).unwrap(), before, "G's sync ID unmoved");
    assert!(lp.peers[2].engine.sync_copies_of(&g).iter().filter(|c| c.0 == osis_base::BlobId([1; 32])).count() == 0, "the garbage is not held");
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
    let mut p = lp.peers[0].engine.edge_piece(&rot, &g, crate::sync_ids::Cut::EdgePiece(t)).unwrap().unwrap();
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

/// A sync copy for holder `h` on `x` with a sync ID of the forger's own making, built by peer
/// `i` (its bytes alone reach the holder's reader, judged by nothing else): a genesis step on
/// `x` from made-up secrets of every role, bearing the made-up sync secret, and a box of that
/// secret to `h`. Peer `i` keeps the commit; nothing is synced. (copy, its sync ID, the secret)
fn forged_sync_copy(lp: &mut LocalPeer, i: usize, x: Tid, h: Tid, seed: u8) -> (osis_commit::SyncCopy, osis_base::SyncId, osis_crypto::Secret32) {
    let mut fake = osis_keys::ActorEpochs::default();
    for r in Role::ALL {
        let s = osis_crypto::Secret32::from_bytes([seed.wrapping_add(r.id()); 32]);
        let e = osis_crypto::Epoch::derive(&x, r, 1, &s).unwrap();
        fake.role_mut(r).set_secret(e, s);
        fake.role_mut(r).set_established(e, osis_keys::Provenance::Fixed);
    }
    let sync = fake.role(Role::Sync).secret(&fake.role(Role::Sync).newest().unwrap()).unwrap().secret().clone();
    let e = &mut lp.peers[i].engine;
    let mut m = crate::Mutation::new();
    let id = e
        .run(|tx| {
            let rcpt = crate::flows::recipient(tx, h, Role::Sync)?;
            let w = osis_keys::box_holder(&x, &fake, &osis_keys::HistoryBoxes::new(), &rcpt, &[Role::Sync].into(), &mut *tx.rng)?.unwrap();
            crate::flows::put_secrets(&mut m, x, &w, true)?;
            crate::flows::sync_ids::new_sync_id(tx, &mut m, x, &fake, &[], &osis_crypto::Secret32::from_bytes([seed; 32]), None)
        })
        .unwrap();
    let c = e.commit_hostile(m).unwrap().unwrap();
    let (copy, _) = e.sync_copy(&c, &x, &h).unwrap().expect("a sync copy of the forgery");
    assert!(copy.piece.is_some() && copy.sync.is_some(), "its box and its genesis step");
    (copy, id, sync)
}

// spec/sync.md §3 (Kept unread: only a step bearing a held secret's sync key keeps entries),
// spec/sync-ids.md §2 (One sync ID per independent thing), spec/sync-set.md §2
// (Counts as independent: a box is any writer's word, a step an admin's): a sync copy is anyone's
// word who may log under its holder's sync ID or seal to its read key, and its steps verify only
// to a genesis of its own making. Peer 2 keeps G unread (T holds sync) and holds G's record: a
// copy for T naming G with a forged genesis bearing a forged secret takes nothing (G's sync ID,
// the sync secrets held, how G is synced: unmoved), at any seed (greater or less than G's own).
// Fails where a copy's own steps are judged beside G's admin-judged `sync.0` at a node holding
// G's record (the forged sync ID owned, synced in place of G's own by a reader).
#[test]
fn a_forged_genesis_in_a_sync_copy_takes_nothing_spec_sync_ids_2() {
    let mut above = BTreeSet::new();
    for reader in [false, true] {
        let (mut lp, g, t) = sync_holder();
        if reader {
            // peer 2 reads G too: a reader syncs G's greatest sync ID, which a forged one must
            // not become
            let me = lp.peers[2].engine.me();
            lp.peers[0].engine.grant(&g, &me, &edge(Role::Read)).unwrap();
            lp.sync_all().unwrap();
        }
        let real = lp.peers[2].engine.sync_id_of(&g).unwrap().unwrap();
        let held = sync_held(&lp, 2, &g);
        let how = lp.peers[2].engine.thing_sync_now(&g).unwrap();
        let want = if reader { crate::sync::ThingSync::Read(vec![real]) } else { crate::sync::ThingSync::Unread(vec![real]) };
        assert_eq!(how, want, "G synced by its own sync ID");
        // a forged sync ID above G's own and one below (its admin secret's)
        let id = |seed: u8| osis_blob::genesis_sync_id(&osis_crypto::Secret32::from_bytes([seed.wrapping_add(Role::Admin.id()); 32]));
        let seeds: Vec<u8> = [true, false].into_iter().filter_map(|up| (1..=u8::MAX).find(|x| (id(*x) > real) == up)).collect();
        // the forgeries stay at peer 0 (G's admin, whose commits would be G's word): no sync
        for seed in seeds {
            let (copy, forged, _) = forged_sync_copy(&mut lp, 0, g, t, seed);
            assert_eq!(forged, id(seed));
            above.insert(forged > real);
            assert!(lp.peers[2].engine.take_sync_copy(&t, &osis_base::BlobId([seed; 32]), &copy.encode()).unwrap(), "well formed: taken");
            assert_eq!(lp.peers[2].engine.sync_id_of(&g).unwrap(), Some(real), "G's sync ID");
            assert!(!lp.peers[2].engine.sync_ids(&g).unwrap().iter().any(|o| o.id == forged), "the forged sync ID is not G's here");
            assert_eq!(lp.peers[2].engine.thing_sync_now(&g).unwrap(), want, "G synced as before");
            assert_eq!(sync_held(&lp, 2, &g), held, "no forged secret kept");
        }
        lp.peers[2].restart(7).unwrap();
        assert_eq!(lp.peers[2].engine.thing_sync_now(&g).unwrap(), want, "G synced as before at a fresh load");
    }
    assert_eq!(above.len(), 2, "forged sync IDs both above and below G's own");
}

// spec/sync-set.md §2 (Counts as independent: a box is any writer's word, a step an admin's),
// spec/sync.md §3: Y is a dependent thing in T (peer 2's), read by peers 1 and 2. Peer 1, a reader
// of T and no admin of Y, forges T's sync copy naming Y: a genesis of its own on Y bearing a
// secret boxed to T. Peer 2 takes it (as it would sealed to T or logged under T's sync ID): Y
// stays dependent there, its secret actor T, synced as before, and peer 2 still reads Y. Fails
// where a copy's own steps make a thing count independent (Y then read by no secret: blinded).
#[test]
fn a_forged_sync_copy_makes_no_dependent_thing_independent_spec_sync_set_2() {
    let (mut lp, _g, t) = sync_holder();
    reads_t(&mut lp, t);
    let y = {
        let mut m = crate::Mutation::new();
        let y = lp.peers[2].engine.new_thing(&mut m, t);
        lp.peers[2].commit(m).unwrap();
        lp.hold(y);
        y
    };
    lp.sync_all().unwrap();
    let how = lp.peers[2].engine.thing_sync_now(&y).unwrap();
    assert_eq!(lp.peers[2].engine.core.secret_actor(&y), Some(t), "Y is T's dependent");
    let (copy, _, _) = forged_sync_copy(&mut lp, 1, y, t, 20);
    let e2 = &mut lp.peers[2].engine;
    assert!(e2.take_sync_copy(&t, &osis_base::BlobId([20; 32]), &copy.encode()).unwrap(), "well formed: taken");
    assert!(!e2.core.counts_independent(&y), "Y counts independent by a forged copy");
    assert_eq!(e2.core.secret_actor(&y), Some(t), "Y's secret actor");
    assert_eq!(e2.thing_sync_now(&y).unwrap(), how, "Y synced as before");
    lp.peers[2].restart(7).unwrap();
    assert_eq!(lp.peers[2].engine.core.secret_actor(&y), Some(t), "Y's secret actor at a fresh load");
}
