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
    let me = lp.peers[1].engine.tid();
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
    let copies: Vec<_> = lp.peers[2].engine.sync_copies_of(&g).into_iter().filter(|c| c.1.copy.commit == rot).collect();
    assert!(copies.len() == 1 && copies[0].1.holder == t && !copies[0].2, "taken as T's, not counted: {copies:?}");
    assert_eq!(sync_held(&lp, 2, &g), was, "no step bears it yet");
    // G's admin issues the step: the secret is kept and the copy counts
    let s = lp.peers[0].engine.sync_id_of(&g).unwrap().unwrap();
    lp.peers[0].engine.issue_step(&g, &s, false).unwrap().expect("a step due");
    lp.sync_all().unwrap();
    let now = sync_held(&lp, 2, &g);
    assert!(now.len() > was.len() && now.is_superset(&was), "G's new sync secret held: {was:?} -> {now:?}");
    assert!(lp.peers[2].engine.sync_copies_of(&g).iter().filter(|c| c.1.copy.commit == rot).all(|c| c.2), "counted once a step bears it");
}

/// Peer 2 forges a role commit on G making T an admin (it holds write there, no admin: the writer
/// rules skipped), and owes it as a sealed copy to T. A writer of G, so its commit has a chain
/// and applies, invalid, wherever it is taken: not one that pends unjudged. (the forged commit,
/// the sealed copy)
fn forged_copy(lp: &mut LocalPeer, g: Tid, t: Tid) -> (CommitId, super::inbox::SealedFireOut) {
    let w = lp.peers[2].engine.tid();
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
    let other = lp.peers[1].engine.tid();
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

// spec/wire.md §4 (sync copy: read for its boxes and steps), spec/sync-ids.md §4 (Owner): G's
// sync role rotated, its next step recorded beside its genesis. The sync copies of G's `sync.0`
// writes for T carry every step of G's path: a later step's write joins the entry its genesis
// made, so a read of that delta alone shows no step. Fails reading the delta as a value (a holder
// granted after the step holds no step bearing its secret: no sync ID, no head).
#[test]
fn sync_copies_carry_every_recorded_step_spec_wire_4() {
    let (mut lp, g, t) = sync_holder();
    lp.peers[0].engine.rotate_leaving_out(&g, &[Role::Sync], &[]).unwrap().unwrap();
    let s = lp.peers[0].engine.sync_id_of(&g).unwrap().unwrap();
    lp.peers[0].engine.issue_step(&g, &s, false).unwrap().expect("a step due");
    let e = &mut lp.peers[0].engine;
    let path: BTreeSet<[u8; 32]> = e.sync_ids(&g).unwrap().iter().flat_map(|o| o.path.steps.iter().map(|(st, _)| st.id().0)).collect();
    assert!(path.len() >= 2, "a step past genesis recorded");
    let writes: Vec<CommitId> = osis_base::Ak::new("sync.0").ok().and_then(|k| e.core.ix.by_aspect.get(&(g, k))).into_iter().flatten().map(|(_, x)| *x).collect();
    let mut carried = BTreeSet::new();
    for c in writes {
        let Some((copy, _)) = e.sync_copy(&c, &g, &t).unwrap() else { continue };
        let held = crate::sync_ids::unread::parse(t, false, &copy.encode()).expect("a sync copy");
        carried.extend(held.steps.values().flat_map(|x| x.steps.keys().copied()));
    }
    assert_eq!(carried, path, "every step of G's path");
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
    assert!(!lp.peers[1].engine.take_sync_copy(&u, &b, &plain, false).unwrap(), "T's piece is no copy of U's");
    assert!(lp.peers[1].engine.sync_copies_of(&g).is_empty(), "nothing taken");
    let was = sync_held(&lp, 2, &g);
    assert!(lp.peers[2].engine.take_sync_copy(&t, &b, &plain, false).unwrap(), "T's own");
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
    assert!(!lp.peers[2].engine.take_sync_copy(&t, &osis_base::BlobId([1; 32]), &junk.encode(), false).unwrap(), "garbage: bad input");
    let other = lp.peers[0].engine.sync_copy(&rot, &g, &t).unwrap().unwrap().0;
    lp.peers[2].engine.take_sync_copy(&t, &osis_base::BlobId([2; 32]), &other.encode(), false).unwrap();
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
            let me = lp.peers[2].engine.tid();
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
            assert!(lp.peers[2].engine.take_sync_copy(&t, &osis_base::BlobId([seed; 32]), &copy.encode(), false).unwrap(), "well formed: taken");
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
    assert!(e2.take_sync_copy(&t, &osis_base::BlobId([20; 32]), &copy.encode(), false).unwrap(), "well formed: taken");
    assert!(!e2.core.counts_independent(&y), "Y counts independent by a forged copy");
    assert_eq!(e2.core.secret_actor(&y), Some(t), "Y's secret actor");
    assert_eq!(e2.thing_sync_now(&y).unwrap(), how, "Y synced as before");
    lp.peers[2].restart(7).unwrap();
    assert_eq!(lp.peers[2].engine.core.secret_actor(&y), Some(t), "Y's secret actor at a fresh load");
}

/// The bytes no sync copy of `g`'s commits may hold at peer `i`: each held header's signer and
/// blind (its path's keys and holders go with them).
fn header_bytes(lp: &LocalPeer, i: usize, g: &Tid) -> Vec<Vec<u8>> {
    let e = &lp.peers[i].engine;
    e.core.on_thing(g).filter_map(|c| e.header(&c)).flat_map(|h| [h.signer.as_bytes().to_vec(), h.blind.to_vec()]).collect()
}

fn holds_any(b: &[u8], xs: &[Vec<u8>]) -> bool {
    xs.iter().any(|x| b.windows(x.len()).any(|w| w == x.as_slice()))
}

// spec/sync-ids.md §2 (What a sync holder learns: of the thing's role commits only sync copies, no
// header, signer, path or other holder), spec/permissions.md §4 (Key part; Delivering an edge
// piece), spec/sync-inbox.md §5 (By hand): T holds sync alone on G. On every path a commit of G
// reaches T's readers by, the bytes carry no header of G's: T's key part as peer 0 (G's admin,
// a reader of T) logs it (sync copies alone, no certificate copy of a part on G); a new grant of
// sync alone to U, delivered as sealed copies (form 2), never a `grant@~0` fire; the offer of
// U's grant by hand (sync copies alone, no evidence or trust record). Fails with any path
// carrying a certificate copy (the header, its signer and blind in the bytes).
#[test]
fn a_sync_alone_holder_gets_no_header_on_any_path_spec_sync_ids_2() {
    let (mut lp, g, t) = sync_holder();
    let me0 = lp.peers[0].engine.tid();
    lp.peers[2].engine.grant(&t, &me0, &edge(Role::Read)).unwrap();
    lp.sync_all().unwrap();
    // the key part
    let s = lp.peers[0].engine.sync_id_of(&t).unwrap().unwrap();
    let carried = lp.peers[0].engine.sync_copies_carried(&s).unwrap();
    assert!(carried.values().any(|(u, p)| *u == t && osis_commit::SyncCopy::decode(p).unwrap().thing == g), "T's key part carries G's sync copies");
    let forbidden = header_bytes(&lp, 0, &g);
    assert!(!forbidden.is_empty());
    assert!(carried.values().all(|(_, p)| !holds_any(p, &forbidden)), "no header byte in a logged sync copy");
    let certs = lp.peers[0].engine.certificates(&t).unwrap();
    let on_g = certs.commits.iter().any(|(c, ps)| lp.peers[0].engine.header(c).is_some_and(|h| ps.iter().any(|ai| h.aspects.get(*ai).is_some_and(|a| a.tid == g))));
    assert!(!on_g && !certs.records.contains(&g), "no certificate copy or record of G under T's sync ID");
    // a grant of sync alone to U: sealed copies, no fire
    let u = independent_thing(&mut lp, 1);
    lp.sync_all().unwrap();
    let before = lp.peers[0].engine.fires_owed();
    lp.peers[0].engine.grant(&g, &u, &edge(Role::Sync)).unwrap();
    let owed = new_owed(&lp, 0, &before);
    assert!(!owed.is_empty(), "the grant is delivered");
    let forbidden = header_bytes(&lp, 0, &g);
    for id in owed {
        let o = lp.peers[0].engine.core.ix.fires.get(&id).cloned().unwrap();
        assert!(o.ak.is_none() && matches!(o.what, Fire::Copy { .. }), "a sealed copy, no `grant@~0` fire: {o:?}");
        let out = lp.peers[0].engine.sealed_fire(&id).unwrap().expect("sealed to U's read key");
        let e1 = &lp.peers[1].engine;
        let (prefix, sealed) = e1.read_epochs(&u, &[]).into_iter().find_map(|(e, x)| osis_blob::open_fire(&out.blob, &u, &e, &osis_crypto::role_kem(&x)).ok()).expect("opens at U's reader");
        let osis_blob::Sealed::SyncCopy(plain) = sealed else { panic!("form 2") };
        assert!(!holds_any(&plain, &forbidden) && !holds_any(&prefix.to_bytes(), &forbidden), "no header byte in a sealed copy");
    }
    // by hand
    let offer = lp.peers[0].engine.offer(&g, &u).unwrap();
    let super::offers::Pieces::SyncAlone(copies) = &offer.pieces else { panic!("an offer of sync alone is its sync copies") };
    assert!(!copies.is_empty());
    assert!(!holds_any(&osis_base::encode(&offer.to_value()), &forbidden), "no header byte in the offer");
}

// spec/permissions.md §4 (Logging certificates: two blobs of one copy are one, the lower blob ID
// its log; copies of one (commit, thing, holder) with different bytes are two), spec/wire.md §4:
// T's reader holds the real sync copy of G's grant to T. A forged copy of the same commit, its box
// a forger's secret, taken under a lower blob ID: both rows kept, the real copy still counts and
// is what T's sync ID carries; the forgery counts for nothing, is carried by nothing, and keeps
// no secret. Fails with copies deduplicated by (commit, thing, holder) alone (the forgery under
// the lower blob ID displacing the real one).
#[test]
fn a_forged_duplicate_does_not_displace_the_real_copy_spec_permissions_4() {
    let (mut lp, g, t) = sync_holder();
    let real = lp.peers[2].engine.sync_copies_of(&g).into_iter().find(|c| c.2 && c.1.copy.piece.is_some()).expect("T's counted copy of a box");
    let held = sync_held(&lp, 2, &g);
    let (forged, _, _) = forged_sync_copy(&mut lp, 0, g, t, 40);
    let fake = osis_commit::SyncCopy { commit: real.1.copy.commit, thing: g, piece: forged.piece, sync: None };
    let low = osis_base::BlobId([0; 32]);
    assert!(low < real.0);
    assert!(lp.peers[2].engine.take_sync_copy(&t, &low, &fake.encode(), false).unwrap(), "well formed: taken");
    let copies = lp.peers[2].engine.sync_copies_of(&g);
    let at = |b: &osis_base::BlobId| copies.iter().find(|c| c.0 == *b).cloned();
    assert!(at(&real.0).is_some_and(|c| c.2), "the real copy kept, counted");
    assert!(at(&low).is_some_and(|c| !c.2 && c.1.key != real.1.key), "the forgery kept beside it, another copy, counting for nothing");
    let s = lp.peers[2].engine.sync_id_of(&t).unwrap().unwrap();
    let carried = lp.peers[2].engine.sync_copies_carried(&s).unwrap();
    assert!(carried.contains_key(&real.1.key) && !carried.contains_key(&at(&low).unwrap().1.key), "T's sync ID carries the real copy, not the forgery");
    assert_eq!(sync_held(&lp, 2, &g), held, "no forged secret kept");
}

// spec/sync-ids.md §5 (Peer budget: a sync copy is anyone's word, kept only while an entry of it
// is): a sync copy's row goes with its blob's last entry (`unnamed_sync_copy`), and what it gave
// with it; at n and 10n copies taken, the rows kept are exactly those whose entries stay, so what
// a party pushes is bounded by what the store keeps of it (its budget). Fails with rows kept past
// their entries (kept until the thing is forgotten).
#[test]
fn sync_copy_rows_go_with_their_entries_spec_sync_ids_5() {
    let (mut lp, g, t) = sync_holder();
    let base = lp.peers[2].engine.sync_copy_blobs().len();
    for n in [3usize, 30] {
        let mut blobs = Vec::new();
        for i in 0..n {
            let (copy, _, _) = forged_sync_copy(&mut lp, 0, g, t, 50 + i as u8);
            let b = osis_base::BlobId(crate::sync_ids::unread::content_key(&copy.encode()));
            assert!(lp.peers[2].engine.take_sync_copy(&t, &b, &copy.encode(), false).unwrap());
            blobs.push(b);
        }
        assert_eq!(lp.peers[2].engine.sync_copy_blobs().len(), base + n, "at {n}: a row per entry");
        // the store drops all but one (past the bringer's budget, or with its peer)
        for b in blobs.iter().skip(1) {
            lp.peers[2].engine.unnamed_sync_copy(b).unwrap();
        }
        assert_eq!(lp.peers[2].engine.sync_copy_blobs().len(), base + 1, "at {n}: rows go with their entries");
        lp.peers[2].engine.unnamed_sync_copy(&blobs[0]).unwrap();
        assert_eq!(lp.peers[2].engine.sync_copy_blobs().len(), base);
    }
}

// spec/sync-inbox.md §5 (By hand: an offer to a holder of sync alone is its sync copies, which give
// nothing until one counts), spec/sync-ids.md §2: a by-hand offer is the hander's word. Peer 2
// keeps G unread for T and holds G's record; an offer naming T on G whose one copy carries a
// forged genesis bearing the forger's secret, boxed to T, is refused, and leaves nothing: no row
// of the copy, G's sync ID and the sync secrets held unmoved. Fails with a refused offer's copies
// kept (rows a hander makes this node keep for nothing).
#[test]
fn a_forged_sync_alone_offer_takes_nothing_spec_sync_inbox_5() {
    let (mut lp, g, t) = sync_holder();
    let (copy, _, _) = forged_sync_copy(&mut lp, 0, g, t, 70);
    let offer = super::offers::Offer { target: g, pieces: super::offers::Pieces::SyncAlone(vec![copy.encode()]) };
    let offer = super::offers::Offer::from_value(&offer.to_value()).expect("round-trips");
    let (rows, id, held) = (lp.peers[2].engine.sync_copy_blobs(), lp.peers[2].engine.sync_id_of(&g).unwrap(), sync_held(&lp, 2, &g));
    assert!(lp.peers[2].engine.take_offer(&offer, &t).is_err(), "a forged offer gives no role");
    assert_eq!(lp.peers[2].engine.sync_copy_blobs(), rows, "no row of the refused offer's copy kept");
    assert_eq!((lp.peers[2].engine.sync_id_of(&g).unwrap(), sync_held(&lp, 2, &g)), (id, held), "G as before");
}

// spec/sync-ids.md §2 (What a sync holder learns), spec/sync-set.md §2 (Stub), spec/crypto.md §4 (Established): a role on a thing is a box a step bears. Any
// syncer of G holds G's `sync.0` writes, and a copy of one boxes nothing: anyone sealing to a
// holder, logging under its sync ID or handing an offer can bring one. Peer 1's node holds no role
// on G; boxless copies of G's real `sync.0` writes taken as its own count (their steps verify) but
// name it holder of nothing, and an offer of them beside a forged box is refused. Fails with a
// boxless copy's holder counted as holding sync (`Unread::holders`: the walk carrying G for it).
#[test]
fn a_boxless_copy_names_no_holder_spec_sync_ids_2() {
    let (mut lp, g, _) = sync_holder();
    let me1 = lp.peers[1].engine.tid();
    let syncs: Vec<CommitId> = osis_base::Ak::new("sync.0").ok().and_then(|k| lp.peers[0].engine.core.ix.by_aspect.get(&(g, k)).cloned()).into_iter().flatten().map(|(_, c)| c).collect();
    let mut copies = Vec::new();
    for c in &syncs {
        if let Some((copy, _)) = lp.peers[0].engine.sync_copy(c, &g, &me1).unwrap() {
            assert!(copy.piece.is_none(), "a `sync.0` write boxes peer 1 nothing");
            copies.push(copy.encode());
        }
    }
    assert!(!copies.is_empty());
    let (forged, _, _) = forged_sync_copy(&mut lp, 0, g, me1, 80);
    let offer = super::offers::Offer { target: g, pieces: super::offers::Pieces::SyncAlone([vec![forged.encode()], copies.clone()].concat()) };
    assert!(lp.peers[1].engine.take_offer(&offer, &me1).is_err(), "boxless copies beside a forged box give no role");
    assert!(!lp.peers[1].engine.core.syncs_by_copies(&me1, &g));
    for (i, c) in copies.iter().enumerate() {
        assert!(lp.peers[1].engine.take_sync_copy(&me1, &osis_base::BlobId([90 + i as u8; 32]), c, true).unwrap(), "well formed: taken");
    }
    let un = lp.peers[1].engine.core.unread(&g);
    assert!(!un.counted.is_empty(), "its steps verify: counted");
    assert!(!un.holders.contains(&me1) && !lp.peers[1].engine.core.syncs_by_copies(&me1, &g), "names peer 1 holder of nothing");
}

/// Whether `g`'s certificates at peer `i` hold a copy of a part on `x` of a commit naming `h` on
/// `x` (an edge write or a box: its key part's commits, `key_part_on`).
fn certifies_on(lp: &mut LocalPeer, i: usize, g: &Tid, x: &Tid, h: &Tid) -> bool {
    let naming = lp.peers[i].engine.edge_on(h, x, false);
    let certs = lp.peers[i].engine.certificates(g).unwrap();
    let e = &lp.peers[i].engine;
    certs.commits.iter().any(|(c, ps)| naming.contains(c) && e.header(c).is_some_and(|hd| ps.iter().any(|ai| hd.aspects.get(*ai).is_some_and(|a| a.tid == *x))))
}

// spec/sync-ids.md §2 (What a sync holder learns: no header, signer or path, its removal
// included), spec/sync-judgement.md §6 (Stops: a step past its keys is its removal),
// spec/permissions.md §4 (Key part; Role changes travel; Delivering an edge piece): T holds sync
// alone on G; peer 0 (G's admin, may not write T) and peer 1 read T. Peer 0 removes T from G: no
// `grant@~0` fire is owed, and neither T's sync ID nor peer 1's node's (whose keys open T: Role
// changes travel) carries a certificate copy of a commit naming T on G, before or after. The step peer 0 issues next, past T's keys, goes to T
// as sealed sync copies (that step and G's other `sync.0` writes), no header byte in them; T's
// reader takes them and judges T holding sync on G no more, its key part's copies naming T no
// holder. A later step goes to T no more. Fails with the removal sent as a fire, carried as a
// certificate copy (key part by the roster now, Role changes travel), or not told.
#[test]
fn a_sync_alone_holders_removal_is_told_by_its_step_alone_spec_sync_ids_2() {
    let (mut lp, g, t) = sync_holder();
    let me0 = lp.peers[0].engine.tid();
    lp.peers[2].engine.grant(&t, &me0, &edge(Role::Read)).unwrap();
    lp.sync_all().unwrap();
    assert!(lp.peers[2].engine.core.unread(&g).holders.contains(&t), "T holds sync on G as its reader knows it");
    reads_t(&mut lp, t);
    let me1 = lp.peers[1].engine.tid();
    let certified = |lp: &mut LocalPeer| certifies_on(lp, 0, &t, &g, &t) || certifies_on(lp, 0, &me1, &g, &t);
    assert!(!certified(&mut lp), "no certificate copy of a commit naming T on G before");
    let before = lp.peers[0].engine.fires_owed();
    lp.peers[0].engine.demote(&g, &super::Demotion { holder: t, new: None, retain: None }).unwrap();
    assert!(new_owed(&lp, 0, &before).is_empty(), "the removal itself is delivered nowhere");
    assert!(!certified(&mut lp), "none after: neither key part nor travel");
    // the step past T's keys
    let s = lp.peers[0].engine.sync_id_of(&g).unwrap().unwrap();
    lp.peers[0].engine.issue_step(&g, &s, false).unwrap().expect("a step due");
    let owed = new_owed(&lp, 0, &before);
    assert!(!owed.is_empty(), "the step is delivered to T");
    let forbidden = header_bytes(&lp, 0, &g);
    for id in &owed {
        let o = lp.peers[0].engine.core.ix.fires.get(id).cloned().unwrap();
        assert!(o.thing == t && o.ak.is_none() && matches!(o.what, Fire::Copy { .. }), "a sealed copy to T: {o:?}");
        let out = lp.peers[0].engine.sealed_fire(id).unwrap().expect("sealed to T's read key");
        let e2 = &lp.peers[2].engine;
        let (prefix, sealed) = e2.read_epochs(&t, &[]).into_iter().find_map(|(e, x)| osis_blob::open_fire(&out.blob, &t, &e, &osis_crypto::role_kem(&x)).ok()).expect("opens at T's reader");
        let osis_blob::Sealed::SyncCopy(plain) = sealed else { panic!("form 2") };
        assert!(!holds_any(&plain, &forbidden) && !holds_any(&prefix.to_bytes(), &forbidden), "no header byte in a sealed copy");
        assert!(matches!(open(&mut lp, 2, &out), Opened::SyncCopy), "taken as a sync copy");
    }
    let un = lp.peers[2].engine.core.unread(&g);
    assert!(!un.holders.contains(&t) && !lp.peers[2].engine.core.syncs_by_copies(&t, &g), "T holds sync on G no more: {un:?}");
    // a later step is no notice of T's: nothing more goes to it
    let before = lp.peers[0].engine.fires_owed();
    lp.peers[0].engine.issue_step(&g, &s, true).unwrap().expect("a fresh step");
    assert!(new_owed(&lp, 0, &before).is_empty(), "nothing after the step past its keys");
}

// spec/permissions.md §4 (Key part: every `sync.0` write of X while H is named, the step past
// its keys among them), spec/sync.md §3 (Holders by copies): as above with peer 0 a writer of T,
// so T's edge piece on G goes in T's key part, which peer 0 logs: after the removal and the step
// past T's keys, T's sync ID carries no header byte of G's and T's reader judges T holding sync on
// G no more. Fails with the key part by the roster now (the removal and the grant as certificate
// copies) or a copy's later steps unread (a lone step delta reads as nothing).
#[test]
fn a_sync_alone_holders_removal_in_its_key_part_is_its_step_spec_sync_ids_2() {
    let (mut lp, g, t) = sync_holder();
    let me0 = lp.peers[0].engine.tid();
    lp.peers[2].engine.grant(&t, &me0, &edge(Role::Write)).unwrap();
    lp.sync_all().unwrap();
    assert!(lp.peers[2].engine.core.unread(&g).holders.contains(&t));
    lp.peers[0].engine.demote(&g, &super::Demotion { holder: t, new: None, retain: None }).unwrap();
    let s = lp.peers[0].engine.sync_id_of(&g).unwrap().unwrap();
    lp.peers[0].engine.issue_step(&g, &s, false).unwrap().expect("a step due");
    lp.sync_all().unwrap();
    let st = lp.peers[0].engine.sync_id_of(&t).unwrap().unwrap();
    let carried = lp.peers[0].engine.sync_copies_carried(&st).unwrap();
    let forbidden = header_bytes(&lp, 0, &g);
    assert!(carried.values().any(|(u, p)| *u == t && osis_commit::SyncCopy::decode(p).unwrap().thing == g), "T's key part carries G's sync copies");
    assert!(carried.values().all(|(_, p)| !holds_any(p, &forbidden)), "no header byte in a logged sync copy");
    assert!(!certifies_on(&mut lp, 0, &t, &g, &t), "no certificate copy of a commit naming T on G");
    let un = lp.peers[2].engine.core.unread(&g);
    assert!(!un.holders.contains(&t) && !lp.peers[2].engine.core.syncs_by_copies(&t, &g), "T holds sync on G no more: {un:?}");
}

// spec/permissions.md §4 (Role changes travel: only on an edge giving read; Key part: sync
// alone, whatever the write), spec/sync-ids.md §2: T holds sync alone on G; peer 0 (G's admin)
// and peer 1 read T. Peer 0 raises T's grant on G to sync with may-grant, then lowers it back (an
// explicit lowering: its frontier the edge's writes). Neither T's sync ID nor peer 1's node's
// carries a certificate copy of a commit naming T on G, and both are owed to T as sealed sync copies
// (one carrying nothing of T's sent as nothing), no fire on an inbox, no header byte. Fails with a lowering on an edge only ever giving sync
// travelling (Role changes travel by the write being a lowering, not by the edge giving read) or
// delivered as a fire.
#[test]
fn a_sync_alone_holders_grant_lowered_travels_nowhere_spec_permissions_4() {
    let (mut lp, g, t) = sync_holder();
    let me0 = lp.peers[0].engine.tid();
    lp.peers[2].engine.grant(&t, &me0, &edge(Role::Read)).unwrap();
    lp.sync_all().unwrap();
    reads_t(&mut lp, t);
    let me1 = lp.peers[1].engine.tid();
    let before = lp.peers[0].engine.fires_owed();
    lp.peers[0].engine.grant(&g, &t, &osis_schema::core_types::Edge { may_grant: true, ..edge(Role::Sync) }).unwrap();
    lp.peers[0].engine.demote(&g, &super::Demotion { holder: t, new: Some(edge(Role::Sync)), retain: None }).unwrap();
    let on = lp.peers[0].engine.edge_on(&t, &g, false);
    let e0 = &lp.peers[0].engine;
    assert!(on.iter().any(|c| e0.core.timelines().role_commit(c).is_some_and(|rc| rc.frontier.is_some())), "a lowering: its frontier stated");
    assert!(e0.core.sync_alone_on(&t, &g), "T holds sync alone on G");
    assert!(!certifies_on(&mut lp, 0, &t, &g, &t) && !certifies_on(&mut lp, 0, &me1, &g, &t), "no certificate copy of a commit naming T on G");
    let owed = new_owed(&lp, 0, &before);
    assert!(!owed.is_empty(), "the change and the lowering are owed to T");
    let forbidden = header_bytes(&lp, 0, &g);
    for id in &owed {
        let o = lp.peers[0].engine.core.ix.fires.get(id).cloned().unwrap();
        assert!(o.thing == t && o.ak.is_none() && matches!(o.what, Fire::Copy { .. }), "a sealed copy to T: {o:?}");
        // a copy carrying nothing of T's (no box, no step) is owed no more
        if let Some(out) = lp.peers[0].engine.sealed_fire(id).unwrap() {
            assert!(!holds_any(&out.blob, &forbidden), "no header byte");
        }
    }
}

// spec/permissions.md §4 (Key part: sync alone, no held edge write valid here giving read; Role
// changes travel: on an edge a valid held write giving read stands on), spec/sync-ids.md §2 (What
// a sync holder learns): T holds sync alone on G; peer 0 (G's admin) and peer 1 read T. Peer 2, a
// writer of G (no admin), signs an edge write on G naming T read, logged under G's sync ID, which
// peer 0 holds and judges invalid. T still holds sync alone at peer 0: neither T's sync ID nor
// peer 1's node's carries a certificate copy of a commit naming T on G, and T's key part carries
// no header byte of G's. Fails with sync alone or the read graph judged over held writes
// whatever their validity (the forged write turning T's pieces, and the real grant's header, to
// certificate copies).
#[test]
fn a_forged_edge_write_giving_read_shows_a_sync_holder_nothing_spec_permissions_4() {
    let (mut lp, g, t) = sync_holder();
    let me0 = lp.peers[0].engine.tid();
    lp.peers[2].engine.grant(&t, &me0, &edge(Role::Read)).unwrap();
    reads_t(&mut lp, t);
    let me1 = lp.peers[1].engine.tid();
    let w = lp.peers[2].engine.tid();
    lp.peers[0].engine.grant(&g, &w, &edge(Role::Write)).unwrap();
    lp.sync_all().unwrap();
    let c = lp.peers[2]
        .engine
        .run(|tx| {
            let mut m = crate::Mutation::new();
            crate::flows::put_edge(&mut m, g, t, &edge(Role::Read))?;
            m.unchecked();
            tx.core.skip_writer_rules = true;
            let c = crate::engine::Engine::commit_tx(tx, m);
            tx.core.skip_writer_rules = false;
            Ok(c?.expect("built"))
        })
        .unwrap();
    lp.sync_all().unwrap();
    let e0 = &lp.peers[0].engine;
    assert!(e0.header(&c).is_some() && e0.core.ix.held.edge_commits(&g).iter().any(|rc| rc.id == c), "peer 0 holds the forged write");
    assert_ne!(e0.core.role_now(&t, &g), Some(Role::Read), "it gives T nothing");
    assert!(e0.core.sync_alone_on(&t, &g), "T holds sync alone on G");
    assert!(!certifies_on(&mut lp, 0, &t, &g, &t) && !certifies_on(&mut lp, 0, &me1, &g, &t), "no certificate copy of a commit naming T on G");
    let s = lp.peers[0].engine.sync_id_of(&t).unwrap().unwrap();
    let carried = lp.peers[0].engine.sync_copies_carried(&s).unwrap();
    let forbidden = header_bytes(&lp, 0, &g);
    assert!(carried.values().any(|(u, p)| *u == t && osis_commit::SyncCopy::decode(p).unwrap().thing == g), "T's key part carries G's sync copies");
    assert!(carried.values().all(|(_, p)| !holds_any(p, &forbidden)), "no header byte in a logged sync copy");
}

// spec/sync-hostile.md §2 (A writer of a holder H of sync alone on X can state a path through H's edge on X),
// spec/permissions.md §4 (Evidence of a commit: every held edge write on a stated path's edges,
// whatever its validity): T holds sync alone on G; peer 0 (G's admin) reads T. Peer 2, T's admin,
// grants G write on D (T's, in T's unit), then signs a body on D stating the path [T, G] (T holds
// sync alone on G: invalid).
// Peer 0 holds it and logs it under T's sync ID with its evidence: G's grant to T as a
// certificate copy, header and all. Pins the stated residual: it fails once a fix keeps the
// writes on a sync-alone holder's edge out of a body's evidence under that holder's sync ID.
#[test]
fn a_writer_of_a_sync_holder_stating_a_path_through_its_edge_shows_its_grant_spec_sync_hostile_2() {
    use osis_commit::{AspectWrite, CommitBuilder, Form, MemoryBlobs, writer_ctx};
    use osis_crdt::{Delta, Source, Writer, create, encode_delta};
    let (mut lp, g, t) = sync_holder();
    let me0 = lp.peers[0].engine.tid();
    lp.peers[2].engine.grant(&t, &me0, &edge(Role::Read)).unwrap();
    let mut m = crate::Mutation::new();
    let d = lp.peers[2].engine.new_thing(&mut m, t);
    lp.peers[2].commit(m).unwrap();
    lp.peers[2].engine.grant(&d, &g, &edge(Role::Write)).unwrap();
    lp.sync_all().unwrap();
    assert!(!certifies_on(&mut lp, 0, &t, &g, &t), "no certificate copy of G's grant to T before");
    lp.advance(1_000);
    let rec = lp.peers[2].engine.get_typed(&d, &osis_schema::core_types::CREATED).unwrap().unwrap();
    let e2 = &lp.peers[2].engine;
    let secrets = e2.hand_secrets(std::slice::from_ref(&rec));
    let ak = osis_base::Ak::new("t:reg.0").unwrap();
    let ts = osis_base::Ts::make(e2.now(), 0).unwrap();
    let mut w = Writer::new(ts, Source::commit(CommitId([0; 32])), 1_000);
    let f = create(&mut w, &osis_crdt::AnyView, &osis_base::Value::Str("via G".into())).unwrap();
    let r = w.range();
    let kind = osis_commit::Kind::Content;
    let bytes = encode_delta(&Delta { nonce: [7; 16], fragment: f }, &writer_ctx(Form::Commit, kind, ts, e2.tid(), r.lo, r.hi), None).unwrap();
    let mut aw = AspectWrite::new(d, ak.clone(), r.lo, r.hi, bytes);
    aw.purge_by = osis_commit::retention::write_purge_by(ak.as_str(), None, None).unwrap();
    let mut cb = CommitBuilder::new(kind, ts, e2.tid(), osis_commit::Path { purge: 0, things: vec![t, g], direct: 0 }, Form::Commit);
    cb.aspects.push(aw);
    let key = e2.identity().signing().clone();
    let forged = cb.build(&key, &secrets, &mut MemoryBlobs::default(), &mut osis_crypto::SeededRng::from_u64(0)).unwrap().commit.encode();
    let crate::Ingested::Applied(c) = lp.peers[0].receive(&forged, Vec::new()).unwrap() else { panic!("taken") };
    assert!(!lp.peers[0].engine.core.ix.commits.get(&c).unwrap().valid().iter().any(|v| *v), "the body is invalid");
    assert!(certifies_on(&mut lp, 0, &t, &g, &t), "the stated path's edge brings G's grant to T as a certificate copy");
    assert!(lp.peers[0].engine.certificates(&t).unwrap().records.contains(&g), "and G's record");
    assert_eq!(lp.peers[0].engine.check_evidence().unwrap(), None);
}

// spec/permissions.md §4 (Key part: sync alone by the writes valid here; Role changes travel),
// §5.1 (A lowering's **list** is its frontier), notes/evidence-derivation.md:
// T holds sync alone on G; peer 1 reads T and G. Peer 0 (G's admin) makes peer 2 an admin of G
// (A); peer 2 raises T to read (B). At peer 1, B applies: T reads G, and B is in the required set
// of peer 1's sync ID (Role changes travel: its keys open T). Peer 0, not holding B, removes peer
// 2: B is dropped, T holds sync alone again at peer 1 and B travels there no more; the kept
// derivation is the one derived anew throughout. Fails if a write's standing changing re-derives
// no copy (a stale `gives_read`), or if read is judged by held writes alone.
#[test]
fn a_read_grant_dropped_turns_a_holder_back_to_sync_alone_spec_permissions_4() {
    let (mut lp, g, t) = sync_holder();
    reads_t(&mut lp, t);
    let (me1, w) = (lp.peers[1].engine.tid(), lp.peers[2].engine.tid());
    lp.peers[0].engine.grant(&g, &me1, &edge(Role::Read)).unwrap();
    lp.sync_all().unwrap();
    lp.peers[0].engine.grant(&g, &w, &edge(Role::Admin)).unwrap();
    lp.sync(0, 2).unwrap();
    lp.advance(1_000);
    let b = lp.peers[2].engine.grant(&g, &t, &edge(Role::Read)).unwrap().commits[0];
    lp.sync(2, 1).unwrap();
    let travels = |lp: &mut LocalPeer| lp.peers[1].engine.kept_evidence().unwrap().required(&me1).is_some_and(|r| r.contains_key(&(b, g)));
    let e1 = &lp.peers[1].engine;
    assert_eq!(e1.core.role_now(&t, &g), Some(Role::Read), "B applies at peer 1");
    assert!(!e1.core.sync_alone_on(&t, &g));
    assert!(travels(&mut lp), "B travels under peer 1's sync ID");
    assert_eq!(lp.peers[1].engine.check_evidence().unwrap(), None);
    assert!(lp.peers[0].engine.header(&b).is_none());
    lp.advance(1_000);
    lp.peers[0].engine.demote(&g, &super::Demotion { holder: w, new: None, retain: None }).unwrap();
    lp.sync(0, 1).unwrap();
    let e1 = &lp.peers[1].engine;
    assert!(e1.core.ix.held.edge_commits(&g).iter().any(|rc| rc.id == b), "peer 1 still holds B");
    assert_eq!(e1.core.role_now(&t, &g), Some(Role::Sync), "B is dropped");
    assert!(e1.core.sync_alone_on(&t, &g), "T holds sync alone again");
    assert!(!travels(&mut lp), "B travels no more");
    assert_eq!(lp.peers[1].engine.check_evidence().unwrap(), None);
}

// spec/sync.md §3 (Holders by copies: a record alone is none of the admins' word), spec/sync-set.md
// §2 (Counts as independent): a fresh node reading T holds G (T holds sync on G) by T's sync
// copies alone, then takes G's record, as a node reading G by its public entry takes it under G's
// sync ID before G's role commits. The record moves nothing: G counts independent, kept by the
// same secrets and sync ID, still synced (what fetches the role commits, which alone decide once
// held). Fails judging by the record alone (G dependent on its mint admin, of which the node holds
// nothing: synced no more). Then G's admin grants the node read, its role commits waiting: a
// reader judging by copies alone syncs a forged sync ID above G's own beside it, never in its
// place (failed syncing the greatest alone: the forged one).
/// A fresh node reading T (granted by peer 2) holding G by T's sync copies on it alone, taken as
/// a reader of T takes them.
fn reader_by_copies(lp: &mut LocalPeer, g: Tid, t: Tid) -> crate::local_peer::Peer {
    let mut p = lp.fresh_reader(2, t, 11);
    p.engine.hold(osis_base::Strong(g)).unwrap();
    let mut copies = Vec::new();
    for c in lp.peers[0].engine.commit_ids() {
        if let Some((copy, _)) = lp.peers[0].engine.sync_copy(&c, &g, &t).unwrap() {
            copies.push(copy);
        }
    }
    assert!(!copies.is_empty(), "T's sync copies on G");
    for (i, copy) in copies.iter().enumerate() {
        assert!(p.engine.take_sync_copy(&t, &osis_base::BlobId([i as u8 + 1; 32]), &copy.encode(), false).unwrap(), "taken");
    }
    p
}

/// Peer `i`'s role commits on `g` not in `skip`, as received by `p`.
fn role_commits_to(lp: &mut LocalPeer, i: usize, g: Tid, skip: &BTreeSet<CommitId>, p: &mut crate::local_peer::Peer) {
    for c in lp.peers[i].engine.commit_ids() {
        let on_g = lp.peers[i].engine.core.ix.commits.get(&c).is_some_and(|m| m.view.kind.is_role() && m.view.aspects.iter().any(|a| a.tid == g));
        if on_g && !skip.contains(&c) && let Some(pk) = lp.peers[i].engine.package(&c).unwrap() {
            p.receive(&pk.bytes, pk.blobs.clone()).unwrap();
        }
    }
}

#[test]
fn a_record_alone_moves_no_copys_word_spec_sync_3() {
    let (mut lp, g, t) = sync_holder();
    let mut p = reader_by_copies(&mut lp, g, t);
    let real = lp.peers[0].engine.sync_id_of(&g).unwrap().unwrap();
    let judged = |p: &mut crate::local_peer::Peer| {
        let ids: Vec<osis_base::SyncId> = p.engine.sync_ids(&g).unwrap().iter().map(|o| o.id).collect();
        (p.engine.core.counts_independent(&g), p.engine.core.unread(&g).secrets.clone(), ids, p.engine.thing_sync_now(&g).unwrap())
    };
    assert!(p.engine.core.created(&g).is_none(), "no record of G yet");
    let before = judged(&mut p);
    assert!(before.0 && !before.1.is_empty() && before.2 == vec![real] && before.3 == crate::sync::ThingSync::Unread(vec![real]), "G kept unread by T's copies: {before:?}");
    let record = lp.peers[0].engine.core.created(&g).cloned().unwrap();
    assert!(record.mint_admin().is_some(), "G minted dependent");
    assert_eq!(p.engine.learn_records(vec![record]).unwrap(), 1, "G's record taken");
    assert_eq!(judged(&mut p), before, "the record moves nothing");
    // G's admin grants the node read; its role commits wait (wrapped under epochs it holds none
    // of): a reader by a box alone
    for c in p.engine.commit_ids() {
        if let Some(pk) = p.engine.package(&c).unwrap() {
            lp.deliver(0, &pk).unwrap();
        }
    }
    let me = p.engine.tid();
    lp.peers[0].engine.grant(&g, &me, &edge(Role::Read)).unwrap();
    role_commits_to(&mut lp, 0, g, &BTreeSet::new(), &mut p);
    assert!(p.engine.core.copies_speak(&g), "no admin's word held yet");
    assert_eq!(p.engine.thing_sync_now(&g).unwrap(), crate::sync::ThingSync::Read(vec![real]), "G read by its own sync ID");
    let id = |seed: u8| osis_blob::genesis_sync_id(&osis_crypto::Secret32::from_bytes([seed.wrapping_add(Role::Admin.id()); 32]));
    let seed = (1..=u8::MAX).find(|x| id(*x) > real).unwrap();
    let (copy, forged, _) = forged_sync_copy(&mut lp, 0, g, t, seed);
    assert!(p.engine.take_sync_copy(&t, &osis_base::BlobId([99; 32]), &copy.encode(), false).unwrap(), "taken");
    match p.engine.thing_sync_now(&g).unwrap() {
        crate::sync::ThingSync::Read(ids) => assert!(ids.contains(&real) && ids.contains(&forged), "the forged sync ID beside G's own, never in its place: {ids:?}"),
        other => panic!("G read: {other:?}"),
    }
}


// spec/sync.md §3 (Holders by copies: where the node holds a keyset part of T, a copy's steps
// count only on a sync ID T's recorded steps place), spec/sync-set.md §2 (a box is any writer's
// word, a step an admin's): P reads G by T's sync copies alone, holds G's record, and is granted
// read on G, its role commits waiting. W, a writer of G (granted after P), rotates G's read role
// past its writer rules (a `keys.0` part writing a keyset on G, invalid), and P receives W's grant
// and the forgery. Neither silences the copies: no commit on G applies at P before its admins'
// steps do (each awaits its chain), so G stays read by its own sync ID, at a fresh load too.
// Fails if a keyset part on G counted at P while its commit waits (P then judges G by a `sync.0`
// it holds none of: synced no more, cut off from the role commits that would decide).
#[test]
fn a_writers_keyset_moves_no_copys_word_spec_sync_3() {
    let (mut lp, g, t) = sync_holder();
    let mut p = reader_by_copies(&mut lp, g, t);
    let real = lp.peers[0].engine.sync_id_of(&g).unwrap().unwrap();
    let record = lp.peers[0].engine.core.created(&g).cloned().unwrap();
    assert_eq!(p.engine.learn_records(vec![record]).unwrap(), 1, "G's record taken");
    for c in p.engine.commit_ids() {
        if let Some(pk) = p.engine.package(&c).unwrap() {
            lp.deliver(0, &pk).unwrap();
        }
    }
    let (me, w) = (p.engine.tid(), lp.peers[1].engine.tid());
    lp.peers[0].engine.grant(&g, &me, &edge(Role::Read)).unwrap();
    lp.peers[0].engine.grant(&g, &w, &edge(Role::Write)).unwrap();
    lp.sync_all().unwrap();
    role_commits_to(&mut lp, 0, g, &BTreeSet::new(), &mut p);
    let want = crate::sync::ThingSync::Read(vec![real]);
    assert_eq!(p.engine.thing_sync_now(&g).unwrap(), want, "G read by its own sync ID");
    let before: BTreeSet<CommitId> = lp.peers[1].engine.commit_ids().into_iter().collect();
    let (forged, _) = crate::rotation::tests::rotate_unchecked(&mut lp, 1, g, &[Role::Read].into());
    assert!(lp.peers[1].engine.core.ix.keyset_parts.get(&g).is_some_and(|s| s.contains(&forged)), "W's forgery writes a keyset on G");
    role_commits_to(&mut lp, 1, g, &before, &mut p);
    assert!(p.engine.header(&forged).is_none(), "W's forgery waits at P");
    assert!(p.engine.core.copies_speak(&g), "no admin's word held");
    assert_eq!(p.engine.thing_sync_now(&g).unwrap(), want, "G read as before");
    p.restart(7).unwrap();
    assert_eq!(p.engine.thing_sync_now(&g).unwrap(), want, "G read as before at a fresh load");
}
