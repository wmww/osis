//! Entries at epochs no valid rotation made (spec/crypto.md §4 Established, the `secrets.0`
//! compaction snapshot). A history add needs only the role its key names and a box only write,
//! so a reader or a writer can key `secrets.0` at a made-up epoch; a snapshot vouches for every
//! epoch it keys, so it leaves those out and never waits for them.

#![allow(clippy::unwrap_used)]
use super::tests::{Rng, drop_covered, edge, granted, newest_read, put_on, reads_key, rotate_leaving_out, rounds_to_settle, secrets_verdicts};
use crate::Mutation;
use crate::local_peer::LocalPeer;
use osis_base::{Ak, CommitId, Role, Tid};
use osis_crypto::{Epoch, Secret32};
use osis_schema::core_types as ct;
use std::collections::BTreeSet;

fn secrets_ak() -> Ak {
    Ak::new("secrets.0").unwrap()
}

/// A made-up read epoch of `g` at `n` with a secret of the planter's choosing.
fn made_up(g: &Tid, n: u64, seed: u8) -> (Epoch, Secret32) {
    let s = Secret32::from_bytes([seed; 32]);
    (Epoch::derive(g, Role::Read, n, &s).unwrap(), s)
}

/// Reader `i`'s history add at (read, e), naming nothing: valid (the role its key names).
fn plant_history(lp: &mut LocalPeer, i: usize, g: Tid, e: &Epoch, s: &Secret32) -> CommitId {
    let ct = osis_crypto::seal_history(s, &g, Role::Read, e, &osis_crypto::HistoryEntry { earlier: Vec::new(), names: osis_keys::Names::default().to_value(), floor: 0, roles: Vec::new() }).unwrap();
    let history = [(osis_keys::aspects::history_key(Role::Read, e), ct)].into_iter().collect();
    let mut m = Mutation::new();
    crate::flows::put_secrets(&mut m, g, &osis_keys::SecretsWrite { history, ..Default::default() }, true).unwrap();
    lp.peers[i].engine.commit_hostile(m).unwrap().unwrap()
}

/// Writer `i`'s box at (read, e) sealed to itself: valid (a box needs write).
fn plant_box(lp: &mut LocalPeer, i: usize, g: Tid, e: &Epoch, s: &Secret32) -> CommitId {
    let me = lp.peers[i].engine.tid();
    let mut fake = osis_keys::ActorEpochs::default();
    fake.role_mut(Role::Read).set_secret(*e, s.clone());
    fake.role_mut(Role::Read).set_established(*e, osis_keys::Provenance::Fixed);
    let rcpt = lp.peers[i].engine.run(|tx| crate::flows::recipient(tx, me, Role::Read)).unwrap();
    let w = lp.peers[i].engine.run(|tx| Ok(osis_keys::box_holder(&g, &fake, &osis_keys::HistoryBoxes::new(), &rcpt, &[Role::Read].into(), &mut *tx.rng)?.unwrap())).unwrap();
    let mut m = Mutation::new();
    crate::flows::put_secrets(&mut m, g, &w, true).unwrap();
    lp.peers[i].engine.commit_hostile(m).unwrap().unwrap()
}

/// Whether peer `i`'s `secrets.0` state keys `e` (a box or a history box).
fn keys_epoch(lp: &mut LocalPeer, i: usize, g: Tid, e: &Epoch) -> bool {
    let s = lp.peers[i].engine.get_typed(&g, &ct::SECRETS).unwrap().unwrap_or_default();
    let e = osis_keys::aspects::to_schema(e);
    s.boxes.keys().any(|k| k.epoch == e) || s.history.keys().any(|k| k.epoch == e)
}

/// Whether a held valid `secrets.0` snapshot of `g` at peer `i` covers commit `c`'s part.
fn covered(lp: &mut LocalPeer, i: usize, g: Tid, c: &CommitId) -> bool {
    let e = &mut lp.peers[i].engine;
    let snaps: Vec<CommitId> = e.core.ix.snapshots.get(&(g, secrets_ak())).into_iter().flatten().map(|x| x.1).collect();
    snaps.iter().any(|s| e.covered(s, c, &g, &secrets_ak()).unwrap() == Some(true))
}

/// Whether peer `i` counts `e` established, names aside, or unsuperseded: what a snapshot keying
/// it would make it.
fn based(lp: &LocalPeer, i: usize, g: Tid, e: &Epoch) -> bool {
    let r = lp.peers[i].engine.epochs(&g).unwrap().read.clone();
    r.established_names_aside().contains_key(e) || r.unsuperseded().contains(e) || r.is_established(e)
}

// spec/crypto.md §4 (A `secrets.0` compaction snapshot leaves out every live box: keys only epochs established at its writer, names
// aside), spec/commits.md §5 (Covered: join). Invariant: a reader's history add or a writer's
// box at an epoch no valid rotation made never stops an admin compacting `secrets.0`, is never
// based anywhere (the snapshot carries it to nobody), and is lost nowhere (its commit stays
// beside the snapshot, uncovered); a node granted after and fed only by the compactor judges every
// `secrets.0` part and the current epochs as the compactor does and reads what came after.
// Randomized over which plants, their n, the rotations around them, the compactor, a `keys.0`
// snapshot, restarts, a second compaction and arrival order. Fails without the fix: the gate
// refused every compaction once the state keyed a planted epoch.
#[test]
#[ignore = "property"]
fn planted_epoch_never_blocks_compaction_plain_spec_crypto_4() {
    let mut dropped = 0;
    for seed in 0..6u64 {
        let mut rng = Rng(seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) ^ 0x2545_f491_4f6c_dd1d);
        let (mut lp, g, tids) = granted(5, &[(1, Role::Read), (2, Role::Write), (3, Role::Admin)]);
        let cur = newest_read(&lp, 0, g).unwrap().n();
        let pick_n = |rng: &mut Rng| [1, cur + 1, cur + 4, 1 << 40][rng.next(4) as usize];
        let which = 1 + rng.next(3);
        let mut planted = Vec::new();
        let mut plants = BTreeSet::new();
        let before = rng.next(2) == 0;
        if !before {
            rotate_leaving_out(&mut lp, [0, 3][rng.next(2) as usize], g, &BTreeSet::from([Role::Read]), &[]);
            lp.sync_all().unwrap();
        }
        if which & 1 != 0 {
            let (e, s) = made_up(&g, pick_n(&mut rng), 0x51);
            plants.insert(plant_history(&mut lp, 1, g, &e, &s));
            planted.push(e);
        }
        if which & 2 != 0 {
            let (e, s) = made_up(&g, pick_n(&mut rng), 0x52);
            plants.insert(plant_box(&mut lp, 2, g, &e, &s));
            planted.push(e);
        }
        lp.sync_all().unwrap();
        for _ in 0..1 + rng.next(2) {
            rotate_leaving_out(&mut lp, [0, 3][rng.next(2) as usize], g, &BTreeSet::from([Role::Read]), &[]);
            lp.sync_all().unwrap();
        }
        rounds_to_settle(&mut lp, g);
        put_on(&mut lp, 0, g, "after", 2);
        lp.sync_all().unwrap();
        let c = [0, 3][rng.next(2) as usize];
        lp.advance(1 + rng.next(1000));
        if rng.next(2) == 0 {
            lp.peers[c].engine.snapshot(&g, &Ak::new("keys.0").unwrap()).unwrap().unwrap();
        }
        lp.peers[c].engine.snapshot(&g, &secrets_ak()).expect("seed {seed}: a planted epoch blocks compaction").unwrap();
        lp.advance(osis_base::format::ROLE_KEEP_MS + 1 + rng.next(3) * 86_400_000);
        if rng.next(2) == 0 {
            lp.peers[c].restart(seed).unwrap();
        }
        dropped += drop_covered(&mut lp, c, g);
        if rng.next(2) == 0 {
            lp.advance(1 + rng.next(1000));
            lp.peers[c].engine.snapshot(&g, &secrets_ak()).expect("seed {seed}: a second compaction").unwrap();
            dropped += drop_covered(&mut lp, c, g);
        }
        // N, granted now, gets what c holds, in some order
        lp.peers[0].engine.grant(&g, &tids[4], &edge(Role::Read)).unwrap();
        lp.sync(0, c).unwrap();
        let mut pks = lp.packages_to(c, 4).unwrap();
        for k in (1..pks.len()).rev() {
            pks.swap(k, rng.next(k as u64 + 1) as usize);
        }
        for _ in 0..2 {
            for pk in &pks {
                let _ = lp.peers[4].receive(&pk.bytes, pk.blobs.clone());
            }
        }
        lp.sync_all().unwrap();
        for e in &planted {
            for p in 0..5 {
                assert!(keys_epoch(&mut lp, p, g, e), "seed {seed}: peer {p} lost a planted entry (data the snapshot left out)");
                assert!(!based(&lp, p, g, e), "seed {seed}: peer {p} bases planted epoch {e:?}");
            }
        }
        // what the snapshot left out stays beside it, uncovered
        for p in &plants {
            assert!(!covered(&mut lp, c, g, p), "seed {seed}: a plant covered at compactor {c}");
            assert!(lp.peers[c].engine.body_not_dropped(p, &g, &secrets_ak()), "seed {seed}: a plant's body dropped at compactor {c}");
        }
        let read = |lp: &LocalPeer, p: usize| lp.peers[p].engine.epochs(&g).unwrap().read.clone();
        assert_eq!(read(&lp, 4).current(), read(&lp, c).current(), "seed {seed}: N and compactor {c} count different current read epochs");
        assert!(reads_key(&mut lp, 4, g, "after"), "seed {seed}: N reads nothing of what came after");
        let differ: Vec<_> = secrets_verdicts(&lp, c, 4, g).into_iter().filter(|(_, a, b)| a != b).collect();
        assert!(differ.is_empty(), "seed {seed}: compactor {c} and N judge `secrets.0` parts differently: {differ:?}");
    }
    assert!(dropped > 0, "no compactor dropped a covered body");
}

/// Peer 0 rotates read of `g` (new epoch e, rotation commit R), grants `n` `role` (boxing it at e)
/// and writes `put` under e if given; admin C (peer 3) gets all of it but R, so e is not verified
/// there. Returns e and the grant's commits.
fn granted_before_rotation(lp: &mut LocalPeer, g: Tid, n: Tid, role: Role, put: Option<&str>) -> (Epoch, Vec<CommitId>) {
    let before: BTreeSet<CommitId> = lp.commit_ids(0).into_iter().collect();
    rotate_leaving_out(lp, 0, g, &BTreeSet::from([Role::Read]), &[]);
    let e = newest_read(lp, 0, g).unwrap();
    let rot: BTreeSet<CommitId> = lp.commit_ids(0).into_iter().filter(|c| !before.contains(c)).collect();
    lp.peers[0].engine.grant(&g, &n, &edge(role)).unwrap();
    let gr: Vec<CommitId> = lp.commit_ids(0).into_iter().filter(|c| !before.contains(c) && !rot.contains(c)).collect();
    if let Some(k) = put {
        put_on(lp, 0, g, k, 1);
    }
    for pk in lp.packages_for(0, 3).unwrap().into_iter().filter(|p| !rot.contains(&p.id)) {
        let _ = lp.peers[3].receive(&pk.bytes, pk.blobs.clone());
    }
    assert!(!based(lp, 3, g, &e), "e verified at C without its rotation commit");
    (e, gr)
}

// spec/crypto.md §4, spec/commits.md §5: a grant boxing N at e reaching admin C before e's
// rotation commit R. C compacts: e is not verified there, so the grant's entries stay beside the
// snapshot, and nothing is lost at the nodes where e is current (N keeps its box and reads under
// e). Once R arrives, C's next snapshot carries them and covers the grant.
#[test]
fn unverified_genuine_entry_kept_beside_spec_crypto_4() {
    let (mut lp, g, tids) = granted(5, &[(3, Role::Admin)]);
    let (e, gr) = granted_before_rotation(&mut lp, g, tids[4], Role::Read, Some("w"));
    lp.peers[3].engine.snapshot(&g, &secrets_ak()).unwrap().unwrap();
    lp.advance(osis_base::format::ROLE_KEEP_MS + 1);
    drop_covered(&mut lp, 3, g);
    for c in &gr {
        assert!(!covered(&mut lp, 3, g, c), "the grant covered at C: N's box at e lost with its body");
    }
    lp.sync_all().unwrap();
    let boxed = |lp: &mut LocalPeer, p: usize| {
        let s = lp.peers[p].engine.get_typed(&g, &ct::SECRETS).unwrap().unwrap();
        s.boxes.contains_key(&osis_keys::aspects::box_key(tids[4], Role::Read, &e))
    };
    for p in 0..5 {
        assert!(boxed(&mut lp, p), "peer {p} lost N's box at e");
    }
    assert!(reads_key(&mut lp, 4, g, "w"), "N reads nothing written under e");
    // R held now: C's next snapshot carries the grant's entries and covers it
    assert!(based(&lp, 3, g, &e));
    lp.advance(1_000);
    lp.peers[3].engine.snapshot(&g, &secrets_ak()).unwrap().unwrap();
    lp.advance(osis_base::format::ROLE_KEEP_MS + 1);
    drop_covered(&mut lp, 3, g);
    assert!(gr.iter().all(|c| covered(&mut lp, 3, g, c)), "the grant stays uncovered once e is verified");
}

// spec/crdt.md §8 (`Absorbed`), spec/commits.md §5: a commit writing both a record a `secrets.0`
// snapshot carries and one it leaves out is not absorbed by it, so a node holding the snapshot
// but not the body judges the body not covered and fetches it. The shape: a write grant boxes N
// at the new read epoch e (its rotation commit R not at admin C yet) and at the write epoch C
// verified; C compacts, carrying the write box and leaving the read box out. Invariant: F,
// holding C's snapshot and the grant's header alone, never judges the grant's `secrets.0` part
// covered (else it never fetches it, and N's box at e is lost there). Fails without the fix: the
// snapshot listed the grant in `Absorbed`, so F judged the unheld body covered.
#[test]
fn mixed_commit_not_absorbed_spec_crdt_8() {
    let (mut lp, g, tids) = granted(6, &[(3, Role::Admin), (5, Role::Read)]);
    let (_, gr) = granted_before_rotation(&mut lp, g, tids[4], Role::Write, None);
    let s = lp.peers[3].engine.snapshot(&g, &secrets_ak()).unwrap().unwrap();
    let boxes = |lp: &mut LocalPeer, p: usize| lp.peers[p].engine.get_typed(&g, &ct::SECRETS).unwrap().unwrap().boxes;
    assert!(boxes(&mut lp, 3).keys().any(|k| k.holder == osis_base::Weak(tids[4]) && k.role == Role::Write), "C lacks N's write box");
    // F gets the snapshot whole and the grant as a header alone
    let pk = lp.peers[3].engine.package(&s).unwrap().unwrap();
    lp.peers[5].receive(&pk.bytes, pk.blobs.clone()).unwrap();
    for c in &gr {
        let pk = lp.peers[0].engine.package(c).unwrap().unwrap();
        let header = osis_commit::rewrite(&osis_commit::CommitBlob::decode(&pk.bytes).unwrap(), |_| true).encode();
        let _ = lp.peers[5].receive(&header, Vec::new());
        assert_ne!(lp.peers[5].engine.covered(&s, c, &g, &secrets_ak()).unwrap(), Some(true), "F judges the grant's unheld `secrets.0` body covered: N's box at e is never fetched");
    }
}

// spec/sync-set.md §2 (Counts as independent), spec/permissions.md §3: Y is a dependent thing of
// g (minted with admin g, no keyset). W (peer 1), a writer of g, writes a `secrets.0` part on Y
// boxing reader R (peer 2) at a read epoch of its choosing, with no `keys.0`. R keeps Y dependent
// as every node does: its writes on Y reach A (peer 0), and A's later writes reach R.
#[test]
fn box_on_a_dependent_thing_splits_nobody_spec_sync_set_2() {
    let (mut lp, g, tids) = granted(3, &[(1, Role::Write), (2, Role::Write)]);
    let y = {
        let mut m = Mutation::new();
        let y = lp.peers[0].engine.new_thing(&mut m, g);
        lp.peers[0].commit(m).unwrap();
        lp.hold(y);
        y
    };
    put_on(&mut lp, 0, y, "before", 1);
    lp.sync_all().unwrap();
    assert!(reads_key(&mut lp, 2, y, "before"));
    let (e, s) = made_up(&y, 5, 7);
    let r = tids[2];
    let mut fake = osis_keys::ActorEpochs::default();
    fake.role_mut(Role::Read).set_secret(e, s.clone());
    fake.role_mut(Role::Read).set_established(e, osis_keys::Provenance::Fixed);
    let rcpt = lp.peers[1].engine.run(|tx| crate::flows::recipient(tx, r, Role::Read)).unwrap();
    let w = lp.peers[1].engine.run(|tx| Ok(osis_keys::box_holder(&y, &fake, &osis_keys::HistoryBoxes::new(), &rcpt, &[Role::Read].into(), &mut *tx.rng)?.unwrap())).unwrap();
    let mut m = Mutation::new();
    crate::flows::put_secrets(&mut m, y, &w, true).unwrap();
    lp.peers[1].engine.commit_hostile(m).unwrap().unwrap();
    lp.sync_all().unwrap();
    // the invariant the issue is about: Y's secret actor stays g at every node
    for i in 0..3 {
        assert_eq!(lp.peers[i].engine.core.secret_actor(&y), Some(g), "peer {i} counts Y independent");
    }
    put_on(&mut lp, 0, y, "by A", 1);
    lp.sync_all().unwrap();
    assert!(reads_key(&mut lp, 2, y, "by A"), "A's write on Y never reaches R");
    assert_eq!(lp.peers[2].engine.role_on(&y), Some(Role::Write), "R's role on Y is not g's");
    put_on(&mut lp, 2, y, "by R", 1);
    lp.sync_all().unwrap();
    assert!(reads_key(&mut lp, 0, y, "by R"), "R's write on Y never reaches A");
}

// spec/sync-set.md §2: a grantee holds no rotation that made a granted epoch current. G (peer 1)
// is granted read on g and holds everything of g but its keysets (each `keys.0` part on g withheld). g counts independent at G by its box and the
// step of g's `sync.0` bearing its sync key: G syncs g's sync ID, and reads g once it does.
#[test]
fn a_grantee_counts_its_target_independent_before_the_keyset_spec_permissions_4() {
    let mut lp = super::tests::synced(2);
    let g = super::tests::target_thing(&mut lp, 0);
    put_on(&mut lp, 0, g, "k", 1);
    let gr = lp.peers[1].engine.tid();
    lp.peers[0].engine.grant(&g, &gr, &edge(Role::Read)).unwrap();
    let keys = Ak::new("keys.0").unwrap();
    for pk in lp.packages_to(0, 1).unwrap() {
        let h = lp.peers[0].engine.header(&pk.id).unwrap();
        let parts: BTreeSet<usize> = (0..h.aspects.len()).filter(|i| h.aspects.get(*i).is_none_or(|a| a.tid != g || a.ak != keys)).collect();
        let Some(pk) = lp.peers[0].engine.package_of_parts(&pk.id, &parts).unwrap() else { continue };
        let _ = lp.deliver(1, &pk);
    }
    lp.settle_needs().unwrap();
    let e1 = &lp.peers[1].engine;
    assert!(!e1.core.is_independent(&g), "G holds a keyset of g");
    assert!(e1.core.counts_independent(&g), "G's box and g's step leave g dependent at G");
    lp.peers[1].restart(7).unwrap();
    assert!(lp.peers[1].engine.core.counts_independent(&g), "a fresh load of G counts g dependent");
    let s = lp.peers[0].engine.sync_ids(&g).unwrap()[0].id;
    assert!(lp.synced(1).unwrap().contains(&s), "G does not sync g's sync ID");
    lp.sync_all().unwrap();
    assert!(reads_key(&mut lp, 1, g, "k"));
}

/// Peer `i`'s genesis step of a made-up sync ID on `y` and a box of the same made-up epochs to
/// `to` (read and sync), in one commit, with no keyset: what only an admin's word places.
fn plant_step_box(lp: &mut LocalPeer, i: usize, y: Tid, to: Tid, seed: u8) -> CommitId {
    let mut fake = osis_keys::ActorEpochs::default();
    for (k, r) in [Role::Sync, Role::Read, Role::Write, Role::Admin].into_iter().enumerate() {
        let s = Secret32::from_bytes([seed.wrapping_add(k as u8); 32]);
        let e = Epoch::derive(&y, r, 5, &s).unwrap();
        fake.role_mut(r).set_secret(e, s);
        fake.role_mut(r).set_established(e, osis_keys::Provenance::Fixed);
    }
    let m = lp.peers[i].engine.run(|tx| {
        let rcpt = crate::flows::recipient(tx, to, Role::Read)?;
        let w = osis_keys::box_holder(&y, &fake, &osis_keys::HistoryBoxes::new(), &rcpt, &[Role::Sync, Role::Read].into(), &mut *tx.rng)?.unwrap();
        let issued = crate::flows::sync_ids::issue(tx, &y, &fake, None, &[], &Secret32::from_bytes([seed; 32]), None)?;
        let mut m = Mutation::new();
        crate::flows::put_secrets(&mut m, y, &w, true)?;
        crate::flows::sync_ids::put_step(&mut m, y, issued.step.sync_id, &issued, true)?;
        Ok(m)
    });
    lp.peers[i].engine.commit_hostile(m.unwrap()).unwrap().unwrap()
}

/// A dependent thing of `g` minted by peer 0 and held by every peer, with "before" on it.
fn dependent_of(lp: &mut LocalPeer, g: Tid) -> Tid {
    let mut m = Mutation::new();
    let y = lp.peers[0].engine.new_thing(&mut m, g);
    lp.peers[0].commit(m).unwrap();
    lp.hold(y);
    put_on(lp, 0, y, "before", 1);
    lp.sync_all().unwrap();
    y
}

// spec/sync-set.md §2 (Counts as independent: a step is an admin's word), spec/permissions.md §2:
// D (peer 1), an admin of g lowered to write, then writes a step and a box to R (peer 2) on Y, a
// dependent of g, with no keyset. Its `sync.0` write is judged at its point like any (D is no
// admin there), so the step places nothing: Y stays dependent at every node and A (peer 0) and R
// read each other's writes on it.
#[test]
fn a_demoted_admins_step_splits_nobody_spec_sync_set_2() {
    let (mut lp, g, tids) = granted(3, &[(1, Role::Admin), (2, Role::Write)]);
    let y = dependent_of(&mut lp, g);
    lp.peers[0].engine.demote(&g, &crate::flows::Demotion { holder: tids[1], new: Some(edge(Role::Write)), retain: None }).unwrap();
    lp.sync_all().unwrap();
    plant_step_box(&mut lp, 1, y, tids[2], 40);
    lp.sync_all().unwrap();
    lp.peers[2].restart(7).unwrap();
    assert!(lp.peers[2].engine.core.ix.secrets.get(&y).is_some_and(|e| e.sync.held().next().is_some()), "R opens no box of D's");
    for i in 0..3 {
        assert!(lp.peers[i].engine.core.ix.steps.get(&y).is_none(), "peer {i} places a demoted admin's step");
        assert_eq!(lp.peers[i].engine.core.secret_actor(&y), Some(g), "peer {i} counts Y independent by a demoted admin's step");
    }
    put_on(&mut lp, 2, y, "by R", 1);
    put_on(&mut lp, 0, y, "by A", 1);
    lp.sync_all().unwrap();
    assert!(reads_key(&mut lp, 0, y, "by R") && reads_key(&mut lp, 2, y, "by A"), "A and R split on Y");
}


// spec/sync-set.md §2 (Counts as independent: a step is an admin's word), spec/permissions.md
// §5.2: D (peer 1), an admin of g, writes a step and a box to R (peer 2) on Y, a dependent of g,
// with no keyset, and is lowered to write after (its demoter holding the plant). The `sync.0`
// write judged at its point stays valid, so the step places everywhere and counts at the boxed
// node alone: Y independent at R, dependent at A (peer 0), a restart of R alike. Fails with the
// step of a since-demoted admin dropped, or with a step not counting a box's thing independent.
#[test]
fn an_admins_step_counts_at_the_boxed_node_after_its_demotion_spec_sync_set_2() {
    let (mut lp, g, tids) = granted(3, &[(1, Role::Admin), (2, Role::Write)]);
    let y = dependent_of(&mut lp, g);
    plant_step_box(&mut lp, 1, y, tids[2], 60);
    lp.sync_all().unwrap();
    lp.peers[0].engine.demote(&g, &crate::flows::Demotion { holder: tids[1], new: Some(edge(Role::Write)), retain: None }).unwrap();
    lp.sync_all().unwrap();
    lp.peers[2].restart(7).unwrap();
    for i in 0..3 {
        assert!(lp.peers[i].engine.core.ix.steps.get(&y).is_some(), "peer {i} places the step: valid at its point");
    }
    assert_eq!(lp.peers[2].engine.core.secret_actor(&y), Some(y), "R counts Y independent by its box and the step");
    assert_eq!(lp.peers[0].engine.core.secret_actor(&y), Some(g), "A, boxed nothing, counts Y dependent");
}
