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
    let ct = osis_crypto::seal_history(s, &g, Role::Read, e, &[], &osis_keys::Names::default().to_value()).unwrap();
    let history = [(osis_keys::aspects::history_key(Role::Read, e), ct)].into_iter().collect();
    let mut m = Mutation::new();
    crate::flows::put_secrets(&mut m, g, &osis_keys::SecretsWrite { history, ..Default::default() }, true).unwrap();
    lp.peers[i].engine.commit_hostile(m).unwrap().unwrap()
}

/// Writer `i`'s box at (read, e) sealed to itself: valid (a box needs write).
fn plant_box(lp: &mut LocalPeer, i: usize, g: Tid, e: &Epoch, s: &Secret32) -> CommitId {
    let me = lp.peers[i].engine.me();
    let mut fake = osis_keys::ActorEpochs::default();
    fake.role_mut(Role::Read).set_secret(*e, s.clone());
    fake.role_mut(Role::Read).set_established(*e, osis_keys::Provenance::Fixed);
    let rcpt = osis_keys::Recipient { holder: me, role: Role::Read, keys: osis_keys::HolderKeys::KeyActor { kem: lp.peers[i].engine.identity().keys().kem.public().clone(), seed: None } };
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

// spec/crypto.md §4 (a `secrets.0` snapshot keys only epochs established at its writer, names
// aside), spec/commits.md §5 (covered by join). Invariant: a reader's history add or a writer's
// box at an epoch no valid rotation made never stops an admin compacting `secrets.0`, is never
// based anywhere (the snapshot carries it to nobody), and is lost nowhere (its commit stays
// beside the snapshot, uncovered); a node granted after and fed only by the compactor judges every
// `secrets.0` part and the current epochs as the compactor does and reads what came after.
// Randomized over which plants, their n, the rotations around them, the compactor, a `keys.0`
// snapshot, restarts, a second compaction and arrival order. Fails without the fix: the gate
// refused every compaction once the state keyed a planted epoch.
#[test]
fn planted_epoch_never_blocks_compaction_spec_crypto_4() {
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
        let mut pks = lp.packages(c).unwrap();
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

// spec/crypto.md §4, spec/commits.md §5: a grant boxing N at e reaching admin C before e's
// rotation commit R. C compacts: e is not verified there, so the grant's entries stay beside the
// snapshot, and nothing is lost at the nodes where e is current (N keeps its box and reads under
// e). Once R arrives, C's next snapshot carries them and covers the grant.
#[test]
fn unverified_genuine_entry_kept_beside_spec_crypto_4() {
    let (mut lp, g, tids) = granted(5, &[(3, Role::Admin)]);
    let before: BTreeSet<CommitId> = lp.packages(0).unwrap().into_iter().map(|p| p.id).collect();
    rotate_leaving_out(&mut lp, 0, g, &BTreeSet::from([Role::Read]), &[]);
    let e = newest_read(&lp, 0, g).unwrap();
    let rot: BTreeSet<CommitId> = lp.packages(0).unwrap().into_iter().map(|p| p.id).filter(|c| !before.contains(c)).collect();
    lp.peers[0].engine.grant(&g, &tids[4], &edge(Role::Read)).unwrap();
    let gr: Vec<CommitId> = lp.packages(0).unwrap().into_iter().map(|p| p.id).filter(|c| !before.contains(c) && !rot.contains(c)).collect();
    put_on(&mut lp, 0, g, "w", 1);
    for pk in lp.packages(0).unwrap().into_iter().filter(|p| !rot.contains(&p.id)) {
        let _ = lp.peers[3].receive(&pk.bytes, pk.blobs.clone());
    }
    assert!(!based(&lp, 3, g, &e), "e verified at C without its rotation commit");
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
    let before: BTreeSet<CommitId> = lp.packages(0).unwrap().into_iter().map(|p| p.id).collect();
    rotate_leaving_out(&mut lp, 0, g, &BTreeSet::from([Role::Read]), &[]);
    let e = newest_read(&lp, 0, g).unwrap();
    let rot: BTreeSet<CommitId> = lp.packages(0).unwrap().into_iter().map(|p| p.id).filter(|c| !before.contains(c)).collect();
    lp.peers[0].engine.grant(&g, &tids[4], &edge(Role::Write)).unwrap();
    let gr: Vec<CommitId> = lp.packages(0).unwrap().into_iter().map(|p| p.id).filter(|c| !before.contains(c) && !rot.contains(c)).collect();
    for pk in lp.packages(0).unwrap().into_iter().filter(|p| !rot.contains(&p.id)) {
        let _ = lp.peers[3].receive(&pk.bytes, pk.blobs.clone());
    }
    assert!(!based(&lp, 3, g, &e), "e verified at C without its rotation commit");
    let s = lp.peers[3].engine.snapshot(&g, &secrets_ak()).unwrap().unwrap();
    let boxes = |lp: &mut LocalPeer, p: usize| lp.peers[p].engine.get_typed(&g, &ct::SECRETS).unwrap().unwrap().boxes;
    assert!(boxes(&mut lp, 3).keys().any(|k| k.holder == tids[4] && k.role == Role::Write), "C lacks N's write box");
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
