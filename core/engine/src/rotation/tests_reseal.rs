//! Content another wrote, encrypted again (spec/crypto.md §5 Passing on; `labeling::opened`).
//! Peers: 0 = A (first admin), 1 = a2 (admin), 2 = M (reader), 3 = R (admin), 4 = V (admin).
//! a2 removes M (W, with its rotation); R, holding W, rotates read (e_R, naming W, boxing V and
//! not M) and writes "w" under e_R. What M observes: whether it reads "w".

#![allow(clippy::unwrap_used)]
use super::tests::{commit_ids, edge, granted, newest_read, rotate_leaving_out, send_skipping};
use crate::Mutation;
use crate::flows::Demotion;
use crate::local_peer::{LocalPeer, SealedPackage};
use crate::sync::HeldBlob;
use osis_base::{Ak, BlobId, CommitId, Role, SyncId, Tid, Value};
use osis_crdt::{Op, PathOp, PathSeg};
use std::collections::BTreeSet;

const A: usize = 0;
const A2: usize = 1;
const M: usize = 2;
const R: usize = 3;
const V: usize = 4;

fn x() -> Ak {
    Ak::new("x:m.0").unwrap()
}

/// Peer `i` puts `k` on `g`'s `x:m.0`: the commit.
fn put(lp: &mut LocalPeer, i: usize, g: Tid, k: &str) -> CommitId {
    lp.advance(7);
    let mut m = Mutation::new();
    m.op(g, &x(), PathOp { path: vec![PathSeg::Key(Value::Str(k.into()))], op: Op::Put(Value::Int(1)) }).unwrap();
    lp.peers[i].commit(m).unwrap().unwrap()
}

/// Whether peer `i` reads key `k` on `g`'s `x:m.0`.
fn reads(lp: &mut LocalPeer, i: usize, g: Tid, k: &str) -> bool {
    matches!(lp.peers[i].engine.get(&g, &x()).unwrap(), Some(Value::Map(m)) if m.contains_key(&Value::Str(k.into())))
}

/// The shape above, `demoted`: A first demotes a2 to write (D), which only A holds, so W
/// applies nowhere D is held. Returns the peers, g, W's commits, e_R, w and R's sealed entry
/// of w (the encryption it logs).
fn shape(demoted: bool) -> (LocalPeer, Tid, BTreeSet<CommitId>, osis_crypto::Epoch, CommitId, Vec<SealedPackage>) {
    let (mut lp, g, tids) = granted(5, &[(A2, Role::Admin), (M, Role::Read), (R, Role::Admin), (V, Role::Admin)]);
    if demoted {
        lp.peers[A].engine.demote(&g, &Demotion { holder: tids[A2], new: Some(edge(Role::Write)), retain: None }).unwrap();
    }
    lp.peers[A2].clock.advance(5_000);
    let before = commit_ids(&mut lp, A2);
    lp.peers[A2].engine.demote(&g, &Demotion { holder: tids[M], new: None, retain: None }).unwrap();
    let w_commits: BTreeSet<CommitId> = commit_ids(&mut lp, A2).difference(&before).copied().collect();
    lp.sync(A2, R).unwrap();
    lp.peers[R].clock.advance(10_000);
    rotate_leaving_out(&mut lp, R, g, &BTreeSet::from([Role::Read]), &[]);
    let e_r = newest_read(&lp, R, g).unwrap();
    let w = put(&mut lp, R, g, "w");
    let entry = lp.sealed(R, &[w]).unwrap();
    assert!(!entry.is_empty(), "R seals its write");
    (lp, g, w_commits, e_r, w, entry)
}

/// V's fresh encryption of `w` (as node-sync places a body with no encryption of it held, or
/// logs it again) delivered to M: whether V sealed anything and whether M reads "w".
fn v_reseals_to_m(lp: &mut LocalPeer, g: Tid, w: CommitId) -> (bool, bool) {
    let pks = lp.sealed(V, &[w]).unwrap();
    let sealed = pks.iter().any(|p| p.id == w);
    lp.deliver_sealed(M, &pks).unwrap();
    (sealed, reads(lp, M, g, "w"))
}

// spec/requirements.md Permissions (removing a holder never re-encrypts existing content; it
// stops reading new content once a writer has written after the removal), spec/crypto.md §5
// (Passing on): V holds e_R's secret by its box but not W (a host withholds it), so e_R is not
// established there. Its fresh encryption of R's write, opened from R's entry, does not go
// under V's own epoch (which M holds); once W arrives V seals it again, and M reads it never.
#[test]
fn reseal_without_the_removal_leaks_nothing_spec_crypto_5() {
    let (mut lp, g, w_commits, e_r, w, entry) = shape(false);
    send_skipping(&mut lp, R, V, &w_commits.iter().copied().chain([w]).collect());
    lp.deliver_sealed(V, &entry).unwrap();
    assert!(reads(&mut lp, V, g, "w"), "V reads w by e_R's box");
    let at_v = lp.peers[V].engine.epochs(&g).unwrap();
    assert!(at_v.read.secret(&e_r).is_some() && !at_v.read.is_established(&e_r), "e_R held, not established at V");
    let (sealed, leak) = v_reseals_to_m(&mut lp, g, w);
    assert!(!leak, "M reads R's write through V's fresh encryption");
    assert!(!sealed, "V seals w with e_R not established");
    // given R's entry's sections (a fresh encryption logged again), V copies them verbatim:
    // a new blob, R's section under e_R, which M does not open
    let e = &entry.iter().find(|p| p.id == w).unwrap().entries[0];
    let v = &mut lp.peers[V].engine;
    let key = e.wraps.iter().find_map(|(a, wr)| osis_label::unwrap_any(v.read_secrets(a).iter(), &e.id, wr).map(|x| x.1)).unwrap();
    let sections = v.open_commit(&e.blob, &key).unwrap().sections;
    let body = v.body(&w).unwrap().unwrap();
    let again = v.seal(&body, osis_label::Class::Durable, &sections, &mut osis_crypto::SeededRng::from_u64(5)).unwrap().expect("sealed from R's sections");
    assert_ne!(again.id, e.id, "a fresh blob");
    assert!(lp.peers[V].engine.open_commit(&again.blob, &again.key).unwrap().sealed.is_empty(), "V opens it");
    assert!(lp.peers[M].engine.open_commit(&again.blob, &again.key).unwrap().commit.parts.is_empty(), "M opens nothing of it");
    // W arrives: e_R established, V seals the write again, and M still reads nothing of it
    for pk in lp.packages(A2).unwrap().into_iter().filter(|p| w_commits.contains(&p.id)) {
        let _ = lp.deliver(V, &pk);
    }
    assert!(lp.peers[V].engine.epochs(&g).unwrap().read.is_established(&e_r));
    let (sealed, leak) = v_reseals_to_m(&mut lp, g, w);
    assert!(sealed, "V seals w once e_R is established");
    assert!(!leak, "M reads R's write once V holds W");
}

// spec/crypto.md §5 (Passing on), spec/sync-compaction.md §1: V's snapshot of the aspect holding
// R's write is V's own commit, under V's epoch: it waits while e_R is not established at V.
#[test]
fn snapshot_without_the_removal_leaks_nothing_spec_crypto_5() {
    let (mut lp, g, w_commits, _, w, entry) = shape(false);
    send_skipping(&mut lp, R, V, &w_commits.iter().copied().chain([w]).collect());
    lp.deliver_sealed(V, &entry).unwrap();
    let s = lp.peers[V].engine.snapshot(&g, &x());
    assert!(s.is_err(), "V snapshots R's write under its own epoch: {s:?}");
    // W arrives: V compacts, and M reads nothing of w through it
    for pk in lp.packages(A2).unwrap().into_iter().filter(|p| w_commits.contains(&p.id)) {
        let _ = lp.deliver(V, &pk);
    }
    let s = lp.peers[V].engine.snapshot(&g, &x()).unwrap().unwrap();
    let pks = lp.sealed(V, &[s]).unwrap();
    lp.deliver_sealed(M, &pks).unwrap();
    assert!(!reads(&mut lp, M, g, "w"));
}

// spec/requirements.md Permissions (Limit: a removal voided by its author's concurrent demotion),
// spec/crypto.md §5 (Passing on): A demoted a2 (D) before W, so wherever D is held W applies
// nothing and M reads on; e_R's names are met nowhere D is. V, holding D and e_R's box, reads R's
// write but neither seals it nor snapshots it under its own epoch, which M holds: in a world where
// an unseen re-grant of a2 makes W apply, M was removed. Also when V had established e_R and
// opened the write before D arrived (establishment is judged when V encrypts, not when it read).
#[test]
fn withdrawn_epoch_content_never_resealed_spec_crypto_5() {
    for d_first in [true, false] {
        let (mut lp, g, _, e_r, w, entry) = shape(true);
        let not_w = BTreeSet::from([w]);
        if d_first {
            lp.sync(A, V).unwrap();
            send_skipping(&mut lp, R, V, &not_w);
        } else {
            send_skipping(&mut lp, R, V, &not_w);
            assert!(lp.peers[V].engine.epochs(&g).unwrap().read.is_established(&e_r), "e_R established at V before D");
        }
        lp.deliver_sealed(V, &entry).unwrap();
        if !d_first {
            lp.sync(A, V).unwrap();
        }
        assert!(lp.peers[V].engine.core.role_now(&lp.peers[M].engine.me(), &g).is_some(), "M reads on at V");
        assert!(!lp.peers[V].engine.epochs(&g).unwrap().read.is_established(&e_r), "e_R unmet at V");
        assert!(reads(&mut lp, V, g, "w"), "V reads w by e_R's box");
        let (_, leak) = v_reseals_to_m(&mut lp, g, w);
        assert!(!leak, "d_first {d_first}: M reads R's write through V's fresh encryption");
        assert!(lp.peers[V].engine.snapshot(&g, &x()).is_err(), "d_first {d_first}: V snapshots R's write");
    }
}

/// M's forgery of a blob of commit `w`: its header, one section under M's newest read secret of
/// `g` (an epoch V holds established) carrying the delta of commit `junk` in place of w's.
fn forged(lp: &mut LocalPeer, g: Tid, w: CommitId, junk: CommitId) -> crate::labeling::Sealed {
    let c = osis_commit::CommitBlob::decode(&lp.peers[R].engine.commit_bytes(&w).unwrap().unwrap()).unwrap();
    let j = osis_commit::CommitBlob::decode(&lp.peers[A].engine.commit_bytes(&junk).unwrap().unwrap()).unwrap();
    let ai = c.header.aspect_index(&g, "x:m.0").unwrap();
    let part = osis_commit::Part { ai, delta: j.parts.iter().find(|p| j.header.aspects[p.ai].ak.as_str() == "x:m.0").unwrap().delta.clone() };
    let secret = lp.peers[M].engine.epochs(&g).unwrap().read.newest_held().unwrap().1.clone();
    let mut rng = osis_crypto::SeededRng::from_u64(3);
    let sec = osis_commit::Section::seal(&w, &[part], Vec::new(), &secret, &mut rng).unwrap();
    let env = osis_commit::Envelope { header: c.header.clone(), sigs: c.sigs.clone(), sections: vec![sec] };
    crate::labeling::frame_envelope(&env, &c.header, osis_label::Class::Durable, &mut rng, &c).unwrap()
}

// spec/crypto.md §5 (Passing on: a section counts only for the delta it carried): M, holding an
// epoch V holds established, forges a blob of R's write whose section opens under it at V, before
// R's entry reaches V. The opening carries no genuine delta of the write, so V still never seals
// it under its own epoch.
#[test]
fn forged_section_unlocks_no_reseal_spec_crypto_5() {
    let (mut lp, g, w_commits, _, w, entry) = shape(false);
    let junk = put(&mut lp, A, g, "junk");
    send_skipping(&mut lp, R, V, &w_commits.iter().copied().chain([w]).collect());
    let f = forged(&mut lp, g, w, junk);
    let o = lp.peers[V].engine.open_commit(&f.blob, &f.key).unwrap();
    assert!(!o.commit.parts.is_empty(), "the forged section opens at V");
    lp.deliver_sealed(V, &entry).unwrap();
    assert!(reads(&mut lp, V, g, "w"));
    let (sealed, leak) = v_reseals_to_m(&mut lp, g, w);
    assert!(!leak, "M reads R's write through V's fresh encryption");
    assert!(!sealed);
    assert!(lp.peers[V].engine.snapshot(&g, &x()).is_err(), "V snapshots R's write");
}

// spec/crypto.md §5 (Passing on), randomized: the shape with or without D, W reaching V or
// not, V reading R's write from R's entry before or after D and W, M
// forging a section or not, V sealing the write and snapshotting its aspect at random points.
// The invariant (`labeling::opened`): M never reads "w", which R wrote knowing W under e_R,
// which M never held; and once V holds W without D, V seals the write.
#[test]
fn reseal_never_hands_m_the_write_randomized_spec_crypto_5() {
    let mut live = 0;
    for seed in 0..8u64 {
        let mut s = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
        let mut coin = || {
            s ^= s << 13;
            s ^= s >> 7;
            s ^= s << 17;
            s & 1 == 1
        };
        let demoted = coin();
        let (mut lp, g, w_commits, e_r, w, entry) = shape(demoted);
        let junk = put(&mut lp, A, g, "junk");
        let send_w = |lp: &mut LocalPeer| {
            for pk in lp.packages(A2).unwrap().into_iter().filter(|p| w_commits.contains(&p.id)) {
                let _ = lp.deliver(V, &pk);
            }
        };
        let w_first = coin();
        if w_first {
            send_w(&mut lp);
        }
        let d_first = demoted && coin();
        if d_first {
            lp.sync(A, V).unwrap();
        }
        send_skipping(&mut lp, R, V, &w_commits.iter().copied().chain([w]).collect());
        let entry_late = coin();
        if !entry_late {
            lp.deliver_sealed(V, &entry).unwrap();
        }
        if coin() {
            let f = forged(&mut lp, g, w, junk);
            let _ = lp.peers[V].engine.open_commit(&f.blob, &f.key);
        }
        let mut tries = Vec::new();
        for step in 0..3 {
            if coin() {
                let (sealed, leak) = v_reseals_to_m(&mut lp, g, w);
                tries.push((step, sealed));
                assert!(!leak, "seed {seed} step {step}: M reads w through V's fresh encryption");
            }
            if coin()
                && let Ok(Some(c)) = lp.peers[V].engine.snapshot(&g, &x())
            {
                let pks = lp.sealed(V, &[c]).unwrap();
                lp.deliver_sealed(M, &pks).unwrap();
                assert!(!reads(&mut lp, M, g, "w"), "seed {seed} step {step}: M reads w through V's snapshot");
            }
            if step == 0 && !w_first && coin() {
                send_w(&mut lp);
            }
            if step == 0 && entry_late {
                lp.deliver_sealed(V, &entry).unwrap();
            }
            if step == 1 && demoted && !d_first {
                lp.sync(A, V).unwrap();
            }
        }
        // the live side: V holding W and no D, R's write read from its entry
        let est = lp.peers[V].engine.epochs(&g).unwrap().read.is_established(&e_r);
        if est {
            live += 1;
            let (sealed, leak) = v_reseals_to_m(&mut lp, g, w);
            assert!(sealed && !leak, "seed {seed}: V holds W, e_R established, sealed {sealed}; tries {tries:?}");
        }
    }
    assert!(live > 0, "no world reached e_R established at V");
}

/// Whether M opens a blob V made of `w` (`sealed`, as a label entry: its header, and a copy's
/// content), wrapped for `g` under what `Engine::wrap_secret` gives V, if anything.
fn m_opens(lp: &mut LocalPeer, g: Tid, w: CommitId, sealed: &crate::labeling::Sealed, parts: &[usize]) -> bool {
    let Some(s) = lp.peers[V].engine.wrap_secret(&g, Some((&w, parts))).unwrap() else { return false };
    let wrap = osis_crypto::wrap(&s, &sealed.id, &sealed.key, 1).unwrap();
    let m = &mut lp.peers[M].engine;
    let Some(key) = osis_label::unwrap_any(m.read_secrets(&g).iter(), &sealed.id, &wrap).map(|x| x.1) else { return false };
    m.open_commit(&sealed.blob, &key).is_ok()
}

// spec/crypto.md §5 (Passing on: wraps too): V, lacking W, makes a fresh encryption of R's write
// from R's own section (verbatim) and a per-label copy of it. The wrap gates the header (and all
// of a copy): V wraps neither under its epoch, so M opens neither, not even the header.
#[test]
fn wrap_of_others_write_withheld_spec_crypto_5() {
    let (mut lp, g, w_commits, _, w, entry) = shape(false);
    send_skipping(&mut lp, R, V, &w_commits.iter().copied().chain([w]).collect());
    lp.deliver_sealed(V, &entry).unwrap();
    let e = &entry.iter().find(|p| p.id == w).unwrap().entries[0];
    let v = &mut lp.peers[V].engine;
    let key = e.wraps.iter().find_map(|(a, wr)| osis_label::unwrap_any(v.read_secrets(a).iter(), &e.id, wr).map(|x| x.1)).unwrap();
    let sections = v.open_commit(&e.blob, &key).unwrap().sections;
    let body = v.body(&w).unwrap().unwrap();
    let mut rng = osis_crypto::SeededRng::from_u64(9);
    let fresh = v.seal(&body, osis_label::Class::Durable, &sections, &mut rng).unwrap().unwrap();
    let copy = v.seal_to(&body, osis_label::Class::Durable, &mut rng).unwrap().unwrap();
    assert!(!m_opens(&mut lp, g, w, &fresh, &body.parts), "M opens the header of V's fresh encryption");
    assert!(!m_opens(&mut lp, g, w, &copy, &body.parts), "M opens V's copy");
    // W arrives: V wraps both, and M still opens neither (V's epoch is e_R now)
    for pk in lp.packages(A2).unwrap().into_iter().filter(|p| w_commits.contains(&p.id)) {
        let _ = lp.deliver(V, &pk);
    }
    assert!(lp.peers[V].engine.wrap_secret(&g, Some((&w, &body.parts))).unwrap().is_some(), "V wraps once e_R is established");
    assert!(!m_opens(&mut lp, g, w, &fresh, &body.parts) && !m_opens(&mut lp, g, w, &copy, &body.parts));
}

// spec/crypto.md §5 (Passing on): R's write reaches V first in no section (the plaintext
// `ingest`, as an inbox payload carries a commit), then V opens R's entry of it under e_R, not
// established at V. The opening of a commit already held counts: V neither seals the write
// under its own (M's) epoch nor wraps a copy of it so. Once W arrives it does, also after a
// restart (the openings were written with the entry's ingest).
#[test]
fn opened_after_plain_arrival_counts_spec_crypto_5() {
    let (mut lp, g, w_commits, e_r, w, entry) = shape(false);
    send_skipping(&mut lp, R, V, &w_commits);
    assert!(reads(&mut lp, V, g, "w"), "V holds w, read in no section");
    lp.deliver_sealed(V, &entry).unwrap();
    assert!(!lp.peers[V].engine.epochs(&g).unwrap().read.is_established(&e_r));
    let body = lp.peers[V].engine.body(&w).unwrap().unwrap();
    let copy = lp.peers[V].engine.seal_to(&body, osis_label::Class::Durable, &mut osis_crypto::SeededRng::from_u64(4)).unwrap().unwrap();
    assert!(!m_opens(&mut lp, g, w, &copy, &body.parts), "M opens V's copy of w");
    let (sealed, leak) = v_reseals_to_m(&mut lp, g, w);
    assert!(!leak, "M reads R's write through V's fresh encryption");
    assert!(!sealed, "V seals w it opened only under e_R, not established");
    for pk in lp.packages(A2).unwrap().into_iter().filter(|p| w_commits.contains(&p.id)) {
        let _ = lp.deliver(V, &pk);
    }
    assert!(lp.peers[V].engine.epochs(&g).unwrap().read.is_established(&e_r));
    lp.peers[V].restart(11).unwrap();
    let (sealed, leak) = v_reseals_to_m(&mut lp, g, w);
    assert!(sealed && !leak, "V seals w once it opened it under e_R, established: sealed {sealed}");
}

// spec/crypto.md §5 (Passing on: the wrap gates the header): V opened R's write only under e_R,
// not established at V. A blob of it carrying no part (a header-only blob, a lasting header)
// is wrapped under no epoch of V's choosing either, so M opens not even its header.
#[test]
fn header_only_wrap_withheld_spec_crypto_5() {
    let (mut lp, g, w_commits, _, w, entry) = shape(false);
    send_skipping(&mut lp, R, V, &w_commits.iter().copied().chain([w]).collect());
    lp.deliver_sealed(V, &entry).unwrap();
    let body = lp.peers[V].engine.body(&w).unwrap().unwrap();
    let copy = lp.peers[V].engine.seal_to(&body, osis_label::Class::Durable, &mut osis_crypto::SeededRng::from_u64(4)).unwrap().unwrap();
    assert!(!m_opens(&mut lp, g, w, &copy, &[]), "M opens a blob of w V wrapped as carrying no part");
    for pk in lp.packages(A2).unwrap().into_iter().filter(|p| w_commits.contains(&p.id)) {
        let _ = lp.deliver(V, &pk);
    }
    assert!(lp.peers[V].engine.wrap_secret(&g, Some((&w, &[]))).unwrap().is_some(), "V wraps w's header once e_R is established");
}

// spec/crypto.md §5 (Passing on): R's write w2, stamped past V's drift window, opened by V from
// R's entry under e_R (not established at V) waits pending; V restarts before it applies. Its
// openings were written with the pending copy, so once it applies V still seals it under no
// epoch of its own choosing.
#[test]
fn openings_of_a_pending_write_survive_a_restart_spec_crypto_5() {
    let (mut lp, g, w_commits, e_r, w, _) = shape(false);
    send_skipping(&mut lp, R, V, &w_commits.iter().copied().chain([w]).collect());
    lp.peers[R].clock.advance(2 * osis_base::format::MAX_DRIFT_MS);
    let w2 = put(&mut lp, R, g, "w2");
    let entry = lp.sealed(R, &[w2]).unwrap();
    lp.deliver_sealed(V, &entry).unwrap();
    assert!(lp.peers[V].engine.core.ix.pending.contains_key(&w2), "w2 waits for V's clock");
    lp.peers[V].restart(13).unwrap();
    lp.peers[V].clock.advance(2 * osis_base::format::MAX_DRIFT_MS);
    lp.peers[V].tick().unwrap();
    assert!(reads(&mut lp, V, g, "w2"), "w2 applies at V");
    assert!(!lp.peers[V].engine.epochs(&g).unwrap().read.is_established(&e_r));
    let pks = lp.sealed(V, &[w2]).unwrap();
    assert!(!pks.iter().any(|p| p.id == w2), "V seals w2 it opened only under e_R");
    lp.deliver_sealed(M, &pks).unwrap();
    assert!(!reads(&mut lp, M, g, "w2"), "M reads R's write through V's fresh encryption");
}

// The sync facade's paths (`Engine::seal_body`, `rewrap`, `open_entry`): every fresh encryption
// and wrap of a body goes through `Engine::seal` and `wrap_secret`.

/// g's home sync ID and R's entry of `w` (`entry`) under it, as the sync store holds it.
fn r_held(lp: &mut LocalPeer, g: Tid, w: CommitId, entry: &[SealedPackage]) -> (SyncId, HeldBlob) {
    let s = lp.peers[V].engine.home_sync_id(&g).unwrap().unwrap();
    let e = &entry.iter().find(|p| p.id == w).unwrap().entries[0];
    let wrap = e.wraps.iter().find(|(a, _)| *a == g).unwrap().1;
    (s, HeldBlob { sync_id: s, wrap, bytes: e.blob.clone() })
}

/// V takes R's entry through the facade (`open_entry`, as sync takes an entry it pulled).
fn v_takes(lp: &mut LocalPeer, s: &SyncId, w: CommitId, h: &HeldBlob) {
    let id = osis_label::blob_id(&h.bytes);
    let o = lp.peers[V].engine.open_entry(s, &id, &h.wrap, &h.bytes).unwrap();
    assert!(matches!(o, crate::sync::Opened::Commit(c, _) if c == w), "V opens R's entry: {o:?}");
}

/// Whether M opens an entry V logs under g's sync ID (blob `id`, `bytes`, `wrap`): the wrap
/// under a read secret M holds (it reads the header), and whether a part of it opens too.
fn m_opens_entry(lp: &mut LocalPeer, g: Tid, w: CommitId, id: &BlobId, bytes: &[u8], wrap: &crate::sync::Wrap) -> (bool, bool) {
    let m = &mut lp.peers[M].engine;
    let Some((_, key)) = osis_label::unwrap_any(m.read_secrets(&g).iter(), id, wrap) else { return (false, false) };
    let content = m.open_commit(bytes, &key).is_ok_and(|o| !o.commit.parts.is_empty());
    m.openings_done(&w);
    (true, content)
}

/// W reaches V: e_R is established there.
fn w_arrives(lp: &mut LocalPeer, g: Tid, w_commits: &BTreeSet<CommitId>, e_r: &osis_crypto::Epoch) {
    for pk in lp.packages(A2).unwrap().into_iter().filter(|p| w_commits.contains(&p.id)) {
        let _ = lp.deliver(V, &pk);
    }
    assert!(lp.peers[V].engine.epochs(&g).unwrap().read.is_established(e_r));
}

// spec/crypto.md §5 (Passing on), spec/sync-judgement.md §1, §4 (a fresh encryption: logging
// again, a deposit, a body with no held encryption): V takes R's entry of w through the facade,
// lacking W. Its fresh encryption of w (`seal_body`, with R's entry as the held blob or with none)
// is refused, so nothing of w goes under V's newest current epoch, which M holds. Once W arrives
// V seals it, and M still opens nothing of it.
#[test]
fn facade_fresh_encryption_withheld_without_the_removal_spec_crypto_5() {
    let (mut lp, g, w_commits, e_r, w, entry) = shape(false);
    send_skipping(&mut lp, R, V, &w_commits.iter().copied().chain([w]).collect());
    let (s, held) = r_held(&mut lp, g, w, &entry);
    v_takes(&mut lp, &s, w, &held);
    assert!(reads(&mut lp, V, g, "w"));
    assert!(!lp.peers[V].engine.epochs(&g).unwrap().read.is_established(&e_r));
    let mut rng = osis_crypto::SeededRng::from_u64(21);
    for given in [Vec::new(), vec![held.clone()]] {
        if let Some((sealed, wrap)) = lp.peers[V].engine.seal_body(&s, &w, &given, &mut rng).unwrap() {
            let (header, content) = m_opens_entry(&mut lp, g, w, &sealed.id, &sealed.blob, &wrap);
            panic!("V sealed w lacking W (held blobs given: {}): M opens its header {header}, content {content}", given.len());
        }
    }
    w_arrives(&mut lp, g, &w_commits, &e_r);
    let (sealed, wrap) = lp.peers[V].engine.seal_body(&s, &w, &[held], &mut rng).unwrap().expect("V seals w once e_R is established");
    assert_eq!(m_opens_entry(&mut lp, g, w, &sealed.id, &sealed.blob, &wrap), (false, false), "M opens V's fresh encryption of w");
}

// spec/crypto.md §5 (Passing on: the wrap of a blob carrying the part), spec/sync-judgement.md
// §3 (Own store: a held blob verbatim under a wrap for S): V, lacking W, wraps R's held entry of
// w for no sync ID (`rewrap`); once W arrives it does, under an epoch M lacks.
#[test]
fn facade_verbatim_wrap_withheld_without_the_removal_spec_crypto_5() {
    let (mut lp, g, w_commits, e_r, w, entry) = shape(false);
    send_skipping(&mut lp, R, V, &w_commits.iter().copied().chain([w]).collect());
    let (s, held) = r_held(&mut lp, g, w, &entry);
    v_takes(&mut lp, &s, w, &held);
    let id = osis_label::blob_id(&held.bytes);
    if let Some(wrap) = lp.peers[V].engine.rewrap(&w, &id, &s, &held.wrap, &s).unwrap() {
        let (header, content) = m_opens_entry(&mut lp, g, w, &id, &held.bytes, &wrap);
        panic!("V wrapped R's entry lacking W: M opens its header {header}, content {content}");
    }
    w_arrives(&mut lp, g, &w_commits, &e_r);
    let wrap = lp.peers[V].engine.rewrap(&w, &id, &s, &held.wrap, &s).unwrap().expect("V wraps R's entry once e_R is established");
    assert_eq!(m_opens_entry(&mut lp, g, w, &id, &held.bytes, &wrap), (false, false));
}

// spec/crypto.md §5 (Passing on: the wrap gates the header): R logs a header-only blob of w
// (a lasting header) under e_R; V, lacking W, takes it through the facade and never opens a
// section of w. The epoch its wrap opened under counts as an opening of the header
// (`note_unwrapped`), so V wraps the header for no sync ID, under no epoch of its choosing,
// until W arrives; then M still opens nothing.
#[test]
fn facade_header_only_wrap_withheld_without_the_removal_spec_crypto_5() {
    let (mut lp, g, w_commits, e_r, w, _) = shape(false);
    send_skipping(&mut lp, R, V, &w_commits.iter().copied().chain([w]).collect());
    let r = &mut lp.peers[R].engine;
    let mut body = r.body(&w).unwrap().unwrap();
    body.parts.clear();
    let hdr = r.seal_to(&body, osis_label::Class::Durable, &mut osis_crypto::SeededRng::from_u64(22)).unwrap().unwrap();
    let k = r.wrap_secret(&g, Some((&w, &[]))).unwrap().expect("R wraps its own");
    let held = HeldBlob { sync_id: lp.peers[V].engine.home_sync_id(&g).unwrap().unwrap(), wrap: osis_crypto::wrap(&k, &hdr.id, &hdr.key, 1).unwrap(), bytes: hdr.blob.clone() };
    let s = held.sync_id;
    v_takes(&mut lp, &s, w, &held);
    assert!(!reads(&mut lp, V, g, "w"), "V holds w's header alone");
    assert!(lp.peers[V].engine.wrap_secret(&g, Some((&w, &[]))).unwrap().is_none(), "V wraps w's header lacking W");
    if let Some(wrap) = lp.peers[V].engine.rewrap(&w, &hdr.id, &s, &held.wrap, &s).unwrap() {
        let (header, _) = m_opens_entry(&mut lp, g, w, &hdr.id, &hdr.blob, &wrap);
        panic!("V wrapped w's header-only blob lacking W: M opens it {header}");
    }
    // after a restart too: the opening was written with the blob's ingest
    lp.peers[V].restart(23).unwrap();
    assert!(lp.peers[V].engine.wrap_secret(&g, Some((&w, &[]))).unwrap().is_none(), "the header opening lasts a restart");
    w_arrives(&mut lp, g, &w_commits, &e_r);
    let wrap = lp.peers[V].engine.rewrap(&w, &hdr.id, &s, &held.wrap, &s).unwrap().expect("V wraps the header once e_R is established");
    assert_eq!(m_opens_entry(&mut lp, g, w, &hdr.id, &hdr.blob, &wrap), (false, false));
}

// spec/crypto.md §5 (Passing on: the wrap gates the header, and all of a copy): R logs w as a
// per-sync-ID copy (one section under its blob key) wrapped under e_R; V, lacking W, reads w's
// content from it in no section of a read epoch. The copy's wrap epoch is an opening of the
// header, so V's fresh encryption of w is wrapped for no sync ID until W arrives.
#[test]
fn facade_copy_read_content_withheld_without_the_removal_spec_crypto_5() {
    let (mut lp, g, w_commits, e_r, w, _) = shape(false);
    send_skipping(&mut lp, R, V, &w_commits.iter().copied().chain([w]).collect());
    let r = &mut lp.peers[R].engine;
    let body = r.body(&w).unwrap().unwrap();
    let copy = r.seal_to(&body, osis_label::Class::Durable, &mut osis_crypto::SeededRng::from_u64(24)).unwrap().unwrap();
    let k = r.wrap_secret(&g, Some((&w, &body.parts))).unwrap().expect("R wraps its own");
    let held = HeldBlob { sync_id: lp.peers[V].engine.home_sync_id(&g).unwrap().unwrap(), wrap: osis_crypto::wrap(&k, &copy.id, &copy.key, 1).unwrap(), bytes: copy.blob.clone() };
    let s = held.sync_id;
    v_takes(&mut lp, &s, w, &held);
    assert!(reads(&mut lp, V, g, "w"), "V reads w from R's copy");
    let mut rng = osis_crypto::SeededRng::from_u64(25);
    if let Some((sealed, wrap)) = lp.peers[V].engine.seal_body(&s, &w, std::slice::from_ref(&held), &mut rng).unwrap() {
        let (header, content) = m_opens_entry(&mut lp, g, w, &sealed.id, &sealed.blob, &wrap);
        panic!("V sealed w read from a copy lacking W: M opens its header {header}, content {content}");
    }
    w_arrives(&mut lp, g, &w_commits, &e_r);
    let (sealed, wrap) = lp.peers[V].engine.seal_body(&s, &w, &[held], &mut rng).unwrap().expect("V seals w once e_R is established");
    assert_eq!(m_opens_entry(&mut lp, g, w, &sealed.id, &sealed.blob, &wrap), (false, false));
}

// spec/crypto.md §5 (Passing on: a copy's content came under its wrap's epoch alone): R's write
// w reaches V first as a per-sync-ID copy under h's sync ID (another thing R and V read, M does
// not, whose actor reads g), so V reads it in no section of g. That opening counts for no epoch of g: V neither seals
// w for g's sync ID nor snapshots it under its own epoch of g, which M holds; not even once W
// arrives. Once V opens R's entry of w under e_R, established, it does, and M reads nothing.
#[test]
fn cross_thing_copy_content_never_resealed_spec_crypto_5() {
    let (mut lp, g, w_commits, e_r, w, entry) = shape(false);
    let h = super::tests::group(&mut lp, R);
    let v_tid = lp.peers[V].engine.me();
    lp.peers[R].engine.grant(&h, &v_tid, &edge(Role::Admin)).unwrap();
    // h's actor reads g, so h's sync ID may carry w as a copy (spec/permissions.md §3: a copy of
    // content its group actor may not read is not taken)
    lp.peers[R].engine.grant(&g, &h, &edge(Role::Read)).unwrap();
    send_skipping(&mut lp, R, V, &w_commits.iter().copied().chain([w]).collect());
    let sh = lp.peers[V].engine.home_sync_id(&h).unwrap().expect("V syncs h");
    let r = &mut lp.peers[R].engine;
    let body = r.body(&w).unwrap().unwrap();
    let copy = r.seal_to(&body, osis_label::Class::Durable, &mut osis_crypto::SeededRng::from_u64(26)).unwrap().unwrap();
    let k = r.wrap_secret(&h, Some((&w, &body.parts))).unwrap().expect("R wraps its own");
    let copied = HeldBlob { sync_id: sh, wrap: osis_crypto::wrap(&k, &copy.id, &copy.key, 1).unwrap(), bytes: copy.blob.clone() };
    v_takes(&mut lp, &sh, w, &copied);
    assert!(reads(&mut lp, V, g, "w"), "V reads w from the copy");
    let s = lp.peers[V].engine.home_sync_id(&g).unwrap().unwrap();
    let mut rng = osis_crypto::SeededRng::from_u64(27);
    for arrived in [false, true] {
        if arrived {
            w_arrives(&mut lp, g, &w_commits, &e_r);
        }
        if let Some((sealed, wrap)) = lp.peers[V].engine.seal_body(&s, &w, std::slice::from_ref(&copied), &mut rng).unwrap() {
            let (header, content) = m_opens_entry(&mut lp, g, w, &sealed.id, &sealed.blob, &wrap);
            panic!("W arrived {arrived}: V sealed w read from h's copy: M opens its header {header}, content {content}");
        }
        assert!(lp.peers[V].engine.snapshot(&g, &x()).is_err(), "W arrived {arrived}: V snapshots w read from h's copy");
    }
    let (_, held) = r_held(&mut lp, g, w, &entry);
    v_takes(&mut lp, &s, w, &held);
    let (sealed, wrap) = lp.peers[V].engine.seal_body(&s, &w, &[copied, held], &mut rng).unwrap().expect("V seals w once it opened R's section under e_R, established");
    assert_eq!(m_opens_entry(&mut lp, g, w, &sealed.id, &sealed.blob, &wrap), (false, false));
    let c = lp.peers[V].engine.snapshot(&g, &x()).unwrap().unwrap();
    let pks = lp.sealed(V, &[c]).unwrap();
    lp.deliver_sealed(M, &pks).unwrap();
    assert!(!reads(&mut lp, M, g, "w"), "M reads w through V's snapshot");
}

// spec/crypto.md §5 (Passing on: a copy's content came under its wrap's epoch): V reads R's
// write w only from a copy under g's own sync ID wrapped under e_R, not established at V. V's
// snapshot of the aspect waits until W arrives; then M reads nothing of w through it.
#[test]
fn copy_read_content_not_snapshotted_without_the_removal_spec_crypto_5() {
    let (mut lp, g, w_commits, e_r, w, _) = shape(false);
    send_skipping(&mut lp, R, V, &w_commits.iter().copied().chain([w]).collect());
    let r = &mut lp.peers[R].engine;
    let body = r.body(&w).unwrap().unwrap();
    let copy = r.seal_to(&body, osis_label::Class::Durable, &mut osis_crypto::SeededRng::from_u64(28)).unwrap().unwrap();
    let k = r.wrap_secret(&g, Some((&w, &body.parts))).unwrap().expect("R wraps its own");
    let held = HeldBlob { sync_id: lp.peers[V].engine.home_sync_id(&g).unwrap().unwrap(), wrap: osis_crypto::wrap(&k, &copy.id, &copy.key, 1).unwrap(), bytes: copy.blob.clone() };
    let s = held.sync_id;
    v_takes(&mut lp, &s, w, &held);
    assert!(reads(&mut lp, V, g, "w"));
    assert!(lp.peers[V].engine.snapshot(&g, &x()).is_err(), "V snapshots w read from a copy under e_R, not established");
    w_arrives(&mut lp, g, &w_commits, &e_r);
    let c = lp.peers[V].engine.snapshot(&g, &x()).unwrap().unwrap();
    let pks = lp.sealed(V, &[c]).unwrap();
    lp.deliver_sealed(M, &pks).unwrap();
    assert!(!reads(&mut lp, M, g, "w"), "M reads w through V's snapshot");
}

// spec/crypto.md §5 (Passing on), spec/sync-judgement.md §1, §4: A, not knowing W, writes w0
// under e0 (an epoch M holds, established at V); V opened A's entry of it under e0 and holds
// e_R, not established. V's fresh encryption of w0 is made (A's section verbatim when given,
// else sealed: e0 is established at V), and M reads w0 through it as it read A's own entry.
#[test]
fn old_epoch_section_sealed_while_newest_unestablished_spec_crypto_5() {
    let (mut lp, g, w_commits, e_r, w, _) = shape(false);
    send_skipping(&mut lp, R, V, &w_commits.iter().copied().chain([w]).collect());
    assert!(!lp.peers[V].engine.epochs(&g).unwrap().read.is_established(&e_r));
    let w0 = put(&mut lp, A, g, "w0");
    let entry = lp.sealed(A, &[w0]).unwrap();
    let s = lp.peers[V].engine.home_sync_id(&g).unwrap().unwrap();
    let e = &entry.iter().find(|p| p.id == w0).unwrap().entries[0];
    let held = HeldBlob { sync_id: s, wrap: e.wraps.iter().find(|(a, _)| *a == g).unwrap().1, bytes: e.blob.clone() };
    v_takes(&mut lp, &s, w0, &held);
    assert_eq!(m_opens_entry(&mut lp, g, w0, &e.id, &e.blob, &held.wrap), (true, true), "M reads A's entry of w0");
    let mut rng = osis_crypto::SeededRng::from_u64(29);
    for given in [vec![held.clone()], Vec::new()] {
        let (sealed, wrap) = lp.peers[V].engine.seal_body(&s, &w0, &given, &mut rng).unwrap().expect("V seals w0, opened under e0, established");
        assert!(!lp.peers[V].engine.open_commit(&sealed.blob, &sealed.key).unwrap().commit.parts.is_empty(), "V opens its fresh encryption");
        let (_, content) = m_opens_entry(&mut lp, g, w0, &sealed.id, &sealed.blob, &wrap);
        assert!(content, "given {}: M reads V's encryption of w0 as it reads A's", given.len());
    }
}

// spec/crypto.md §5 (Passing on: an opening counts only under an epoch established here, and
// only for the delta it carried): M forges a copy of R's write w (its header, junk delta, one
// section under the blob key) wrapped under M's newest epoch of g, established at V. V takes it
// through the facade before R's entry: the forged copy's opening carries no genuine delta of w,
// so V still neither seals w for g's sync ID nor snapshots it under its own epoch.
#[test]
fn planted_copy_unlocks_no_reseal_spec_crypto_5() {
    let (mut lp, g, w_commits, _, w, entry) = shape(false);
    let junk = put(&mut lp, A, g, "junk");
    send_skipping(&mut lp, R, V, &w_commits.iter().copied().chain([w]).collect());
    let c = osis_commit::CommitBlob::decode(&lp.peers[R].engine.commit_bytes(&w).unwrap().unwrap()).unwrap();
    let j = osis_commit::CommitBlob::decode(&lp.peers[A].engine.commit_bytes(&junk).unwrap().unwrap()).unwrap();
    let ai = c.header.aspect_index(&g, "x:m.0").unwrap();
    let part = osis_commit::Part { ai, delta: j.parts.iter().find(|p| j.header.aspects[p.ai].ak.as_str() == "x:m.0").unwrap().delta.clone() };
    let mut rng = osis_crypto::SeededRng::from_u64(31);
    let key = osis_crypto::Secret32::random(&mut rng);
    let sec = osis_commit::Section::seal(&w, &[part], Vec::new(), &key, &mut rng).unwrap();
    let env = osis_commit::Envelope { header: c.header.clone(), sigs: c.sigs.clone(), sections: vec![sec] };
    let f = crate::labeling::frame_envelope(&env, &c.header, osis_label::Class::Durable, &mut rng, &c).unwrap();
    let mk = lp.peers[M].engine.epochs(&g).unwrap().read.newest_held().unwrap().1.clone();
    let s = lp.peers[V].engine.home_sync_id(&g).unwrap().unwrap();
    let planted = HeldBlob { sync_id: s, wrap: osis_crypto::wrap(&mk, &f.id, &f.key, 1).unwrap(), bytes: f.blob.clone() };
    let o = lp.peers[V].engine.open_entry(&s, &f.id, &planted.wrap, &planted.bytes).unwrap();
    assert!(matches!(o, crate::sync::Opened::Commit(c, _) if c == w) && !reads(&mut lp, V, g, "w"), "V takes the planted copy, its junk delta refused: {o:?}");
    let (_, held) = r_held(&mut lp, g, w, &entry);
    v_takes(&mut lp, &s, w, &held);
    assert!(reads(&mut lp, V, g, "w"));
    if let Some((sealed, wrap)) = lp.peers[V].engine.seal_body(&s, &w, &[planted, held], &mut rng).unwrap() {
        let (header, content) = m_opens_entry(&mut lp, g, w, &sealed.id, &sealed.blob, &wrap);
        panic!("V sealed w after a planted copy: M opens its header {header}, content {content}");
    }
    assert!(lp.peers[V].engine.snapshot(&g, &x()).is_err(), "V snapshots w after a planted copy");
}

// spec/crypto.md §5 (Passing on): R's write w2, stamped past V's drift window, reaches V as a
// copy wrapped under e_R (not established at V) and waits pending; V restarts before it applies.
// The copy's opening was written with the pending commit, so once w2 applies V still seals it
// under no epoch of its own choosing, nor snapshots it.
#[test]
fn copy_opening_of_a_pending_write_survives_a_restart_spec_crypto_5() {
    let (mut lp, g, w_commits, e_r, w, _) = shape(false);
    send_skipping(&mut lp, R, V, &w_commits.iter().copied().chain([w]).collect());
    lp.peers[R].clock.advance(2 * osis_base::format::MAX_DRIFT_MS);
    let w2 = put(&mut lp, R, g, "w2");
    let r = &mut lp.peers[R].engine;
    let body = r.body(&w2).unwrap().unwrap();
    let copy = r.seal_to(&body, osis_label::Class::Durable, &mut osis_crypto::SeededRng::from_u64(32)).unwrap().unwrap();
    let k = r.wrap_secret(&g, Some((&w2, &body.parts))).unwrap().expect("R wraps its own");
    let s = lp.peers[V].engine.home_sync_id(&g).unwrap().unwrap();
    let held = HeldBlob { sync_id: s, wrap: osis_crypto::wrap(&k, &copy.id, &copy.key, 1).unwrap(), bytes: copy.blob.clone() };
    let _ = lp.peers[V].engine.open_entry(&s, &copy.id, &held.wrap, &held.bytes).unwrap();
    assert!(lp.peers[V].engine.core.ix.pending.contains_key(&w2), "w2 waits for V's clock");
    lp.peers[V].restart(33).unwrap();
    lp.peers[V].clock.advance(2 * osis_base::format::MAX_DRIFT_MS);
    lp.peers[V].tick().unwrap();
    assert!(reads(&mut lp, V, g, "w2"), "w2 applies at V");
    assert!(!lp.peers[V].engine.epochs(&g).unwrap().read.is_established(&e_r));
    let mut rng = osis_crypto::SeededRng::from_u64(34);
    assert!(lp.peers[V].engine.seal_body(&s, &w2, std::slice::from_ref(&held), &mut rng).unwrap().is_none(), "V seals w2 read from a copy under e_R");
    assert!(lp.peers[V].engine.snapshot(&g, &x()).is_err(), "V snapshots w2 read from a copy under e_R");
}

// spec/crypto.md §4 (State at a cut: a part's floor is the greatest floor of an epoch it was
// opened under), §5 (Passing on): A writes w0, then grants N read without history (the cut).
// P (an admin, with history), holding the cut, reads w0 only from A's copy wrapped under e0: the
// copy's opening keeps e0's floor, so P's fresh encryption of w0, given the copy or A's own
// entry, goes under no epoch N opens, and N reads nothing of it.
#[test]
fn copy_read_below_a_cut_keeps_its_floor_spec_crypto_5() {
    let mut lp = super::tests::synced(3);
    let tids: Vec<Tid> = (0..3).map(|i| lp.peers[i].engine.me()).collect();
    let (a, p, n) = (0, 1, 2);
    let g = super::tests::group(&mut lp, a);
    lp.peers[a].engine.grant(&g, &tids[p], &edge(Role::Admin)).unwrap();
    lp.sync_all().unwrap();
    let w0 = put(&mut lp, a, g, "w0");
    let ra = &mut lp.peers[a].engine;
    let body = ra.body(&w0).unwrap().unwrap();
    let copy = ra.seal_to(&body, osis_label::Class::Durable, &mut osis_crypto::SeededRng::from_u64(35)).unwrap().unwrap();
    let k = ra.wrap_secret(&g, Some((&w0, &body.parts))).unwrap().expect("A wraps its own");
    let entry = lp.sealed(a, &[w0]).unwrap();
    let s = lp.peers[p].engine.home_sync_id(&g).unwrap().unwrap();
    let copied = HeldBlob { sync_id: s, wrap: osis_crypto::wrap(&k, &copy.id, &copy.key, 1).unwrap(), bytes: copy.blob.clone() };
    lp.peers[a].engine.grant_with(&g, &tids[n], &edge(Role::Read), crate::flows::edges::History::None).unwrap();
    send_skipping(&mut lp, a, p, &BTreeSet::from([w0]));
    send_skipping(&mut lp, a, n, &BTreeSet::from([w0]));
    // P takes the copy once it holds the cut: the opening is e0's, not P's newest epoch's
    assert!(matches!(lp.peers[p].engine.open_entry(&s, &copy.id, &copied.wrap, &copied.bytes).unwrap(), crate::sync::Opened::Commit(c, _) if c == w0));
    assert!(reads(&mut lp, p, g, "w0"), "P reads w0 from A's copy");
    let e = &entry.iter().find(|x| x.id == w0).unwrap().entries[0];
    let held = HeldBlob { sync_id: s, wrap: e.wraps.iter().find(|(t, _)| *t == g).unwrap().1, bytes: e.blob.clone() };
    let mut rng = osis_crypto::SeededRng::from_u64(36);
    for given in [vec![copied.clone()], vec![copied, held]] {
        let Some((sealed, wrap)) = lp.peers[p].engine.seal_body(&s, &w0, &given, &mut rng).unwrap() else { continue };
        let ne = &mut lp.peers[n].engine;
        let Some((_, key)) = osis_label::unwrap_any(ne.read_secrets(&g).iter(), &sealed.id, &wrap) else { continue };
        let content = ne.open_commit(&sealed.blob, &key).is_ok_and(|o| !o.commit.parts.is_empty());
        ne.openings_done(&w0);
        panic!("given {}: N opens P's fresh encryption of w0 from before its cut (content {content})", given.len());
    }
}

// spec/crypto.md §5 (Passing on), spec/sync-ids.md §1 (Repair): a repair writes the aspect's
// current value again under V's own epoch, so it carries state as a snapshot does and waits as one
// does. V wrote a large value; R, after removing M, edits it under e_R, reusing V's chunks. V,
// holding e_R's box but not W, repairs the reused chunks only once W makes e_R established, and M
// reads none of R's edit through the repair.
#[test]
fn relink_without_the_removal_leaks_nothing_spec_crypto_5() {
    let big_ak = Ak::new("x:big.0").unwrap();
    let (mut lp, g, tids) = granted(5, &[(A2, Role::Admin), (M, Role::Read), (R, Role::Admin), (V, Role::Admin)]);
    let mut v = vec![0u8; 256 << 10];
    osis_crypto::RngCore::fill_bytes(&mut osis_crypto::SeededRng::from_u64(9), &mut v);
    let mut m = Mutation::new();
    m.set(g, &big_ak, &Value::Bytes(v.clone())).unwrap();
    lp.peers[V].commit(m).unwrap().unwrap();
    lp.sync_all().unwrap();
    lp.peers[A2].clock.advance(5_000);
    let before = commit_ids(&mut lp, A2);
    lp.peers[A2].engine.demote(&g, &Demotion { holder: tids[M], new: None, retain: None }).unwrap();
    let w_commits: BTreeSet<CommitId> = commit_ids(&mut lp, A2).difference(&before).copied().collect();
    lp.sync(A2, R).unwrap();
    lp.peers[R].clock.advance(10_000);
    rotate_leaving_out(&mut lp, R, g, &BTreeSet::from([Role::Read]), &[]);
    let n = v.len();
    v[n - 4..].copy_from_slice(b"by R");
    lp.advance(7);
    let mut m = Mutation::new();
    m.set(g, &big_ak, &Value::Bytes(v.clone())).unwrap();
    let w = lp.peers[R].commit(m).unwrap().unwrap();
    let entry = lp.sealed(R, &[w]).unwrap();
    send_skipping(&mut lp, R, V, &w_commits.iter().copied().chain([w]).collect());
    lp.deliver_sealed(V, &entry).unwrap();
    let read_v = |lp: &mut LocalPeer, i: usize| match lp.peers[i].engine.get(&g, &big_ak).unwrap() {
        Some(Value::Link(l)) => lp.peers[i].engine.read_large(&g, &l).ok(),
        x => x,
    };
    assert_eq!(read_v(&mut lp, V), Some(Value::Bytes(v.clone())), "V reads R's edit by e_R's box");
    let lost = lp.peers[V].engine.live_trees(&g).unwrap().blobs;
    let r = lp.peers[V].engine.relink(&lost, &[g].into(), &mut |_, _| true).unwrap();
    if let Some(c) = r {
        let pks = lp.sealed(V, &[c]).unwrap();
        lp.deliver_sealed(M, &pks).unwrap();
        assert_ne!(read_v(&mut lp, M), Some(Value::Bytes(v.clone())), "M reads R's edit through V's repair");
    }
    assert_eq!(r, None, "V repairs R's edit under its own epoch with e_R not established");
    // W arrives: V repairs, and M reads nothing of R's edit through it
    for pk in lp.packages(A2).unwrap().into_iter().filter(|p| w_commits.contains(&p.id)) {
        let _ = lp.deliver(V, &pk);
    }
    let c = lp.peers[V].engine.relink(&lost, &[g].into(), &mut |_, _| true).unwrap().expect("a repair once e_R is established");
    let pks = lp.sealed(V, &[c]).unwrap();
    lp.deliver_sealed(M, &pks).unwrap();
    assert_ne!(read_v(&mut lp, M), Some(Value::Bytes(v)), "M reads R's edit through V's repair");
}

// spec/permissions.md §3 (Lost access): of a copy opened under a sync ID, a node takes no content
// part on a thing under an actor with secrets of its own that the sync ID's group actor may not
// read now, and keeps none of the copy's bytes. Peer 0's X derives its secrets from Y, which group G reads
// by role; X is filed in G, so G's sync ID carries X's write w as a copy. Once G is removed from
// Y, peer 1 (a reader of G) opening that copy takes nothing of it
#[test]
fn a_stale_copy_gives_no_content_spec_permissions_3() {
    let (mut lp, _, tids) = granted(2, &[]);
    let g = super::tests::group(&mut lp, 0);
    let y = super::tests::group(&mut lp, 0);
    let mut m = Mutation::new();
    let t = lp.peers[0].engine.new_thing(&mut m, y);
    let mut items = osis_schema::core_types::Group::default();
    items.items.insert(t);
    m.set(g, &osis_schema::core_types::GROUP, &items).unwrap();
    lp.peers[0].commit(m).unwrap();
    lp.peers[0].engine.grant(&y, &g, &edge(Role::Read)).unwrap();
    lp.peers[0].engine.grant(&g, &tids[1], &edge(Role::Read)).unwrap();
    lp.sync_all().unwrap();
    let w = put(&mut lp, 0, t, "w");
    let p0 = &mut lp.peers[0].engine;
    let body = p0.body(&w).unwrap().unwrap();
    let copy = p0.seal_to(&body, osis_label::Class::Durable, &mut osis_crypto::SeededRng::from_u64(40)).unwrap().unwrap();
    let k = p0.wrap_secret(&g, Some((&w, &body.parts))).unwrap().expect("peer 0 wraps its own");
    let s = p0.home_sync_id(&g).unwrap().unwrap();
    lp.peers[0].engine.demote(&y, &Demotion { holder: g, new: None, retain: None }).unwrap();
    send_skipping(&mut lp, 0, 1, &BTreeSet::from([w]));
    assert!(!lp.peers[1].engine.reads_in(&g, &t), "G reads X no more");
    let wrap = osis_crypto::wrap(&k, &copy.id, &copy.key, 1).unwrap();
    let o = lp.peers[1].engine.open_entry(&s, &copy.id, &wrap, &copy.blob).unwrap();
    assert!(matches!(o, crate::sync::Opened::NotOpen), "the stale copy is not taken: {o:?}");
    assert!(!lp.peers[1].engine.holds_commit(&w), "nothing of w is held");
}

// spec/crypto.md §4 (Encrypting under): a node MUST NOT encrypt under an epoch blocked at it,
// wrapping included; one that may not rotate waits for a rotation. Admin A removes reader M; a
// writer W holding the removal but not its rotation (the removal's `secrets.0` part) holds the read epoch M holds as its newest,
// blocked: W wraps nothing of g under it, A's earlier write included, until the rotation arrives
#[test]
fn a_wrap_waits_for_a_rotation_covering_a_known_removal_spec_crypto_4() {
    let (mut lp, g, tids) = granted(3, &[(1, Role::Write), (2, Role::Read)]);
    let c0 = put(&mut lp, 0, g, "before");
    lp.sync(0, 1).unwrap();
    let removal = lp.peers[0].engine.demote(&g, &Demotion { holder: tids[2], new: None, retain: None }).unwrap().commits[0];
    super::tests::deliver_without_secrets(&mut lp, 0, 1, g);
    assert!(lp.peers[1].engine.holds_commit(&removal));
    let parts: Vec<usize> = lp.peers[1].engine.body(&c0).unwrap().unwrap().parts;
    assert!(lp.peers[1].engine.wrap_secret(&g, Some((&c0, &parts))).unwrap().is_none(), "W wraps under no epoch the removed reader holds");
    lp.peers[1].engine.forget_awaiting(&removal).unwrap();
    send_skipping(&mut lp, 0, 1, &BTreeSet::new());
    assert!(lp.peers[1].engine.wrap_secret(&g, Some((&c0, &parts))).unwrap().is_some(), "the rotation held, W wraps");
}

// spec/permissions.md §2 (Finalize: a node with write holding a grant past its `until` writes the
// finalize before its next commit encrypting under the target), spec/crypto.md §4 (Encrypting
// under): with the role duties not yet run, admin A wraps nothing of its write after the `until`
// (the gate refuses); the duties finalize with the rotation, and the write then wraps under the
// new epoch, which the departed reader is not boxed at
#[test]
fn a_write_after_a_passed_until_waits_for_the_finalize_spec_permissions_2() {
    let (mut lp, g, tids) = granted(2, &[]);
    let until = osis_base::WallMs(lp.peers[0].engine.core.now().0 + 100);
    lp.peers[0].engine.grant(&g, &tids[1], &osis_schema::core_types::Edge { until: Some(until), ..edge(Role::Read) }).unwrap();
    lp.sync_all().unwrap();
    let old = newest_read(&lp, 0, g);
    lp.peers[0].clock.advance(1_000);
    let w = put(&mut lp, 0, g, "after");
    let parts = lp.peers[0].engine.body(&w).unwrap().unwrap().parts;
    assert!(lp.peers[0].engine.wrap_secret(&g, Some((&w, &parts))).unwrap().is_none(), "no wrap before the finalize");
    assert!(lp.peers[0].engine.role_duties_due(), "the `until` is due on the work list");
    lp.peers[0].engine.role_duties().unwrap();
    assert_ne!(newest_read(&lp, 0, g), old, "the finalize rotated read");
    assert!(lp.peers[0].engine.wrap_secret(&g, Some((&w, &parts))).unwrap().is_some(), "then the write wraps");
}
