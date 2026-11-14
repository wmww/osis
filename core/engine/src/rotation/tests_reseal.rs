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
    if let Some((sealed, wrap)) = lp.peers[V].engine.seal_body(&s, &w, &[held.clone()], &mut rng).unwrap() {
        let (header, content) = m_opens_entry(&mut lp, g, w, &sealed.id, &sealed.blob, &wrap);
        panic!("V sealed w read from a copy lacking W: M opens its header {header}, content {content}");
    }
    w_arrives(&mut lp, g, &w_commits, &e_r);
    let (sealed, wrap) = lp.peers[V].engine.seal_body(&s, &w, &[held], &mut rng).unwrap().expect("V seals w once e_R is established");
    assert_eq!(m_opens_entry(&mut lp, g, w, &sealed.id, &sealed.blob, &wrap), (false, false));
}
