//! Possession (spec/crypto.md §4, Holder actors; issues/keys-depth0-removed-member-rotates.md,
//! model `D0_rm_possess*`): a rotation of G counts its writer's role through holder actor X1
//! only where its keysets prove X1 (a signature by the possession key of a keyset of X1), and a
//! removal of G's box to X1 only where it puts that box again signed by the keyset it boxes at.
//! Shape: G <- X1 <- X2 <- W, X2 removing W where G's admin never learns of it.

#![allow(clippy::unwrap_used)]
use super::tests::{blocked_at, commit_ids, edge, group, held_by, newest_read, openable, send_skipping};
use crate::Mutation;
use crate::flows::Demotion;
use crate::local_peer::LocalPeer;
use osis_base::{CommitId, Role, Tid, WallMs};
use osis_crypto::Epoch;
use osis_keys::{HolderKeys, Recipient};
use std::collections::BTreeSet;

const A: usize = 0;
const B: usize = 1;
const W: usize = 2;

struct Shape {
    lp: LocalPeer,
    g: Tid,
    x1: Tid,
    x2: Tid,
}

/// Peers A (G's admin), B (admin of X1 and X2), W (a writer of X2). X2 writes X1, X1 writes G:
/// W writes G through X1. All synced.
fn shape(seed: u64) -> Shape {
    let mut lp = LocalPeer::new(3, seed, WallMs(1_700_000_000_000)).unwrap();
    lp.sync_all().unwrap();
    let w = lp.peers[W].engine.me();
    let x2 = group(&mut lp, B);
    lp.peers[B].engine.grant(&x2, &w, &edge(Role::Write)).unwrap();
    let x1 = group(&mut lp, B);
    lp.peers[B].engine.grant(&x1, &x2, &edge(Role::Write)).unwrap();
    lp.sync_all().unwrap();
    let g = group(&mut lp, A);
    lp.peers[A].engine.grant(&g, &x1, &edge(Role::Write)).unwrap();
    lp.sync_all().unwrap();
    assert_eq!(lp.peers[W].engine.core.role_now(&w, &g), Some(Role::Write));
    assert!(held_by(&lp, W, &[g]).contains(&(g, Role::Read, newest_read(&lp, A, g).unwrap())), "W reads G through X1");
    Shape { lp, g, x1, x2 }
}

/// B removes W from X2 and rotates X1 (its box to X2 stale); W gets all of it but the removal
/// (its removal never reaches it), and so does A (which never syncs X2) unless `hold_x1`, when A
/// gets nothing yet. Returns W's secrets before, and the commits of B's rotation of X1.
fn removed_holding(s: &mut Shape, hold_x1: bool) -> (BTreeSet<(Tid, Role, Epoch)>, BTreeSet<CommitId>) {
    let start = held_by(&s.lp, W, &[s.g, s.x1, s.x2]);
    let w = s.lp.peers[W].engine.me();
    let before = commit_ids(&mut s.lp, B);
    s.lp.peers[B].engine.demote(&s.x2, &Demotion { holder: w, new: None, retain: None }).unwrap();
    let rm: BTreeSet<CommitId> = commit_ids(&mut s.lp, B).difference(&before).copied().collect();
    let before = commit_ids(&mut s.lp, B);
    let (done, still) = s.lp.peers[B].engine.ensure_rotated(&s.x1).unwrap();
    assert!(still.is_empty() && !done.commits.is_empty(), "B rotates X1");
    let x1_rot: BTreeSet<CommitId> = commit_ids(&mut s.lp, B).difference(&before).copied().collect();
    if !hold_x1 {
        send_skipping(&mut s.lp, B, A, &rm);
    }
    send_skipping(&mut s.lp, B, W, &rm);
    assert_eq!(s.lp.peers[A].engine.core.role_now(&w, &s.g), Some(Role::Write), "A does not know W left");
    (start, x1_rot)
}

fn removed(s: &mut Shape) -> BTreeSet<(Tid, Role, Epoch)> {
    removed_holding(s, false).0
}

/// How W's forged rotation of G treats X1.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Forged {
    /// Left out.
    Out,
    /// Sealed at X1's current keyset, no proof (W holds no secret of it).
    Sealed,
    /// Sealed at X1's current keyset, its keysets proving X1 by the old keyset W holds.
    ProvedOld,
    /// Sealed at X1's current keyset, its keysets carrying a proof naming that keyset signed by
    /// the old one W holds (verifies under nothing).
    ProvedNew,
}

/// W rotates read and write of G as a party removed from X2 may: boxing A, and X1 as `how`
/// says. Returns the commit and the new read epoch, whose secret W holds.
fn forged_rotation(s: &mut Shape, how: Forged) -> (CommitId, Epoch) {
    let (g, x1) = (s.g, s.x1);
    let a = s.lp.peers[A].engine.me();
    let before = commit_ids(&mut s.lp, W);
    let e = s.lp.peers[W]
        .engine
        .run(|tx| {
            let held = tx.core.epochs(&g).unwrap();
            let secrets = crate::flows::secrets_in(tx, &g)?;
            let mut holders = vec![crate::flows::recipient(tx, a, Role::Admin)?];
            let keys = crate::engine::Core::keys_in(tx, &x1)?.unwrap();
            if how != Forged::Out {
                holders.push(Recipient { holder: x1, role: Role::Write, keys: HolderKeys::from_keys(&keys).unwrap() });
            }
            let names = super::departures::names(tx.core, &g, None);
            let roles = BTreeSet::from([Role::Read, Role::Write]);
            let mut rot = osis_keys::rotate(&g, &roles, &held, &secrets, &holders, &names, &mut *tx.rng).unwrap();
            if let Forged::ProvedOld | Forged::ProvedNew = how {
                let x1_held = tx.core.epochs(&x1).unwrap();
                for (r, ks) in rot.keys.keysets.iter_mut() {
                    // (a role W holds no secret of goes unproved: one proof shows X1)
                    let Some((old, secret)) = x1_held.role(*r).newest_secret().map(|(e, s)| (e, s.clone())) else { continue };
                    let new = osis_keys::aspects::from_schema(&osis_keys::aspects::keyset_of(&keys, *r).unwrap().epoch).unwrap();
                    assert_ne!(old, new, "W holds no secret of X1's new keyset");
                    let named = if how == Forged::ProvedOld { old } else { new };
                    let p = osis_keys::possession::prove(&g, *r, ks, &x1, named, &osis_keys::possession::possession_secret(&secret));
                    ks.proofs.insert(x1, p);
                }
            }
            // signed as W's engine would refuse to: every node judges it invalid
            tx.core.skip_writer_rules = true;
            let mut m = Mutation::new();
            m.unchecked();
            crate::flows::put_secrets(&mut m, g, &rot.secrets, false)?;
            crate::flows::put_keysets(&mut m, g, &rot.keys)?;
            crate::engine::Engine::commit_tx(tx, m)?;
            tx.core.skip_writer_rules = false;
            Ok(rot.rotated.iter().find(|r| r.role == Role::Read).unwrap().epoch)
        })
        .unwrap();
    let id = *commit_ids(&mut s.lp, W).difference(&before).next().unwrap();
    (id, e)
}

/// W's commits reach A and B.
fn deliver_w(s: &mut Shape) {
    for to in [A, B] {
        send_skipping(&mut s.lp, W, to, &BTreeSet::new());
    }
}

/// Peer `i` judges commit `c`'s `secrets.0` part on G invalid, and its `keys.0` part too where it
/// has one (a rotation is invalid whole), and `e` is no epoch it uses.
fn refused_at(s: &mut Shape, i: usize, c: CommitId, e: Option<Epoch>) {
    let m = s.lp.peers[i].engine.core.ix.commits.get(&c).cloned().expect("held");
    for (ai, x) in m.view.aspects.iter().enumerate().filter(|(_, x)| x.tid == s.g) {
        if matches!(x.ak.as_str(), "secrets.0" | "keys.0") {
            assert!(!m.valid_at(ai), "peer {i}: W's {} part valid", x.ak.as_str());
        }
    }
    if let Some(e) = e {
        assert!(!s.lp.peers[i].engine.epochs(&s.g).unwrap().read.is_established(&e), "peer {i}: W's epoch not established");
    }
}

/// A writes G (rotating first as due): W, with its old secrets and the forged epoch, opens
/// nothing A uses.
fn a_writes_unread(s: &mut Shape, mut known: BTreeSet<(Tid, Role, Epoch)>) {
    let (done, still) = s.lp.peers[A].engine.ensure_rotated(&s.g).unwrap();
    assert!(still.is_empty(), "{still:?}");
    assert!(!done.commits.is_empty(), "A rotates: its box to X1 is stale");
    known.extend(held_by(&s.lp, W, &[s.g]));
    let w = s.lp.peers[W].engine.me();
    let opened = openable(&mut s.lp, A, &[s.g, s.x1, s.x2], w, known);
    let e = newest_read(&s.lp, A, s.g).unwrap();
    assert!(!opened.contains(&(s.g, Role::Read, e)), "W opens A's newest epoch of G");
}

// The honest side: W, not knowing it left X2, finds G's box to X1 stale but holds no secret of
// X1's new keyset: it does not rotate G (every node would refuse it) and stays blocked, writing
// nothing under G, until it learns or is re-sealed (spec/crypto.md §4, Possession, Writers).
#[test]
fn removed_member_waits_spec_crypto_4() {
    let mut s = shape(7_001);
    removed(&mut s);
    let (done, still) = s.lp.peers[W].engine.ensure_rotated(&s.g).unwrap();
    assert!(done.commits.is_empty(), "W rotates G");
    assert!(still.contains(&Role::Read) && still.contains(&Role::Write), "W blocked on G: {still:?}");
    assert!(blocked_at(&mut s.lp, W, s.g).contains(&Role::Read));
    // nor does a rotation asked for directly go through (a node never commits what it would
    // judge invalid)
    let (w, g) = (s.lp.peers[W].engine.me(), s.g);
    let r = s.lp.peers[W].engine.run(|tx| super::rotate_now(tx, w, g, &BTreeSet::from([Role::Read, Role::Write])));
    assert!(r.is_err(), "W rotates G when asked: {r:?}");
}

// A removed W that keeps its secrets forges a rotation of G sealing X1 at X1's new keyset, which
// it cannot open: no possession signature, so W's role on G (only through X1) does not count
// for it (Authority). Refused at A (which never learns W left) and at B; A rotates on its stale
// box and W opens nothing A uses.
#[test]
fn removed_member_forged_rotation_refused_spec_crypto_4() {
    let mut s = shape(7_002);
    let start = removed(&mut s);
    let (c, e) = forged_rotation(&mut s, Forged::Sealed);
    deliver_w(&mut s);
    refused_at(&mut s, A, c, Some(e));
    refused_at(&mut s, B, c, Some(e));
    a_writes_unread(&mut s, start);
}

// The same rotation leaving X1 out: no box to show possession by, so W's role on G (only
// through X1) does not count for it (Authority). Refused everywhere.
#[test]
fn removed_member_rotation_leaving_holder_out_refused_spec_crypto_4() {
    let mut s = shape(7_003);
    let start = removed(&mut s);
    let (c, e) = forged_rotation(&mut s, Forged::Out);
    deliver_w(&mut s);
    refused_at(&mut s, A, c, Some(e));
    refused_at(&mut s, B, c, Some(e));
    a_writes_unread(&mut s, start);
}

// W removes G's stale box to X1 at G's current epoch (which W holds), so that a re-seal would
// box X1 there at its new keyset: a removal counts W's role only with possession (Authority).
// Refused: A still holds the stale box and rotates.
#[test]
fn removed_member_box_removal_refused_spec_crypto_4() {
    let mut s = shape(7_004);
    let start = removed(&mut s);
    let (g, x1) = (s.g, s.x1);
    let e = newest_read(&s.lp, W, g).unwrap();
    let before = commit_ids(&mut s.lp, W);
    s.lp.peers[W]
        .engine
        .run(|tx| {
            let k = osis_keys::aspects::box_key(x1, Role::Read, &e);
            let w = osis_keys::SecretsWrite { removed: [k].into(), ..Default::default() };
            tx.core.skip_writer_rules = true;
            let mut m = Mutation::new();
            m.unchecked();
            crate::flows::put_secrets(&mut m, g, &w, false)?;
            crate::engine::Engine::commit_tx(tx, m)?;
            tx.core.skip_writer_rules = false;
            Ok(())
        })
        .unwrap();
    let c = *commit_ids(&mut s.lp, W).difference(&before).next().unwrap();
    deliver_w(&mut s);
    refused_at(&mut s, A, c, None);
    let held = s.lp.peers[A].engine.get_typed(&g, &osis_schema::core_types::SECRETS).unwrap().unwrap();
    assert!(held.boxes.keys().any(|k| k.holder == x1 && k.role == Role::Read && osis_keys::aspects::from_schema(&k.epoch).is_ok_and(|x| x == e)), "A keeps the box");
    a_writes_unread(&mut s, start);
}

// W re-seals X1 at G's current epochs (which it holds) at X1's new keyset, which it cannot open,
// over the stale boxes: a removal of each and a put without a possession signature. Were it
// valid, A would find G's epochs boxed at X1's knowing keyset, fresh, and write under one W
// holds. A removal counts W's role only with possession (Authority): refused; A rotates on its
// stale box and W opens nothing A uses.
#[test]
fn removed_member_reseal_refused_spec_crypto_4() {
    let mut s = shape(7_007);
    let start = removed(&mut s);
    let (g, x1) = (s.g, s.x1);
    let before = commit_ids(&mut s.lp, W);
    s.lp.peers[W]
        .engine
        .run(|tx| {
            let held = tx.core.epochs(&g).unwrap();
            let hist = super::history_boxes(tx, &tx.core.writer().unwrap(), &g)?;
            let keys = crate::engine::Core::keys_in(tx, &x1)?.unwrap();
            let rcpt = Recipient { holder: x1, role: Role::Write, keys: HolderKeys::from_keys(&keys).unwrap() };
            let roles = BTreeSet::from([Role::Read, Role::Write]);
            let w = osis_keys::box_holder(&g, &held, &hist, &rcpt, &roles, &mut *tx.rng).unwrap().unwrap();
            assert!(w.removed.is_empty());
            tx.core.skip_writer_rules = true;
            let mut m = Mutation::new();
            m.unchecked();
            crate::flows::put_secrets(&mut m, g, &w, false)?;
            crate::engine::Engine::commit_tx(tx, m)?;
            tx.core.skip_writer_rules = false;
            Ok(())
        })
        .unwrap();
    let c = *commit_ids(&mut s.lp, W).difference(&before).next().unwrap();
    deliver_w(&mut s);
    refused_at(&mut s, A, c, None);
    refused_at(&mut s, B, c, None);
    a_writes_unread(&mut s, start);
}

// W proves X1 by the old keyset of it that it holds (a valid proof: the rotation counts) while
// sealing X1 at X1's new keyset: A finds the epoch's proof names a superseded keyset of X1, a
// stale box (spec/crypto.md §4, Stale), and rotates; W opens nothing A uses.
#[test]
fn removed_member_proving_an_old_keyset_is_stale_spec_crypto_4() {
    let mut s = shape(7_008);
    let start = removed(&mut s);
    let (c, _) = forged_rotation(&mut s, Forged::ProvedOld);
    deliver_w(&mut s);
    let m = s.lp.peers[A].engine.core.ix.commits.get(&c).cloned().expect("held");
    assert!(m.valid.iter().all(|v| *v), "a proof by a keyset W holds shows X1");
    a_writes_unread(&mut s, start);
}

// Judged again when the keyset arrives (arrival-order independence): A holds W's forged
// rotation (its proof naming X1's new keyset, signed by another) before X1's rotation: it holds
// no body of that keyset, so the proof is not judged (within the stated limit) and the rotation
// is valid there; once X1's rotation arrives, it is invalid, as where it arrived first.
#[test]
fn possession_judged_again_when_keyset_arrives_spec_crypto_4() {
    let mut s = shape(7_006);
    let (_, x1_rot) = removed_holding(&mut s, true);
    let (c, e) = forged_rotation(&mut s, Forged::ProvedNew);
    for pk in s.lp.packages(W).unwrap().into_iter().filter(|p| p.id == c) {
        s.lp.peers[A].receive(&pk.bytes, pk.blobs).unwrap();
    }
    let m = s.lp.peers[A].engine.core.ix.commits.get(&c).cloned().expect("held");
    assert!(m.valid.iter().all(|v| *v), "valid while A holds no body of the keyset the proof names");
    let mut skip = commit_ids(&mut s.lp, B);
    skip.retain(|x| !x1_rot.contains(x));
    send_skipping(&mut s.lp, B, A, &skip);
    refused_at(&mut s, A, c, Some(e));
}
