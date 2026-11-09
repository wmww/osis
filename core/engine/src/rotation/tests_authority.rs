//! Authority judged whole from the keyset (spec/crypto.md §4, Possession, Authority;
//! models `D0_half*`, `Authority.tla`): a rotation through a holder actor counts only where its
//! keysets prove that actor, so a rotation failing it is invalid whole (keyset, establishment and
//! boxes) at every node holding its keyset, one holding certificates only included; and keysets
//! are read as of just before the commit's key, so validity has one result in any arrival order.

#![allow(clippy::unwrap_used)]
use super::tests::{commit_ids, deliver_without_secrets, edge, group, held_by, newest_read, openable, send_skipping};
use crate::Mutation;
use crate::local_peer::LocalPeer;
use osis_base::{CommitId, Role, Tid, WallMs};
use osis_crypto::{Epoch, Secret32};
use std::collections::{BTreeMap, BTreeSet};

const A1: usize = 0;
const M1: usize = 1;
const F: usize = 2;

/// A {a1, M}, M {m1, S}, S {f}: f reaches M only through S, and reads A through M. Returns
/// (A, M, S).
fn half_shape(seed: u64) -> (LocalPeer, Tid, Tid, Tid) {
    let mut lp = LocalPeer::new(3, seed, WallMs(1_700_000_000_000)).unwrap();
    lp.sync_all().unwrap();
    let s = group(&mut lp, F);
    let m = group(&mut lp, M1);
    lp.sync_all().unwrap();
    lp.peers[M1].engine.grant(&m, &s, &edge(Role::Write)).unwrap();
    let a = group(&mut lp, A1);
    lp.sync_all().unwrap();
    lp.peers[A1].engine.grant(&a, &m, &edge(Role::Read)).unwrap();
    lp.sync_all().unwrap();
    assert!(held_by(&lp, F, &[a]).contains(&(a, Role::Read, newest_read(&lp, A1, a).unwrap())), "f reads A through M");
    (lp, a, m, s)
}

/// f removes S from M in a commit that also rotates M boxing everyone but S: unless `prove`, its
/// proofs show no possession of S, the only way f holds a role on M; with `prove`, they prove S
/// by the keyset of S f holds.
/// Returns the commit and the secrets f holds of M (its own new epochs included).
fn half_valid(lp: &mut LocalPeer, m: Tid, s: Tid, prove: bool) -> (CommitId, BTreeSet<(Tid, Role, Epoch)>) {
    let before = commit_ids(lp, F);
    let made = lp.peers[F]
        .engine
        .run(|tx| {
            let me = tx.core.id.tid();
            let held = tx.core.epochs(&m).unwrap();
            let holders = super::recipients(tx, &me, &m, &[(s, None)])?.ok_or(super::SEAL_WAITS)?;
            let mut mu = Mutation::new();
            crate::flows::edges::removal(tx, &mut mu, m, s)?;
            // the rotation written beside, its keysets proved first
            let mut aside = Mutation::new();
            let mut rot = super::rotation_into(tx, &mut aside, m, &[Role::Read, Role::Write].into(), &held, &holders, true)?;
            assert!(rot.keys.keysets.values().all(|ks| ks.proofs.is_empty()), "S left out: nothing proved");
            if prove {
                let sh = tx.core.epochs(&s).unwrap();
                for (r, ks) in rot.keys.keysets.iter_mut() {
                    let (k, sec) = sh.role(*r).newest_secret().map(|(e, x)| (e, x.clone())).unwrap();
                    let p = osis_keys::possession::prove(&m, *r, ks, &s, k, &osis_keys::possession::possession_secret(&sec));
                    ks.proofs.insert(s, p);
                }
            }
            (mu.ts, mu.blind) = (aside.ts, aside.blind);
            crate::flows::put_secrets(&mut mu, m, &rot.secrets, false)?;
            crate::flows::put_keysets(&mut mu, m, &rot.keys)?;
            mu.unchecked();
            // past this node's own refusal: receivers judge it
            tx.core.skip_writer_rules = true;
            let c = crate::engine::Engine::commit_tx(tx, mu);
            tx.core.skip_writer_rules = false;
            c?;
            Ok(rot.rotated.iter().map(|r| (m, r.role, r.epoch)).collect::<BTreeSet<_>>())
        })
        .unwrap();
    let c = *commit_ids(lp, F).difference(&before).next().unwrap();
    let mut known = held_by(lp, F, &[m]);
    known.extend(made);
    (c, known)
}

/// The validity of commit `c`'s `keys.0` and `secrets.0` parts on `t` at peer `i`, where held.
fn verdicts(lp: &LocalPeer, i: usize, c: &CommitId, t: Tid) -> Vec<(String, bool)> {
    let m = lp.peers[i].engine.core.ix.commits.get(c).cloned().expect("held");
    m.view.aspects.iter().enumerate().filter(|(_, x)| x.tid == t && matches!(x.ak.as_str(), "keys.0" | "secrets.0")).map(|(ai, x)| (x.ak.as_str().to_string(), m.valid_at(ai))).collect()
}

// The half-valid leak, reproduced small (model `D0_half`): a1, A's admin, holds M's keysets as
// certificates only (it does not read M). f's rotation of M must be invalid there too, else a1
// finds A's box to M's first keyset stale (f's keyset lists it), seals M at f's keyset, and keeps
// doing so after m1's knowing rotation (which cannot list an epoch it never established): f opens
// what a1 writes under A from then on.
#[test]
fn half_valid_rotation_leaks_nothing_spec_crypto_4() {
    let (mut lp, a, m, s) = half_shape(7_101);
    let (c, known) = half_valid(&mut lp, m, s, false);
    deliver_without_secrets(&mut lp, F, A1, m);
    send_skipping(&mut lp, F, M1, &BTreeSet::new());
    lp.peers[A1].engine.ensure_rotated(&a).unwrap();
    // m1 knows S left M and rotates M; a1 gets it as certificates
    lp.peers[M1].engine.ensure_rotated(&m).unwrap();
    deliver_without_secrets(&mut lp, M1, A1, m);
    let (_, still) = lp.peers[A1].engine.ensure_rotated(&a).unwrap();
    assert!(still.is_empty(), "a1 blocked on A: {still:?}");
    let mut known = known;
    known.extend(held_by(&lp, F, &[a]));
    let f = lp.peers[F].engine.tid();
    let opened = openable(&mut lp, A1, &[a, m], f, known);
    let e = newest_read(&lp, A1, a).unwrap();
    assert!(!opened.contains(&(a, Role::Read, e)), "f opens a1's newest epoch of A");
    assert!(verdicts(&lp, A1, &c, m).iter().all(|(_, v)| !v), "a1 holds f's rotation of M invalid");
}

// One verdict on a rotation, whatever a node holds of it (spec/crypto.md §4, Authority, Carried):
// m1 holds f's whole commit, a1 its certificate (no `secrets.0` part on M); both hold its keyset
// invalid, and m1 its boxes too, so f's epoch is established nowhere and its keyset is no anchor.
#[test]
fn half_valid_rotation_refused_alike_with_certificates_only_spec_crypto_4() {
    let (mut lp, _, m, s) = half_shape(7_102);
    let before = held_by(&lp, F, &[m]);
    let (c, known) = half_valid(&mut lp, m, s, false);
    let made: Vec<(Role, Epoch)> = known.difference(&before).map(|(_, r, e)| (*r, *e)).collect();
    deliver_without_secrets(&mut lp, F, A1, m);
    send_skipping(&mut lp, F, M1, &BTreeSet::new());
    let at_a1 = verdicts(&lp, A1, &c, m);
    let at_m1 = verdicts(&lp, M1, &c, m);
    let missing = |i: usize| lp.peers[i].engine.core.ix.commits.get(&c).unwrap().missing.len();
    assert!(missing(A1) > missing(M1), "a1 holds the certificate only");
    assert_eq!(at_m1.len(), 2, "m1 holds both parts");
    assert!(at_a1.iter().chain(&at_m1).all(|(_, v)| !v), "a1: {at_a1:?}, m1: {at_m1:?}");
    for i in [A1, M1] {
        let held: BTreeSet<(Role, Epoch)> = lp.peers[i].engine.core.keysets_of(&m).map(|x| (x.0, x.1)).collect();
        assert!(made.iter().all(|x| !held.contains(x)), "peer {i} holds f's keyset valid");
    }
    let e = lp.peers[M1].engine.epochs(&m).unwrap();
    assert!(made.iter().all(|(r, x)| !e.role(*r).is_established(x)), "m1 establishes f's epoch");
}

// A rotation's verdict reads its keysets' proofs; a node holding its `secrets.0` part without the
// `keys.0` one reads the commit as one without that body (spec/commits.md §4: nothing waits for a
// part), so it shows nothing: f reaches M only through S, invalid. The `keys.0` part counts
// missing (fetched again); once it comes the one verdict is valid, as at a node that held both,
// and a rebuild agrees.
#[test]
fn rotation_without_its_keyset_shows_nothing_until_it_comes_spec_crypto_4() {
    let (mut lp, _, m, s) = half_shape(7_103);
    let (c, _) = half_valid(&mut lp, m, s, true);
    for pk in lp.packages(F).unwrap() {
        let b = osis_commit::CommitBlob::decode(&pk.bytes).unwrap();
        let cut = osis_commit::rewrite(&b, |ai| b.header.aspects.get(ai).is_some_and(|x| x.tid == m && x.ak.as_str() == "keys.0"));
        let _ = lp.peers[M1].receive(&cut.encode(), pk.blobs.clone());
    }
    let keys_ai = lp.peers[M1].engine.core.ix.commits.get(&c).unwrap().view.aspects.iter().position(|x| x.tid == m && x.ak.as_str() == "keys.0").unwrap();
    assert!(lp.peers[M1].engine.core.ix.commits.get(&c).unwrap().missing.contains(&keys_ai), "the keyset counts missing");
    let secrets = |lp: &LocalPeer| verdicts(lp, M1, &c, m).into_iter().find(|x| x.0 == "secrets.0").map(|x| x.1);
    assert_eq!(secrets(&lp), Some(false), "shows nothing: invalid");
    send_skipping(&mut lp, F, M1, &BTreeSet::new());
    assert!(verdicts(&lp, M1, &c, m).iter().all(|(_, v)| *v), "valid once the keyset came: {:?}", verdicts(&lp, M1, &c, m));
    let d0 = lp.peers[M1].engine.index_digest();
    lp.peers[M1].engine.rebuild_index().unwrap();
    assert_eq!(d0.first_diff(&lp.peers[M1].engine.index_digest()), None, "rebuild = live");
}

// A 3-cycle of holder actors X <- Y <- Z <- X (model `A_order_3`): three rotations, each by
// an author reaching its actor only through the next actor, each proving it by a bad signature
// naming the keyset the next one writes. Read as held now, each is valid iff the next is not:
// no result, and re-judging loops. Read as of just before each commit's key, validity follows
// the key order: one result, the same in every arrival order.
#[test]
fn authority_cycle_has_one_result_spec_crypto_4() {
    let n = 3;
    let mut lp = LocalPeer::new(n + 6, 7_103, WallMs(1_700_000_000_000)).unwrap();
    lp.sync_all().unwrap();
    let acts: Vec<Tid> = (0..n).map(|i| group(&mut lp, i)).collect();
    lp.sync_all().unwrap();
    // actor i+1 holds write on actor i: peer i+1 (its first admin) reaches actor i only through it
    for i in 0..n {
        let next = (i + 1) % n;
        lp.peers[i].engine.grant(&acts[i], &acts[next], &edge(Role::Write)).unwrap();
        lp.sync_all().unwrap();
    }
    let secrets: Vec<Secret32> = (0..n).map(|i| Secret32::from_bytes([40 + i as u8; 32])).collect();
    let epochs: Vec<Epoch> = (0..n).map(|i| Epoch::derive(&acts[i], Role::Read, 2, &secrets[i]).unwrap()).collect();
    let mut rots: Vec<CommitId> = Vec::new();
    for i in 0..n {
        let (by, next) = ((i + 1) % n, (i + 1) % n);
        let (t, h) = (acts[i], acts[next]);
        let before = commit_ids(&mut lp, by);
        let (e, sec, named) = (epochs[i], secrets[i].clone(), epochs[next]);
        lp.peers[by]
            .engine
            .run(|tx| {
                let mut ks = osis_keys::aspects::keyset(&e, &sec, &BTreeSet::new(), &osis_keys::Names::default());
                let p = osis_keys::possession::prove(&t, Role::Read, &ks, &h, named, &osis_keys::possession::possession_secret(&Secret32::from_bytes([99; 32])));
                ks.proofs.insert(h, p);
                let keys = osis_keys::KeysWrite { keysets: BTreeMap::from([(Role::Read, ks)]) };
                let mut m = Mutation::new();
                m.unchecked();
                crate::flows::put_keysets(&mut m, t, &keys)?;
                tx.core.skip_writer_rules = true;
                let c = crate::engine::Engine::commit_tx(tx, m);
                tx.core.skip_writer_rules = false;
                c.map(|_| ())
            })
            .unwrap();
        rots.push(*commit_ids(&mut lp, by).difference(&before).next().unwrap());
    }
    let pkgs: Vec<_> = (0..n).map(|i| lp.packages((i + 1) % n).unwrap().into_iter().find(|p| p.id == rots[i]).unwrap()).collect();
    // the expected result: down the key order, rotation i is valid iff the keyset it names
    // (rotation i+1's) is not held valid before it
    let key = |i: usize| {
        let m = lp.peers[(i + 1) % n].engine.core.ix.commits.get(&rots[i]).cloned().unwrap();
        (m.view.ts, m.view.author, rots[i])
    };
    let mut order: Vec<usize> = (0..n).collect();
    order.sort_by_key(|i| key(*i));
    let mut want = vec![true; n];
    for &i in &order {
        let j = (i + 1) % n;
        want[i] = !(key(j) < key(i) && want[j]);
    }
    assert!(want.iter().any(|v| *v) && want.iter().any(|v| !*v), "the cycle decides something: {want:?}");
    let perms = [[0, 1, 2], [0, 2, 1], [1, 0, 2], [1, 2, 0], [2, 0, 1], [2, 1, 0]];
    for (k, p) in perms.iter().enumerate() {
        let judge = n + k;
        for &i in p {
            lp.peers[judge].receive(&pkgs[i].bytes, pkgs[i].blobs.clone()).unwrap();
        }
        let got: Vec<bool> = (0..n).map(|i| verdicts(&lp, judge, &rots[i], acts[i]).iter().all(|(_, v)| *v)).collect();
        assert_eq!(got, want, "arrival order {p:?}");
    }
}

// Authority asks for the right to rotate the rotated roles, nothing more (spec/crypto.md §4,
// Authority): P writes A directly and is admin of A only through M, whose grant on A is keyless
// (A held M first), so P's rotations of A box M nothing and prove nothing. P's rotation of read
// (which also refreshes A's deposit seed, an admin field judged by role) is valid.
#[test]
fn authority_needs_only_the_rotated_roles_spec_crypto_4() {
    let mut lp = LocalPeer::new(2, 7_104, WallMs(1_700_000_000_000)).unwrap();
    lp.sync_all().unwrap();
    let p = lp.peers[1].engine.tid();
    let a = group(&mut lp, 0);
    let m = group(&mut lp, 1);
    lp.sync_all().unwrap();
    lp.peers[1].engine.grant(&m, &a, &edge(Role::Read)).unwrap();
    lp.sync_all().unwrap();
    lp.peers[0].engine.grant(&a, &p, &edge(Role::Write)).unwrap();
    lp.peers[0].engine.grant(&a, &m, &edge(Role::Admin)).unwrap();
    lp.sync_all().unwrap();
    assert_eq!(lp.peers[1].engine.core.role_now(&p, &a), Some(Role::Admin));
    let before = commit_ids(&mut lp, 1);
    lp.peers[1].engine.run(|tx| super::rotate_now(tx, p, a, &BTreeSet::from([Role::Read]))).unwrap();
    let c = *commit_ids(&mut lp, 1).difference(&before).next().unwrap();
    assert!(verdicts(&lp, 1, &c, a).iter().all(|(_, v)| *v));
}

// The order reading's other half (spec/crypto.md §4, Authority; spec/permissions.md §5.1): f's
// role on M through S counts just before the commit removing S, so the same rotation proving S
// by the keyset of S it holds is valid at every node. It leaks nothing: f made the epoch, so it
// covers no departure of f's (m1 rotates M again), and a1 seals A at m1's keyset.
#[test]
fn route_removal_proved_leaks_nothing_spec_crypto_4() {
    let (mut lp, a, m, s) = half_shape(7_105);
    let (c, known) = half_valid(&mut lp, m, s, true);
    deliver_without_secrets(&mut lp, F, A1, m);
    send_skipping(&mut lp, F, M1, &BTreeSet::new());
    assert!(verdicts(&lp, A1, &c, m).iter().chain(&verdicts(&lp, M1, &c, m)).all(|(_, v)| *v), "a proof of S counts");
    lp.peers[A1].engine.ensure_rotated(&a).unwrap();
    lp.peers[M1].engine.ensure_rotated(&m).unwrap();
    deliver_without_secrets(&mut lp, M1, A1, m);
    let (_, still) = lp.peers[A1].engine.ensure_rotated(&a).unwrap();
    assert!(still.is_empty(), "a1 blocked on A: {still:?}");
    let mut known = known;
    known.extend(held_by(&lp, F, &[a]));
    let f = lp.peers[F].engine.tid();
    let (e, em) = (newest_read(&lp, A1, a).unwrap(), newest_read(&lp, M1, m).unwrap());
    assert!(!openable(&mut lp, A1, &[a, m], f, known.clone()).contains(&(a, Role::Read, e)), "f opens a1's newest epoch of A");
    assert!(!openable(&mut lp, M1, &[m], f, known).contains(&(m, Role::Read, em)), "f opens m1's newest epoch of M");
}
