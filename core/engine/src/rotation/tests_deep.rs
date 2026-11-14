//! A departure below a holder actor, judged by a writer above it (spec/crypto.md §4, Encrypting
//! under: the box clause, stale boxes at any epoch it follows; model Depth0 `NoLeakDeep`). G holds
//! a chain of holder actors (X1 in G, X2 in X1, maybe X3 in X2), each with its own admin and
//! readers; V reads X1 or X2 only and is removed from it. Peers then act in a random order on
//! partial knowledge (pairwise syncs, rotations due, re-seals). Invariant: a writer of G holding
//! every commit any peer holds (so every keyset and box record of the chain: no stated limit
//! applies) writes, after rotating what is due, under no epoch V opens from the secrets it kept
//! and every box written. Liveness: once every peer but V settles, no epoch is blocked at G's
//! admin and every holder with key access is boxed.

#![allow(clippy::unwrap_used)]
use super::tests::{Key, Pass, Rng, all_boxed, blocked_at, edge, group, held_by, newest_read, opens_in, settle, synced};
use crate::flows::Demotion;
use crate::local_peer::LocalPeer;
use osis_base::{Role, Tid};
use osis_schema::core_types as ct;
use std::collections::{BTreeMap, BTreeSet};

/// Peers 0..V act; V is the removed reader.
const V: usize = 5;

struct World {
    lp: LocalPeer,
    /// G, X1, X2 (, X3).
    xs: Vec<Tid>,
    /// Each actor's admin.
    adm: Vec<usize>,
    /// G's writers (its admin among them).
    writers: Vec<usize>,
    /// What V held before its removal.
    kept: BTreeSet<Key>,
    log: Vec<String>,
}

fn world(seed: u64) -> World {
    let mut rng = Rng(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1);
    let mut lp = synced(V + 1);
    let tids: Vec<Tid> = (0..=V).map(|i| lp.peers[i].engine.me()).collect();
    let depth = 2 + rng.next(2) as usize;
    let adm: Vec<usize> = (0..=depth).map(|_| rng.next(V as u64) as usize).collect();
    let xs: Vec<Tid> = adm.iter().map(|&a| group(&mut lp, a)).collect();
    lp.sync_all().unwrap();
    let at = 1 + rng.next(2) as usize;
    let mut log = vec![format!("depth {depth}, admins {adm:?}, V reads X{at}")];
    // readers of each actor below G, V of X`at` only; the actor edges before or after them
    let mut members: Vec<(usize, usize)> = (1..=depth).flat_map(|k| (0..V).filter(|p| *p != adm[k]).map(|p| (k, p)).collect::<Vec<_>>()).collect();
    members.retain(|_| rng.next(3) == 0);
    members.push((at, V));
    let edges_first = rng.next(2) == 0;
    let actor_edges = |lp: &mut LocalPeer| {
        for k in (1..=depth).rev() {
            lp.peers[adm[k - 1]].engine.grant(&xs[k - 1], &xs[k], &edge(Role::Read)).unwrap();
            lp.sync_all().unwrap();
        }
    };
    if edges_first {
        actor_edges(&mut lp);
    }
    for &(k, p) in &members {
        lp.peers[adm[k]].engine.grant(&xs[k], &tids[p], &edge(Role::Read)).unwrap();
    }
    lp.sync_all().unwrap();
    if !edges_first {
        actor_edges(&mut lp);
    }
    let mut writers = vec![adm[0]];
    for p in (0..V).filter(|p| *p != adm[0]) {
        if rng.next(2) == 0 {
            lp.peers[adm[0]].engine.grant(&xs[0], &tids[p], &edge(Role::Write)).unwrap();
            writers.push(p);
        }
    }
    lp.sync_all().unwrap();
    log.push(format!("members {members:?}, edges first {edges_first}, writers {writers:?}"));
    let kept = held_by(&lp, V, &xs);
    assert!(kept.iter().any(|k| k.0 == xs[0]), "V reads G before its removal");
    lp.peers[adm[at]].engine.demote(&xs[at], &Demotion { holder: tids[V], new: None, retain: None }).unwrap();
    log.push(format!("peer {} removes V from X{at}", adm[at]));
    World { lp, xs, adm, writers, kept, log }
}

/// What V opens of the chain from what it kept and every box any other peer holds.
fn opened(w: &mut World) -> BTreeSet<Key> {
    let mut states: Vec<(Tid, ct::Secrets)> = Vec::new();
    let mut secrets = BTreeMap::new();
    for p in 0..V {
        for a in &w.xs {
            states.extend(w.lp.peers[p].engine.get_typed(a, &ct::SECRETS).unwrap().map(|s| (*a, s)));
        }
        secrets.extend(super::tests::held_secrets(&w.lp.peers[p], &w.xs));
    }
    opens_in(&w.lp, &states, &secrets, w.lp.peers[V].engine.me(), w.kept.clone(), &BTreeSet::new())
}

/// Writer `h` of G pulls every commit the others hold, rotates what is due, and would write: G's
/// read epoch it encrypts under, if not blocked there, opens nothing to V.
fn write_check(w: &mut World, seed: u64, h: usize) {
    for q in (0..V).filter(|q| *q != h) {
        w.lp.sync(q, h).unwrap();
    }
    let g = w.xs[0];
    w.lp.peers[h].engine.ensure_rotated(&g).unwrap();
    w.log.push(format!("peer {h} writes G"));
    if blocked_at(&mut w.lp, h, g).contains(&Role::Read) {
        return;
    }
    let e = newest_read(&w.lp, h, g).unwrap();
    assert!(!opened(w).contains(&(g, Role::Read, e)), "seed {seed}: V opens G's epoch {e:?} writer {h} encrypts under: {:?}", w.log);
}

fn deep_history(seed: u64) {
    let mut w = world(seed);
    let mut rng = Rng(seed.wrapping_mul(0xD1B5_4A32_D192_ED03) | 1);
    for _ in 0..(4 + rng.next(8)) {
        let p = rng.next(V as u64) as usize;
        let x = w.xs[rng.next(w.xs.len() as u64) as usize];
        match rng.next(4) {
            0 => {
                let q = rng.next(V as u64) as usize;
                if p != q {
                    w.lp.sync(p, q).unwrap();
                    w.log.push(format!("{p} -> {q}"));
                }
            }
            1 => {
                let n = w.lp.peers[p].engine.ensure_rotated(&x).unwrap().0.commits.len();
                w.log.push(format!("peer {p} rotates what is due on {}: {n}", w.xs.iter().position(|y| *y == x).unwrap()));
            }
            2 => {
                let n = w.lp.peers[p].engine.reseal_due(&x, &Pass).unwrap().commits.len();
                w.log.push(format!("peer {p} re-seals {}: {n}", w.xs.iter().position(|y| *y == x).unwrap()));
            }
            _ => {
                let h = w.writers[rng.next(w.writers.len() as u64) as usize];
                write_check(&mut w, seed, h);
            }
        }
    }
    for h in w.writers.clone() {
        write_check(&mut w, seed, h);
    }
    // every peer but V settles: nothing stays blocked, every holder is boxed, V opens nothing new
    let staff: Vec<usize> = (0..V).collect();
    let xs = w.xs.clone();
    w.lp.sync_all().unwrap();
    settle(&mut w.lp, &staff, &xs);
    let g = xs[0];
    assert!(blocked_at(&mut w.lp, w.adm[0], g).is_empty(), "seed {seed}: G blocked after settling: {:?}", w.log);
    for (k, x) in xs.iter().enumerate() {
        assert!(all_boxed(&mut w.lp, w.adm[k], &[*x]), "seed {seed}: a holder of X{k} lacks a box after settling: {:?}", w.log);
    }
    let open = opened(&mut w);
    for &h in &w.writers {
        let e = newest_read(&w.lp, h, g).unwrap();
        assert!(!open.contains(&(g, Role::Read, e)), "seed {seed}: V opens G's settled epoch at {h}: {:?}", w.log);
    }
}

fn replay(s: u64) -> String {
    format!("OSIS_DEEP_START={s} OSIS_DEEP_SEEDS=1 cargo test -p osis-engine --lib -- --ignored --exact rotation::tests_deep::deep_departure_holds_large_spec_crypto_4")
}

// spec/crypto.md §4 (Encrypting under, Holder actors: Stale): module doc. Quick size: seeds 0..4.
#[test]
fn deep_departure_holds_spec_crypto_4() {
    osis_base::testenv::run_seeds("rotation::tests_deep::deep_departure_holds_spec_crypto_4", &(0..4).collect::<Vec<u64>>(), false, replay, deep_history);
}

/// Small size (a tenth of large) or large under `OSIS_FULL=1`; seeds: OSIS_DEEP_START,
/// OSIS_DEEP_SEEDS.
#[test]
#[ignore = "property"]
fn deep_departure_holds_large_spec_crypto_4() {
    let s = osis_base::testenv::Seeds::from_env("OSIS_DEEP_START", "OSIS_DEEP_SEEDS", osis_base::testenv::large(0..1_000));
    s.run("rotation::tests_deep::deep_departure_holds_large_spec_crypto_4", replay, deep_history);
}
