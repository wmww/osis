//! Incremental evaluation (spec/permissions.md §5.1 step 5: D is rebuilt from
//! scratch on any change): per-component timelines, cached or continued past their last write,
//! equal the whole held set's timeline after every arrival, in random and in timeline order.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

mod common;

use common::*;
use membership_model::{edges, joint, snapshot, Rng};
use osis_core::Tid;
use osis_perm::{At, HeldSet, Timeline, Timelines, WriteId};
use std::collections::BTreeSet;

fn check(held: &osis_perm::MemoryHeldSet, inc: &Timelines, nodes: &[Tid]) -> Option<String> {
    let full = Timeline::evaluate(held);
    let mut dropped = BTreeSet::new();
    let mut applied = BTreeSet::new();
    let mut seen = BTreeSet::new();
    for t in held.things() {
        let Some(part) = inc.get(&t) else { return Some(format!("{t:?} has no component")) };
        if part.roster(&t, At::END) != full.roster(&t, At::END) {
            return Some(format!("roster of {t:?}: part {:?} full {:?}", part.roster(&t, At::END), full.roster(&t, At::END)));
        }
        for n in nodes {
            if part.standing(n, &t, At::END) != full.standing(n, &t, At::END) {
                return Some(format!("standing of {n:?} on {t:?}"));
            }
            if part.demotions(n, &t) != full.demotions(n, &t) {
                return Some(format!("demotions of {n:?} on {t:?}"));
            }
        }
        if part.epoch_start(&t) != full.epoch_start(&t) {
            return Some(format!("epoch start of {t:?}"));
        }
        // the edge history too: roles before every applied write
        for a in full.applied().values() {
            for n in nodes {
                if part.role(n, &t, At::before(a.point)) != full.role(n, &t, At::before(a.point)) {
                    return Some(format!("role of {n:?} on {t:?} before {:?}", a.point));
                }
            }
        }
        if seen.insert(part as *const Timeline) {
            dropped.extend(part.dropped().iter().map(|(w, p)| (*w, *p)));
            applied.extend(part.applied().keys().copied());
        }
    }
    let fd: BTreeSet<(WriteId, osis_perm::Point)> = full.dropped().iter().map(|(w, p)| (*w, *p)).collect();
    let fa: BTreeSet<WriteId> = full.applied().keys().copied().collect();
    if dropped != fd || applied != fa {
        return Some("applied or dropped sets".into());
    }
    None
}

fn run(samples: u64, seed: u64) {
    let mut rng = Rng(seed);
    for s in 0..samples {
        // Two or three independent histories in one held set: several components; or one
        // snapshot-model history (its roster snapshots held from the start, epoch starts).
        let mut w = World::new();
        let mut nodes = Vec::new();
        let snap = rng.below(3) == 0;
        if snap {
            let sw = snap_world(&snapshot::random_hist(&mut rng));
            w = sw.w;
            nodes = sw.nodes;
        }
        for k in 0..if snap { 0 } else { 2 + rng.below(2) } {
            let salt = 10 + k as u8;
            let (wk, nk) = if rng.below(2) == 0 {
                let (wk, nk, _) = joint_world(&joint::random_hist(&mut rng), salt);
                (wk, nk)
            } else {
                let (wk, nk, _) = edges_world(&edges::random_hist(&mut rng), salt);
                (wk, nk)
            };
            w.merge(wk);
            nodes.extend(nk);
        }
        // random arrivals, or in timeline order (each new write after every held one: the
        // cached walk is continued, `Timeline::extend`)
        let order = if rng.below(2) == 0 {
            rng.perm(w.commits.len())
        } else {
            let mut o: Vec<usize> = (0..w.commits.len()).collect();
            o.sort_by_key(|&i| (w.commits[i].t, w.commits[i].author, w.commits[i].id));
            o
        };
        let mut held_ids = BTreeSet::new();
        let mut inc = Timelines::new();
        let all: BTreeSet<_> = w.commits.iter().map(|c| c.id).collect();
        for (step, &i) in order.iter().enumerate() {
            held_ids.insert(w.commits[i].id);
            let skip: BTreeSet<_> = all.difference(&held_ids).copied().collect();
            let held = w.held_without(&skip);
            inc.update(&held);
            if let Some(d) = check(&held, &inc, &nodes) {
                panic!("sample {s} step {step}: {d}");
            }
        }
        // Nothing changed: nothing is evaluated again.
        assert_eq!(inc.update(&w.held()), 0);
    }
}

/// §5.1 step 5: incremental equals from scratch.
#[test]
fn incremental_equals_from_scratch() {
    run(25, 0x5eed_0301);
}

#[test]
#[ignore]
fn incremental_equals_from_scratch_large() {
    run(2_000, 0x5eed_0302);
}

/// A `/created` arriving before, between or after the commits naming its thing: the cached
/// component is re-evaluated, in every arrival order.
#[test]
fn created_late_every_order() {
    let mut w = World::new();
    let n = w.nodes(2);
    let (k, x) = (n[0], n[1]);
    let g = w.thing(k);
    let d = w.thing(g);
    let c1 = w.set(k, g, x, edge(osis_core::Role::Admin), 10, &[]);
    let c2 = w.set(x, d, k, edge(osis_core::Role::Write), 11, &[]);
    // Arrivals: 0 = g's /created, 1 = c1, 2 = c2.
    let perms = [[0, 1, 2], [0, 2, 1], [1, 0, 2], [1, 2, 0], [2, 0, 1], [2, 1, 0]];
    for order in perms {
        let mut inc = Timelines::new();
        let mut have: BTreeSet<usize> = BTreeSet::new();
        for a in order {
            have.insert(a);
            let skip: BTreeSet<_> = [(1, c1), (2, c2)].into_iter().filter(|(i, _)| !have.contains(i)).map(|(_, c)| c).collect();
            let mut held = w.held_without(&skip);
            if !have.contains(&0) {
                held.created.remove(&g);
            }
            inc.update(&held);
            if let Some(dd) = check(&held, &inc, &n) {
                panic!("order {order:?} after {a}: {dd}");
            }
            let full = Timeline::evaluate(&held);
            assert_eq!(inc.get(&d).map(|t| t.role(&x, &d, At::END)), Some(full.role(&x, &d, At::END)), "order {order:?}");
        }
    }
}
