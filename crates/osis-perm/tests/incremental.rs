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

/// Things whose held inputs differ between two held sets (what a node tracks as it adds).
fn touched(a: &osis_perm::MemoryHeldSet, b: &osis_perm::MemoryHeldSet) -> BTreeSet<Tid> {
    let mut all: BTreeSet<Tid> = a.things().into_iter().collect();
    all.extend(b.things());
    let key = |h: &osis_perm::MemoryHeldSet, t: &Tid| {
        let c: BTreeSet<_> = h.edge_commits(t).iter().map(|c| c.id).collect();
        let s: BTreeSet<_> = h.roster_snapshots(t).iter().map(|s| s.id).collect();
        (c, s, h.created(t))
    };
    all.into_iter().filter(|t| key(a, t) != key(b, t)).collect()
}

fn run(samples: u64, seed: u64) {
    let seed = seeded(seed);
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
        // half the samples re-partition only around what changed
        let around = rng.below(2) == 0;
        let mut prev = w.held_without(&all);
        if around {
            inc.update(&prev);
        }
        for (step, &i) in order.iter().enumerate() {
            held_ids.insert(w.commits[i].id);
            let skip: BTreeSet<_> = all.difference(&held_ids).copied().collect();
            let held = w.held_without(&skip);
            if around {
                inc.update_touched(&held, &touched(&prev, &held));
            } else {
                inc.update(&held);
            }
            prev = held.clone();
            if let Some(d) = check(&held, &inc, &nodes) {
                panic!("seed {seed:#x} sample {s} step {step}: {d}");
            }
        }
        // Nothing changed: nothing is evaluated again.
        assert_eq!(inc.update(&w.held()), 0);
    }
}

/// §5.1 step 5, §6: two sibling teams that are admins of each other (owner-chain authority on
/// each may come through the other), with a snapshot that is never a start: each write in
/// timeline order continues the walk (`extend`), equal to evaluating from scratch.
#[test]
fn mutual_admin_teams_extend() {
    use osis_core::Role::{Admin, Write};
    let mut w = World::new();
    let n = w.nodes(4);
    let (k, n1, n2, n3) = (n[0], n[1], n[2], n[3]);
    let (a, b) = (w.thing(k), w.thing(k));
    let all: Vec<(Tid, u64)> = n.iter().map(|x| (*x, 0)).collect();
    w.set(k, a, b, edge(Admin), 0, &all);
    w.set(k, b, a, edge(Admin), 0, &all);
    w.set(k, a, n1, edge(Admin), 0, &all);
    // n1 holds no owner-chain authority on A: never an epoch start
    w.snapshot(n1, a, &[(n1, osis_perm::Edge::new(Admin))], 1, &all);
    w.set(n1, b, n2, edge(Admin), 2, &all);
    w.set(n2, a, n3, edge(Write), 3, &all);
    w.set(n1, a, n2, None, 4, &[]);
    w.set(k, a, n1, None, 5, &[]);
    w.set(n2, b, n3, edge(Admin), 6, &all);
    let mut order: Vec<usize> = (0..w.commits.len()).collect();
    order.sort_by_key(|&i| (w.commits[i].t, w.commits[i].author, w.commits[i].id));
    let all_ids: BTreeSet<_> = w.commits.iter().map(|c| c.id).collect();
    let mut held_ids = BTreeSet::new();
    let mut tl: Option<Timeline> = None;
    for i in order {
        held_ids.insert(w.commits[i].id);
        let held = w.held_without(&all_ids.difference(&held_ids).copied().collect());
        let next = match tl.take() {
            None => Timeline::evaluate(&held),
            Some(t) => t.extend(&held).expect("the walk goes on"),
        };
        let full = Timeline::evaluate(&held);
        assert_eq!(next.epoch_starts(), full.epoch_starts());
        assert_eq!(next.dropped(), full.dropped());
        assert_eq!(next.applied().keys().collect::<Vec<_>>(), full.applied().keys().collect::<Vec<_>>());
        for t in [a, b] {
            assert_eq!(next.roster(&t, At::END), full.roster(&t, At::END));
        }
        tl = Some(next);
    }
    assert!(tl.unwrap().epoch_starts().is_empty());
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

/// §5.1: a new thing's `/created` alone (nothing names it yet) and a write after every held one
/// continue the component's timeline; each reports what changed (the leaf; the write's target),
/// and the result equals an evaluation from scratch.
#[test]
fn leaves_and_appends_extend() {
    let mut w = World::new();
    let n = w.nodes(2);
    let (k, x) = (n[0], n[1]);
    let g = w.thing(k);
    w.set(k, g, x, edge(osis_core::Role::Write), 10, &[]);
    let leaf = w.thing(k);
    let mut held = w.held();
    held.created.remove(&leaf);
    let mut inc = Timelines::new();
    let touched: BTreeSet<Tid> = held.things().into_iter().collect();
    inc.update_touched(&held, &touched);
    let held = w.held();
    let c = inc.update_touched(&held, &BTreeSet::from([leaf]));
    assert!(c.evaluated.is_empty(), "{c:?}");
    assert_eq!(c.extended, BTreeSet::from([leaf]));
    assert!(check(&held, &inc, &n).is_none());
    let prev = w.held();
    w.set(k, g, leaf, edge(osis_core::Role::Read), 20, &[]);
    let held = w.held();
    let c = inc.update_touched(&held, &touched_of(&prev, &held));
    assert_eq!(c.extended, BTreeSet::from([g]), "{c:?}");
    assert!(check(&held, &inc, &n).is_none());
}

fn touched_of(a: &osis_perm::MemoryHeldSet, b: &osis_perm::MemoryHeldSet) -> BTreeSet<Tid> {
    touched(a, b)
}
