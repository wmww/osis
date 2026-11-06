//! Incremental evaluation (spec/permissions.md §5.1 step 5: D is rebuilt from
//! scratch on any change): per-component timelines, cached or continued past their last write,
//! equal the whole held set's timeline after every arrival, in random and in timeline order.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

use crate::common;

use common::*;
use roles_model::{edges, joint, Rng};
use osis_base::Tid;
use osis_perm::{At, HeldSet, Timeline, Timelines, WriteId};
use std::collections::{BTreeMap, BTreeSet};

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
            if part.falls(n, &t) != full.falls(n, &t) {
                return Some(format!("falls of {n:?} on {t:?}: part {:?} full {:?}", part.falls(n, &t), full.falls(n, &t)));
            }
        }
        // the index `departures` reads, kept over this `inc`'s appends and resumes
        let on = |tl: &Timeline| tl.applied_on(&t).map(|(c, o)| (c.point(), o.clone())).collect::<Vec<_>>();
        let scan: Vec<_> = full.applied().keys().filter_map(|w| full.role_commit(&w.0).and_then(|mc| mc.ops.get(w.1 as usize).map(|o| (mc.point(), o.clone())))).filter(|(_, o)| o.target == t).collect();
        if on(part) != scan {
            return Some(format!("edge writes applied on {t:?}: part {:?} scan {scan:?}", on(part)));
        }
        if part.standing_since(&t) != full.standing_since(&t) {
            return Some(format!("standing since of {t:?}"));
        }
        // the edge history too: roles before every applied write
        for a in full.applied().values() {
            for n in nodes {
                if part.role(n, &t, At::before(a.point)) != full.role(n, &t, At::before(a.point)) {
                    return Some(format!("role of {n:?} on {t:?} before {:?}", a.point));
                }
                // layer 2 there (re-grant's `first_held` is carried over `extend`)
                let p = osis_perm::Point { node: *n, commit: osis_base::CommitId([0xee; 32]), ..a.point };
                for r in [osis_base::Role::Read, osis_base::Role::Write, osis_base::Role::Admin] {
                    if part.delta_valid(p, &t, r) != full.delta_valid(p, &t, r) {
                        return Some(format!("validity of {n:?}'s {r:?} delta on {t:?} at {p:?}"));
                    }
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

/// 1-3 leaves (things only their `created.0` names) under random held things, leaves included,
/// and 0-2 things the history names whose `created.0` arrives late (§1: their record
/// edges), each with the step from which its `created.0` is held
/// (0: from the start).
fn add_leaves(w: &mut World, rng: &mut Rng, steps: usize) -> Vec<(Tid, usize)> {
    let mut out = Vec::new();
    for _ in 0..1 + rng.below(3) {
        let admins: Vec<Tid> = w.created.keys().copied().collect();
        let t = w.thing(admins[rng.below(admins.len())]);
        out.push((t, rng.below(steps + 1)));
    }
    let named: Vec<Tid> = w.created.iter().filter(|(t, r)| !matches!(r, osis_base::CreationRecord::KeyActor { .. }) && !out.iter().any(|l| l.0 == **t)).map(|(t, _)| *t).collect();
    for _ in 0..rng.below(3) {
        if !named.is_empty() {
            out.push((named[rng.below(named.len())], rng.below(steps + 1)));
        }
    }
    out
}

/// The held set without `skip` and without the leaves not held by `step`.
fn held_at(w: &World, skip: &BTreeSet<osis_base::CommitId>, leaves: &[(Tid, usize)], step: usize) -> osis_perm::MemoryHeldSet {
    let mut h = w.held_without(skip);
    for (t, at) in leaves {
        if *at > step {
            h.created.remove(t);
        }
    }
    h
}

/// Things whose held inputs differ between two held sets (what a node tracks as it adds).
fn touched(a: &osis_perm::MemoryHeldSet, b: &osis_perm::MemoryHeldSet) -> BTreeSet<Tid> {
    let mut all: BTreeSet<Tid> = a.things().into_iter().collect();
    all.extend(b.things());
    let key = |h: &osis_perm::MemoryHeldSet, t: &Tid| {
        let c: BTreeSet<_> = h.edge_commits(t).iter().map(|c| c.id).collect();
        (c, h.created(t))
    };
    all.into_iter().filter(|t| key(a, t) != key(b, t)).collect()
}

/// (appended, placed) summed over shards.
fn sum(v: Vec<(usize, usize)>) -> (usize, usize) {
    v.into_iter().fold((0, 0), |a, b| (a.0 + b.0, a.1 + b.1))
}

/// Returns how many updates `Timelines::append` did alone.
fn run(samples: u64, seed: u64) -> usize {
    let mut appended = 0;
    let seed = seeded(seed);
    let mut rng = Rng(seed);
    for s in 0..samples {
        // Two or three independent histories in one held set: several components.
        let mut w = World::new();
        let mut nodes = Vec::new();
        for k in 0..2 + rng.below(2) {
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
        let leaves = add_leaves(&mut w, &mut rng, order.len());
        let mut held_ids = BTreeSet::new();
        let mut inc = Timelines::new();
        let all: BTreeSet<_> = w.commits.iter().map(|c| c.id).collect();
        // half the samples re-partition only around what changed
        let around = rng.below(2) == 0;
        let mut prev = held_at(&w, &all, &leaves, 0);
        if around {
            inc.update(&prev);
        }
        // each step: the leaves arriving then (alone), then the commit
        for (step, &i) in order.iter().enumerate() {
            for leaves_only in [true, false] {
                if leaves_only {
                    if !leaves.iter().any(|l| l.1 == step + 1) {
                        continue;
                    }
                } else {
                    held_ids.insert(w.commits[i].id);
                }
                let skip: BTreeSet<_> = all.difference(&held_ids).copied().collect();
                let held = held_at(&w, &skip, &leaves, step + 1);
                if around {
                    update_moved(&mut inc, &held, &prev);
                    appended += inc.appended();
                } else {
                    inc.update(&held);
                }
                prev = held.clone();
                if let Some(d) = check(&held, &inc, &nodes) {
                    panic!("seed {seed:#x} sample {s} step {step} (leaves only: {leaves_only}): {d}");
                }
            }
        }
        // Nothing changed: nothing is evaluated again.
        assert_eq!(inc.update(&w.held()), 0);
    }
    appended
}

/// §5.1 step 5: two sibling teams that are admins of each other (authority on each may come
/// through the other): each write in timeline order continues the walk (`extend`),
/// equal to evaluating from scratch.
#[test]
fn mutual_admin_teams_extend() {
    use osis_base::Role::{Admin, Write};
    let mut w = World::new();
    let n = w.nodes(4);
    let (k, n1, n2, n3) = (n[0], n[1], n[2], n[3]);
    let (a, b) = (w.thing(k), w.thing(k));
    let all: Vec<(Tid, u64)> = n.iter().map(|x| (*x, 0)).collect();
    w.set(k, a, b, edge(Admin), 0, &all);
    w.set(k, b, a, edge(Admin), 0, &all);
    w.set(k, a, n1, edge(Admin), 0, &all);
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
        assert_eq!(next.dropped(), full.dropped());
        assert_eq!(next.applied().keys().collect::<Vec<_>>(), full.applied().keys().collect::<Vec<_>>());
        for t in [a, b] {
            assert_eq!(next.roster(&t, At::END), full.roster(&t, At::END));
        }
        tl = Some(next);
    }
}

/// §5.1 step 5: incremental equals from scratch.
#[test]
fn incremental_equals_from_scratch() {
    assert!(run(10, 0x5eed_0301) > 0);
}

#[test]
#[ignore]
fn incremental_equals_from_scratch_large() {
    assert!(sharded(1_024, 0x5eed_0302, run).iter().sum::<usize>() > 0);
}

/// A `created.0` arriving before, between or after the commits naming its thing: the cached
/// component is re-evaluated, in every arrival order.
#[test]
fn created_late_every_order() {
    let mut w = World::new();
    let n = w.nodes(2);
    let (k, x) = (n[0], n[1]);
    let g = w.thing(k);
    let d = w.thing(g);
    let c1 = w.set(k, g, x, edge(osis_base::Role::Admin), 10, &[]);
    let c2 = w.set(x, d, k, edge(osis_base::Role::Write), 11, &[]);
    // Arrivals: 0 = g's created.0, 1 = c1, 2 = c2.
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

/// §1, §5.1: a record edge removed by another admin (cut, stored nowhere) and the record of
/// a thing below arriving before, between or after the commits: by re-partition and by touched
/// things, every arrival order of the record and four commits equals from scratch (the record
/// edge in force from the start, its removal holding, the removed first admin's grant void).
#[test]
fn record_edge_cut_late_record_every_order_spec_permissions_1() {
    let mut w = World::new();
    let n = w.nodes(3);
    let g = w.thing(n[0]);
    let d = w.thing(g);
    let c1 = w.set(n[0], g, n[1], edge(osis_base::Role::Admin), 10, &[(n[1], 10)]);
    let c2 = w.set(n[1], g, n[0], None, 11, &[(n[0], 12)]);
    let c3 = w.set(n[0], g, n[2], edge(osis_base::Role::Write), 13, &[]);
    let c4 = w.set(n[1], d, n[2], edge(osis_base::Role::Read), 14, &[]);
    let cs = [c1, c2, c3, c4];
    // arrivals: 0 = g's created.0, 1 = d's, 2.. = the commits
    let mut orders: Vec<Vec<usize>> = vec![vec![]];
    for k in 0..6 {
        orders = orders.into_iter().flat_map(|o: Vec<usize>| (0..=o.len()).map(move |p| { let mut o = o.clone(); o.insert(p, k); o })).collect();
    }
    for order in orders {
        for touched_only in [false, true] {
            let held_with = |have: &BTreeSet<usize>| {
                let skip: BTreeSet<_> = cs.iter().enumerate().filter(|(i, _)| !have.contains(&(i + 2))).map(|(_, c)| *c).collect();
                let mut h = w.held_without(&skip);
                for (i, t) in [(0, g), (1, d)] {
                    if !have.contains(&i) {
                        h.created.remove(&t);
                    }
                }
                h
            };
            let mut have = BTreeSet::new();
            let mut prev = held_with(&have);
            let mut inc = Timelines::new();
            inc.update(&prev);
            for &a in &order {
                have.insert(a);
                let held = held_with(&have);
                if touched_only {
                    inc.update_touched(&held, &touched(&prev, &held));
                } else {
                    inc.update(&held);
                }
                if let Some(dd) = check(&held, &inc, &n) {
                    panic!("order {order:?} touched {touched_only} after {a}: {dd}");
                }
                prev = held;
            }
            let full = Timeline::evaluate(&prev);
            assert_eq!(full.role(&n[0], &g, At::END), None, "the removed first admin");
            assert!(!full.is_applied(&WriteId(c3, 0)));
            assert_eq!(full.role(&n[2], &d, At::END), Some(osis_base::Role::Read));
            for t in [g, d] {
                assert_eq!(inc.get(&t).map(|tl| tl.roster(&t, At::END)), Some(full.roster(&t, At::END)), "order {order:?} touched {touched_only}");
            }
        }
    }
}

/// spec/permissions.md §5.1 "R never demotes its own author": the kept standing carried through a removal of an
/// absent edge (`differential::absent_edge_removal_spread_hist`), its writes arriving in every
/// order after the genesis (late ones inserted mid-walk), by re-partition and by touched
/// things; each equals from scratch.
#[test]
fn kept_standing_absent_edge_every_order() {
    let (w, n, _) = joint_world(&crate::differential::absent_edge_removal_spread_hist(), 1);
    let ids: Vec<_> = w.commits.iter().map(|c| c.id).collect();
    let genesis = 2;
    let mut orders = vec![vec![]];
    for k in genesis..ids.len() {
        orders = orders.into_iter().flat_map(|o: Vec<usize>| (0..=o.len()).map(move |p| { let mut o = o.clone(); o.insert(p, k); o })).collect();
    }
    for order in orders {
        for touched_only in [false, true] {
            let mut skip: BTreeSet<_> = ids[genesis..].iter().copied().collect();
            let mut prev = w.held_without(&skip);
            let mut inc = Timelines::new();
            inc.update(&prev);
            for &i in &order {
                skip.remove(&ids[i]);
                let held = w.held_without(&skip);
                if touched_only {
                    inc.update_touched(&held, &touched(&prev, &held));
                } else {
                    inc.update(&held);
                }
                if let Some(d) = check(&held, &inc, &n) {
                    panic!("order {order:?} (touched {touched_only}) after {i}: {d}");
                }
                prev = held;
            }
        }
    }
}

/// §5.1: a new thing's `created.0` alone (nothing names it yet: `Timeline::add_leaves`, no held-set
/// gathering) and a write after every held one continue the component's timeline; each reports what
/// changed (the leaf; the write's target), and the result equals an evaluation from scratch.
#[test]
fn leaves_and_appends_extend() {
    let mut w = World::new();
    let n = w.nodes(2);
    let (k, x) = (n[0], n[1]);
    let g = w.thing(k);
    w.set(k, g, x, edge(osis_base::Role::Write), 10, &[]);
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
    // O(1) in the component: no re-partition, no held-set gathering
    assert_eq!(inc.appended(), 1);
    assert!(check(&held, &inc, &n).is_none());
    let prev = w.held();
    w.set(k, g, leaf, edge(osis_base::Role::Read), 20, &[]);
    let held = w.held();
    let c = inc.update_touched(&held, &touched_of(&prev, &held));
    assert_eq!(c.extended, BTreeSet::from([g]), "{c:?}");
    assert_eq!(inc.appended(), 1);
    assert!(check(&held, &inc, &n).is_none());
}

/// §5.1, §5.2: a write arriving late in the middle of a history longer than the timeline's kept
/// edge states rolls the walk back there (`extend`); the states and the re-grant answers
/// (`first_held`) kept from before it, and those rebuilt after, equal an evaluation from
/// scratch. Holder 1, admin at the end, has its first point holding admin moved earlier by the late
/// write.
#[test]
fn late_write_mid_history_keeps_states_exact() {
    use osis_base::Role::{Admin, Read, Write};
    let mut w = World::new();
    let n = w.nodes(6);
    let k = n[0];
    let g = w.thing(k);
    for i in 0..600u64 {
        let (m, e) = match i {
            550 | 599 => (n[1], edge(Admin)),
            _ => (n[1 + (i % 5) as usize], edge(if (i / 5) % 2 == 0 { Read } else { Write })),
        };
        w.set(k, g, m, e, 2 * i + 2, &[]);
    }
    let late = w.set(k, g, n[1], edge(Admin), 601, &[]);
    let held = w.held_without(&BTreeSet::from([late]));
    let mut inc = Timelines::new();
    inc.update(&held);
    let tl = inc.get(&g).unwrap();
    for x in &n {
        for a in tl.applied().values() {
            for r in [Read, Write, Admin] {
                let _ = tl.delta_valid(osis_perm::Point { node: *x, ..a.point }, &g, r);
            }
        }
    }
    let all = w.held();
    let c = inc.update_touched(&all, &touched_of(&held, &all));
    assert!(c.evaluated.is_empty(), "{c:?}");
    assert_eq!(inc.appended(), 1);
    assert!(check(&all, &inc, &n).is_none(), "{:?}", check(&all, &inc, &n));
}

// spec: none (costs, spec/requirements.md Scale): an edge joining a person's component to a chat's
// of T things finds the region reading each component's things once: T, not T^2.
#[test]
fn region_reads_each_component_once() {
    use osis_base::Role::{Admin, Write};
    let mut w = World::new();
    let n = w.nodes(42);
    let (k, y) = (n[0], n[41]);
    let g = w.thing(k);
    for (i, m) in n[1..41].iter().enumerate() {
        w.set(k, g, *m, edge(Write), 10 + i as u64, &[]);
    }
    // a person of its own, with a commit: not a lone node, so the general path
    let p = w.thing(y);
    w.set(y, p, y, edge(Admin), 100, &[]);
    let held = w.held();
    let mut inc = Timelines::new();
    let all: BTreeSet<Tid> = held.things().into_iter().collect();
    inc.update_touched(&held, &all);
    w.set(k, g, p, edge(Write), 200, &[]);
    let joined = w.held();
    inc.update_touched(&joined, &touched_of(&held, &joined));
    assert_eq!(inc.appended(), 0, "the general path");
    assert!(inc.region_queued() <= 2 * n.len(), "{} things queued for {} things", inc.region_queued(), n.len());
    assert!(check(&joined, &inc, &n).is_none(), "{:?}", check(&joined, &inc, &n));
}

// spec: none (costs, spec/requirements.md Scale): the edge writes on each of a component's things
// are read off one index, so departures below a chat of M members read M writes, not M^2; a write
// after it moves them.
#[test]
fn applied_on_indexes_a_timeline_once() {
    use osis_base::Role::Write;
    let mut w = World::new();
    let n = w.nodes(30);
    let k = n[0];
    let things: Vec<Tid> = (0..10).map(|_| w.thing(k)).collect();
    for (i, t) in things.iter().enumerate() {
        w.set(k, *t, n[1 + i], edge(Write), 10 + i as u64, &[]);
    }
    let held = w.held();
    let mut inc = Timelines::new();
    inc.update(&held);
    let tl = inc.get(&things[0]).unwrap();
    for t in &things {
        assert_eq!(tl.applied_on(t).count(), 1);
    }
    assert_eq!(tl.applied_on_built(), 1, "one index for all the things");
    let prev = w.held();
    w.set(k, things[3], n[20], edge(Write), 100, &[]);
    let held = w.held();
    inc.update_touched(&held, &touched_of(&prev, &held));
    let tl = inc.get(&things[3]).unwrap();
    assert_eq!(tl.applied_on(&things[3]).count(), 2, "the write after it");
}

fn touched_of(a: &osis_perm::MemoryHeldSet, b: &osis_perm::MemoryHeldSet) -> BTreeSet<Tid> {
    touched(a, b)
}

const SALT: &[u8] = b"rules";

/// A node's walk cache: what `to_save` asked to keep, by root.
type Disk = BTreeMap<Tid, Vec<u8>>;

fn store(disk: &mut Disk, s: osis_perm::Saves) {
    for r in s.delete {
        disk.remove(&r);
    }
    disk.extend(s.put);
}

/// A restart: fresh timelines over `held`, components restored from `disk`.
fn reopen(held: &osis_perm::MemoryHeldSet, disk: &Disk, salt: &[u8]) -> Timelines {
    let mut inc = Timelines::new();
    let all: BTreeSet<Tid> = held.things().into_iter().collect();
    inc.update_touched_cached(held, &all, &mut |r| disk.get(r).cloned(), salt);
    inc
}

/// Random arrivals with the walks saved now and then (stale in between) and restarts from
/// them: equal to a from-scratch evaluation after every step; a walk saved over exactly the
/// held inputs and restored saves byte-identical bytes again.
fn run_restarts(samples: u64, seed: u64) {
    let seed = seeded(seed);
    let mut rng = Rng(seed);
    let mut restored = 0;
    for s in 0..samples {
        let mut w = World::new();
        let mut nodes = Vec::new();
        for k in 0..1 + rng.below(2) {
            let (wk, nk) = if rng.below(2) == 0 {
                let (wk, nk, _) = joint_world(&joint::random_hist(&mut rng), 10 + k as u8);
                (wk, nk)
            } else {
                let (wk, nk, _) = edges_world(&edges::random_hist(&mut rng), 10 + k as u8);
                (wk, nk)
            };
            w.merge(wk);
            nodes.extend(nk);
        }
        let order = if rng.below(2) == 0 {
            rng.perm(w.commits.len())
        } else {
            let mut o: Vec<usize> = (0..w.commits.len()).collect();
            o.sort_by_key(|&i| (w.commits[i].t, w.commits[i].author, w.commits[i].id));
            o
        };
        let leaves = add_leaves(&mut w, &mut rng, order.len());
        let all: BTreeSet<_> = w.commits.iter().map(|c| c.id).collect();
        let mut held_ids = BTreeSet::new();
        let mut prev = held_at(&w, &all, &leaves, 0);
        let mut inc = Timelines::new();
        inc.update(&prev);
        let mut disk = Disk::new();
        let min = 1 + rng.below(4);
        // half the samples deliver the leaves of a step alone, before its commit
        let alone = rng.below(2) == 0;
        for (step, &i) in order.iter().enumerate() {
            if alone && leaves.iter().any(|l| l.1 == step + 1) {
                let held = held_at(&w, &all.difference(&held_ids).copied().collect(), &leaves, step + 1);
                inc.update_touched(&held, &touched(&prev, &held));
                prev = held.clone();
                if let Some(d) = check(&held, &inc, &nodes) {
                    panic!("seed {seed:#x} sample {s} step {step} (leaves alone): {d}");
                }
            }
            held_ids.insert(w.commits[i].id);
            let held = held_at(&w, &all.difference(&held_ids).copied().collect(), &leaves, step + 1);
            inc.update_touched(&held, &touched(&prev, &held));
            prev = held.clone();
            let saved_all = rng.below(4) == 0;
            if saved_all || rng.below(3) == 0 {
                let mut saves = inc.to_save(SALT, min, saved_all);
                inc.saved(std::mem::take(&mut saves.done));
                if saved_all {
                    disk.clear();
                }
                store(&mut disk, saves);
            }
            if rng.below(3) == 0 {
                inc = reopen(&held, &disk, SALT);
                restored += inc.restored();
                if let Some(d) = check(&held, &inc, &nodes) {
                    panic!("seed {seed:#x} sample {s} step {step} after a restart: {d}");
                }
                if saved_all {
                    // restored over exactly its inputs: the same bytes again
                    let again: Disk = inc.to_save(SALT, min, true).put.into_iter().collect();
                    assert_eq!(again, disk, "seed {seed:#x} sample {s} step {step}: restored walks save other bytes");
                }
            } else if let Some(d) = check(&held, &inc, &nodes) {
                panic!("seed {seed:#x} sample {s} step {step}: {d}");
            }
        }
    }
    assert!(restored > 0, "no walk was restored");
}

// spec/permissions.md §5.1 step 5 (a pure function of the held set): a restart from saved walks
// (notes/local-store.md, rebuildable caches) gives what a from-scratch evaluation gives.
#[test]
fn restart_from_saved_walks_equals_from_scratch() {
    run_restarts(25, 0x5eed_0303);
}

#[test]
#[ignore]
fn restart_from_saved_walks_equals_from_scratch_large() {
    sharded(2_000, 0x5eed_0304, run_restarts);
}

// spec/permissions.md §5.1 step 5: a saved walk that is damaged, truncated, saved under other
// rules (salt) or over other inputs is never used; the component is evaluated from scratch.
#[test]
fn damaged_or_foreign_saved_walk_is_ignored() {
    let mut rng = Rng(seeded(0x5eed_0305));
    let mut tried = 0;
    while tried < 20 {
        let (w, nodes, _) = edges_world(&edges::random_hist(&mut rng), 10);
        let held = w.held();
        let mut inc = Timelines::new();
        inc.update(&held);
        let disk: Disk = inc.to_save(SALT, 1, true).put.into_iter().collect();
        if disk.is_empty() {
            continue;
        }
        tried += 1;
        assert!(reopen(&held, &disk, SALT).restored() > 0);
        let mut bad: Vec<(&str, Disk, &[u8])> = vec![("other rules", disk.clone(), b"other rules")];
        let (root, bytes) = disk.iter().next().map(|(r, b)| (*r, b.clone())).unwrap();
        let mut flipped = bytes.clone();
        let at = rng.below(flipped.len());
        flipped[at] ^= 1 << rng.below(8);
        bad.push(("a flipped bit", BTreeMap::from([(root, flipped)]), SALT));
        let cut = rng.below(bytes.len());
        bad.push(("truncated", BTreeMap::from([(root, bytes[..cut].to_vec())]), SALT));
        bad.push(("extended", BTreeMap::from([(root, [bytes.as_slice(), &[0]].concat())]), SALT));
        // another history's walk under this root
        let (w2, _, _) = edges_world(&edges::random_hist(&mut rng), 10);
        let mut other = Timelines::new();
        other.update(&w2.held());
        if let Some((_, b)) = other.to_save(SALT, 1, true).put.into_iter().next() {
            bad.push(("another history", BTreeMap::from([(root, b)]), SALT));
        }
        for (what, d, salt) in bad {
            let inc = reopen(&held, &d, salt);
            let n = if what == "other rules" { 0 } else { disk.len() - 1 };
            assert!(inc.restored() <= n, "{what}: used");
            assert_eq!(check(&held, &inc, &nodes), None, "{what}");
            // the unusable walk is overwritten
            let s = inc.to_save(salt, 1, false);
            assert!(s.put.iter().any(|(r, _)| *r == root) || s.delete.contains(&root), "{what}: not replaced");
        }
    }
}

/// §5.1 step 5: `Timeline::extend` given new commits and new leaves at once (some named by the
/// new commits) equals an evaluation from scratch, or declines.
#[test]
fn extend_over_commits_and_leaves_together() {
    let mut rng = Rng(seeded(0x5eed_0306));
    let mut extended = 0;
    for s in 0..60 {
        let (mut w, nodes, _) = edges_world(&edges::random_hist(&mut rng), 10);
        let mut order: Vec<usize> = (0..w.commits.len()).collect();
        order.sort_by_key(|&i| (w.commits[i].t, w.commits[i].author, w.commits[i].id));
        let leaves = add_leaves(&mut w, &mut rng, 0);
        // later commits, some naming a leaf
        let tmax = w.commits.iter().map(|c| c.t).max().unwrap_or(0);
        let authors: Vec<Tid> = w.commits.iter().map(|c| c.author).collect();
        for (k, (leaf, _)) in leaves.iter().enumerate() {
            if rng.below(2) == 0 && !authors.is_empty() {
                let a = authors[rng.below(authors.len())];
                let m = nodes[rng.below(nodes.len())];
                w.set(a, *leaf, m, edge(osis_base::Role::Write), tmax + 1 + k as u64, &[]);
            }
        }
        let split = rng.below(order.len() + 1);
        let skip: BTreeSet<_> = w.commits.iter().map(|c| c.id).filter(|id| order[..split].iter().all(|&i| w.commits[i].id != *id)).collect();
        let mut before = w.held_without(&skip);
        for (l, _) in &leaves {
            before.created.remove(l);
        }
        let after = w.held();
        let Some(tl) = Timeline::evaluate(&before).extend(&after) else { continue };
        extended += 1;
        let full = Timeline::evaluate(&after);
        for t in after.things() {
            for n in &nodes {
                assert_eq!(tl.demotions(n, &t), full.demotions(n, &t), "sample {s}: demotions of {n:?} on {t:?}");
                assert_eq!(tl.falls(n, &t), full.falls(n, &t), "sample {s}: falls of {n:?} on {t:?}");
                assert_eq!(tl.standing(n, &t, At::END), full.standing(n, &t, At::END), "sample {s}");
            }
        }
        assert_eq!(tl.dropped(), full.dropped(), "sample {s}");
    }
    assert!(extended > 10, "{extended}");
}

/// §5.1 steps 4-5: a write arriving late before a demotion whose audit dropped an earlier write
/// goes on from the dropped write (that drop is forgotten and found again), not from scratch;
/// a later one that keeps the demoted node's class (a second admin edge) undoes the drop.
#[test]
fn late_write_before_a_drop_goes_on_spec_permissions_5_1() {
    use osis_base::Role::{Admin, Read, Write};
    let mut w = World::new();
    let n = w.nodes(5);
    let (k, a, b, m) = (n[0], n[1], n[2], n[3]);
    let g = w.thing(k);
    let team = w.thing(k);
    w.set(k, g, a, edge(Admin), 1, &[]);
    w.set(k, g, b, edge(Read), 1, &[]);
    w.set(k, g, team, edge(Read), 1, &[]);
    w.set(k, team, a, edge(Read), 1, &[]);
    w.set(a, g, m, edge(Write), 2, &[]);
    w.set(k, g, a, None, 6, &[]);
    let late = [w.set(k, g, b, edge(Write), 3, &[]), w.set(k, g, team, edge(Admin), 4, &[]), w.set(k, team, a, edge(Admin), 5, &[])];
    let mut skip: BTreeSet<_> = late.into_iter().collect();
    let mut prev = w.held_without(&skip);
    let mut inc = Timelines::new();
    inc.update(&prev);
    assert_eq!(inc.get(&g).unwrap().dropped().len(), 1);
    for id in late {
        skip.remove(&id);
        let held = w.held_without(&skip);
        let c = inc.update_touched(&held, &touched(&prev, &held));
        assert!(c.evaluated.is_empty(), "{c:?}");
        assert_eq!(inc.appended(), 1);
        assert!(check(&held, &inc, &n).is_none(), "{:?}", check(&held, &inc, &n));
        prev = held;
    }
    // a keeps edge admin through the team: no fall, nothing dropped
    assert!(inc.get(&g).unwrap().dropped().is_empty());
}

/// §5.1 step 2: late writes in the middle of a history that apply nothing there (by a node with
/// no authority at that point) leave the walk as it is (`Timeline::append` judges them over the
/// edge state at their place), equal to an evaluation from scratch.
#[test]
fn late_writes_applying_nothing_spec_permissions_5_1() {
    use osis_base::Role::{Admin, Read, Write};
    let mut w = World::new();
    let n = w.nodes(5);
    let (k, a, x) = (n[0], n[1], n[4]);
    let (g, h) = (w.thing(k), w.thing(k));
    w.set(k, g, a, edge(Admin), 1, &[]);
    w.set(k, h, x, edge(Read), 1, &[]);
    for i in 0..40u64 {
        w.set(a, g, n[2 + (i % 2) as usize], edge(if (i / 2) % 2 == 0 { Read } else { Write }), 2 + 2 * i, &[]);
        // x writes on h (rejected: read only) and on g (rejected), early on
        if i < 2 {
            w.set(x, h, n[2], edge(Write), 3 + 2 * i, &[]);
            w.set(x, g, n[3], edge(Write), 3 + 2 * i, &[]);
        }
    }
    // late: x's writes in the middle (rejected)
    let late = [w.set(x, h, n[3], edge(Write), 41, &[]), w.set(x, g, n[2], edge(Admin), 43, &[])];
    let mut skip: BTreeSet<_> = late.into_iter().collect();
    let mut prev = w.held_without(&skip);
    let mut inc = Timelines::new();
    inc.update(&prev);
    for id in late {
        skip.remove(&id);
        let held = w.held_without(&skip);
        let c = inc.update_touched(&held, &touched(&prev, &held));
        assert!(c.evaluated.is_empty(), "{c:?}");
        assert_eq!(inc.appended(), 1);
        assert!(check(&held, &inc, &n).is_none(), "{:?}", check(&held, &inc, &n));
        prev = held;
    }
}

/// §5.1 steps 4-5 (D only grows across the walks): a late write that applies nothing in the
/// final walk may apply in an earlier walk, before a later drop took its author's authority,
/// and drop there; a's removal of x applies while b's grant to a stands, dropping x's grant to
/// y, and stays dropped after k's removal of b drops that grant.
#[test]
fn late_write_idle_only_in_final_walk_spec_permissions_5_1() {
    use osis_base::Role::{Admin, Write};
    let mut w = World::new();
    let n = w.nodes(6);
    let (k, a, b, x, y, z) = (n[0], n[1], n[2], n[3], n[4], n[5]);
    let g = w.thing(k);
    w.set(k, g, b, edge(Admin), 1, &[]);
    w.set(k, g, x, edge(Admin), 1, &[]);
    w.set(b, g, a, edge(Admin), 2, &[]);
    w.set(x, g, y, edge(Write), 2, &[]);
    w.set(a, g, z, edge(Write), 3, &[]);
    w.set(k, g, b, None, 6, &[]);
    let late = w.set(a, g, x, None, 4, &[]);
    let prev = w.held_without(&BTreeSet::from([late]));
    let mut inc = Timelines::new();
    inc.update(&prev);
    let held = w.held();
    inc.update_touched(&held, &touched(&prev, &held));
    assert!(check(&held, &inc, &n).is_none(), "{:?}", check(&held, &inc, &n));
}

/// Random small histories built to drop and un-drop (few nodes, every one an admin at first;
/// grants, removals, demotions with partial frontiers, invites, `until`, a team; two nodes
/// only some writes name, one with its
/// `created.0` held, one without), the second half arriving late in random order through
/// `update_touched`: equal to an evaluation from scratch after every arrival. Returns how many
/// updates `Timelines::append` did alone.
fn adversarial(samples: u64, seed: u64) -> usize {
    use osis_base::Role::{Admin, Read, Write};
    let seed = seeded(seed);
    let mut rng = Rng(seed);
    let mut appended = 0;
    for s in 0..samples {
        let mut w = World::new();
        let mut n = w.nodes(5);
        let k = n[0];
        let g = w.thing(k);
        let team = w.thing(k);
        let extra = [w.nodes_salted(1, 0x77)[0], key_actors(1, 0x78)[0].0];
        let targets = [g, g, g, team];
        for (i, x) in n.iter().enumerate().skip(1) {
            w.set(k, if i == 4 { team } else { g }, *x, edge(Admin), 1, &[]);
        }
        w.set(k, g, team, edge(if rng.below(2) == 0 { Admin } else { Write }), 1, &[]);
        let mut late = Vec::new();
        for _ in 0..10 + rng.below(10) {
            let author = if rng.below(10) == 0 { extra[rng.below(2)] } else { n[if rng.below(6) == 0 { 0 } else { 1 + rng.below(4) }] };
            let target = targets[rng.below(targets.len())];
            let holder = match rng.below(10) {
                0 if target == g => team,
                1 => extra[rng.below(2)],
                _ => n[1 + rng.below(4)],
            };
            let e = match rng.below(7) {
                0 | 1 => None,
                2 => edge(Read),
                3 => edge(Write),
                4 => edge_inv(Write, Some(Read), None),
                5 => edge_inv(Admin, None, Some(5 + rng.below(25) as u64)),
                _ => edge(Admin),
            };
            let t = 2 + rng.below(30) as u64;
            // a frontier covering some of what came before
            let recv: Vec<(Tid, u64)> = if rng.below(3) == 0 { Vec::new() } else { n.iter().map(|x| (*x, rng.below(32) as u64)).collect() };
            let id = w.set(author, target, holder, e, t, &[]);
            if let Some(c) = w.commits.iter_mut().find(|c| c.id == id) {
                for (x, r) in &recv {
                    c.recv.entry(*x).or_insert(*r);
                }
            }
            if rng.below(2) == 0 {
                late.push(id);
            }
        }
        n.extend(extra);
        let order = rng.perm(late.len());
        let mut skip: BTreeSet<_> = late.iter().copied().collect();
        let mut prev = w.held_without(&skip);
        let mut inc = Timelines::new();
        inc.update(&prev);
        for (step, i) in order.into_iter().enumerate() {
            skip.remove(&late[i]);
            let held = w.held_without(&skip);
            update_moved(&mut inc, &held, &prev);
            appended += inc.appended();
            if let Some(d) = check(&held, &inc, &n) {
                panic!("seed {seed:#x} sample {s} step {step}: {d}");
            }
            prev = held;
        }
    }
    appended
}

/// §5.1 steps 4-5: late arrivals through `update_touched` equal from scratch.
#[test]
fn append_adversarial_equals_from_scratch() {
    assert!(adversarial(30, 0x5eed_0311) > 0);
}

#[test]
#[ignore]
fn append_adversarial_equals_from_scratch_large() {
    assert!(sharded(3_000, 0x5eed_0312, adversarial).iter().sum::<usize>() > 0);
}

/// §5.1 steps 2-4: writes arriving late in the middle of a history that apply, by an admin
/// with an earlier write there, are placed in the walk without walking again when no later
/// item reads what they change (a read or write grant to a holder no later write names);
/// one that a later write on its edge reads, or an admin grant whose holder writes later,
/// goes on from it. Each equals an evaluation from scratch.
#[test]
fn late_writes_placed_in_walk_spec_permissions_5_1() {
    use osis_base::Role::{Admin, Read, Write};
    let mut w = World::new();
    let n = w.nodes(8);
    let (k, a, b) = (n[0], n[1], n[2]);
    let g = w.thing(k);
    let team = w.thing(k);
    w.set(k, g, a, edge(Admin), 1, &[]);
    w.set(k, g, b, edge(Admin), 1, &[]);
    w.set(k, g, team, edge(Write), 1, &[]);
    for i in 0..200u64 {
        let m = n[3 + (i % 3) as usize];
        let e = match i % 4 {
            0 => None,
            1 => edge(Read),
            _ => edge(Write),
        };
        let author = if i % 2 == 0 { a } else { b };
        w.set(author, if i % 5 == 0 { team } else { g }, m, e, 10 + 2 * i, &[(m, 10 + 2 * i)]);
    }
    w.set(b, g, n[3], edge(Admin), 300, &[]);
    w.set(n[3], g, n[4], edge(Read), 310, &[]);
    // (late write, placed without a walk)
    let late = [
        (w.set(a, g, n[6], edge(Read), 101, &[]), true),
        (w.set(b, g, n[7], edge(Write), 151, &[]), true),
        (w.set(a, team, n[6], edge(Write), 201, &[]), true),
        (w.set(a, g, n[4], edge(Read), 251, &[]), false),
        (w.set(a, g, n[3], edge(Admin), 203, &[]), false),
    ];
    let mut skip: BTreeSet<_> = late.iter().map(|l| l.0).collect();
    let mut prev = w.held_without(&skip);
    let mut inc = Timelines::new();
    inc.update(&prev);
    for (id, placed) in late {
        skip.remove(&id);
        let held = w.held_without(&skip);
        let c = inc.update_touched(&held, &touched(&prev, &held));
        assert!(c.evaluated.is_empty(), "{c:?}");
        assert_eq!(inc.appended(), 1);
        assert_eq!(inc.placed() == 1, placed, "{id:?}");
        assert!(check(&held, &inc, &n).is_none(), "{:?}", check(&held, &inc, &n));
        prev = held;
    }
}

/// §5.1 steps 2-4: late writes placed in a history of many kept edge states: near its start,
/// at its end, forty between the same two kept states (one ts, both authors), several in one
/// update; then the removal of a placed write's holder (an audit nothing later reads: placed)
/// and a removal of their author, which walks again from kept states the placements moved.
/// Each equals an evaluation from scratch.
#[test]
fn late_writes_across_kept_states_spec_permissions_5_1() {
    use osis_base::Role::{Admin, Read, Write};
    let mut w = World::new();
    let n = w.nodes(56);
    let (k, a, b) = (n[0], n[1], n[2]);
    let g = w.thing(k);
    w.set(k, g, a, edge(Admin), 1, &[]);
    w.set(k, g, b, edge(Admin), 1, &[]);
    for i in 0..160u64 {
        let e = match i % 4 {
            0 => None,
            1 => edge(Read),
            _ => edge(Write),
        };
        w.set(if i % 2 == 0 { a } else { b }, g, n[3 + (i % 3) as usize], e, 10 + 2 * i, &[]);
    }
    // (batch, late write, placed without a walk)
    let mut late = vec![(0, w.set(k, g, n[6], edge(Read), 2, &[]), true), (1, w.set(a, g, n[7], edge(Write), 400, &[]), true)];
    for j in 0..40 {
        late.push((2 + j / 3, w.set([a, b][j % 2], g, n[8 + j], edge(Read), 201 + 2 * (j % 2) as u64, &[]), true));
    }
    late.push((20, w.set(b, g, n[6], None, 51, &[]), true));
    late.push((21, w.set(k, g, a, None, 199, &[]), false));
    let mut skip: BTreeSet<_> = late.iter().map(|l| l.1).collect();
    let mut prev = w.held_without(&skip);
    let mut inc = Timelines::new();
    inc.update(&prev);
    let watch = [a, n[3], n[6], n[7], n[9], n[47]];
    let mut i = 0;
    while i < late.len() {
        let batch: Vec<_> = late.iter().skip(i).take_while(|l| l.0 == late[i].0).collect();
        i += batch.len();
        for l in &batch {
            skip.remove(&l.1);
        }
        let held = w.held_without(&skip);
        let c = inc.update_touched(&held, &touched(&prev, &held));
        assert!(c.evaluated.is_empty(), "{c:?}");
        assert_eq!(inc.appended(), 1);
        let want = batch.iter().take_while(|l| l.2).count();
        assert_eq!(inc.placed(), want, "batch {}", batch[0].0);
        if batch[0].0 % 5 == 0 || batch[0].0 > 14 {
            assert!(check(&held, &inc, &watch).is_none(), "batch {}: {:?}", batch[0].0, check(&held, &inc, &watch));
        }
        prev = held;
    }
}

/// §5.1: a holder new to the group (a key actor whose `created.0` alone is held, or no record
/// at all) granted late joins the group's walk by `Timelines::append` (a node no earlier write
/// names reaches nothing before it), not by an evaluation from scratch, as does one whose
/// `created.0` arrives with the grant; then writes of its own. Each equals an evaluation from
/// scratch.
#[test]
fn new_holder_joins_walk_spec_permissions_5_1() {
    use osis_base::Role::{Admin, Read, Write};
    let mut w = World::new();
    let n = w.nodes(4);
    let (k, a) = (n[0], n[1]);
    let g = w.thing(k);
    w.set(k, g, a, edge(Admin), 1, &[]);
    for i in 0..50u64 {
        w.set(a, g, n[2 + (i % 2) as usize], edge(if i % 2 == 0 { Read } else { Write }), 2 + i, &[]);
    }
    // new tids above the component's root (a smaller one would move the root)
    let root = *n.iter().chain([&g]).min().unwrap();
    let above = |salt: u8| key_actors(8, salt).into_iter().find(|(t, _)| *t > root).unwrap();
    let (y, yrec) = above(21);
    w.created.insert(y, yrec);
    let z = above(22).0;
    let (v, vrec) = above(23);
    let mut nodes = n.clone();
    nodes.extend([y, z, v]);
    let steps = [
        (w.set(a, g, y, edge(Write), 60, &[]), true),
        (w.set(y, g, y, edge(Read), 61, &[]), true),
        (w.set(a, g, z, edge(Admin), 30, &[]), true),
        (w.set(z, g, n[2], None, 62, &[]), true),
    ];
    let mut skip: BTreeSet<_> = steps.iter().map(|s| s.0).collect();
    let mut prev = w.held_without(&skip);
    let mut inc = Timelines::new();
    inc.update(&prev);
    for (id, alone) in steps {
        skip.remove(&id);
        let held = w.held_without(&skip);
        let c = inc.update_touched(&held, &touched(&prev, &held));
        assert!(c.evaluated.is_empty(), "{c:?}");
        assert_eq!(inc.appended() == 1, alone);
        assert!(check(&held, &inc, &nodes).is_none(), "{:?}", check(&held, &inc, &nodes));
        prev = held;
    }
    w.set(a, g, v, edge(Write), 63, &[]);
    w.created.insert(v, vrec);
    let held = w.held();
    inc.update_touched(&held, &touched(&prev, &held));
    assert_eq!(inc.appended(), 1);
    assert!(check(&held, &inc, &nodes).is_none(), "{:?}", check(&held, &inc, &nodes));
}

/// §5.1: `Timelines::append` records a commit under every thing it writes, touched or not: a
/// later commit on a thing the first named but the update did not touch goes on by `append`.
#[test]
fn append_records_every_target_spec_permissions_5_1() {
    use osis_base::Role::{Admin, Write};
    let mut w = World::new();
    let n = w.nodes(4);
    let k = n[0];
    let (g, h) = (w.thing(k), w.thing(k));
    w.set(k, g, n[1], edge(Admin), 1, &[]);
    w.set(k, h, n[1], edge(Admin), 1, &[]);
    let prev = w.held();
    let mut inc = Timelines::new();
    inc.update(&prev);
    w.commit(n[1], 2, &[(g, n[2], edge(Write)), (h, n[2], edge(Write))], &[]);
    let held = w.held();
    inc.update_touched(&held, &BTreeSet::from([g]));
    assert_eq!(inc.appended(), 1);
    w.set(n[1], h, n[3], edge(Write), 3, &[]);
    let held = w.held();
    inc.update_touched(&held, &BTreeSet::from([h]));
    assert_eq!(inc.appended(), 1);
    assert!(check(&held, &inc, &n).is_none(), "{:?}", check(&held, &inc, &n));
}

/// `check`, plus every node's standing on every thing before every applied write and its
/// certificates after the last one (against a fresh evaluation of the components).
fn check_more(held: &osis_perm::MemoryHeldSet, inc: &Timelines, nodes: &[Tid]) -> Option<String> {
    if let Some(d) = check(held, inc, nodes) {
        return Some(d);
    }
    let full = Timeline::evaluate(held);
    let mut fresh = Timelines::new();
    fresh.update(held);
    for t in held.things() {
        let part = inc.get(&t)?;
        for n in nodes {
            for a in full.applied().values() {
                if part.standing(n, &t, At::before(a.point)) != full.standing(n, &t, At::before(a.point)) {
                    return Some(format!("standing of {n:?} on {t:?} before {:?}", a.point));
                }
            }
            // (per component: a node of another one brings no `keys.0` here)
            let f = fresh.get(&t)?.certificates(n, &t);
            if part.certificates(n, &t) != f {
                return Some(format!("certificates of {n:?} on {t:?}: part {:?} fresh {f:?}", part.certificates(n, &t)));
            }
        }
    }
    None
}

/// Random histories over a record chain (P's first admin the key, Q's P, R's Q), two nested
/// teams and a thing as holder, with `until` on every role, invites of every level, removals,
/// widenings, two-op commits; half the commits arrive late, one to three at a time, in random
/// order through `update_touched`, with restarts from saved walks now and then; equal to an
/// evaluation from scratch after every arrival. Returns (updates `append` did alone, commits
/// placed without walking again).
fn adversarial_shapes(samples: u64, seed: u64) -> (usize, usize) {
    use osis_base::Role::{Admin, Read, Write};
    let seed = seeded(seed);
    let mut rng = Rng(seed);
    let (mut appended, mut placed) = (0, 0);
    for s in 0..samples {
        let mut w = World::new();
        let mut n = w.nodes(6);
        let k = n[0];
        let p = w.thing(k);
        let q = w.thing(p);
        let r = w.thing(q);
        let g = w.thing(k);
        let team = w.thing(k);
        let team2 = w.thing(p);
        let extra = [w.nodes_salted(1, 0x77)[0], key_actors(1, 0x78)[0].0];
        let targets = [p, q, r, g, g, team, team2];
        let holders = [team, team2, p];
        // everyone has a write on every target before the late ones (so they may be placed)
        w.set(k, p, n[1], edge(Admin), 1, &[]);
        w.set(k, p, n[2], edge(Admin), 1, &[]);
        w.set(k, g, n[3], edge(Admin), 1, &[]);
        w.set(k, g, team, edge(if rng.below(2) == 0 { Admin } else { Write }), 1, &[]);
        w.set(k, team, n[4], edge(Admin), 1, &[]);
        w.set(k, team, team2, edge(if rng.below(2) == 0 { Admin } else { Write }), 1, &[]);
        w.set(k, team2, n[5], edge(Admin), 1, &[]);
        for a in &n[1..] {
            for t in targets {
                w.set(*a, t, *a, edge(Admin), 2, &[]);
            }
        }
        let mut late = Vec::new();
        let op = |rng: &mut Rng, n: &[Tid]| {
            let target = targets[rng.below(targets.len())];
            let holder = match rng.below(12) {
                0 | 1 => holders[rng.below(holders.len())],
                2 => extra[rng.below(2)],
                _ => n[1 + rng.below(5)],
            };
            let until = (rng.below(3) == 0).then(|| 5 + rng.below(40) as u64);
            let role = [Read, Write, Admin][rng.below(3)];
            let e = match rng.below(8) {
                0 | 1 => None,
                2 => edge_inv(role, Some([Read, Write, Admin][rng.below(3)].min(role)), until),
                _ => edge_inv(role, None, until),
            };
            (target, holder, e)
        };
        for _ in 0..12 + rng.below(12) {
            let author = if rng.below(12) == 0 { extra[rng.below(2)] } else { n[if rng.below(8) == 0 { 0 } else { 1 + rng.below(5) }] };
            let mut ops = vec![op(&mut rng, &n)];
            if rng.below(4) == 0 {
                let o = op(&mut rng, &n);
                if (o.0, o.1) != (ops[0].0, ops[0].1) {
                    ops.push(o);
                }
            }
            let t = 3 + rng.below(40) as u64;
            let recv: Vec<(Tid, u64)> = if rng.below(3) == 0 { Vec::new() } else { n.iter().map(|x| (*x, rng.below(45) as u64)).collect() };
            let id = w.commit(author, t, &ops, &recv);
            if rng.below(2) == 0 {
                late.push(id);
            }
        }
        n.extend(extra);
        let order = rng.perm(late.len());
        let mut skip: BTreeSet<_> = late.iter().copied().collect();
        let mut prev = w.held_without(&skip);
        let mut inc = Timelines::new();
        inc.update(&prev);
        let mut i = 0;
        while i < order.len() {
            let take = if rng.below(3) == 0 { 1 + rng.below(3) } else { 1 };
            for j in order.iter().skip(i).take(take) {
                skip.remove(&late[*j]);
            }
            i += take;
            let held = w.held_without(&skip);
            update_moved(&mut inc, &held, &prev);
            appended += inc.appended();
            placed += inc.placed();
            if let Some(d) = check_more(&held, &inc, &n) {
                panic!("seed {seed:#x} sample {s} arrival {i}: {d}");
            }
            // now and then a restart from the walks saved now: later arrivals go on from them
            if rng.below(4) == 0 {
                let mut disk = Disk::new();
                store(&mut disk, inc.to_save(SALT, 1, true));
                inc = reopen(&held, &disk, SALT);
                if let Some(d) = check_more(&held, &inc, &n) {
                    panic!("seed {seed:#x} sample {s} arrival {i} after a restart: {d}");
                }
            }
            prev = held;
        }
    }
    (appended, placed)
}

/// §5.1 steps 2-5: late arrivals over record chains, teams, `until`, invites and removals
/// equal from scratch; the placement path runs.
#[test]
fn append_shapes_equals_from_scratch_spec_permissions_5_1() {
    let (appended, placed) = adversarial_shapes(4, 0x5eed_0313);
    eprintln!("appended {appended} placed {placed}");
    assert!(appended > 0 && placed > 0, "{appended} {placed}");
}

#[test]
#[ignore]
fn append_shapes_equals_from_scratch_large() {
    let (appended, placed) = sum(sharded(384, 0x5eed_0314, adversarial_shapes));
    eprintln!("appended {appended} placed {placed}");
    assert!(appended > 0 && placed > osis_base::testenv::large_n(1_000) as usize, "{appended} {placed}");
}

/// §5.1 step 5: a held commit replaced under its ID by a fuller one (more of its edge writes)
/// changes the input: through `update_touched`, after a restart from walks saved before, and
/// with a cached component of the same IDs, equal to an evaluation from scratch.
#[test]
fn record_replaced_under_its_id_spec_permissions_5_1() {
    use osis_base::Role::{Admin, Read, Write};
    let mut w = World::new();
    let n = w.nodes(4);
    let k = n[0];
    let g = w.thing(k);
    w.set(k, g, n[1], edge(Admin), 1, &[]);
    w.set(k, g, n[2], edge(Write), 2, &[]);
    w.set(n[1], g, n[2], None, 5, &[]);
    let c = w.set(n[1], g, n[3], edge(Read), 12, &[]);
    let mut part = w.clone();
    // the commit's second edge write arrives late
    w.commits.iter_mut().find(|x| x.id == c).unwrap().ops.push((g, n[2], edge(Admin)));
    part.commits.iter_mut().find(|x| x.id == c).unwrap().ops.truncate(1);
    let first = part.held();
    let held = w.held();
    // incrementally
    let mut inc = Timelines::new();
    inc.update(&first);
    inc.update_touched(&held, &BTreeSet::from([g]));
    assert!(check(&held, &inc, &n).is_none(), "{:?}", check(&held, &inc, &n));
    // the general path (a cached component of the same IDs)
    let mut inc = Timelines::new();
    inc.update(&first);
    inc.update(&held);
    assert!(check(&held, &inc, &n).is_none(), "(update): {:?}", check(&held, &inc, &n));
    // a restart from walks saved over the partial records
    let mut inc = Timelines::new();
    inc.update(&first);
    let mut disk = Disk::new();
    store(&mut disk, inc.to_save(SALT, 1, true));
    let inc = reopen(&held, &disk, SALT);
    assert!(check(&held, &inc, &n).is_none(), "(restart): {:?}", check(&held, &inc, &n));
    // a walk continued over a new commit after the replacement
    let mut more = w.clone();
    more.set(n[1], g, n[3], None, 20, &[]);
    let last = more.held();
    let mut inc = Timelines::new();
    inc.update(&first);
    inc.update_touched(&last, &BTreeSet::from([g]));
    assert!(check(&last, &inc, &n).is_none(), "(with a new commit): {:?}", check(&last, &inc, &n));
}

/// §5.1 steps 2-4: late writes in the middle that later items read, placed by walking those
/// items again at their place (with the write and without; equal, nothing new dropped): an
/// explicit removal (an audit: the holder's demotion recorded at its point), a write by an
/// admin with no earlier write on the doc whose class there falls later (the fall recorded,
/// the write covered by the remover's frontier), an admin grant to an admin whose later write
/// on the doc applies either way. One whose later reader does otherwise (an admin grant to a
/// node that writes later), and one the later fall drops (not covered), go on from them. Each
/// equals an evaluation from scratch.
#[test]
fn late_writes_read_later_placed_spec_permissions_5_1() {
    use osis_base::Role::{Admin, Read, Write};
    let mut w = World::new();
    let n = w.nodes(12);
    let (k, a, b) = (n[0], n[1], n[2]);
    let g = w.thing(k);
    let d = w.thing(g);
    let e = w.thing(g);
    w.set(k, g, a, edge(Admin), 1, &[]);
    w.set(k, g, b, edge(Admin), 1, &[]);
    w.set(k, g, n[7], edge(Admin), 2, &[]);
    w.set(a, g, n[6], edge(Write), 3, &[]);
    for i in 0..120u64 {
        let m = n[3 + (i % 3) as usize];
        let v = match i % 4 {
            0 => None,
            1 => edge(Read),
            _ => edge(Write),
        };
        w.set(if i % 2 == 0 { a } else { b }, g, m, v, 10 + 2 * i, &[(m, 10 + 2 * i), (k, 10 + 2 * i)]);
    }
    // later readers: b loses admin (its class on d and e falls); n[7] writes on d; n[8] on e
    w.set(k, g, b, None, 150, &[]);
    w.set(n[7], d, n[9], edge(Read), 160, &[]);
    w.set(n[8], e, n[10], edge(Read), 170, &[]);
    // (late write, placed without a walk)
    let late = [
        (w.set(b, g, n[6], None, 101, &[(k, 102)]), true),
        (w.set(b, d, n[11], edge(Read), 103, &[(k, 104)]), true),
        (w.set(a, d, n[7], edge(Admin), 105, &[]), true),
        (w.set(a, e, n[8], edge(Admin), 107, &[]), false),
        (w.set(b, e, n[11], edge(Read), 109, &[]), false),
    ];
    let mut skip: BTreeSet<_> = late.iter().map(|l| l.0).collect();
    let mut prev = w.held_without(&skip);
    let mut inc = Timelines::new();
    inc.update(&prev);
    for (id, placed) in late {
        skip.remove(&id);
        let held = w.held_without(&skip);
        let c = inc.update_touched(&held, &touched(&prev, &held));
        assert!(c.evaluated.is_empty(), "{c:?}");
        assert_eq!(inc.appended(), 1);
        assert_eq!(inc.placed() == 1, placed, "{id:?}");
        assert!(check(&held, &inc, &n).is_none(), "{:?}", check(&held, &inc, &n));
        prev = held;
    }
    let full = Timeline::evaluate(&prev);
    assert!(!full.demotions(&n[6], &g).is_empty(), "the removal demotes");
    assert!(!full.falls(&b, &d).is_empty(), "b's class on d falls");
}

/// §1, §5.1: a thing an earlier write names (as holder) whose `created.0` arrives late, and one
/// named as target: the walk goes on from the first item naming it (before it, a node's role on
/// it is its role on its first admin), not evaluated anew; equal to an evaluation from scratch.
#[test]
fn created_late_after_writes_naming_it_spec_permissions_5_1() {
    use osis_base::Role::{Admin, Read, Write};
    let mut w = World::new();
    let n = w.nodes(6);
    let (k, a) = (n[0], n[1]);
    let g = w.thing(k);
    let team = w.thing(k);
    let doc = w.thing(team);
    w.set(k, g, a, edge(Admin), 1, &[]);
    w.set(k, team, n[5], edge(Admin), 35, &[]);
    for i in 0..60u64 {
        w.set(a, g, n[2 + (i % 3) as usize], edge(if i % 2 == 0 { Read } else { Write }), 2 + i, &[]);
    }
    w.set(a, g, team, edge(Write), 40, &[]);
    w.set(n[5], doc, n[4], edge(Write), 45, &[]);
    for i in 0..10u64 {
        w.set(a, g, n[2 + (i % 3) as usize], None, 70 + i, &[]);
    }
    for late in [team, doc] {
        let mut prev = w.held();
        prev.created.remove(&team);
        prev.created.remove(&doc);
        let mut inc = Timelines::new();
        inc.update(&prev);
        let mut held = w.held();
        held.created.remove(&[team, doc].into_iter().find(|t| *t != late).unwrap());
        let c = inc.update_touched(&held, &touched(&prev, &held));
        assert!(c.evaluated.is_empty(), "{late:?}: {c:?}");
        assert!(c.extended.contains(&late), "{c:?}");
        assert!(check(&held, &inc, &n).is_none(), "{:?}", check(&held, &inc, &n));
        let c = inc.update_touched(&w.held(), &touched(&held, &w.held()));
        assert!(c.evaluated.is_empty(), "{c:?}");
        assert!(check(&w.held(), &inc, &n).is_none(), "{:?}", check(&w.held(), &inc, &n));
    }
}

/// §5.1 step 5 (notes/local-store.md, rebuildable caches): a walk saved before a new node
/// joined (its `created.0`, a grant to it, a write of its own) and a thing named before its
/// `created.0` arrived is restored and continued, not evaluated anew; equal to an evaluation
/// from scratch.
#[test]
fn saved_walk_restored_after_a_node_joined_spec_permissions_5_1() {
    use osis_base::Role::{Admin, Read, Write};
    let mut w = World::new();
    let n = w.nodes(5);
    let (k, a) = (n[0], n[1]);
    let g = w.thing(k);
    let team = w.thing(k);
    w.set(k, g, a, edge(Admin), 1, &[]);
    for i in 0..40u64 {
        w.set(a, g, n[2 + (i % 3) as usize], edge(if i % 2 == 0 { Read } else { Write }), 2 + i, &[]);
    }
    w.set(a, g, team, edge(Read), 30, &[]);
    let mut held = w.held();
    held.created.remove(&team);
    let mut inc = Timelines::new();
    inc.update(&held);
    let mut disk = Disk::new();
    store(&mut disk, inc.to_save(SALT, 1, true));
    let root = *n.iter().chain([&g, &team]).min().unwrap();
    let (y, yrec) = key_actors(8, 31).into_iter().find(|(t, _)| *t > root).unwrap();
    w.created.insert(y, yrec);
    w.set(a, g, y, edge(Write), 50, &[]);
    w.set(y, g, y, edge(Read), 51, &[]);
    let mut nodes = n.clone();
    nodes.push(y);
    let held = w.held();
    let inc = reopen(&held, &disk, SALT);
    assert_eq!(inc.restored(), 1);
    assert!(check(&held, &inc, &nodes).is_none(), "{:?}", check(&held, &inc, &nodes));
}

/// Two components with saved walks merge (the root of one is no root any more) and the node
/// restarts before saving: the walk under the old root is still deleted by the next save.
#[test]
fn saved_walk_under_old_root_deleted_after_restart() {
    use osis_base::Role::{Admin, Write};
    let mut w = World::new();
    let n = w.nodes(4);
    let (g1, g2) = (w.thing(n[0]), w.thing(n[1]));
    w.set(n[0], g1, n[2], edge(Write), 1, &[]);
    w.set(n[1], g2, n[3], edge(Write), 2, &[]);
    let held = w.held();
    let mut inc = Timelines::new();
    inc.update(&held);
    let mut disk = Disk::new();
    let mut saves = inc.to_save(SALT, 1, true);
    inc.saved(std::mem::take(&mut saves.done));
    store(&mut disk, saves);
    assert_eq!(disk.len(), 2);
    w.set(n[0], g1, n[1], edge(Admin), 3, &[]);
    let held = w.held();
    let inc = reopen(&held, &disk, SALT);
    assert_eq!(inc.restored(), 1);
    store(&mut disk, inc.to_save(SALT, 1, false));
    let root = *n.iter().chain([&g1, &g2]).min().unwrap();
    assert_eq!(disk.keys().copied().collect::<Vec<_>>(), vec![root]);
}

/// Random histories built for the placement paths' corners (spec/permissions.md §5.1 steps
/// 2-5): no writes before the late ones (a late write is often its author's first on its
/// target, so falls before the old first write appear), ties in ts, a record chain through
/// things (a doc under a team, a sub-doc under the doc) and things as holders, invites,
/// `until`, removals, two-op commits, late writes by the key actor at the top, and
/// `created.0` records of named things and of new nodes arriving late, with commits or
/// alone; restarts from saved walks now and then. Equal to an evaluation from scratch after
/// every arrival. Returns (updates `append` did alone, commits placed without walking again).
fn adversarial_corners(samples: u64, seed: u64) -> (usize, usize) {
    use osis_base::Role::{Admin, Read, Write};
    let seed = seeded(seed);
    let mut rng = Rng(seed);
    let (mut appended, mut placed) = (0, 0);
    for s in 0..samples {
        let mut w = World::new();
        let mut n = w.nodes(6);
        let k = n[0];
        let g = w.thing(k);
        let team = w.thing(k);
        let doc = w.thing(team);
        let sub = w.thing(doc);
        let extra = [w.nodes_salted(1, 0x77)[0], key_actors(1, 0x78)[0].0];
        let targets = [g, g, team, doc, sub];
        let holders = [team, doc];
        w.set(k, g, n[1], edge(Admin), 1, &[]);
        w.set(k, g, n[2], edge(Admin), 1, &[]);
        w.set(k, team, n[3], edge(Admin), 1, &[]);
        w.set(k, g, team, edge([Admin, Write, Read][rng.below(3)]), 1, &[]);
        let mut late = Vec::new();
        let op = |rng: &mut Rng, n: &[Tid]| {
            let target = targets[rng.below(targets.len())];
            let holder = match rng.below(12) {
                0 | 1 => holders[rng.below(holders.len())],
                2 => extra[rng.below(2)],
                _ => n[1 + rng.below(5)],
            };
            let until = (rng.below(4) == 0).then(|| 3 + rng.below(25) as u64);
            let role = [Read, Write, Admin, Admin][rng.below(4)];
            let e = match rng.below(8) {
                0..=2 => None,
                3 => edge_inv(role, Some([Read, Write, Admin][rng.below(3)].min(role)), until),
                _ => edge_inv(role, None, until),
            };
            (target, holder, e)
        };
        // admins and the team's admin edge removed and given back: classes fall and return
        let toggle = |rng: &mut Rng, n: &[Tid]| {
            let (target, holder) = [(g, n[1]), (g, n[2]), (team, n[3]), (g, team), (team, n[4]), (doc, n[5])][rng.below(6)];
            (target, holder, [None, edge(Admin), edge(Write)][rng.below(3)])
        };
        for _ in 0..10 + rng.below(16) {
            let author = match rng.below(12) {
                0 => extra[rng.below(2)],
                1 | 2 => k,
                _ => n[1 + rng.below(5)],
            };
            let mut ops = vec![if rng.below(3) == 0 { toggle(&mut rng, &n) } else { op(&mut rng, &n) }];
            if rng.below(4) == 0 {
                let o = op(&mut rng, &n);
                if (o.0, o.1) != (ops[0].0, ops[0].1) {
                    ops.push(o);
                }
            }
            // few distinct ts: ties ordered by node, then commit ID
            let t = 2 + rng.below(18) as u64;
            let recv: Vec<(Tid, u64)> = if rng.below(3) == 0 { Vec::new() } else { n.iter().map(|x| (*x, rng.below(24) as u64)).collect() };
            let id = w.commit(author, t, &ops, &recv);
            if rng.below(2) == 0 {
                late.push(id);
            }
        }
        // `created.0` records held late: a team or doc the history names, the node with one
        let mut created_late: Vec<(Tid, usize)> = Vec::new();
        for t in [team, doc, extra[0]] {
            if rng.below(3) == 0 {
                created_late.push((t, rng.below(late.len() + 1)));
            }
        }
        n.extend(extra);
        let order = rng.perm(late.len());
        let mut skip: BTreeSet<_> = late.iter().copied().collect();
        let mut prev = held_at(&w, &skip, &created_late, 0);
        let mut inc = Timelines::new();
        inc.update(&prev);
        let mut i = 0;
        while i < order.len() {
            let take = if rng.below(3) == 0 { 1 + rng.below(3) } else { 1 };
            let step = i + 1;
            // (half the time the `created.0` records of this step alone first)
            if rng.below(2) == 0 && created_late.iter().any(|c| c.1 == step) {
                let held = held_at(&w, &skip, &created_late, step);
                update_moved(&mut inc, &held, &prev);
                if let Some(d) = check(&held, &inc, &n) {
                    panic!("seed {seed:#x} sample {s} arrival {i} (records alone): {d}");
                }
                prev = held;
            }
            for j in order.iter().skip(i).take(take) {
                skip.remove(&late[*j]);
            }
            i += take;
            let held = held_at(&w, &skip, &created_late, step);
            update_moved(&mut inc, &held, &prev);
            appended += inc.appended();
            placed += inc.placed();
            if let Some(d) = check(&held, &inc, &n) {
                panic!("seed {seed:#x} sample {s} arrival {i}: {d}");
            }
            if rng.below(5) == 0 {
                let mut disk = Disk::new();
                store(&mut disk, inc.to_save(SALT, 1, true));
                inc = reopen(&held, &disk, SALT);
                if let Some(d) = check(&held, &inc, &n) {
                    panic!("seed {seed:#x} sample {s} arrival {i} after a restart: {d}");
                }
            }
            prev = held;
        }
        let held = w.held();
        update_moved(&mut inc, &held, &prev);
        if let Some(d) = check(&held, &inc, &n) {
            panic!("seed {seed:#x} sample {s} (all records): {d}");
        }
    }
    (appended, placed)
}

/// §5.1 steps 2-5: late arrivals at the placement paths' corners equal from scratch.
#[test]
fn append_corners_equals_from_scratch_spec_permissions_5_1() {
    let (appended, placed) = adversarial_corners(12, 0x5eed_0315);
    eprintln!("appended {appended} placed {placed}");
    assert!(appended > 0 && placed > 0, "{appended} {placed}");
}

#[test]
#[ignore]
fn append_corners_equals_from_scratch_large() {
    let (appended, placed) = sum(sharded(1_600, 0x5eed_0316, adversarial_corners));
    eprintln!("appended {appended} placed {placed}");
    assert!(appended > 0 && placed > osis_base::testenv::large_n(1_000) as usize, "{appended} {placed}");
}

/// §5.1 step 5: the cost guard on re-judging later items in a shadow (`SHADOW_SHARE`) only
/// chooses between two exact paths: the same random late arrivals with every shadow placement
/// declined (the walk goes on from the write) and with none declined for its cost equal an
/// evaluation from scratch, and the first places fewer.
#[cfg(debug_assertions)]
#[test]
fn shadow_cost_guard_changes_no_outcome_spec_permissions_5_1() {
    let mut placed = Vec::new();
    for on in [Some(true), Some(false)] {
        osis_perm::force_shadow_guard(on);
        let (_, p) = adversarial_corners(4, 0x5eed_0317);
        let (_, q) = adversarial_falls(4, 0x5eed_0318);
        placed.push(p + q);
    }
    osis_perm::force_shadow_guard(None);
    assert!(placed[0] < placed[1], "{placed:?}");
}

/// §5.1 step 5: a late admin grant to a team whose holders write on the thing in every later
/// commit (each later item re-judged): with 520 later items the cost guard walks on from the
/// write; with the guard off it is placed by re-judging them. Both equal an evaluation from
/// scratch.
#[cfg(debug_assertions)]
#[test]
fn long_rest_both_paths_equal_spec_permissions_5_1() {
    use osis_base::Role::{Admin, Read, Write};
    let mut w = World::new();
    let n = w.nodes(8);
    let k = n[0];
    let g = w.thing(k);
    let team = w.thing(k);
    w.set(k, g, n[1], edge(Admin), 1, &[]);
    w.set(k, team, n[1], edge(Admin), 1, &[]);
    w.set(k, team, n[2], edge(Write), 1, &[]);
    w.set(n[1], g, n[3], edge(Read), 2, &[]);
    for i in 0..520u64 {
        let m = n[3 + (i % 5) as usize];
        w.set(n[1], g, m, if i % 3 == 0 { None } else { edge([Read, Write][(i % 2) as usize]) }, 10 + i, &[]);
    }
    let late = w.set(k, g, team, edge(Admin), 5, &[]);
    let skip = BTreeSet::from([late]);
    let prev = w.held_without(&skip);
    let held = w.held();
    let mut placed = Vec::new();
    for on in [None, Some(false)] {
        osis_perm::force_shadow_guard(on);
        let mut inc = Timelines::new();
        inc.update(&prev);
        let c = inc.update_touched(&held, &touched(&prev, &held));
        assert!(c.evaluated.is_empty(), "{c:?}");
        assert_eq!(inc.appended(), 1);
        placed.push(inc.placed());
        let watch = [n[1], n[2], n[3]];
        assert!(check(&held, &inc, &watch).is_none(), "{on:?}: {:?}", check(&held, &inc, &watch));
    }
    osis_perm::force_shadow_guard(None);
    assert_eq!(placed, [0, 1]);
}

/// Random histories of admins removed and given back by the key actor (directly and through a
/// team), with rare writes of their own on the group, a doc it owns and the team: a late write
/// is often its author's first on its target, and the class falls between it and the old first
/// write are recorded only with it (spec/permissions.md §5.1 step 4); frontiers cover some of
/// them, so some of those falls drop it. Ties in ts. Equal to an evaluation from scratch after
/// every arrival. Returns (updates `append` did alone, commits placed without walking again).
fn adversarial_falls(samples: u64, seed: u64) -> (usize, usize) {
    use osis_base::Role::{Admin, Read, Write};
    let seed = seeded(seed);
    let mut rng = Rng(seed);
    let (mut appended, mut placed) = (0, 0);
    for s in 0..samples {
        let mut w = World::new();
        let n = w.nodes(6);
        let k = n[0];
        let g = w.thing(k);
        let doc = w.thing(g);
        let team = w.thing(k);
        for x in &n[1..3] {
            w.set(k, g, *x, edge(Admin), 1, &[]);
        }
        w.set(k, g, team, edge(Admin), 1, &[]);
        w.set(k, team, n[3], edge(Admin), 1, &[]);
        w.set(k, team, n[4], edge(Write), 1, &[]);
        let mut late = Vec::new();
        for _ in 0..12 + rng.below(16) {
            let t = 2 + rng.below(14) as u64;
            let recv: Vec<(Tid, u64)> = if rng.below(2) == 0 { Vec::new() } else { n.iter().map(|x| (*x, rng.below(18) as u64)).collect() };
            let id = if rng.below(5) < 3 {
                // the key actor (or an admin) takes a class away or gives it back
                let author = if rng.below(4) == 0 { n[1 + rng.below(2)] } else { k };
                let (target, holder) = [(g, n[1]), (g, n[2]), (g, team), (team, n[3]), (team, n[4]), (doc, n[3])][rng.below(6)];
                let e = [None, None, edge(Admin), edge(Write), edge_inv(Admin, None, Some(t + 1 + rng.below(6) as u64))][rng.below(5)];
                w.set(author, target, holder, e, t, &recv)
            } else {
                let author = n[1 + rng.below(4)];
                let target = [g, doc, doc, team][rng.below(4)];
                let holder = n[1 + rng.below(5)];
                let e = [None, edge(Read), edge(Write), edge(Admin), edge_inv(Write, Some(Read), None)][rng.below(5)];
                w.set(author, target, holder, e, t, &recv)
            };
            if rng.below(2) == 0 {
                late.push(id);
            }
        }
        let order = rng.perm(late.len());
        let mut skip: BTreeSet<_> = late.iter().copied().collect();
        let mut prev = w.held_without(&skip);
        let mut inc = Timelines::new();
        inc.update(&prev);
        let mut i = 0;
        while i < order.len() {
            let take = if rng.below(4) == 0 { 2 } else { 1 };
            for j in order.iter().skip(i).take(take) {
                skip.remove(&late[*j]);
            }
            i += take;
            let held = w.held_without(&skip);
            update_moved(&mut inc, &held, &prev);
            appended += inc.appended();
            placed += inc.placed();
            if let Some(d) = check(&held, &inc, &n) {
                panic!("seed {seed:#x} sample {s} arrival {i}: {d}");
            }
            prev = held;
        }
    }
    (appended, placed)
}

/// §5.1 steps 2-5: late writes before class falls of their author, through `update_touched`,
/// equal from scratch.
#[test]
fn append_falls_equals_from_scratch_spec_permissions_5_1() {
    let (appended, placed) = adversarial_falls(15, 0x5eed_0319);
    eprintln!("appended {appended} placed {placed}");
    assert!(appended > 0 && placed > 0, "{appended} {placed}");
}

#[test]
#[ignore]
fn append_falls_equals_from_scratch_large() {
    let (appended, placed) = sum(sharded(1_600, 0x5eed_031a, adversarial_falls));
    eprintln!("appended {appended} placed {placed}");
    assert!(appended > 0 && placed > osis_base::testenv::large_n(1_000) as usize, "{appended} {placed}");
}

/// §1, §5.1 step 4: a thing named as a holder by a write that a later fall drops (a node
/// until its `created.0` names its first admin) gets its `created.0` late: the walk goes on from the
/// dropped write, which is dropped again; and with a late write before it in the same update.
/// Equal to an evaluation from scratch, not evaluated anew.
#[test]
fn created_late_for_a_dropped_write_spec_permissions_5_1() {
    use osis_base::Role::{Admin, Read};
    for with_commit in [false, true] {
        let mut w = World::new();
        let n = w.nodes(4);
        let (k, a) = (n[0], n[1]);
        let g = w.thing(k);
        let team = w.thing(k);
        let doc = w.thing(team);
        w.set(k, g, a, edge(Admin), 1, &[]);
        w.set(k, team, n[2], edge(Admin), 1, &[]);
        for i in 0..20u64 {
            w.set(a, g, n[3], edge(Read), 2 + i, &[]);
        }
        let dropped = w.set(a, g, doc, edge(Read), 30, &[]);
        w.set(k, g, a, None, 40, &[]);
        w.set(n[2], doc, n[3], edge(Read), 45, &[]);
        let late = w.set(k, g, n[2], edge(Admin), 25, &[]);
        let mut prev = w.held_without(&BTreeSet::from([late]));
        prev.created.remove(&doc);
        let mut inc = Timelines::new();
        inc.update(&prev);
        let full = Timeline::evaluate(&prev);
        assert!(full.dropped().contains_key(&WriteId(dropped, 0)), "the fall drops it");
        let mut held = if with_commit { w.held() } else { w.held_without(&BTreeSet::from([late])) };
        held.created.insert(doc, w.created[&doc].clone());
        let c = inc.update_touched(&held, &touched(&prev, &held));
        assert!(c.evaluated.is_empty(), "{with_commit}: {c:?}");
        assert!(check(&held, &inc, &n).is_none(), "{with_commit}: {:?}", check(&held, &inc, &n));
        assert!(Timeline::evaluate(&held).dropped().contains_key(&WriteId(dropped, 0)));
    }
}

/// §5.1 step 4: falls of a late write's author recorded only with it (its first write on the
/// thing moved earlier), at items sharing a ts with other authors' writes and with the late
/// write's own: in timeline order, before the falls recorded after the old first write, and
/// one of them dropping the late write (not covered) so the walk goes on from that item. Each
/// equals an evaluation from scratch.
#[test]
fn falls_before_old_first_write_spec_permissions_5_1() {
    use osis_base::Role::{Admin, Read, Write};
    for covered in [true, false] {
        let mut w = World::new();
        let n = w.nodes(5);
        let (k, a, b) = (n[0], n[1], n[2]);
        let g = w.thing(k);
        let doc = w.thing(g);
        w.set(k, g, a, edge(Admin), 1, &[]);
        w.set(k, g, b, edge(Admin), 1, &[]);
        w.set(b, doc, n[3], edge(Read), 2, &[]);
        // a's class on doc falls (admin taken by k, given back; then by b) twice before its old
        // first write at 20, at ts shared with b's writes, then again after it; k's frontier
        // covers the late write, b's only when `covered`
        let recv: &[(Tid, u64)] = if covered { &[(k, 6), (b, 6)] } else { &[(k, 6)] };
        let late = w.set(a, doc, n[4], edge(Write), 5, recv);
        for (t, by) in [(8u64, k), (12, b)] {
            w.set(b, doc, n[3], edge(Write), t, &[]);
            w.set(by, g, a, None, t, &[]);
            w.set(k, g, a, edge(Admin), t + 1, &[]);
        }
        w.set(a, doc, n[3], edge(Read), 20, &[(k, 21), (b, 21)]);
        w.set(k, g, a, None, 25, &[(k, 26)]);
        w.set(b, doc, n[3], None, 26, &[]);
        let prev = w.held_without(&BTreeSet::from([late]));
        let mut inc = Timelines::new();
        inc.update(&prev);
        let held = w.held();
        let c = inc.update_touched(&held, &touched(&prev, &held));
        assert!(c.evaluated.is_empty(), "{c:?}");
        assert_eq!(inc.appended(), 1);
        assert!(check(&held, &inc, &n).is_none(), "{covered}: {:?}", check(&held, &inc, &n));
        let full = Timeline::evaluate(&held);
        assert_eq!(full.falls(&a, &doc).len(), 3, "{covered}: {:?}", full.falls(&a, &doc));
        assert_eq!(full.dropped().contains_key(&WriteId(late, 0)), !covered);
    }
}

/// §1, §5.1: leaves joining a record chain around `MAX_CHAIN_DEPTH` (perm follows record edges
/// at any depth; the engine judges deltas on a deeper thing invalid): through `update_touched`
/// equal to from scratch.
#[test]
fn leaves_past_record_depth_spec_permissions_1() {
    use osis_base::Role::Admin;
    let mut w = World::new();
    let n = w.nodes(2);
    let (k, x) = (n[0], n[1]);
    let mut chain = vec![w.thing(k)];
    for _ in 0..osis_base::format::MAX_CHAIN_DEPTH + 2 {
        let t = w.thing(*chain.last().unwrap());
        chain.push(t);
    }
    w.set(k, chain[0], x, edge(Admin), 1, &[]);
    w.set(k, chain[0], x, None, 5, &[]);
    let leaves: Vec<Tid> = chain[chain.len() - 6..].to_vec();
    let mut held = w.held();
    for l in &leaves {
        held.created.remove(l);
    }
    let mut inc = Timelines::new();
    inc.update(&held);
    assert!(check(&held, &inc, &n).is_none());
    for l in &leaves {
        let prev = held.clone();
        held.created.insert(*l, w.created[l].clone());
        inc.update_touched(&held, &touched_of(&prev, &held));
        if let Some(d) = check(&held, &inc, &n) {
            panic!("leaf at {}: {d}", chain.iter().position(|t| t == l).unwrap());
        }
    }
}

/// Saves `inc`'s walks to `disk` (`to_save`, all or the due ones) and checks each saved walk is
/// under a component's root (its least thing): a walk under a thing that is no root any more
/// is retired and deleted, never left behind (across restarts too).
fn save_checked(inc: &mut Timelines, held: &osis_perm::MemoryHeldSet, disk: &mut Disk, min: usize, all: bool) -> Option<Tid> {
    let mut saves = inc.to_save(SALT, min, all);
    inc.saved(std::mem::take(&mut saves.done));
    store(disk, saves);
    // every tid the held set names
    let mut all: BTreeSet<Tid> = held.things().into_iter().collect();
    for t in held.things() {
        if let Some(osis_base::CreationRecord::Thing { admin, .. }) = held.created(&t) {
            all.insert(admin);
        }
        for c in held.edge_commits(&t) {
            all.insert(c.author);
            all.extend(c.ops.iter().flat_map(|o| [o.holder, o.target]));
        }
    }
    let mut comps: BTreeMap<*const Timeline, Tid> = BTreeMap::new();
    for x in all {
        if let Some(tl) = inc.get(&x) {
            let r = comps.entry(tl as *const Timeline).or_insert(x);
            *r = (*r).min(x);
        }
    }
    disk.keys().find(|r| !inc.get(r).is_some_and(|tl| comps.get(&(tl as *const Timeline)) == Some(*r))).copied()
}

/// Random histories biased toward thing creation: record trees grown as commits arrive (leaves,
/// chains of new things in one arrival, things created then named by later commits, `created.0`
/// arriving after commits naming the thing, nodes joining), arrivals mixing records and commits,
/// walks saved now and then, restarts from them. After every arrival the fast path (`append`,
/// `Timeline::add_leaves`) reports what the general path reports (or less, where that is covered),
/// equals an evaluation from scratch, and both leave saved walks only under component roots.
/// Returns the updates the fast path did alone.
fn creation_histories(samples: u64, seed: u64) -> usize {
    use osis_base::Role::{Admin, Read, Write};
    let seed = seeded(seed);
    let mut rng = Rng(seed);
    let mut appended = 0;
    for s in 0..samples {
        let mut w = World::new();
        let n = w.nodes(4);
        let k = n[0];
        let late_node = w.nodes_salted(1, 0x79)[0];
        // held from the start: two groups and a team
        let base = [w.thing(k), w.thing(k), w.thing(n[1])];
        w.set(k, base[0], n[1], edge(Admin), 1, &[]);
        w.set(n[1], base[2], n[2], edge(Admin), 1, &[]);
        w.set(k, base[1], base[2], edge(if rng.below(2) == 0 { Admin } else { Write }), 1, &[]);
        let start = w.created.clone();
        let start_commits: BTreeSet<_> = w.commits.iter().map(|c| c.id).collect();
        // new things, first admins among everything so far (chains, siblings, deep trees)
        let mut things: Vec<Tid> = base.to_vec();
        let mut fresh = Vec::new();
        for _ in 0..6 + rng.below(14) {
            let admin = match rng.below(8) {
                0 => n[rng.below(3)],
                1 | 2 if !fresh.is_empty() => fresh[fresh.len() - 1],
                _ => things[rng.below(things.len())],
            };
            let t = w.thing(admin);
            things.push(t);
            fresh.push(t);
        }
        let mut all_nodes = n.clone();
        all_nodes.push(late_node);
        // commits naming old and new things (some new things never named: leaves)
        let named: Vec<Tid> = things.iter().copied().filter(|_| rng.below(3) != 0).collect();
        for _ in 0..4 + rng.below(10) {
            let author = all_nodes[if rng.below(10) == 0 { 4 } else { rng.below(4) }];
            let target = if rng.below(3) == 0 { base[rng.below(3)] } else { named.get(rng.below(named.len().max(1))).copied().unwrap_or(base[0]) };
            let holder = match rng.below(6) {
                0 => named.get(rng.below(named.len().max(1))).copied().unwrap_or(base[2]),
                1 => base[2],
                _ => all_nodes[rng.below(5)],
            };
            let until = (rng.below(4) == 0).then(|| 5 + rng.below(40) as u64);
            let e = match rng.below(5) {
                0 => None,
                _ => edge_inv([Read, Write, Admin][rng.below(3)], None, until),
            };
            w.commit(author, 2 + rng.below(40) as u64, &[(target, holder, e)], &[]);
        }
        // arrivals: each new `created.0` and each commit, in random order, 1-4 at a time
        #[derive(Clone, Copy)]
        enum Item {
            Created(Tid),
            Commit(osis_base::CommitId),
        }
        let mut items: Vec<Item> = w.created.keys().filter(|t| !start.contains_key(*t)).map(|t| Item::Created(*t)).collect();
        items.extend(w.commits.iter().map(|c| c.id).filter(|id| !start_commits.contains(id)).map(Item::Commit));
        let order = rng.perm(items.len());
        let all_ids: BTreeSet<_> = w.commits.iter().map(|c| c.id).collect();
        let mut skip: BTreeSet<_> = all_ids.difference(&start_commits).copied().collect();
        let mut created: BTreeSet<Tid> = start.keys().copied().collect();
        let held_now = |skip: &BTreeSet<osis_base::CommitId>, created: &BTreeSet<Tid>| {
            let mut h = w.held_without(skip);
            h.created.retain(|t, _| created.contains(t));
            h
        };
        let mut prev = held_now(&skip, &created);
        let (mut fast, mut general) = (Timelines::new(), Timelines::new());
        general.set_general_only(true);
        fast.update(&prev);
        general.update(&prev);
        let (mut disk, mut gdisk) = (Disk::new(), Disk::new());
        let min = 1 + rng.below(3);
        let mut i = 0;
        while i < order.len() {
            let take = 1 + rng.below(4);
            for j in order.iter().skip(i).take(take) {
                match items[*j] {
                    Item::Created(t) => {
                        created.insert(t);
                    }
                    Item::Commit(id) => {
                        skip.remove(&id);
                    }
                }
            }
            i += take;
            let held = held_now(&skip, &created);
            let t = touched(&prev, &held);
            let a = update_moved(&mut fast, &held, &prev);
            let b = general.update_touched(&held, &t);
            appended += fast.appended();
            // The general path may report more: when several old components merge it continues
            // the one with the most commits, then things, and names the others' things. Each
            // must be a node bringing nothing, or below a thing the fast path names by record
            // edges (authority there follows its first admin's).
            let fa: BTreeSet<Tid> = a.evaluated.union(&a.extended).copied().collect();
            let fb: BTreeSet<Tid> = b.evaluated.union(&b.extended).copied().collect();
            let covered = |x: &Tid| {
                let mut cur = *x;
                for _ in 0..64 {
                    if fa.contains(&cur) {
                        return true;
                    }
                    match held.created(&cur) {
                        Some(osis_base::CreationRecord::Thing { admin, .. }) => cur = admin,
                        _ => return cur == *x && held.edge_commits(x).is_empty(),
                    }
                }
                false
            };
            assert!(
                a.evaluated.is_subset(&b.evaluated) && fa.is_subset(&fb) && fb.iter().all(covered),
                "seed {seed:#x} sample {s} arrival {i}: what changed, fast {a:?} general {b:?}"
            );
            if let Some(d) = check_more(&held, &fast, &all_nodes) {
                panic!("seed {seed:#x} sample {s} arrival {i}: {d}");
            }
            // walks saved now and then, kept across restarts: each one under its component's
            // root once written (a leaf below the root moves it: the old one is retired)
            if rng.below(3) == 0 {
                let all = rng.below(4) == 0;
                let g = save_checked(&mut general, &held, &mut gdisk, min, all);
                assert!(g.is_none(), "seed {seed:#x} sample {s} arrival {i}: general: a walk saved under {g:?}, not a root");
                let f = save_checked(&mut fast, &held, &mut disk, min, all);
                assert!(f.is_none(), "seed {seed:#x} sample {s} arrival {i}: a walk saved under {f:?}, not a root");
            }
            if rng.below(5) == 0 {
                fast = reopen(&held, &disk, SALT);
                if let Some(d) = check_more(&held, &fast, &all_nodes) {
                    panic!("seed {seed:#x} sample {s} arrival {i} after a restart: {d}");
                }
            }
            prev = held;
        }
    }
    appended
}

/// §5.1: a lone node's first commit joins it to a component without commits (a record chain):
/// the general path continues the larger component and reports the node and the commit's
/// target, as `append` does, not the target's first admins (seed 7301 of
/// `creation_fast_equals_general_large`: it continued the node's walk and reported them all).
#[test]
fn merge_continues_the_larger_component_spec_permissions_5_1() {
    use osis_base::Role::Write;
    let mut w = World::new();
    let mut n = w.nodes(4);
    n.sort();
    // the lone node sorts after the record chain's root, so `{lone}` is the larger key
    let (admin, lone) = (n[0], n[3]);
    let a = w.thing(admin);
    let b = w.thing(a);
    let c = w.set(lone, b, lone, edge(Write), 1, &[]);
    let prev = w.held_without(&BTreeSet::from([c]));
    let held = w.held();
    for general_only in [false, true] {
        let mut inc = Timelines::new();
        inc.set_general_only(general_only);
        inc.update(&prev);
        assert!(!std::ptr::eq(inc.get(&lone).unwrap(), inc.get(&b).unwrap()));
        let ch = update_moved(&mut inc, &held, &prev);
        assert!(ch.evaluated.is_empty(), "{ch:?}");
        let want: BTreeSet<Tid> = if general_only { [lone, b].into() } else { [b].into() };
        assert_eq!(ch.extended, want, "general only: {general_only}");
        assert!(check(&held, &inc, &n).is_none(), "{:?}", check(&held, &inc, &n));
    }
}

/// §1, §5.1: a leaf whose first admin has no record held (a node so far only the target of
/// a commit) joins that component by the fast path; the next growth of the component that
/// the fast path declines continues the walk (a first admin without a record is a node to
/// `Timeline::add_leaves` as to `Input::gather`, so none "comes" at the extension), as the
/// general path does (`creation_fast_equals_general_large` seed 0x5005eed0a02 sample 11: the
/// fast path evaluated the component instead).
#[test]
fn leaf_under_a_late_node_continues_spec_permissions_5_1() {
    use osis_base::Role::Write;
    let mut w = World::new();
    let n = w.nodes(2);
    let m = w.nodes_salted(1, 0x79)[0];
    let a = w.thing(n[0]);
    w.set(n[0], a, n[1], edge(Write), 1, &[]);
    w.set(n[0], m, n[1], edge(Write), 2, &[]);
    let x = w.thing(m);
    let h0 = {
        let mut h = w.held();
        h.created.remove(&m);
        h.created.remove(&x);
        h
    };
    let h1 = {
        let mut h = w.held();
        h.created.remove(&m);
        h
    };
    // a new thing with its record and a commit naming it: not a leaf, the general path
    let y = w.thing(a);
    w.set(n[0], y, n[1], edge(Write), 3, &[]);
    let h2 = {
        let mut h = w.held();
        h.created.remove(&m);
        h
    };
    for general_only in [false, true] {
        let mut inc = Timelines::new();
        inc.set_general_only(general_only);
        inc.update(&h0);
        let ch = update_moved(&mut inc, &h1, &h0);
        assert!(ch.evaluated.is_empty(), "general only {general_only}: the leaf {ch:?}");
        assert_eq!(inc.appended() > 0, !general_only, "general only {general_only}: the leaf by the fast path");
        assert!(std::ptr::eq(inc.get(&x).unwrap(), inc.get(&a).unwrap()), "general only {general_only}: the leaf joins the node's component");
        let ch = update_moved(&mut inc, &h2, &h1);
        assert!(ch.evaluated.is_empty(), "general only {general_only}: the named thing {ch:?}");
        assert!(ch.extended.contains(&y), "general only {general_only}: {ch:?}");
        assert!(check(&h2, &inc, &n).is_none(), "{:?}", check(&h2, &inc, &n));
    }
}

/// §1, §5.1: thing creation arriving among role commits; the fast path equals the
/// general path and an evaluation from scratch.
#[test]
fn creation_fast_equals_general_spec_permissions_5_1() {
    let appended = creation_histories(12, 0x5eed_0a01);
    assert!(appended > 0, "{appended}");
}

#[test]
#[ignore]
fn creation_fast_equals_general_large() {
    let appended: usize = sharded(1024, 0x5eed_0a02, creation_histories).into_iter().sum();
    eprintln!("appended {appended}");
}

// spec/permissions.md §3, Retain: a saved walk restores how each ended edge ended.
#[test]
fn saved_walk_keeps_keep_spec_permissions_3() {
    let mut w = World::new();
    let n = w.nodes(2);
    let g = w.thing(n[0]);
    w.set(n[0], g, n[1], edge(osis_base::Role::Read), 1, &[]);
    w.set(n[0], g, n[1], Some(osis_perm::Edge::kept_end()), 2, &[]);
    let held = w.held();
    let mut inc = Timelines::new();
    let all: BTreeSet<Tid> = held.things().into_iter().collect();
    inc.update_touched_cached(&held, &all, &mut |_| None, SALT);
    let mut disk = Disk::new();
    store(&mut disk, inc.to_save(SALT, 1, true));
    assert!(!disk.is_empty());
    let back = reopen(&held, &disk, SALT);
    assert!(back.restored() > 0, "restored, not walked");
    let ended = back.get(&g).unwrap().ended(&g, ts(100));
    assert_eq!(ended.get(&n[1]).unwrap().0, osis_perm::EdgeEnd::Said(true));
}

thread_local! {
    /// Whether `update_moved` checks what it reports (the `role_moves_*` tests turn it on).
    static MOVES: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Every (node, thing) answer validity and sync read of the timeline: roles and demotions, and
/// validity at `points` for a delta of the node's with no frontier naming it, or its own commit.
fn answers(inc: &Timelines, nodes: &BTreeSet<Tid>, things: &BTreeSet<Tid>, points: &BTreeSet<osis_perm::Point>) -> BTreeMap<(Tid, Tid), String> {
    use std::fmt::Write;
    let none = osis_perm::Validity::Invalid { by: None };
    let mut out = BTreeMap::new();
    for t in things {
        let tl = inc.get(t);
        for n in nodes {
            let mut a = format!("{:?} {:?} {:?}", tl.map_or(osis_perm::Class::None, |tl| tl.class(n, t, At::END)), tl.and_then(|tl| tl.role(n, t, At::END)), tl.map_or(&[][..], |tl| tl.demotions(n, t)));
            for p in points {
                let _ = write!(a, " {:?}", tl.and_then(|tl| tl.role(n, t, At::before(*p))));
                for r in [osis_base::Role::Read, osis_base::Role::Write, osis_base::Role::Admin] {
                    let _ = write!(a, " {:?}", tl.and_then(|tl| tl.valid_from(n, t, r)));
                    let any = osis_perm::Point { node: *n, commit: osis_base::CommitId([0xee; 32]), ..*p };
                    let _ = write!(a, " {:?}", tl.map_or(none, |tl| tl.delta_valid(any, t, r)));
                    if p.node == *n {
                        let _ = write!(a, " {:?}", tl.map_or(none, |tl| tl.delta_valid(*p, t, r)));
                    }
                }
            }
            out.insert((*n, *t), a);
        }
    }
    out
}

/// The invite grants applied, by write: (author, target), what `validity::valid_on` reads beside roles.
fn invite_grants(inc: &Timelines, things: &BTreeSet<Tid>) -> BTreeMap<WriteId, (Tid, Tid)> {
    let mut out = BTreeMap::new();
    for tl in things.iter().filter_map(|t| inc.get(t)) {
        out.extend(tl.applied().iter().filter(|(_, a)| matches!(a.attr, osis_perm::Attr::By(osis_perm::Class::Invite(_)))).map(|(w, a)| (*w, (a.author, a.target))));
    }
    out
}

/// `update_touched`, with `MOVES` checking the rule the engine's and sync's narrow paths rest on
/// (`Core::timelines_changed`, `SyncEngine::note_role_moves`): an answer about (node, thing)
/// differs only where the thing's component was evaluated, it is below a new record, or the node
/// is upstream of a reported edge's holder or new record and the thing reachable from its target or
/// that record; in the walk's past too, and however the node stands now.
fn update_moved(inc: &mut Timelines, held: &osis_perm::MemoryHeldSet, prev: &osis_perm::MemoryHeldSet) -> osis_perm::Changed {
    let t = touched(prev, held);
    if !MOVES.get() {
        return inc.update_touched(held, &t);
    }
    // holder -> target and first admin -> thing, of any validity: `Held::named_on`, `Held::first_admin_of`
    let mut down: BTreeMap<Tid, BTreeSet<Tid>> = BTreeMap::new();
    let mut up: BTreeMap<Tid, BTreeSet<Tid>> = BTreeMap::new();
    let mut first_admin_of: BTreeMap<Tid, BTreeSet<Tid>> = BTreeMap::new();
    let mut link = |a: Tid, b: Tid| {
        down.entry(a).or_default().insert(b);
        up.entry(b).or_default().insert(a);
    };
    let mut nodes = BTreeSet::new();
    let mut points = BTreeSet::new();
    for c in held.commits.values().flatten() {
        nodes.insert(c.author);
        points.insert(c.point());
        for o in &c.ops {
            nodes.insert(o.holder);
            link(o.holder, o.target);
        }
    }
    for (x, r) in &held.created {
        if let osis_base::RecordLink::Admin(o) = r.record_link() {
            link(o, *x);
            first_admin_of.entry(o).or_default().insert(*x);
        }
        if matches!(r, osis_base::CreationRecord::KeyActor { .. }) {
            nodes.insert(*x);
        }
    }
    let closure = |from: BTreeSet<Tid>, by: &BTreeMap<Tid, BTreeSet<Tid>>| {
        let (mut out, mut stack) = (BTreeSet::new(), from.into_iter().collect::<Vec<_>>());
        while let Some(x) = stack.pop() {
            if out.insert(x) {
                stack.extend(by.get(&x).into_iter().flatten().copied());
            }
        }
        out
    };
    let mut things: BTreeSet<Tid> = held.things().into_iter().collect();
    things.extend(prev.things());
    // a thing with no timeline holds no delta to judge (a node only named till now)
    things.retain(|t| inc.get(t).is_some() || held.created.contains_key(t));
    let before = answers(inc, &nodes, &things, &points);
    let grants = invite_grants(inc, &things);
    let c = inc.update_touched(held, &t);
    let after = answers(inc, &nodes, &things, &points);
    let holders: BTreeSet<Tid> = c.edges.iter().map(|p| p.0).chain(c.created.iter().copied()).collect();
    let targets: BTreeSet<Tid> = c.edges.iter().map(|p| p.1).chain(c.created.iter().copied()).collect();
    let (subjects, reached, below) = (closure(holders, &up), closure(targets, &down), closure(c.created.clone(), &first_admin_of));
    let covered = |n: &Tid, t: &Tid| c.evaluated.contains(t) || below.contains(t) || subjects.contains(n) && reached.contains(t);
    for (k, a) in &after {
        assert!(*a == before[k] || covered(&k.0, &k.1), "an answer about {:?} on {:?} moved unreported: edges {:?}, created {:?}\nwas {}\nnow {a}", k.0, k.1, c.edges, c.created, before[k]);
    }
    let new = invite_grants(inc, &things);
    let old_ids: BTreeSet<osis_base::CommitId> = prev.commits.values().flatten().map(|c| c.id).collect();
    for (w, k) in grants.iter().filter(|(w, _)| !new.contains_key(*w)).chain(new.iter().filter(|(w, _)| !grants.contains_key(*w))) {
        let held_before = old_ids.contains(&w.0);
        // the engine judges again the commits writing a reported edge (`Core::timelines_changed`)
        let own = held.commits.values().flatten().find(|x| x.id == w.0).and_then(|x| x.ops.get(w.1 as usize)).is_some_and(|o| c.edges.contains(&(o.holder, o.target)));
        assert!(!held_before || own || covered(&k.0, &k.1), "invite grant {w:?} of {:?} on {:?} moved unreported: edges {:?}", k.0, k.1, c.edges);
    }
    c
}

/// Late rises of an invite holder over its writes on others' edges: the same edge's write turns
/// from an invite grant to an audited one, so a holder that gave its edge up is demoted (§5.1 step 4).
fn invite_turns(samples: u64, seed: u64) {
    use osis_base::Role::{Admin, Read, Write};
    let seed = seeded(seed);
    let mut rng = Rng(seed);
    for s in 0..samples {
        let mut w = World::new();
        let n = w.nodes(5);
        let (k, a, hs) = (n[0], n[1], &n[2..]);
        let g = w.thing(k);
        w.set(k, g, a, edge_inv(Read, Some(Read), None), 1, &[]);
        for h in hs {
            w.set(k, g, *h, edge(Write), 1, &[]);
        }
        let mut late = Vec::new();
        for _ in 0..8 + rng.below(8) {
            let t = 2 + rng.below(30) as u64;
            let h = hs[rng.below(hs.len())];
            let id = match rng.below(6) {
                0 | 1 => w.set(h, g, h, None, t, &[]),
                2 | 3 => w.set(a, g, h, edge(Read), t, &[]),
                4 => w.set(k, g, a, edge(Admin), t, &[]),
                _ => w.set(k, g, a, edge_inv(Read, Some(Read), None), t, &[]),
            };
            if rng.below(2) == 0 {
                late.push(id);
            }
        }
        let order = rng.perm(late.len());
        let mut skip: BTreeSet<_> = late.iter().copied().collect();
        let mut prev = w.held_without(&skip);
        let mut inc = Timelines::new();
        inc.update(&prev);
        for (step, i) in order.into_iter().enumerate() {
            skip.remove(&late[i]);
            let held = w.held_without(&skip);
            update_moved(&mut inc, &held, &prev);
            if let Some(d) = check(&held, &inc, &n) {
                panic!("seed {seed:#x} sample {s} step {step}: {d}");
            }
            prev = held;
        }
    }
}

/// A role moves only as `Changed` says (`update_moved`) under each generator's histories.
fn moves_on(samples: u64, seed: u64) {
    MOVES.set(true);
    invite_turns(16 * samples, seed ^ 6);
    run(samples, seed);
    adversarial(samples, seed ^ 1);
    adversarial_shapes(samples, seed ^ 2);
    adversarial_corners(samples, seed ^ 3);
    adversarial_falls(samples, seed ^ 4);
    creation_histories(samples, seed ^ 5);
    MOVES.set(false);
}

// spec/permissions.md §5, §5.2: what the engine re-judges and a pass looks at follows `Changed`.
#[test]
fn role_moves_as_reported_spec_permissions_5_2() {
    moves_on(2, 0x5eed_0b01);
}

#[test]
#[ignore]
fn role_moves_as_reported_large() {
    sharded(320, 0x5eed_0b02, moves_on);
}
