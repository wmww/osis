//! Incremental evaluation (spec/permissions.md §5.1 step 5: D is rebuilt from
//! scratch on any change): per-component timelines, cached or continued past their last write,
//! equal the whole held set's timeline after every arrival, in random and in timeline order.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

mod common;

use common::*;
use membership_model::{edges, joint, snapshot, Rng};
use osis_core::Tid;
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
        }
        if part.epoch_start(&t) != full.epoch_start(&t) {
            return Some(format!("epoch start of {t:?}"));
        }
        if part.roster_state(&t) != full.roster_state(&t) {
            return Some(format!("roster state (ledger) of {t:?}"));
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

/// 1-3 leaves (things only their `/created` names) under random held things, leaves included,
/// each with the step from which it is held (0: from the start).
fn add_leaves(w: &mut World, rng: &mut Rng, steps: usize) -> Vec<(Tid, usize)> {
    let mut out = Vec::new();
    for _ in 0..1 + rng.below(3) {
        let owners: Vec<Tid> = w.created.keys().copied().collect();
        let t = w.thing(owners[rng.below(owners.len())]);
        out.push((t, rng.below(steps + 1)));
    }
    out
}

/// The held set without `skip` and without the leaves not held by `step`.
fn held_at(w: &World, skip: &BTreeSet<osis_core::CommitId>, leaves: &[(Tid, usize)], step: usize) -> osis_perm::MemoryHeldSet {
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
                    inc.update_touched(&held, &touched(&prev, &held));
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
        if rng.below(3) == 0 {
            let sw = snap_world(&snapshot::random_hist(&mut rng));
            w = sw.w;
            nodes = sw.nodes;
        } else {
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
    run_restarts(2_000, 0x5eed_0304);
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
                w.set(a, *leaf, m, edge(osis_core::Role::Write), tmax + 1 + k as u64, &[]);
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
                assert_eq!(tl.standing(n, &t, At::END), full.standing(n, &t, At::END), "sample {s}");
            }
        }
        assert_eq!(tl.dropped(), full.dropped(), "sample {s}");
    }
    assert!(extended > 10, "{extended}");
}
