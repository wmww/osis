//! Incremental evaluation (spec/permissions.md §5.1 step 5: D is rebuilt from
//! scratch on any change): per-component timelines, cached or continued past their last write,
//! equal the whole held set's timeline after every arrival, in random and in timeline order.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

use crate::common;

use common::*;
use membership_model::{edges, joint, snapshot, Rng};
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
                // layer 2 there (re-grant's first tenure is carried over `extend`)
                let p = osis_perm::Point { node: *n, commit: osis_base::CommitId([0xee; 32]), ..a.point };
                for r in [osis_base::Role::Read, osis_base::Role::Write, osis_base::Role::Admin] {
                    if part.delta_valid(p, &t, "/x", osis_perm::Dots::Commit, r) != full.delta_valid(p, &t, "/x", osis_perm::Dots::Commit, r) {
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

/// 1-3 leaves (things only their `/created` names) under random held things, leaves included,
/// and 0-2 things the history names whose `/created` arrives late (§1: their owner links),
/// each with the step from which its `/created` is held (0: from the start).
fn add_leaves(w: &mut World, rng: &mut Rng, steps: usize) -> Vec<(Tid, usize)> {
    let mut out = Vec::new();
    for _ in 0..1 + rng.below(3) {
        let owners: Vec<Tid> = w.created.keys().copied().collect();
        let t = w.thing(owners[rng.below(owners.len())]);
        out.push((t, rng.below(steps + 1)));
    }
    let named: Vec<Tid> = w.created.iter().filter(|(t, r)| matches!(r, osis_base::CreationRecord::Thing { .. }) && !out.iter().any(|l| l.0 == **t)).map(|(t, _)| *t).collect();
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
        let s: BTreeSet<_> = h.roster_snapshots(t).iter().map(|s| s.id).collect();
        (c, s, h.created(t))
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

/// §5.1 step 5, §6: two sibling teams that are admins of each other (owner-chain authority on
/// each may come through the other), with a snapshot that is never a start: each write in
/// timeline order continues the walk (`extend`), equal to evaluating from scratch.
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
    assert!(run(10, 0x5eed_0301) > 0);
}

#[test]
#[ignore]
fn incremental_equals_from_scratch_large() {
    assert!(sharded(1_024, 0x5eed_0302, run).iter().sum::<usize>() > 0);
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
    let c1 = w.set(k, g, x, edge(osis_base::Role::Admin), 10, &[]);
    let c2 = w.set(x, d, k, edge(osis_base::Role::Write), 11, &[]);
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

/// §5.1: a new thing's `/created` alone (nothing names it yet: `Timeline::add_leaves`, no held-set
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
/// (first tenures) kept from before it, and those rebuilt after, equal an evaluation from
/// scratch. Member 1, admin at the end, has its first admin tenure moved earlier by the late
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
                let _ = tl.delta_valid(osis_perm::Point { node: *x, ..a.point }, &g, "/x", osis_perm::Dots::Commit, r);
            }
        }
    }
    let all = w.held();
    let c = inc.update_touched(&all, &touched_of(&held, &all));
    assert!(c.evaluated.is_empty(), "{c:?}");
    assert_eq!(inc.appended(), 1);
    assert!(check(&all, &inc, &n).is_none(), "{:?}", check(&all, &inc, &n));
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

/// spec/commits.md §4 (overlapping node-form `/members` ranges void both commits), spec/permissions.md §5.1:
/// writes after every held one go on by `Timelines::append` alone while their ranges are
/// disjoint; one overlapping a held range (or a voided one) takes the general path, and every
/// step equals an evaluation from scratch.
#[test]
fn append_declines_overlapping_ranges_spec_commits_4() {
    use osis_base::Role::{Admin, Read, Write};
    let mut w = World::new();
    let n = w.nodes(4);
    let (k, a) = (n[0], n[1]);
    let g = w.thing(k);
    w.set(k, g, a, edge(Admin), 1, &[]);
    // members already known: a new node always takes the general path
    w.set(k, g, n[2], edge(Read), 2, &[]);
    w.set(k, g, n[3], edge(Read), 3, &[]);
    let mut held = w.held();
    let mut inc = Timelines::new();
    inc.update(&held);
    // (member, role, range, appended alone)
    let steps = [(n[2], Write, (0, 2), true), (n[3], Read, (2, 4), true), (n[2], Read, (3, 5), false), (n[3], Write, (4, 6), false), (n[2], Write, (6, 7), true)];
    for (i, (m, r, (lo, hi), alone)) in steps.into_iter().enumerate() {
        let op = osis_perm::EdgeOp { target: g, member: m, edge: edge(r), dots: osis_perm::Dots::Node { lo, hi } };
        let id = osis_base::CommitId([0x40 + i as u8; 32]);
        held.add_commit(osis_perm::MembershipCommit { id, ts: ts(10 + i as u64), author: a, actor: a, frontier: None, ops: vec![op] });
        inc.update_touched(&held, &BTreeSet::from([g]));
        assert_eq!(inc.appended() == 1, alone, "step {i}");
        assert!(check(&held, &inc, &n).is_none(), "step {i}: {:?}", check(&held, &inc, &n));
    }
    let full = Timeline::evaluate(&held);
    assert!(full.membership_commit(&osis_base::CommitId([0x41; 32])).is_none(), "voided");
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

/// §5.1 step 2, §6: late writes in the middle of a history that apply nothing there (by a node
/// with no authority at that point; on a thing before its epoch start) leave the walk as it is
/// (`Timeline::append` judges them over the edge state at their place), equal to an evaluation
/// from scratch.
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
    w.snapshot(k, h, &[(x, osis_perm::Edge::new(Read))], 50, &[]);
    // late: x's writes in the middle (rejected), k's write on h before its epoch start
    let late = [w.set(x, h, n[3], edge(Write), 41, &[]), w.set(x, g, n[2], edge(Admin), 43, &[]), w.set(k, h, n[2], edge(Write), 45, &[])];
    let mut skip: BTreeSet<_> = late.into_iter().collect();
    let mut prev = w.held_without(&skip);
    let mut inc = Timelines::new();
    inc.update(&prev);
    assert!(inc.get(&h).unwrap().epoch_start(&h).is_some());
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
/// grants, removals, demotions with partial frontiers, invites, `until`, a team, sometimes a
/// roster snapshot held from the start; two nodes only some writes name, one with its
/// `/created` held, one without), the second half arriving late in random order through
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
        if rng.below(4) == 0 {
            w.snapshot(k, g, &[(n[1], osis_perm::Edge::new(Admin)), (n[2], osis_perm::Edge::new(Admin)), (team, osis_perm::Edge::new(Admin))], 2 + rng.below(20) as u64, &[]);
        }
        let mut late = Vec::new();
        for _ in 0..10 + rng.below(10) {
            let author = if rng.below(10) == 0 { extra[rng.below(2)] } else { n[if rng.below(6) == 0 { 0 } else { 1 + rng.below(4) }] };
            let target = targets[rng.below(targets.len())];
            let member = match rng.below(10) {
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
            let id = w.set(author, target, member, e, t, &[]);
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
            inc.update_touched(&held, &touched(&prev, &held));
            appended += inc.appended();
            if let Some(d) = check(&held, &inc, &n) {
                panic!("seed {seed:#x} sample {s} step {step}: {d}");
            }
            prev = held;
        }
    }
    appended
}

/// §5.1 steps 4-5, §6: late arrivals through `update_touched` equal from scratch.
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
/// item reads what they change (a read or write grant to a member no later write names);
/// one that a later write on its edge reads, or an admin grant whose member writes later,
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
/// update; then the removal of a placed write's member (an audit nothing later reads: placed)
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

/// §5.1: a member new to the group (a key actor whose `/created` alone is held, or no record
/// at all) granted late joins the group's walk by `Timelines::append` (a node no earlier write
/// names reaches nothing before it), not by an evaluation from scratch, as does one whose
/// `/created` arrives with the grant; then writes of its own. Each equals an evaluation from
/// scratch.
#[test]
fn new_member_joins_walk_spec_permissions_5_1() {
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
    let end = osis_perm::Point { ts: ts(LATE), node: nodes[0], commit: osis_base::CommitId([0xff; 32]) };
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
            // (per component: a node of another one brings no `/keys` here)
            let f = fresh.get(&t)?.certificates(n, &t, end);
            if part.certificates(n, &t, end) != f {
                return Some(format!("certificates of {n:?} on {t:?}: part {:?} fresh {f:?}", part.certificates(n, &t, end)));
            }
        }
    }
    None
}

/// Random histories over an owner chain (P owned by the key, Q by P, R by Q), two nested
/// teams and a thing as member, with `until` on every role, invites of every level, removals,
/// widenings, two-op commits, sometimes a snapshot held from the start or arriving late; half
/// the commits arrive late, one to three at a time, in random order through `update_touched`,
/// with restarts from saved walks now and then; equal to an evaluation from scratch after every arrival. Returns (updates `append` did
/// alone, commits placed without walking again).
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
        let members = [team, team2, p];
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
        if rng.below(4) == 0 {
            let thing = [g, p][rng.below(2)];
            let id = w.snapshot(k, thing, &[(n[1], osis_perm::Edge::new(Admin)), (n[3], osis_perm::Edge::new(Admin)), (team, osis_perm::Edge::new(Write))], 3 + rng.below(30) as u64, &[]);
            if rng.below(2) == 0 {
                late.push(id);
            }
        }
        let op = |rng: &mut Rng, n: &[Tid]| {
            let target = targets[rng.below(targets.len())];
            let member = match rng.below(12) {
                0 | 1 => members[rng.below(members.len())],
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
            (target, member, e)
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
            inc.update_touched(&held, &touched(&prev, &held));
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

/// §5.1 steps 2-5, §6: late arrivals over owner chains, teams, `until`, invites and removals
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
    assert!(appended > 0 && placed > 1_000, "{appended} {placed}");
}

/// §5.1 step 5, §6: a held record replaced under its commit ID by a fuller one (a roster
/// snapshot whose `/tenures` part arrives after its `/members` part; a commit with more of its
/// edge writes) changes the input: through `update_touched`, after a restart from walks saved
/// before, and with a cached component of the same IDs, equal to an evaluation from scratch.
#[test]
fn record_replaced_under_its_id_spec_permissions_6() {
    use osis_base::Role::{Admin, Read, Write};
    for fuller in [true, false] {
        let mut w = World::new();
        let n = w.nodes(4);
        let k = n[0];
        let g = w.thing(k);
        w.set(k, g, n[1], edge(Admin), 1, &[]);
        w.set(k, g, n[2], edge(Write), 2, &[]);
        w.set(n[1], g, n[2], None, 5, &[]);
        let s = w.snapshot(k, g, &[(n[1], osis_perm::Edge::new(Admin))], 10, &[]);
        let c = w.set(n[1], g, n[3], edge(Read), 12, &[]);
        let mut part = w.clone();
        if fuller {
            // the snapshot's `/tenures` part arrives late
            w.snaps.iter_mut().find(|x| x.id == s).unwrap().ledger = vec![(n[2], Write, Some((2, k, None)), (5, n[1], None), true)];
        } else {
            // the commit's second edge write arrives late
            w.commits.iter_mut().find(|x| x.id == c).unwrap().ops.push((g, n[2], edge(Admin)));
            part.commits.iter_mut().find(|x| x.id == c).unwrap().ops.truncate(1);
        }
        let first = part.held();
        let held = w.held();
        // incrementally
        let mut inc = Timelines::new();
        inc.update(&first);
        inc.update_touched(&held, &BTreeSet::from([g]));
        assert!(check(&held, &inc, &n).is_none(), "{fuller}: {:?}", check(&held, &inc, &n));
        // the general path (a cached component of the same IDs)
        let mut inc = Timelines::new();
        inc.update(&first);
        inc.update(&held);
        assert!(check(&held, &inc, &n).is_none(), "{fuller} (update): {:?}", check(&held, &inc, &n));
        // a restart from walks saved over the partial records
        let mut inc = Timelines::new();
        inc.update(&first);
        let mut disk = Disk::new();
        store(&mut disk, inc.to_save(SALT, 1, true));
        let inc = reopen(&held, &disk, SALT);
        assert!(check(&held, &inc, &n).is_none(), "{fuller} (restart): {:?}", check(&held, &inc, &n));
        // a walk continued over a new commit after the replacement
        let mut more = w.clone();
        more.set(n[1], g, n[3], None, 20, &[]);
        let last = more.held();
        let mut inc = Timelines::new();
        inc.update(&first);
        inc.update_touched(&last, &BTreeSet::from([g]));
        assert!(check(&last, &inc, &n).is_none(), "{fuller} (with a new commit): {:?}", check(&last, &inc, &n));
    }
}

/// §5.1 steps 2-4: late writes in the middle that later items read, placed by walking those
/// items again at their place (with the write and without; equal, nothing new dropped): an
/// explicit removal (an audit: the member's demotion recorded at its point), a write by an
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

/// §1, §5.1: a thing an earlier write names (as member) whose `/created` arrives late, and one
/// named as target: the walk goes on from the first item naming it (before it, a node's role on
/// it is its role on its owner), not evaluated anew; equal to an evaluation from scratch.
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
/// joined (its `/created`, a grant to it, a write of its own) and a thing named before its
/// `/created` arrived is restored and continued, not evaluated anew; equal to an evaluation
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
/// 2-5, §6): no writes before the late ones (a late write is often its author's first on its
/// target, so falls before the old first write appear), ties in ts, an owner chain through
/// things (a doc owned by a team, a sub-doc by the doc) and things as members, invites,
/// `until`, removals, two-op commits, late writes by the key actor at the top, sometimes an
/// epoch start with an audited ledger (virtual writes with a frontier) held from the start,
/// and `/created` records of named things and of new nodes arriving late, with commits or
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
        let members = [team, doc];
        w.set(k, g, n[1], edge(Admin), 1, &[]);
        w.set(k, g, n[2], edge(Admin), 1, &[]);
        w.set(k, team, n[3], edge(Admin), 1, &[]);
        w.set(k, g, team, edge([Admin, Write, Read][rng.below(3)]), 1, &[]);
        let mut late = Vec::new();
        if rng.below(3) == 0 {
            // an epoch start whose ledger records audited demotions before it
            let thing = [g, team][rng.below(2)];
            let a = n[1 + rng.below(3)];
            let ledger: Vec<LedgerSpec> = (0..1 + rng.below(2)).map(|_| {
                let t0 = 2 + rng.below(6) as u64;
                (n[3 + rng.below(3)], [Write, Admin][rng.below(2)], (rng.below(2) == 0).then_some((t0, a, None)), (t0 + 1 + rng.below(6) as u64, a, None), rng.below(3) != 0)
            }).collect();
            let roster = [(n[1], osis_perm::Edge::new(Admin)), (n[3], osis_perm::Edge::new([Write, Admin][rng.below(2)])), (team, osis_perm::Edge::new(Write))];
            let recv: Vec<(Tid, u64)> = n.iter().map(|x| (*x, rng.below(20) as u64)).collect();
            let id = w.snapshot_l(k, thing, &roster, &ledger, 8 + rng.below(12) as u64, &recv);
            if rng.below(4) == 0 {
                late.push(id);
            }
        }
        let op = |rng: &mut Rng, n: &[Tid]| {
            let target = targets[rng.below(targets.len())];
            let member = match rng.below(12) {
                0 | 1 => members[rng.below(members.len())],
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
            (target, member, e)
        };
        // admins and the team's admin edge removed and given back: classes fall and return
        let toggle = |rng: &mut Rng, n: &[Tid]| {
            let (target, member) = [(g, n[1]), (g, n[2]), (team, n[3]), (g, team), (team, n[4]), (doc, n[5])][rng.below(6)];
            (target, member, [None, edge(Admin), edge(Write)][rng.below(3)])
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
        // `/created` records held late: a team or doc the history names, the node with one
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
            // (half the time the `/created` records of this step alone first)
            if rng.below(2) == 0 && created_late.iter().any(|c| c.1 == step) {
                let held = held_at(&w, &skip, &created_late, step);
                inc.update_touched(&held, &touched(&prev, &held));
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
            inc.update_touched(&held, &touched(&prev, &held));
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
        inc.update_touched(&held, &touched(&prev, &held));
        if let Some(d) = check(&held, &inc, &n) {
            panic!("seed {seed:#x} sample {s} (all records): {d}");
        }
    }
    (appended, placed)
}

/// §5.1 steps 2-5, §6: late arrivals at the placement paths' corners equal from scratch.
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
    assert!(appended > 0 && placed > 1_000, "{appended} {placed}");
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

/// §5.1 step 5: a late admin grant to a team whose members write on the thing in every later
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
                let (target, member) = [(g, n[1]), (g, n[2]), (g, team), (team, n[3]), (team, n[4]), (doc, n[3])][rng.below(6)];
                let e = [None, None, edge(Admin), edge(Write), edge_inv(Admin, None, Some(t + 1 + rng.below(6) as u64))][rng.below(5)];
                w.set(author, target, member, e, t, &recv)
            } else {
                let author = n[1 + rng.below(4)];
                let target = [g, doc, doc, team][rng.below(4)];
                let member = n[1 + rng.below(5)];
                let e = [None, edge(Read), edge(Write), edge(Admin), edge_inv(Write, Some(Read), None)][rng.below(5)];
                w.set(author, target, member, e, t, &recv)
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
            inc.update_touched(&held, &touched(&prev, &held));
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
    assert!(appended > 0 && placed > 1_000, "{appended} {placed}");
}

/// §1, §5.1 step 4: a thing named as a member by a write that a later fall drops (a node
/// until its `/created` says it is owned) gets its `/created` late: the walk goes on from the
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
        assert!(full.dropped().contains_key(&WriteId::Op(dropped, 0)), "the fall drops it");
        let mut held = if with_commit { w.held() } else { w.held_without(&BTreeSet::from([late])) };
        held.created.insert(doc, w.created[&doc].clone());
        let c = inc.update_touched(&held, &touched(&prev, &held));
        assert!(c.evaluated.is_empty(), "{with_commit}: {c:?}");
        assert!(check(&held, &inc, &n).is_none(), "{with_commit}: {:?}", check(&held, &inc, &n));
        assert!(Timeline::evaluate(&held).dropped().contains_key(&WriteId::Op(dropped, 0)));
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
        assert_eq!(full.dropped().contains_key(&WriteId::Op(late, 0)), !covered);
    }
}

/// §1, §5.1: leaves joining an owner chain around `MAX_OWNER_DEPTH` (a deeper thing has no owner
/// chain, so no role there and no demotion): through `update_touched` equal to from scratch.
#[test]
fn leaves_past_owner_depth_spec_permissions_1() {
    use osis_base::Role::Admin;
    let mut w = World::new();
    let n = w.nodes(2);
    let (k, x) = (n[0], n[1]);
    let mut chain = vec![w.thing(k)];
    for _ in 0..osis_base::format::MAX_OWNER_DEPTH + 2 {
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
        if let Some(osis_base::CreationRecord::Thing { owner, .. }) = held.created(&t) {
            all.insert(owner);
        }
        for c in held.edge_commits(&t) {
            all.insert(c.author);
            all.extend(c.ops.iter().flat_map(|o| [o.member, o.target]));
        }
        for x in held.roster_snapshots(&t) {
            all.insert(x.author);
            all.extend(x.roster.keys().copied());
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

/// Random histories biased toward thing creation: owner trees grown as commits arrive (leaves,
/// chains of new things in one arrival, things created then named by later commits, `/created`
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
        // new things, owners among everything so far (chains, siblings, deep trees)
        let mut things: Vec<Tid> = base.to_vec();
        let mut fresh = Vec::new();
        for _ in 0..6 + rng.below(14) {
            let owner = match rng.below(8) {
                0 => n[rng.below(3)],
                1 | 2 if !fresh.is_empty() => fresh[fresh.len() - 1],
                _ => things[rng.below(things.len())],
            };
            let t = w.thing(owner);
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
            let member = match rng.below(6) {
                0 => named.get(rng.below(named.len().max(1))).copied().unwrap_or(base[2]),
                1 => base[2],
                _ => all_nodes[rng.below(5)],
            };
            let until = (rng.below(4) == 0).then(|| 5 + rng.below(40) as u64);
            let e = match rng.below(5) {
                0 => None,
                _ => edge_inv([Read, Write, Admin][rng.below(3)], None, until),
            };
            w.commit(author, 2 + rng.below(40) as u64, &[(target, member, e)], &[]);
        }
        if rng.below(5) == 0 {
            let t = named.first().copied().unwrap_or(base[0]);
            w.snapshot(k, t, &[(n[1], osis_perm::Edge::new(Admin))], 2 + rng.below(40) as u64, &[]);
        }
        // arrivals: each new `/created` and each commit, in random order, 1-4 at a time
        #[derive(Clone, Copy)]
        enum Item {
            Created(Tid),
            Commit(osis_base::CommitId),
        }
        let mut items: Vec<Item> = w.created.keys().filter(|t| !start.contains_key(*t)).map(|t| Item::Created(*t)).collect();
        items.extend(w.commits.iter().map(|c| c.id).chain(w.snaps.iter().map(|x| x.id)).filter(|id| !start_commits.contains(id)).map(Item::Commit));
        let order = rng.perm(items.len());
        let all_ids: BTreeSet<_> = w.commits.iter().map(|c| c.id).chain(w.snaps.iter().map(|x| x.id)).collect();
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
            let a = fast.update_touched(&held, &t);
            let b = general.update_touched(&held, &t);
            appended += fast.appended();
            // The general path may report more: when several old components merge it continues
            // the one with the most commits, then things, and names the others' things. Each
            // must be a node bringing nothing, or owned under a thing the fast path names
            // (authority there follows its owner's).
            let fa: BTreeSet<Tid> = a.evaluated.union(&a.extended).copied().collect();
            let fb: BTreeSet<Tid> = b.evaluated.union(&b.extended).copied().collect();
            let covered = |x: &Tid| {
                let mut cur = *x;
                for _ in 0..64 {
                    if fa.contains(&cur) {
                        return true;
                    }
                    match held.created(&cur) {
                        Some(osis_base::CreationRecord::Thing { owner, .. }) => cur = owner,
                        _ => return cur == *x && held.edge_commits(x).is_empty() && held.roster_snapshots(x).is_empty(),
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

/// §5.1: a lone node's first commit joins it to a component without commits (an owner chain):
/// the general path continues the larger component and reports the node and the commit's
/// target, as `append` does, not the target's owners (seed 7301 of
/// `creation_fast_equals_general_large`: it continued the node's walk and reported them all).
#[test]
fn merge_continues_the_larger_component_spec_permissions_5_1() {
    use osis_base::Role::Write;
    let mut w = World::new();
    let mut n = w.nodes(4);
    n.sort();
    // the lone node sorts after the owner chain's root, so `{lone}` is the larger key
    let (owner, lone) = (n[0], n[3]);
    let a = w.thing(owner);
    let b = w.thing(a);
    let c = w.set(lone, b, lone, edge(Write), 1, &[]);
    let prev = w.held_without(&BTreeSet::from([c]));
    let held = w.held();
    for general_only in [false, true] {
        let mut inc = Timelines::new();
        inc.set_general_only(general_only);
        inc.update(&prev);
        assert!(!std::ptr::eq(inc.get(&lone).unwrap(), inc.get(&b).unwrap()));
        let ch = inc.update_touched(&held, &touched(&prev, &held));
        assert!(ch.evaluated.is_empty(), "{ch:?}");
        let want: BTreeSet<Tid> = if general_only { [lone, b].into() } else { [b].into() };
        assert_eq!(ch.extended, want, "general only: {general_only}");
        assert!(check(&held, &inc, &n).is_none(), "{:?}", check(&held, &inc, &n));
    }
}

/// §1, §5.1: thing creation arriving among membership commits; the fast path equals the
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
