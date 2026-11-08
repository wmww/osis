//! Scale checks of the role timeline (spec/requirements.md Scale): each counts the work an
//! operation does (`osis_perm::commits_walked`, the timeline's measures) at n and 10n and asserts
//! the growth the requirement allows. Tier 1, debug.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

use crate::common;

use common::*;
use osis_base::Role::{Admin, Read, Write};
use osis_base::{CommitId, Tid};
use osis_perm::{At, EdgeOp, Frontier, HeldSet, RoleCommit, Timeline, Timelines, commits_walked};
use roles_model::Rng;
use std::collections::{BTreeMap, BTreeSet};

/// An organization: key actor K is first admin of root actor R (10 admins), first admin of
/// 20 teams; each team is first admin of 10 docs; 300 holder nodes; `n` edge writes (grants,
/// changes, removals on teams and docs) by admins, a few percent received late.
fn org(n: usize) -> (World, Vec<Tid>, Tid) {
    let mut rng = Rng(0x5eed_0401);
    let mut w = World::new();
    let nodes = w.nodes(311);
    let k = nodes[0];
    let root = w.thing(k);
    let teams: Vec<Tid> = (0..20).map(|_| w.thing(root)).collect();
    let docs: Vec<Tid> = teams.iter().flat_map(|t| (0..10).map(|_| *t).collect::<Vec<_>>()).map(|t| w.thing(t)).collect();
    let admins = &nodes[1..11];
    for (i, a) in admins.iter().enumerate() {
        w.set(k, root, *a, edge(Admin), 0, &[(nodes[i], 0)]);
    }
    let holders = &nodes[11..];
    for i in 0..n {
        let t = 1 + i as u64;
        let author = admins[rng.below(admins.len())];
        let target = if rng.below(3) == 0 { teams[rng.below(teams.len())] } else { docs[rng.below(docs.len())] };
        let holder = if rng.below(10) == 0 { teams[rng.below(teams.len())] } else { holders[rng.below(holders.len())] };
        let e = match rng.below(5) {
            0 => None,
            1 => edge(Read),
            2 | 3 => edge(Write),
            _ => edge(Admin),
        };
        let late = rng.below(25) == 0;
        let recv: Vec<(Tid, u64)> = admins.iter().map(|a| (*a, if late { LATE } else { t })).collect();
        w.set(author, target, holder, e, t, &recv);
    }
    (w, nodes, root)
}

/// The commits `f` walked, and its result.
fn walked<T>(f: impl FnOnce() -> T) -> (u64, T) {
    let w0 = commits_walked();
    let r = f();
    (commits_walked() - w0, r)
}

const N: usize = 100;

// spec/requirements.md Scale (role history: a node judges all of it, O(history)),
// spec/permissions.md §5.1: evaluating the org's timeline from scratch walks each commit a bounded
// number of times: the commits walked grow about linearly with the edge writes, not with their
// square.
#[test]
fn evaluate_walks_linear_in_edge_writes() {
    let mut per = Vec::new();
    for n in [N, 10 * N] {
        let (w, _, _) = org(n);
        let held = w.held();
        let (scratch, tl) = walked(|| Timeline::evaluate(&held));
        let (inc, _) = walked(|| Timelines::new().update(&held));
        assert_eq!(tl.passes(), 1);
        per.push((scratch, inc));
    }
    let (a, b) = (per[0], per[1]);
    assert!(b.0 <= 15 * a.0, "evaluate: {a:?} -> {b:?}");
    assert!(b.1 <= 15 * a.1, "update: {a:?} -> {b:?}");
}

/// The org at `n` with one write arriving late, ordered in the middle (its author's later commits
/// list it), held without it; the late write's ID, a doc and the nodes.
fn org_late(n: usize) -> (World, BTreeSet<CommitId>, Tid, Vec<Tid>) {
    let (mut w, nodes, _) = org(n);
    let doc = *w.created.keys().last().unwrap();
    let late = w.set(nodes[2], doc, nodes[201], edge(Read), n as u64 / 2, &[]);
    (w, BTreeSet::from([late]), doc, nodes)
}

// spec/requirements.md Scale (no operation O(history)), spec/permissions.md §5.1: what a node does
// per received role write: 20 writes after every held one, each its own `update_touched` around
// the thing it touched, are placed without walking again (each appended, commits walked flat in
// the history); a walk saved and restored walks nothing, one restored and continued over writes
// added since walks those.
#[test]
fn one_more_write_walks_flat() {
    let mut per = Vec::new();
    for n in [N, 10 * N] {
        let (w, no_late, doc, nodes) = org_late(n);
        let mut held = w.held_without(&no_late);
        let mut inc = Timelines::new();
        inc.update(&held);
        let saved: BTreeMap<Tid, Vec<u8>> = inc.to_save(b"rules", 1, true).put.into_iter().collect();
        let touched = BTreeSet::from([doc]);
        let (mut appended, mut placed) = (0, 0);
        let (each, ()) = walked(|| {
            for i in 0..20u8 {
                let op = EdgeOp { target: doc, holder: nodes[210 + usize::from(i % 20)], edge: edge(if i % 2 == 0 { Read } else { Write }) };
                held.add_commit(RoleCommit { id: CommitId([i; 32]), ts: ts(n as u64 + 100 + u64::from(i)), author: nodes[1], actor: nodes[1], frontier: None, ops: vec![op] });
                inc.update_touched(&held, &touched);
                appended += inc.appended();
                placed += inc.placed();
            }
        });
        assert_eq!((appended, placed), (20, 20), "each write placed in its component's walk");
        // the walk saved before them, restored exact and continued over n/100 more writes
        let held = w.held_without(&no_late);
        let all: BTreeSet<Tid> = held.things().into_iter().collect();
        let mut back = Timelines::new();
        let (restore, ()) = walked(|| {
            back.update_touched_cached(&held, &all, &mut |r| saved.get(r).cloned(), b"rules");
        });
        assert_eq!(back.restored(), 1);
        let mut w2 = w.clone();
        for i in 0..n / 100 {
            w2.set(nodes[1 + i % 10], doc, nodes[200 + i % 2], edge(if i % 2 == 0 { Read } else { Write }), n as u64 + 200 + i as u64, &[]);
        }
        let held2 = w2.held_without(&no_late);
        let all2: BTreeSet<Tid> = held2.things().into_iter().collect();
        let mut stale = Timelines::new();
        let (cont, ()) = walked(|| {
            stale.update_touched_cached(&held2, &all2, &mut |r| saved.get(r).cloned(), b"rules");
        });
        assert_eq!(stale.restored(), 1);
        per.push((each, restore, cont));
    }
    let (a, b) = (per[0], per[1]);
    assert!(b.0 <= 3 * a.0 + 20, "20 more writes: {a:?} -> {b:?}");
    assert_eq!((a.1, b.1), (0, 0), "a restore walks nothing");
    assert!(a.2 <= 2 * (N / 100) as u64 && b.2 <= 2 * N as u64 / 10, "a restore continued walks what was added: {a:?} -> {b:?}");
}

// spec/requirements.md Scale (no operation O(history)), spec/permissions.md §5.1: late writes
// in the middle of the org's history, each through `update_touched` after the ones before:
// one that applies nothing a later item reads is placed in the walk without walking what follows
// it (commits walked flat in the history).
#[test]
fn late_write_placed_without_rewalk() {
    let per = [late_walks(N), late_walks(10 * N)];
    // the read grant reads nothing later: placed walking nothing; the others re-judge the later
    // items that read what they change (issues/perm-eval-cost.md), never a walk of what follows
    assert_eq!((per[0][0], per[1][0]), (0, 0), "{per:?}");
    assert!(per[1].iter().all(|k| *k < (10 * N / 10) as u64), "{per:?}");
}

/// The commits each of five late writes in the middle of the org's history at `n` walks, each
/// through `update_touched` after the ones before: a read grant, a removal of a held edge, an
/// admin grant, a write grant on a team, a read grant by the key actor at the top.
fn late_walks(n: usize) -> Vec<u64> {
    {
        let (mut w, nodes, _) = org(n);
        let mid = n as u64 / 2;
        // a thing with a first admin that is a thing, and a node holding an edge on it just
        // before the middle (by the last write on it)
        let held_before = |t: Tid| {
            let mut last: BTreeMap<Tid, Option<osis_perm::Edge>> = BTreeMap::new();
            for c in w.commits.iter().filter(|c| c.t < mid) {
                for (x, m, e) in &c.ops {
                    if *x == t && nodes.contains(m) {
                        last.insert(*m, *e);
                    }
                }
            }
            last.into_iter().find(|(_, e)| e.is_some()).map(|(m, _)| m)
        };
        let (doc, team, held_holder) = w
            .created
            .iter()
            .rev()
            .find_map(|(t, r)| match r {
                osis_base::CreationRecord::Thing { admin, .. } if w.created.contains_key(admin) => held_before(*t).map(|h| (*t, *admin, h)),
                _ => None,
            })
            .unwrap();
        let cases = [
            ("a read grant", nodes[2], doc, nodes[201], edge(Read)),
            ("a removal", nodes[3], doc, held_holder, None),
            ("an admin grant", nodes[4], doc, nodes[202], edge(Admin)),
            ("a write grant on a team", nodes[5], team, nodes[203], edge(Write)),
            ("a read grant by the top", nodes[0], doc, nodes[204], edge(Read)),
        ];
        let ids: Vec<_> = cases.iter().enumerate().map(|(i, (_, a, t, m, e))| w.set(*a, *t, *m, *e, mid + i as u64, &[])).collect();
        w.set(nodes[1], doc, nodes[200], edge(Write), n as u64 + 5, &[]);
        let mut inc = Timelines::new();
        inc.update(&w.held_without(&ids.iter().copied().collect()));
        let mut counts = Vec::new();
        for (i, (what, _, t, _, _)) in cases.iter().enumerate() {
            let held = w.held_without(&ids[i + 1..].iter().copied().collect());
            let (k, _) = walked(|| inc.update_touched(&held, &BTreeSet::from([*t])));
            assert_eq!((inc.appended(), inc.placed()), (1, 1), "{n}: {what} placed");
            counts.push(k);
        }
        counts
    }
}

// spec/permissions.md §5.1; spec/requirements.md Scale (no operation O(history)): every late write placed with work flat in
// the history. Fails: one that changes what later items read re-judges them (13, 39 at 10^3 against
// 1, 8 at 10^2).
#[test]
#[ignore = "issues/perm-eval-cost.md"]
fn repro_late_write_rejudges_flat() {
    let (a, b) = (late_walks(N), late_walks(10 * N));
    assert!(a.iter().zip(&b).all(|(a, b)| *b <= 3 * a + 5), "{a:?} -> {b:?}");
}

// spec/requirements.md Scale, spec/permissions.md §3 (record chains up to `MAX_CHAIN_DEPTH`): a
// record chain of depth d (each thing's first admin the previous), one holder granted at the top,
// 100 edge writes at the leaf: the walk steps through each commit once at any depth.
#[test]
fn deep_record_chain_walks_each_commit_once() {
    for depth in [6usize, osis_base::format::MAX_CHAIN_DEPTH] {
        let mut w = World::new();
        let nodes = w.nodes(3);
        let mut chain = vec![w.thing(nodes[0])];
        for _ in 1..depth {
            let top = *chain.last().unwrap();
            chain.push(w.thing(top));
        }
        let (top, leaf) = (chain[0], *chain.last().unwrap());
        w.set(nodes[0], top, nodes[1], edge(Admin), 1, &[(nodes[0], 1)]);
        for i in 0..100u64 {
            let e = if i % 2 == 0 { edge(Read) } else { edge(Write) };
            w.set(nodes[1], leaf, nodes[2], e, 2 + i, &[(nodes[1], 2 + i)]);
        }
        let held = w.held();
        let (k, tl) = walked(|| Timeline::evaluate(&held));
        assert_eq!(tl.role(&nodes[1], &leaf, At::END), Some(Admin));
        assert_eq!(tl.role(&nodes[2], &leaf, At::END), Some(Write));
        assert_eq!((k, tl.passes()), (101, 1), "depth {depth}");
    }
}

/// The org at `n` with drops: every 40th write an admin writes unseen (received late), another
/// removes it from the root at once (dropping that write) and grants it back; the doc written
/// unseen, the root and the nodes.
fn org_drops(n: usize) -> (World, Tid, Tid, Vec<Tid>) {
    let (mut w, nodes, root) = org(n);
    let admins = nodes[1..11].to_vec();
    let doc = *w.created.keys().last().unwrap();
    let mut rng = Rng(0x5eed_0402);
    for i in (0..n).step_by(40) {
        let t = n as u64 + 10 + 4 * i as u64;
        let a = 1 + rng.below(10);
        let b = 1 + (a + rng.below(9)) % 10;
        let (a, b) = (nodes[a], nodes[b]);
        let unseen: Vec<(Tid, u64)> = admins.iter().map(|x| (*x, if *x == a { t } else { LATE })).collect();
        w.set(a, doc, nodes[11 + rng.below(300)], edge(Write), t, &unseen);
        let seen: Vec<(Tid, u64)> = admins.iter().map(|x| (*x, t + 1)).collect();
        w.set(b, root, a, None, t + 1, &seen);
        let seen: Vec<(Tid, u64)> = admins.iter().map(|x| (*x, t + 2)).collect();
        w.set(b, root, a, edge(Admin), t + 2, &seen);
    }
    (w, doc, root, nodes)
}

/// Commits evaluating `org_drops(n)` from scratch walks, and its drops.
fn drops_walked(n: usize) -> (u64, usize) {
    let (w, ..) = org_drops(n);
    let (k, tl) = walked(|| Timeline::evaluate(&w.held()));
    (k, tl.dropped().len())
}

// spec/requirements.md Scale (role history: judged whole), spec/permissions.md §5.1 step 5 (walk
// until D stops growing): with drops in proportion to the writes, each new drop resumes the walk
// from the first write it skips, so the commits walked grow with writes times drops: bounded here
// by the square (issues/perm-eval-cost.md; `repro_evaluate_with_drops_linear` states the target).
#[test]
fn evaluate_with_drops_at_most_quadratic() {
    let (a, b) = (drops_walked(N), drops_walked(10 * N));
    assert!(b.1 >= 5 * a.1, "drops grow with the writes: {a:?} -> {b:?}");
    assert!(b.0 <= 100 * a.0, "{a:?} -> {b:?}");
}

// spec/permissions.md §5.1 step 5; spec/requirements.md Scale (no operation O(history) beyond judging the role history once):
// evaluating the org with drops walks about linearly many commits. Fails: 125 at 10^2 (3 drops),
// 8039 at 10^3 (60 drops).
#[test]
#[ignore = "issues/perm-eval-cost.md"]
fn repro_evaluate_with_drops_linear() {
    let (a, b) = (drops_walked(N), drops_walked(10 * N));
    assert!(b.0 <= 15 * a.0, "{a:?} -> {b:?}");
}

// spec/requirements.md Scale (no operation O(history)), spec/permissions.md §5.1 (demotion
// scope): a demotion's scope (`Timeline::demotion_scope`: the walk copied, the demotion
// appended) on the org with drops, removing a holder from a doc and an admin from the root, with
// an empty frontier and one listing all held: placed walking a bounded number of commits, except
// the admin's removal under an empty frontier, whose audit drops what it puts in question and
// walks on from there: linear in the history.
#[test]
fn demotion_scope_walks_at_most_the_history() {
    let mut per = Vec::new();
    for n in [N, 10 * N] {
        let (w, doc, root, nodes) = org_drops(n);
        let tl = Timeline::evaluate(&w.held());
        let end = 5 * n as u64 + 100;
        let holder = tl.roster(&doc, At::END).into_keys().find(|h| nodes.contains(h)).unwrap();
        let mut scope = Vec::new();
        for (target, holder) in [(doc, holder), (root, nodes[1])] {
            for f in [Frontier::default(), tl.all_held()] {
                let r = RoleCommit { id: CommitId([0xee; 32]), ts: ts(end), author: nodes[0], actor: nodes[0], frontier: Some(std::sync::Arc::new(f)), ops: vec![EdgeOp { target, holder, edge: None }] };
                scope.push(walked(|| tl.demotion_scope(r)).0);
            }
        }
        per.push((scope, w.commits.len() as u64));
    }
    let ((a, _), (b, commits)) = (&per[0], &per[1]);
    for i in [0, 1, 3] {
        assert!(b[i] <= 2 * a[i] + 2, "case {i}: {a:?} -> {b:?}");
    }
    assert!(b[2] <= 15 * a[2] && b[2] <= *commits, "{a:?} -> {b:?}");
}

// spec/requirements.md Scale (no operation O(total data)), spec/permissions.md §3 (a record edge in
// force by its record alone): n plain things under one actor: evaluating walks only the role
// commits, not the leaves; one more leaf through `update_touched` walks nothing.
#[test]
fn record_leaves_walk_nothing_per_leaf() {
    let mut per = Vec::new();
    for n in [1_000usize, 10_000] {
        let mut w = World::new();
        let nodes = w.nodes(3);
        let a = w.thing(nodes[0]);
        w.set(nodes[0], a, nodes[1], edge(Admin), 1, &[(nodes[0], 1)]);
        w.set(nodes[1], a, nodes[2], edge(Read), 2, &[(nodes[0], 2), (nodes[1], 2)]);
        let leaves: Vec<Tid> = (0..n).map(|_| w.thing(a)).collect();
        let held = w.held();
        let (eval, tl) = walked(|| Timeline::evaluate(&held));
        let leaf = leaves[n / 2];
        assert_eq!(tl.role(&nodes[1], &leaf, At::END), Some(Admin));
        assert_eq!(tl.role(&nodes[2], &leaf, At::END), Some(Read));
        assert_eq!(tl.roster(&leaf, At::END).keys().copied().collect::<Vec<_>>(), vec![a], "the record edge alone");
        drop(tl);
        let mut inc = Timelines::new();
        inc.update(&held);
        let mut w2 = w.clone();
        let extra = w2.thing(a);
        let held2 = w2.held();
        let (one, changed) = walked(|| inc.update_touched(&held2, &BTreeSet::from([extra])));
        assert_eq!(inc.get(&extra).unwrap().role(&nodes[1], &extra, At::END), Some(Admin));
        assert_eq!(changed.evaluated.len(), 0, "{n}: the leaf joins its component without a walk");
        per.push((eval, one));
    }
    assert_eq!(per, [(2, 0), (2, 0)], "the two role commits walked once; a leaf walks nothing");
}
