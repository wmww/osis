//! Incremental update is from-scratch evaluation restricted to what changed (notes/perm-paths.md,
//! One definition): commits added one at a time in any arrival order read as the walk of all of
//! them from scratch, and each update's `Changed` names exactly the parts whose status changed
//! and, per edge, the first key from which its history changed.
//! spec: none (the walk's update path; its rules are those of spec/permissions.md §5.1).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

use super::{input, rules, MODES};
use osis_base::{CommitId, Role, Tid};
use osis_perm::paths::{Changed, Content, History, Key, Paths, Status};
use osis_perm::WriteId;
use roles_model::paths as m;
use roles_model::Rng;
use std::collections::{BTreeMap, BTreeSet};

type Finals = BTreeMap<(Tid, Tid), (Option<Role>, Option<Role>)>;
type Reading = (BTreeMap<WriteId, Status>, BTreeMap<(Tid, Tid), History>, Finals, BTreeMap<WriteId, Content>, BTreeSet<CommitId>, BTreeSet<WriteId>, BTreeMap<(Tid, Tid), [Option<Key>; 2]>);

pub(super) fn reading(p: &Paths) -> Reading {
    (p.statuses(), p.histories(), p.finals(), p.contents(), p.copies(), p.purged(), p.chained())
}

fn valid(c: Option<&Content>) -> bool {
    matches!(c, Some(Content::Valid(_)))
}

/// Whether `ch`, reported by the update from `a` to `b`, is what the two readings differ by:
/// exact for edge-class statuses, history, cuts and re-grant points; every new part reported;
/// any other delta reported is one whose validity changed (an addendum's); and every delta whose
/// verdict or purge changed is reachable from `ch` by `Changed`'s rule.
pub(super) fn check(a: &Paths, b: &Paths, ch: &Changed) -> Option<String> {
    let (sa, ha, fa, ca, _, pa, xa) = reading(a);
    let (sb, hb, fb, cb, _, pb, xb) = reading(b);
    let mut want = Changed::default();
    for (id, s) in &sb {
        if sa.get(id) != Some(s) {
            want.parts.insert(*id);
        }
    }
    want.parts.extend(cb.keys().filter(|id| !ca.contains_key(id)));
    let extra: Vec<&WriteId> = ch.parts.iter().filter(|id| !want.parts.contains(id)).collect();
    if let Some(id) = extra.iter().find(|id| !ca.contains_key(id) || valid(ca.get(id)) == valid(cb.get(id))) {
        return Some(format!("reported {id:?}, which did not change"));
    }
    if let Some(id) = want.parts.iter().find(|id| !ch.parts.contains(id)) {
        return Some(format!("{id:?} changed unreported: {ch:?}"));
    }
    let empty = vec![];
    let edges: BTreeSet<&(Tid, Tid)> = ha.keys().chain(hb.keys()).collect();
    for e in edges {
        let (x, y) = (ha.get(e).unwrap_or(&empty), hb.get(e).unwrap_or(&empty));
        let at = x.iter().zip(y).position(|(p, q)| p != q).unwrap_or(x.len().min(y.len()));
        if let Some(k) = x.get(at).map(|p| p.0).into_iter().chain(y.get(at).map(|q| q.0)).min() {
            want.edges.insert(*e, k);
        }
        let cuts = |p: &Paths| -> BTreeSet<(Key, [bool; 2])> { p.writes(&e.0, &e.1).iter().map(|w| (w.key, [w.cuts(Role::Write), w.cuts(Role::Admin)])).filter(|c| c.1 != [false, false]).collect() };
        if let Some(k) = cuts(a).symmetric_difference(&cuts(b)).map(|c| c.0).max() {
            want.cuts.insert(*e, k);
        }
    }
    let fin: BTreeSet<&(Tid, Tid)> = fa.keys().chain(fb.keys()).chain(xa.keys()).chain(xb.keys()).collect();
    for e in fin {
        if fa.get(e).and_then(|f| f.0) != fb.get(e).and_then(|f| f.0) || xa.get(e).copied().unwrap_or_default() != xb.get(e).copied().unwrap_or_default() {
            want.regrant.insert(*e);
        }
    }
    if (&ch.edges, &ch.cuts, &ch.regrant) != (&want.edges, &want.cuts, &want.regrant) {
        return Some(format!("reported {ch:?}, readings differ by {want:?}"));
    }
    // every delta whose verdict or purge changed: itself or what names it reached by `ch`
    let direct = |id: &WriteId| -> bool {
        ch.parts.contains(id)
            || ch.named.contains(&id.0)
            || b.rests(id).is_some_and(|(hops, pos)| hops.iter().any(|e| ch.edges.get(e).is_some_and(|k| *k < pos) || ch.cuts.get(e).is_some_and(|k| *k >= pos) || ch.regrant.contains(e)))
    };
    for (id, c) in &cb {
        let moved = ca.get(id) != Some(c) || pa.contains(id) != pb.contains(id);
        if moved && !direct(id) && !b.naming(id).iter().any(|n| direct(n) || ca.get(n) != cb.get(n)) {
            return Some(format!("delta {id:?} moved from {:?} to {c:?} (purged {} to {}) unreached by {ch:?}", ca.get(id), pa.contains(id), pb.contains(id)));
        }
    }
    None
}

/// A view's commits added one at a time in an order shuffled by `seed`: each `Changed` against the
/// readings, and the end against from scratch.
fn shuffled(w: &m::World, v: &m::View, seed: u64) -> Option<String> {
    let inp = input(w, v);
    let mut order = inp.commits.clone();
    let mut rng = Rng(seed);
    for k in (1..order.len()).rev() {
        order.swap(k, rng.below(k + 1));
    }
    let mut p = Paths::new(&inp.records, inp.trust.clone());
    for c in &order {
        let before = p.clone();
        let ch = p.add(std::slice::from_ref(c));
        if let Some(d) = check(&before, &p, &ch) {
            return Some(format!("adding {:?}: {d}\n{}", c.id, m::tiny_trace(w)));
        }
    }
    let scratch = Paths::evaluate(&inp.records, inp.trust.clone(), &inp.commits);
    (reading(&p) != reading(&scratch)).then(|| "incremental and from scratch differ".to_string())
}

/// Tiny worlds of every kind and content worlds `start..start + n`: the failures, at most three.
fn arrivals(start: u64, n: u64) -> Vec<String> {
    let tiny = MODES.iter().flat_map(|&mode| {
        (start..start + n).filter_map(move |i| {
            let t = m::tiny_world(i, mode, &rules());
            shuffled(&t.w, &t.v, i).map(|d| format!("world {i} {mode:?}: {d}"))
        })
    });
    let content = (start..start + n).filter_map(|i| {
        let (w, v) = super::content::world(i);
        shuffled(&w, &v, i).map(|d| format!("content world {i}: {d}"))
    });
    tiny.chain(content).take(3).collect()
}

// Every commit order reads as from scratch, and each update reports what it changed.
#[test]
fn incremental_equals_from_scratch() {
    let fails = arrivals(0, 200);
    assert!(fails.is_empty(), "{}", fails.join("\n"));
}

// As above, more worlds (a property).
#[test]
#[ignore]
fn paths_incremental_agrees_large() {
    let f: Vec<String> = crate::common::sharded(60_000, 0x5eed_0a1c, |n, seed| arrivals(crate::common::seeded(seed) % (1 << 40), n.div_ceil(7))).concat();
    assert!(f.is_empty(), "{}", f.join("\n"));
}

/// Every arrival order of `w`'s commits (all held, trusting nothing): each `Changed` exact, the
/// end as from scratch; from scratch as the model reads it.
#[track_caller]
fn every_order(w: &m::World) {
    super::agree_all(w, &[]);
    let inp = input(w, &m::View::all(w));
    let n = inp.commits.len();
    let mut orders = vec![vec![]];
    for k in 0..n {
        orders = orders.into_iter().flat_map(|o: Vec<usize>| (0..=o.len()).map(move |at| [&o[..at], &[k], &o[at..]].concat())).collect();
    }
    let scratch = Paths::evaluate(&inp.records, BTreeSet::new(), &inp.commits);
    for order in orders {
        let mut p = Paths::new(&inp.records, BTreeSet::new());
        for &k in &order {
            let before = p.clone();
            let ch = p.add(std::slice::from_ref(&inp.commits[k]));
            assert_eq!(check(&before, &p, &ch), None, "order {order:?}, adding {k}");
        }
        assert!(reading(&p) == reading(&scratch), "order {order:?}");
    }
}

// A commit arriving before a lowering's verdict undoes it: H removes B at 5, so B's removal of X
// at 10 no longer holds its right, and X's grant of N5 at 2, which that removal dropped, applies
// again (the update rolls back to the drop, not only to the new commit's key).
#[test]
fn a_commit_before_a_verdict_undoes_its_drops() {
    use m::{account, A, B, H, N5, X};
    use roles_model::Role::{Admin, None as Gone};
    let mut w = account();
    w.edge(H, 1, &[], A, X, Admin, &[]);
    w.edge(H, 1, &[], A, B, Admin, &[]);
    w.edge(X, 2, &[], A, N5, Admin, &[]);
    w.edge(B, 10, &[], A, X, Gone, &[]);
    w.edge(H, 5, &[], A, B, Gone, &[]);
    every_order(&w);
    // the same, the late commit ordered before the restart point (X's grant at 2)
    let mut w = account();
    w.edge(H, 1, &[], A, X, Admin, &[]);
    w.edge(H, 1, &[], A, B, Admin, &[]);
    w.edge(X, 2, &[], A, N5, Admin, &[]);
    w.edge(B, 10, &[], A, X, Gone, &[]);
    w.edge(H, 2, &[], A, X, Gone, &[]);
    every_order(&w);
}

// A commit arriving far before a void lowering makes it applied: B's removal of X at 10 would drop
// X's grant of B, its own authority (void), until H's own grant of B at 3 arrives; and with H's
// removal of B at 4 it holds no right at all.
#[test]
fn a_commit_far_before_a_void_lowering_flips_it() {
    use m::{account, A, B, H, X};
    use roles_model::Role::{Admin, None as Gone};
    let mut w = account();
    w.edge(H, 1, &[], A, X, Admin, &[]);
    w.edge(X, 2, &[], A, B, Admin, &[]);
    w.edge(B, 10, &[], A, X, Gone, &[]);
    w.edge(H, 3, &[], A, B, Admin, &[]);
    every_order(&w);
    w.edge(H, 4, &[], A, B, Gone, &[1, 3]);
    every_order(&w);
}

// Switching the trust set reads as evaluating under the new one, and reports what changed: from
// nothing to each held lowering and back.
#[test]
fn a_trust_switch_equals_evaluating_under_it() {
    for &mode in &MODES[..2] {
        for i in 0..100 {
            let mut t = m::tiny_world(i, mode, &rules());
            t.v.trust.clear();
            let inp = input(&t.w, &t.v);
            let lows: Vec<WriteId> = (0..t.w.commits.len()).filter(|&k| t.w.lowers(k).is_some() && !t.w.leave(k)).map(|k| inp.ids[&k]).collect();
            let mut p = Paths::evaluate(&inp.records, BTreeSet::new(), &inp.commits);
            for r in lows {
                for trust in [BTreeSet::from([r]), BTreeSet::new()] {
                    let before = p.clone();
                    let ch = p.set_trust(trust.clone());
                    assert_eq!(check(&before, &p, &ch), None, "world {i} {mode:?} trust {trust:?}");
                    assert!(reading(&p) == reading(&Paths::evaluate(&inp.records, trust.clone(), &inp.commits)), "world {i} {mode:?} trust {trust:?}");
                }
            }
        }
    }
}
