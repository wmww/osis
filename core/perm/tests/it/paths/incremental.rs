//! Incremental update is from-scratch evaluation restricted to what changed (notes/perm-paths.md,
//! One definition): commits added one at a time in any arrival order read as the walk of all of
//! them from scratch, and each update's `Changed` names exactly the parts whose status changed
//! and, per edge, the first key from which its history changed.
//! spec: none (the walk's update path; its rules are those of spec/permissions.md §5.1).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

use super::{input, rules, MODES};
use osis_base::{CommitId, Role, Tid};
use osis_perm::paths::{Changed, Commit, Content, History, Key, Paths, Right, Status, Store};
use osis_perm::WriteId;
use roles_model::paths as m;
use roles_model::Rng;
use std::collections::{BTreeMap, BTreeSet};

type Finals = BTreeMap<(Tid, Tid), (Option<Role>, Option<Role>)>;
pub(super) type Reading = (BTreeMap<WriteId, Status>, BTreeMap<(Tid, Tid), History>, Finals, BTreeMap<WriteId, Content>, BTreeSet<CommitId>, BTreeSet<WriteId>, BTreeMap<(Tid, Tid), [Option<Key>; 2]>, Purges);
/// The purged copies, each request's right.
type Purges = (BTreeSet<CommitId>, BTreeMap<WriteId, Right>);

pub(super) fn reading<S: Store>(p: &Paths<S>) -> Reading {
    let rights = p.store().all().into_iter().filter_map(|id| Some((id, p.right(&id)?))).collect();
    (p.statuses(), p.histories(), p.finals(), p.contents(), p.copies(), p.purged(), p.first_points(), (p.purged_copies(), rights))
}

fn valid(c: Option<&Content>) -> bool {
    matches!(c, Some(Content::Valid(_)))
}

/// A `Paths` beside its reading, so an update reads only the state it leaves: the reading before
/// is the one the last update left.
#[derive(Clone)]
pub(super) struct Tracked {
    pub(super) p: Paths,
    pub(super) r: Reading,
}

impl Tracked {
    pub(super) fn new(p: Paths) -> Self {
        Tracked { r: reading(&p), p }
    }

    /// `f`'s update: the state before it and what it reported.
    pub(super) fn update(&mut self, f: impl FnOnce(&mut Paths) -> Changed) -> (Tracked, Changed) {
        let before = Tracked { p: self.p.clone(), r: std::mem::take(&mut self.r) };
        let ch = f(&mut self.p);
        self.r = reading(&self.p);
        (before, ch)
    }

    /// `f`'s update checked (`differs_by`): the first difference.
    pub(super) fn step(&mut self, f: impl FnOnce(&mut Paths) -> Changed) -> Option<String> {
        self.renewing(&BTreeSet::new(), f)
    }

    /// `step`, where every part of a commit in `renewed` (updated in place: `Paths::update`) may
    /// be reported as new.
    pub(super) fn renewing(&mut self, renewed: &BTreeSet<CommitId>, f: impl FnOnce(&mut Paths) -> Changed) -> Option<String> {
        let (before, ch) = self.update(f);
        differs_by(&before, self, &ch, renewed)
    }
}

/// Whether `ch`, reported by the update from `a` to `b`, is what the two readings differ by:
/// exact for edge-class statuses, history, cuts and re-grant points; every new part reported;
/// any other delta reported is one whose validity changed (an addendum's); and every delta whose
/// verdict or purge changed is reachable from `ch` by `Changed`'s rule. A part of a commit in
/// `renewed` may be reported as new.
fn differs_by(ta: &Tracked, tb: &Tracked, ch: &Changed, renewed: &BTreeSet<CommitId>) -> Option<String> {
    let ((sa, ha, fa, ca, _, pa, xa, (_, ra)), a) = (&ta.r, &ta.p);
    let ((sb, hb, fb, cb, _, pb, xb, (_, rb)), b) = (&tb.r, &tb.p);
    let mut want = Changed::default();
    for (id, s) in sb {
        if sa.get(id) != Some(s) {
            want.parts.insert(*id);
        }
    }
    want.parts.extend(cb.keys().filter(|id| !ca.contains_key(id)));
    let extra: Vec<&WriteId> = ch.parts.iter().filter(|id| !want.parts.contains(id) && !renewed.contains(&id.0)).collect();
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
    // purges: exactly the scopes of the requests whose right changed (arrived or went holding
    // one), each request's stored right its right judged now
    if let Some((id, r)) = rb.iter().find(|(id, r)| b.store().right(id) != **r) {
        return Some(format!("request {id:?}: stored right {:?}, judged {r:?}", b.store().right(id)));
    }
    let scope = |id: &WriteId| a.store().get(id).or_else(|| b.store().get(id)).and_then(|f| f.scope()).unwrap();
    let mut renewed_scopes = BTreeSet::new();
    for id in ra.keys().chain(rb.keys()) {
        let (x, y) = (ra.get(id).copied().unwrap_or_default(), rb.get(id).copied().unwrap_or_default());
        if x != y {
            want.purges.insert(scope(id));
        }
        if renewed.contains(&id.0) && (x.any() || y.any()) {
            renewed_scopes.insert(scope(id));
        }
    }
    if !want.purges.is_subset(&ch.purges) || ch.purges.iter().any(|s| !want.purges.contains(s) && !renewed_scopes.contains(s)) {
        return Some(format!("reported purges {:?}, rights changed for {:?}", ch.purges, want.purges));
    }
    let (judged, moved) = rejudged(ta, tb, ch);
    // a delta `carried` alone reaches moved between a copy and invalid, its purge unmoved: an
    // engine holding copies invalid skips it
    let copy = |c: Option<&Content>| matches!(c, Some(Content::Copied | Content::Invalid));
    let skipped = |id: &WriteId| ch.carried.contains(&id.0) && copy(ca.get(id)) && copy(cb.get(id)) && pa.contains(id) == pb.contains(id);
    if let Some(id) = ch.carried.iter().find(|c| ch.named.contains(c)) {
        return Some(format!("{id:?} both named and carried: {ch:?}"));
    }
    if let Some(id) = moved.difference(&judged).find(|id| !skipped(id)) {
        return Some(format!("delta {id:?} moved from {:?} to {:?} (purged {} to {}) unreached by {ch:?}", ca.get(id), cb.get(id), pa.contains(id), pb.contains(id)));
    }
    None
}

/// The deltas an engine holding only `ch` and the indexes (`Paths::rests`, `Paths::naming`, its
/// deltas' facts) judges again after the update from `a` to `b`: those `ch` reaches (new or in
/// `parts`, its commit in `named`, a hop in `edges` before its position, in `cuts` at or after
/// it, in `regrant`, a scope in `purges` covering it), then, while one judged again moved, every
/// delta it names; and the deltas whose verdict or purge moved.
pub(super) fn rejudged(ta: &Tracked, tb: &Tracked, ch: &Changed) -> (BTreeSet<WriteId>, BTreeSet<WriteId>) {
    let ((ca, pa, a), (cb, pb, b)) = ((&ta.r.3, &ta.r.5, &ta.p), (&tb.r.3, &tb.r.5, &tb.p));
    let direct = |id: &WriteId| -> bool {
        ch.parts.contains(id)
            || ch.named.contains(&id.0)
            || b.rests(id).is_some_and(|(hops, pos)| hops.iter().any(|e| ch.edges.get(e).is_some_and(|k| *k < pos) || ch.cuts.get(e).is_some_and(|k| *k >= pos) || ch.regrant.contains(e)))
            || b.store().get(id).is_some_and(|f| ch.purges.iter().any(|s| s.covers(&f.on, &f.aspect, f.ts, &f.commit(), f.purge_author.as_ref())))
    };
    let moved: BTreeSet<WriteId> = cb.keys().filter(|id| ca.get(id) != cb.get(id) || pa.contains(id) != pb.contains(id)).copied().collect();
    let names: Vec<(WriteId, Vec<WriteId>)> = cb.keys().map(|id| (*id, b.naming(id))).collect();
    // a forgotten delta counts as moved: what it named is judged again (the engine knows it)
    let gone: BTreeSet<WriteId> = ca.keys().filter(|id| !cb.contains_key(id)).copied().collect();
    let by_gone = |id: &WriteId| !gone.is_empty() && a.naming(id).iter().any(|n| gone.contains(n));
    let mut judged: BTreeSet<WriteId> = cb.keys().filter(|id| direct(id) || by_gone(id)).copied().collect();
    let mut queue: Vec<WriteId> = judged.intersection(&moved).copied().collect();
    while let Some(n) = queue.pop() {
        for (id, by) in &names {
            if by.contains(&n) && judged.insert(*id) && moved.contains(id) {
                queue.push(*id);
            }
        }
    }
    (judged, moved)
}

/// A view's commits added one at a time in an order shuffled by `seed`, then in batches: each
/// `Changed` against the readings, and the end against from scratch.
fn shuffled(w: &m::World, v: &m::View, seed: u64) -> Option<String> {
    let inp = input(w, v);
    let mut order = inp.commits.clone();
    let mut rng = Rng(seed);
    for k in (1..order.len()).rev() {
        order.swap(k, rng.below(k + 1));
    }
    let start = Tracked::new(Paths::new(&inp.records, inp.trust.clone()));
    let mut t = start.clone();
    for c in &order {
        if let Some(d) = t.step(|p| p.add(std::slice::from_ref(c))) {
            return Some(format!("adding {:?}: {d}\n{}", c.id, m::tiny_trace(w)));
        }
    }
    let scratch = reading(&Paths::evaluate(&inp.records, inp.trust.clone(), &inp.commits));
    if t.r != scratch {
        return Some("incremental and from scratch differ".to_string());
    }
    // the same order in batches of one to four commits
    let mut t = start;
    let mut rest = &order[..];
    while !rest.is_empty() {
        let (batch, more) = rest.split_at((1 + rng.below(4)).min(rest.len()));
        if let Some(d) = t.step(|p| p.add(batch)) {
            return Some(format!("adding {:?}: {d}\n{}", batch.iter().map(|c| c.id).collect::<Vec<_>>(), m::tiny_trace(w)));
        }
        rest = more;
    }
    (t.r != scratch).then(|| "batched and from scratch differ".to_string())
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
    tiny.chain(content).chain(purges(start, n, shuffled)).take(3).collect()
}

/// Purge worlds `start..start + n / 4` (each about twice a content world's commits), each at one
/// node's view (in turn), `f` run on each; the failures.
fn purges(start: u64, n: u64, f: fn(&m::World, &m::View, u64) -> Option<String>) -> impl Iterator<Item = String> {
    (start..start + n.div_ceil(4)).filter_map(move |i| {
        let pw = m::purge_world(i, &rules());
        let node = pw.nodes()[i as usize % pw.nodes().len()];
        let v = pw.view_at(node, None);
        let w = super::as_known(&pw.w, &v);
        f(&w, &v, i).map(|d| format!("purge world {i} node {node}: {d}"))
    })
}

// What an engine judges again from `Changed` (`rejudged`) holds every delta whose verdict moved,
// and is not much more: over content worlds' arrivals, deltas judged again per delta moved.
#[test]
fn changed_reaches_every_moved_delta_and_little_more() {
    let (mut judged, mut moved, mut held) = (0usize, 0usize, 0usize);
    for i in 0..200 {
        let (w, v) = super::content::world(i);
        let inp = input(&w, &v);
        let mut t = Tracked::new(Paths::new(&inp.records, inp.trust.clone()));
        for c in &inp.commits {
            let (before, ch) = t.update(|p| p.add(std::slice::from_ref(c)));
            let (j, m) = rejudged(&before, &t, &ch);
            assert!(m.is_subset(&j), "content world {i}, adding {:?}: {:?} unreached", c.id, m.difference(&j).collect::<Vec<_>>());
            // new deltas are judged by the engine anyway: count the rest
            let new: BTreeSet<WriteId> = t.r.3.keys().filter(|id| !before.r.3.contains_key(id)).copied().collect();
            judged += j.difference(&new).count();
            moved += m.difference(&new).count();
            held += before.r.3.len();
        }
    }
    println!("judged again {judged}, moved {moved}, held {held}");
    assert!(moved > 0 && judged <= 4 * moved, "judged again {judged} for {moved} moved");
}

// Every commit order reads as from scratch, and each update reports what it changed.
#[test]
#[ignore = "property"]
fn paths_incremental_agrees_plain() {
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
pub(super) fn every_order(w: &m::World) {
    super::agree_all(w, &[]);
    let inp = input(w, &m::View::all(w));
    let scratch = reading(&Paths::evaluate(&inp.records, BTreeSet::new(), &inp.commits));
    in_every_order(&inp.records, &inp.commits, |t, order| assert!(t.r == scratch, "order {order:?}"));
}

/// Every arrival order of `commits`, from nothing held and trusting nothing (prefixes shared):
/// each `Changed` exact; `end` reads each whole order.
#[track_caller]
pub(super) fn in_every_order(records: &BTreeMap<Tid, Tid>, commits: &[Commit], mut end: impl FnMut(&mut Tracked, &[usize])) {
    let mut add = |t: &mut Tracked, order: &[usize], k: usize| {
        assert_eq!(t.step(|p| p.add(std::slice::from_ref(&commits[k]))), None, "order {order:?}, adding {k}");
    };
    crate::common::every_order(commits.len(), Tracked::new(Paths::new(records, BTreeSet::new())), &mut add, &mut end);
}

// A commit arriving before a lowering's verdict undoes it: H removes B at 5, so B's removal of X
// at 10 no longer holds its right, and X's grant of N5 at 2, which that removal dropped, applies
// again (the update walks again from the drop, not only from the new commit's key).
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
            let mut t = Tracked::new(Paths::evaluate(&inp.records, BTreeSet::new(), &inp.commits));
            let none = t.r.clone();
            for r in lows {
                for trust in [BTreeSet::from([r]), BTreeSet::new()] {
                    assert_eq!(t.step(|p| p.set_trust(trust.clone())), None, "world {i} {mode:?} trust {trust:?}");
                    let scratch = if trust.is_empty() { none.clone() } else { reading(&Paths::evaluate(&inp.records, trust.clone(), &inp.commits)) };
                    assert!(t.r == scratch, "world {i} {mode:?} trust {trust:?}");
                }
            }
        }
    }
    // content worlds: verdicts, copies, purges and counting entries follow the trust set too
    for i in 0..60 {
        let (w, mut v) = super::content::world(i);
        v.trust.clear();
        let inp = input(&w, &v);
        let lows: Vec<WriteId> = v.held.iter().filter(|&&k| w.lowers(k).is_some() && !w.leave(k)).map(|k| inp.ids[k]).collect();
        let mut t = Tracked::new(Paths::evaluate(&inp.records, BTreeSet::new(), &inp.commits));
        let none = t.r.clone();
        for r in lows {
            for trust in [BTreeSet::from([r]), BTreeSet::new()] {
                assert_eq!(t.step(|p| p.set_trust(trust.clone())), None, "content world {i} trust {trust:?}");
                let scratch = if trust.is_empty() { none.clone() } else { reading(&Paths::evaluate(&inp.records, trust.clone(), &inp.commits)) };
                assert!(t.r == scratch, "content world {i} trust {trust:?}");
            }
        }
    }
}

/// A view's commits added and forgotten one to three at a time at random (a commit forgotten
/// while not held, added while held, forgotten and added again), each `Changed` checked; the end
/// reads as from scratch over what is held (counting entries and void trusted writes too; the
/// dispute set in one world in eight).
fn forgetting(w: &m::World, v: &m::View, seed: u64) -> Option<String> {
    let inp = input(w, v);
    let n = inp.commits.len();
    let mut rng = Rng(seed);
    let mut t = Tracked::new(Paths::new(&inp.records, inp.trust.clone()));
    let mut held = vec![false; n];
    for step in 0..3 * n {
        let pick: Vec<usize> = (0..1 + rng.below(3)).map(|_| rng.below(n)).collect();
        let forget = rng.below(5) < 2;
        pick.iter().for_each(|&i| held[i] = !forget);
        let d = if forget {
            t.step(|p| p.forget(&pick.iter().map(|&i| inp.commits[i].id).collect::<Vec<_>>()))
        } else {
            t.step(|p| p.add(&pick.iter().map(|&i| inp.commits[i].clone()).collect::<Vec<_>>()))
        };
        if let Some(d) = d {
            return Some(format!("step {step}, {} {pick:?}: {d}\n{}", if forget { "forgetting" } else { "adding" }, m::tiny_trace(w)));
        }
    }
    let rest: Vec<Commit> = (0..n).filter(|&i| held[i]).map(|i| inp.commits[i].clone()).collect();
    let mut scratch = Paths::evaluate(&inp.records, inp.trust.clone(), &rest);
    let mut p = t.p;
    if t.r != reading(&scratch) || p.void_trusted() != scratch.void_trusted() {
        return Some(format!("forgetting and from scratch differ, held {held:?}\n{}", m::tiny_trace(w)));
    }
    if seed.is_multiple_of(8) && p.disputes() != scratch.disputes() {
        return Some(format!("disputes differ after forgetting, held {held:?}\n{}", m::tiny_trace(w)));
    }
    None
}

/// A view seeing no frontier leaf: its commits added, then each commit updated with every leaf
/// seen, one to three at a time (a chunked frontier's leaves arriving late), each `Changed`
/// checked; the end reads as from scratch over the full view.
fn leaves_arriving(w: &m::World, v: &m::View, seed: u64) -> Option<String> {
    let mut part = v.clone();
    part.leaves = Some(Default::default());
    let mut full = v.clone();
    full.leaves = None;
    let (a, b) = (input(w, &part), input(w, &full));
    let mut t = Tracked::new(Paths::evaluate(&a.records, a.trust.clone(), &a.commits));
    let mut rng = Rng(seed);
    let mut order: Vec<usize> = (0..b.commits.len()).collect();
    for k in (1..order.len()).rev() {
        order.swap(k, rng.below(k + 1));
    }
    let mut rest = &order[..];
    while !rest.is_empty() {
        let (batch, more) = rest.split_at((1 + rng.below(3)).min(rest.len()));
        let cs: Vec<Commit> = batch.iter().map(|&i| b.commits[i].clone()).collect();
        let renewed: BTreeSet<CommitId> = cs.iter().map(|c| c.id).collect();
        if let Some(d) = t.renewing(&renewed, |p| p.update(&cs)) {
            return Some(format!("updating {renewed:?}: {d}\n{}", m::tiny_trace(w)));
        }
        rest = more;
    }
    let scratch = Paths::evaluate(&b.records, b.trust.clone(), &b.commits);
    (t.r != reading(&scratch)).then(|| format!("updated and from scratch differ\n{}", m::tiny_trace(w)))
}

/// Tiny worlds of every kind and content worlds `start..start + n`, forgetting and leaves
/// arriving: the failures, at most three.
fn forgets(start: u64, n: u64) -> Vec<String> {
    let tiny = MODES.iter().flat_map(|&mode| {
        (start..start + n).filter_map(move |i| {
            let t = m::tiny_world(i, mode, &rules());
            forgetting(&t.w, &t.v, i).or_else(|| leaves_arriving(&t.w, &t.v, i)).map(|d| format!("world {i} {mode:?}: {d}"))
        })
    });
    let content = (start..start + n).filter_map(|i| {
        let (w, v) = super::content::world(i);
        forgetting(&w, &v, i).or_else(|| leaves_arriving(&w, &v, i)).map(|d| format!("content world {i}: {d}"))
    });
    let purge = purges(start, n, |w, v, i| forgetting(w, v, i).or_else(|| leaves_arriving(w, v, i)));
    tiny.chain(content).chain(purge).take(3).collect()
}

// notes/perm-paths.md, Forget and update: any order of adds and forgets (a forget of a commit not
// held, a forget then the same add) and any order of frontier leaves arriving reads as from
// scratch over what is held, each update's `Changed` exact.
#[test]
#[ignore = "property"]
fn paths_forget_agrees_plain() {
    let fails = forgets(0, 60);
    assert!(fails.is_empty(), "{}", fails.join("\n"));
}

// As above, more worlds (a property).
#[test]
#[ignore]
fn paths_forget_agrees_large() {
    let f: Vec<String> = crate::common::sharded(30_000, 0x5eed_0a1d, |n, seed| forgets(crate::common::seeded(seed) % (1 << 40), n.div_ceil(7))).concat();
    assert!(f.is_empty(), "{}", f.join("\n"));
}

// notes/perm-paths.md, One definition: which of two lowerings a pass reaches
// first is set by the component's restart sequence, so an update forgets every verdict given after
// its key. X (admin on A by H) grants B admin on T1 at 40 (j: sets g = B's edge, rests on X's);
// B removes Z from T1 at 60 along g (Q); H removes X from A at 70 listing nothing (E: drops j, the
// pass restarts, Q applies by its verdict). A part at 50 changes what Q reads and nothing E reads
// (H granting Z write on T1; or B write, where Q then holds no right): Q is judged before E's drop of j, as the model reads it
// from scratch. Every arrival order, and every subset forgotten from all held, reads as from
// scratch and as the model at that held set.
#[test]
fn a_verdict_kept_past_a_later_restart_would_misjudge() {
    use m::{account, A, B, H, T1, X, Z};
    use roles_model::Role::{Admin, None as Gone, Write};
    for variant in 0..3 {
        let mut w = account();
        w.edge(H, 1, &[], A, X, Admin, &[]);
        w.edge(H, 2, &[A], T1, Z, Admin, &[]);
        let j = w.edge(X, 40, &[A], T1, B, Admin, &[]);
        match variant {
            0 => {}
            1 => {
                w.edge(H, 50, &[A], T1, Z, Write, &[]);
            }
            _ => {
                w.edge(H, 50, &[A], T1, B, Write, &[]);
            }
        }
        let q = w.edge(B, 60, &[], T1, Z, Gone, &[]);
        let e = w.edge(H, 70, &[], A, X, Gone, &[]);
        let all = m::View::all(&w);
        let rd = m::judge(&w, &rules(), &all);
        // (variant 2: B holds only write on T1 at 60, so Q holds no right)
        assert_eq!(rd.applied.contains(&q), variant < 2, "variant {variant}: Q");
        assert!(rd.applied.contains(&e) && !rd.applied.contains(&j), "variant {variant}: the model applies E, drops j");
        every_order(&w);
        let n = w.commits.len();
        let inp = input(&w, &all);
        let full = Tracked::new(Paths::evaluate(&inp.records, BTreeSet::new(), &inp.commits));
        assert_eq!(full.p.status(&inp.ids[&q]) == Some(Status::Applied), variant < 2, "variant {variant}");
        for mask in 0u32..1 << n {
            let gone: Vec<usize> = (0..n).filter(|k| mask >> k & 1 == 1).collect();
            let kept: m::Set = (0..n).filter(|k| mask >> k & 1 == 0).collect();
            super::agree(&w, &m::View { held: kept.clone(), leaves: None, trust: m::Set::new() });
            let mut t = full.clone();
            assert_eq!(t.step(|p| p.forget(&gone.iter().map(|&k| inp.commits[k].id).collect::<Vec<_>>())), None, "variant {variant} forgetting {gone:?}");
            let rest: Vec<Commit> = (0..n).filter(|k| kept.contains(k)).map(|k| inp.commits[k].clone()).collect();
            assert!(t.r == reading(&Paths::evaluate(&inp.records, BTreeSet::new(), &rest)), "variant {variant} forgetting {gone:?}");
        }
    }
}

// Draft §5.1 step 3 and step 5 (a commit's edge-class parts on a thing fall together; nothing is
// undropped): X's one commit removes N5 from A (dropping N5's grant of Z) and lowers B to write;
// H then removes X listing nothing (or listing X's commit), dropping both of X's lowerings, the
// applied one's drop staying. Trusting nothing or H's removal: every arrival order and every
// subset forgotten reads as from scratch and as the model.
#[test]
fn two_lowerings_on_one_thing_fall_together_in_every_order_and_forget() {
    use m::{account, A, B, H, N5, X, Z};
    use roles_model::Role::{Admin, None as Gone, Write};
    for listed in [false, true] {
        let mut w = account();
        for h in [X, N5, B] {
            w.edge(H, 1, &[], A, h, Admin, &[]);
        }
        w.edge(N5, 3, &[], A, Z, Admin, &[]);
        let out = w.edge(X, 5, &[], A, N5, Gone, &[]);
        let low = w.edge(X, 5, &[], A, B, Write, &[]);
        w.group(&[out, low]);
        let list = if listed { vec![out] } else { vec![] };
        let r = w.edge(H, 7, &[], A, X, Gone, &list);
        every_order(&w);
        for trust in [vec![], vec![r]] {
            let all = m::View::all(&w).trusting(&trust);
            let inp = input(&w, &all);
            let n = inp.commits.len();
            let full = Tracked::new(Paths::evaluate(&inp.records, inp.trust.clone(), &inp.commits));
            for mask in 0u32..1 << n {
                let gone: Vec<CommitId> = (0..n).filter(|k| mask >> k & 1 == 1).map(|k| inp.commits[k].id).collect();
                let held: m::Set = all.held.iter().copied().filter(|&i| !gone.contains(&inp.ids[&i].0)).collect();
                super::agree(&w, &m::View { held, leaves: None, trust: all.trust.clone() });
                let mut t = full.clone();
                assert_eq!(t.step(|p| p.forget(&gone)), None, "{listed} {trust:?} forgetting {gone:?}");
                let rest: Vec<Commit> = inp.commits.iter().filter(|c| !gone.contains(&c.id)).cloned().collect();
                assert!(t.r == reading(&Paths::evaluate(&inp.records, inp.trust.clone(), &rest)), "{listed} {trust:?} forgetting {gone:?}");
            }
            let st = |i| full.p.status(&inp.ids[&i]);
            let fallen = if listed { Status::Applied } else { Status::Dropped };
            assert_eq!((st(out), st(low)), (Some(fallen), Some(fallen)), "{listed} {trust:?}");
        }
    }
}

