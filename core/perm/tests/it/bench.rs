//! Cost of a 10^4-edge-write history (issues/perm-eval-cost.md): from scratch and incremental. Tier 2:
//! `cargo test --release --workspace --test it bench::bench_ -- --ignored --nocapture`. Run it alone:
//! `bench_10k_edges` peaks at about 13 GB (each held set of the org at 10^4 is about 3 GB).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

use crate::common;

use common::*;
use roles_model::Rng;
use osis_base::Role::{Admin, Read, Write};
use osis_base::Tid;
use osis_perm::{At, Timeline, Timelines};
use std::time::Instant;

/// An organization: key actor K owns root actor R (10 admins) owning 20 teams; each team owns
/// 10 docs; 300 holder nodes; `n` edge writes (grants, changes, removals on teams and docs)
/// by admins, a few percent received late.
fn org(n: usize, rng: &mut Rng) -> (World, Vec<Tid>) {
    let (w, nodes, _) = org_root(n, rng);
    (w, nodes)
}

/// `org` and its root actor.
fn org_root(n: usize, rng: &mut Rng) -> (World, Vec<Tid>, Tid) {
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

// spec: none (cost measurement)
#[test]
#[ignore]
fn bench_10k_edges() {
    let mut rng = Rng(0x5eed_0401);
    // `OSIS_BENCH_N` picks one size (for profiling).
    let sizes: Vec<usize> = std::env::var("OSIS_BENCH_N").ok().and_then(|v| v.parse().ok()).map_or(vec![1_000, 10_000], |n| vec![n]);
    for n in sizes {
        let (mut w, nodes) = org(n, &mut rng);
        // a write arriving late, ordered in the middle of the history: its author's later
        // commits list it in their frontiers (held from the start without it)
        let doc = *w.created.keys().last().unwrap();
        let late_id = w.set(nodes[2], doc, nodes[201], edge(Read), n as u64 / 2, &[]);
        let no_late = std::collections::BTreeSet::from([late_id]);
        let held = w.held_without(&no_late);
        let t0 = Instant::now();
        let tl = Timeline::evaluate(&held);
        let scratch = t0.elapsed();
        let t1 = Instant::now();
        let mut inc = Timelines::new();
        inc.update(&held);
        let first = t1.elapsed();
        let mut w3 = w.clone();
        w3.set(nodes[1], doc, nodes[200], edge(Write), n as u64 + 5, &[]);
        // (`held2` lives on: the timelines hold its records, as a node's do its held set's;
        // else the update would time freeing them)
        let held2 = w3.held_without(&no_late);
        let t2 = Instant::now();
        let evaluated = inc.update(&held2);
        let again = t2.elapsed();
        let mut held3 = w3.held();
        let tl3 = Instant::now();
        inc.update_touched(&held3, &std::collections::BTreeSet::from([doc]));
        let late = tl3.elapsed();
        drop(held2);
        let ts3 = Instant::now();
        let passes3 = Timeline::evaluate(&held3).passes();
        let scratch3 = ts3.elapsed();
        // what a node does per write: 100 writes after every held one, each its own update
        // around the thing it touched (`update_touched`), then taken out again
        let touched = std::collections::BTreeSet::from([doc]);
        let mut appended = 0;
        let ta = Instant::now();
        for i in 0..100u8 {
            let id = osis_base::CommitId([i; 32]);
            let op = osis_perm::EdgeOp { target: doc, holder: nodes[210 + usize::from(i % 20)], edge: edge(if i % 2 == 0 { Read } else { Write }) };
            held3.add_commit(osis_perm::RoleCommit { id, ts: ts(n as u64 + 100 + u64::from(i)), author: nodes[1], actor: nodes[1], frontier: None, ops: vec![op] });
            inc.update_touched(&held3, &touched);
            appended += inc.appended();
        }
        let appends = ta.elapsed() / 100;
        for i in 0..100u8 {
            held3.remove(&osis_base::CommitId([i; 32]));
        }
        inc.update_touched(&held3, &touched);
        let t3 = Instant::now();
        let r = tl.role(&nodes[200], &doc, At::END);
        let query = t3.elapsed();
        // a point query in the middle of the history, and a delta's validity (cold, then memoized)
        let mid = tl.applied().values().nth(tl.applied().len() / 2).map(|a| a.point).unwrap();
        let t4 = Instant::now();
        let _ = tl.role(&nodes[200], &doc, At::before(mid));
        let point_query = t4.elapsed();
        let t5 = Instant::now();
        let v = tl.delta_valid(mid, &doc, "app:x.0", osis_perm::Dots::Commit, Write);
        let valid_cold = t5.elapsed();
        let t6 = Instant::now();
        let _ = tl.delta_valid(mid, &doc, "app:x.0", osis_perm::Dots::Commit, Write);
        let valid_warm = t6.elapsed();
        // what a node re-judges after a change in this component: one content delta per
        // applied write, by its author on its target, on a fresh timeline (nothing memoized)
        let fresh = Timeline::evaluate(&held);
        let deltas: Vec<_> = fresh.applied().values().take(1000).map(|a| (a.point, a.target)).collect();
        let t7 = Instant::now();
        for (p, t) in &deltas {
            let _ = fresh.delta_valid(*p, t, "app:x.0", osis_perm::Dots::Commit, Write);
        }
        let rejudge = t7.elapsed();
        drop(fresh);
        // holders' deltas: one by each holder granted write or more, just after the grant
        let fresh = Timeline::evaluate(&held);
        let mut by_holders = Vec::new();
        for id in fresh.applied().keys() {
            let osis_perm::WriteId::Op(c, k) = id else { continue };
            let cm = fresh.role_commit(c).unwrap();
            let o = &cm.ops[*k as usize];
            if o.edge.is_some_and(|e| e.role >= Write) && nodes.contains(&o.holder) {
                let p = cm.point();
                by_holders.push((osis_perm::Point { ts: ts(p.ts.wall_ms().0 + 1), node: o.holder, commit: osis_base::CommitId([0x11; 32]) }, o.target));
            }
        }
        by_holders.truncate(1000);
        let t7b = Instant::now();
        let mut valid_holders = 0;
        for (p, t) in &by_holders {
            valid_holders += usize::from(fresh.delta_valid(*p, t, "app:x.0", osis_perm::Dots::Commit, Write) == osis_perm::Validity::Valid);
        }
        let rejudge_holders = t7b.elapsed();
        drop(fresh);
        // what a demotion's frontier lists (§5.1): two admins' chain certificates on a doc
        let t8 = Instant::now();
        let certs = tl.certificates(&nodes[1], &doc);
        let cert = t8.elapsed();
        let t9 = Instant::now();
        let _ = tl.certificates(&nodes[2], &doc);
        let cert2 = t9.elapsed();
        // a restart: the walk saved (as a node's cache) and restored, exact and with the last
        // 1% of the writes added since the save
        let t10 = Instant::now();
        let saved: std::collections::BTreeMap<Tid, Vec<u8>> = inc.to_save(b"rules", 1, true).put.into_iter().collect();
        let save = t10.elapsed();
        let bytes: usize = saved.values().map(|b| b.len()).sum();
        let all: std::collections::BTreeSet<Tid> = osis_perm::HeldSet::things(&held3).into_iter().collect();
        let t11 = Instant::now();
        let mut back = Timelines::new();
        back.update_touched_cached(&held3, &all, &mut |r| saved.get(r).cloned(), b"rules");
        let restore = t11.elapsed();
        assert_eq!(back.restored(), 1);
        drop((back, held3));
        let mut w4 = w3;
        for i in 0..n / 100 {
            w4.set(nodes[1 + i % 10], doc, nodes[200 + i % 2], edge(if i % 2 == 0 { Read } else { Write }), n as u64 + 10 + i as u64, &[]);
        }
        let held4 = w4.held();
        let all4: std::collections::BTreeSet<Tid> = osis_perm::HeldSet::things(&held4).into_iter().collect();
        let t12 = Instant::now();
        let mut stale = Timelines::new();
        stale.update_touched_cached(&held4, &all4, &mut |r| saved.get(r).cloned(), b"rules");
        let restore_stale = t12.elapsed();
        assert_eq!(stale.restored(), 1);
        drop(stale);
        // a new thing (a leaf: only its `created.0`) under the team and under the doc with the
        // most demotions recorded
        inc.update(&held4);
        let tl4 = Timeline::evaluate(&held4);
        let most = |things: Vec<Tid>| things.into_iter().map(|t| (nodes.iter().map(|x| tl4.demotions(x, &t).len()).sum::<usize>(), t)).max().unwrap();
        let teams: Vec<Tid> = w.created.iter().filter(|(_, r)| matches!(r, osis_base::CreationRecord::Thing { owner, .. } if w.created.get(owner).is_some_and(|o| matches!(o, osis_base::CreationRecord::Thing { owner: oo, .. } if !w.created.get(oo).is_some_and(|x| matches!(x, osis_base::CreationRecord::Thing { .. })))))).map(|(t, _)| *t).collect();
        let docs: Vec<Tid> = w.created.iter().filter(|(t, r)| !teams.contains(t) && matches!(r, osis_base::CreationRecord::Thing { owner, .. } if teams.contains(owner))).map(|(t, _)| *t).collect();
        for (what, (dn, owner)) in [("team", most(teams)), ("doc", most(docs))] {
            let mut w5 = w4.clone();
            let leaf = w5.thing(owner);
            let held5 = w5.held();
            let t13 = Instant::now();
            inc.update_touched(&held5, &std::collections::BTreeSet::from([leaf]));
            eprintln!("{n} edge writes: a new thing under a {what} with {dn} demotions {:?}", t13.elapsed());
            inc.update(&held4);
        }
        eprintln!("{n} edge writes: walk saved {save:?} ({bytes} bytes), restored {restore:?}, restored and continued over {} more {restore_stale:?}", n / 100);
        eprintln!(
            "{n} edge writes: from scratch {scratch:?} ({} passes, {} dropped), incremental first {first:?}, after one more write {again:?} ({evaluated} components), one more write around its thing {appends:?} (mean of 100, {appended} appended), a late write in the middle {late:?} (from scratch {scratch3:?}, {passes3} passes), one role query {query:?} ({r:?}), role at a mid point {point_query:?}, delta_valid {valid_cold:?} then {valid_warm:?} ({v:?}), {} deltas judged cold {rejudge:?}, {} holders' deltas cold {rejudge_holders:?} ({valid_holders} valid), chain certificates of an admin {cert:?} ({} commits, {} snapshots), of another {cert2:?}",
            tl.passes(),
            tl.dropped().len(),
            deltas.len(),
            by_holders.len(),
            certs.commits.len(),
            certs.snapshots.len()
        );
    }
}

// spec: none (cost measurement, issues/perm-eval-cost.md): an owner chain of depth d (each thing
// owned by the previous), one holder granted at the top, 100 edge writes at the bottom; evaluate
// and a role query at the leaf.
#[test]
#[ignore]
fn bench_deep_owner_chain() {
    for depth in [10usize, osis_base::format::MAX_OWNER_DEPTH] {
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
        let t0 = Instant::now();
        let tl = Timeline::evaluate(&held);
        let eval = t0.elapsed();
        let t1 = Instant::now();
        let r = tl.role(&nodes[1], &leaf, At::END);
        let query = t1.elapsed();
        assert_eq!(r, Some(Admin));
        assert_eq!(tl.role(&nodes[2], &leaf, At::END), Some(Write));
        eprintln!("owner chain depth {depth}, 100 edge writes at the leaf: evaluate {eval:?} ({} passes), role query at the leaf {query:?}", tl.passes());
    }
}

// spec: none (cost measurement, issues/perm-eval-cost.md): chain certificates alone on the org
// history (`OSIS_BENCH_N`, default 10^4), for profiling.
#[test]
#[ignore]
fn bench_certificates() {
    let n: usize = std::env::var("OSIS_BENCH_N").ok().and_then(|v| v.parse().ok()).unwrap_or(10_000);
    let (w, nodes) = org(n, &mut Rng(0x5eed_0401));
    let held = w.held();
    let te = Instant::now();
    let tl = Timeline::evaluate(&held);
    let eval = te.elapsed();
    let doc = *w.created.keys().last().unwrap();
    let t0 = Instant::now();
    let certs = tl.certificates(&nodes[1], &doc);
    let t1 = Instant::now();
    let certs2 = tl.certificates(&nodes[2], &doc);
    eprintln!("{n} edge writes ({} dropped): evaluate {eval:?}, chain certificates of an admin {:?} ({} commits), of another {:?} ({} commits)", tl.dropped().len(), t1 - t0, certs.commits.len(), t1.elapsed(), certs2.commits.len());
}

// spec: none (cost measurement, notes/permissions.md): `Timeline::demotion_scope` on the org
// history (`OSIS_BENCH_N`, default 10^4): the walk copied and the demotion appended, for a
// holder removed from a doc and an admin removed from the root, with a frontier listing
// nothing (its audit drops every write it puts in question) and `Timeline::all_held`.
#[test]
#[ignore]
fn bench_demotion_scope() {
    use osis_perm::{EdgeOp, Frontier, RoleCommit};
    let n: usize = std::env::var("OSIS_BENCH_N").ok().and_then(|v| v.parse().ok()).unwrap_or(10_000);
    let (w, nodes, root) = org_root(n, &mut Rng(0x5eed_0401));
    let tl = Timeline::evaluate(&w.held());
    let doc = *w.created.keys().last().unwrap();
    let t = n as u64 + 10;
    let holder = tl.roster(&doc, At::END).into_keys().find(|h| nodes.contains(h)).unwrap();
    for (what, target, holder) in [("a holder from a doc", doc, holder), ("an admin from the root", root, nodes[1])] {
        for (fname, f) in [("empty", Frontier::default()), ("all held", tl.all_held())] {
            let r = RoleCommit { id: osis_base::CommitId([0xee; 32]), ts: ts(t), author: nodes[0], actor: nodes[0], frontier: Some(std::sync::Arc::new(f)), ops: vec![EdgeOp { target, holder, edge: None }] };
            let t0 = Instant::now();
            let s = tl.demotion_scope(r);
            let el = t0.elapsed();
            let size = |m: &std::collections::BTreeMap<Tid, std::collections::BTreeSet<Tid>>| m.values().map(|s| s.len()).sum::<usize>();
            eprintln!("{n} edge writes: removing {what}, {fname} frontier: {el:?} (roles {}, content {})", size(&s.roles), size(&s.content));
        }
    }
}

// spec: none (cost measurement, issues/perm-eval-cost.md): layer-2 re-judging alone on the org
// history (`OSIS_BENCH_N`, default 10^4), for profiling: 1000 admins' deltas (one per applied
// write, by its author on its target) and holders' deltas (one by each holder granted write,
// just after the grant), each on a fresh timeline.
#[test]
#[ignore]
fn bench_deltas() {
    let n: usize = std::env::var("OSIS_BENCH_N").ok().and_then(|v| v.parse().ok()).unwrap_or(10_000);
    let (w, nodes) = org(n, &mut Rng(0x5eed_0401));
    let held = w.held();
    let tl = Timeline::evaluate(&held);
    let deltas: Vec<_> = tl.applied().values().take(1000).map(|a| (a.point, a.target)).collect();
    let t0 = Instant::now();
    for (p, t) in &deltas {
        let _ = tl.delta_valid(*p, t, "app:x.0", osis_perm::Dots::Commit, Write);
    }
    let admins = t0.elapsed();
    let fresh = Timeline::evaluate(&held);
    let mut by_holders = Vec::new();
    for id in fresh.applied().keys() {
        let osis_perm::WriteId::Op(c, k) = id else { continue };
        let cm = fresh.role_commit(c).unwrap();
        let o = &cm.ops[*k as usize];
        if o.edge.is_some_and(|e| e.role >= Write) && nodes.contains(&o.holder) {
            let p = cm.point();
            by_holders.push((osis_perm::Point { ts: ts(p.ts.wall_ms().0 + 1), node: o.holder, commit: osis_base::CommitId([0x11; 32]) }, o.target));
        }
    }
    by_holders.truncate(1000);
    let t1 = Instant::now();
    for (p, t) in &by_holders {
        let _ = fresh.delta_valid(*p, t, "app:x.0", osis_perm::Dots::Commit, Write);
    }
    eprintln!("{n} edge writes: {} admins' deltas cold {admins:?}, {} holders' deltas cold {:?}", deltas.len(), by_holders.len(), t1.elapsed());
}

// spec: none (cost measurement, issues/perm-eval-cost.md): late writes in the middle of the org
// history (`OSIS_BENCH_N`, default 10^4), each through `update_touched` after the ones before it,
// for profiling: a read grant on a doc by an admin, the removal of an edge held there (an audit),
// an admin grant, a write grant on a team, and a read grant by the key actor at the top (no
// earlier write of its own on the doc).
#[test]
#[ignore]
fn bench_late_write() {
    let n: usize = std::env::var("OSIS_BENCH_N").ok().and_then(|v| v.parse().ok()).unwrap_or(10_000);
    let (mut w, nodes) = org(n, &mut Rng(0x5eed_0401));
    // as `bench_10k_edges`: each late write's author lists it in its later commits' frontiers;
    // one more write at the end first
    let doc = *w.created.keys().last().unwrap();
    let team = match w.created[&doc] {
        osis_base::CreationRecord::Thing { owner, .. } => owner,
        _ => unreachable!(),
    };
    let mid = n as u64 / 2;
    // an edge on the doc held just before the middle, by the last write on it
    let mut last: std::collections::BTreeMap<Tid, Option<osis_perm::Edge>> = std::collections::BTreeMap::new();
    for c in w.commits.iter().filter(|c| c.t < mid) {
        for (t, m, e) in &c.ops {
            if *t == doc && nodes.contains(m) {
                last.insert(*m, *e);
            }
        }
    }
    let held_holder = last.iter().find(|(_, e)| e.is_some()).map(|(m, _)| *m).unwrap();
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
    let mut prev = w.held_without(&ids.iter().copied().collect());
    inc.update(&prev);
    for (i, (what, _, t, _, _)) in cases.iter().enumerate() {
        let held = w.held_without(&ids[i + 1..].iter().copied().collect());
        let t0 = Instant::now();
        inc.update_touched(&held, &std::collections::BTreeSet::from([*t]));
        let late = t0.elapsed();
        eprintln!("{n} edge writes: {what} late in the middle {late:?} ({} appended, {} placed)", inc.appended(), inc.placed());
        prev = held;
    }
    drop(prev);
}

// spec: none (cost measurement): `bench_certificates` on the org history with drops: every
// 40th write, an admin writes unseen (received late), another admin removes it from the root
// at once (dropping that write) and grants it back. Then one more write: extended, and the
// certificates of the extended timeline (its first, which builds the index).
#[test]
#[ignore]
fn bench_certificates_drops() {
    let n: usize = std::env::var("OSIS_BENCH_N").ok().and_then(|v| v.parse().ok()).unwrap_or(10_000);
    let (mut w, nodes, root) = org_root(n, &mut Rng(0x5eed_0401));
    let admins = &nodes[1..11];
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
    let held = w.held();
    let te = Instant::now();
    let tl = Timeline::evaluate(&held);
    let eval = te.elapsed();
    let end_t = n as u64 + 10 + 4 * n as u64 + 10;
    let t0 = Instant::now();
    let certs = tl.certificates(&nodes[1], &doc);
    let first = t0.elapsed();
    let t1 = Instant::now();
    let again = tl.certificates(&nodes[2], &doc);
    let second = t1.elapsed();
    let mut w2 = w.clone();
    w2.set(nodes[1], doc, nodes[200], edge(Write), end_t + 1, &[]);
    let held2 = w2.held();
    let dropped = tl.dropped().len();
    let t2 = Instant::now();
    let tl2 = tl.extend(&held2).unwrap();
    let ext = t2.elapsed();
    let t3 = Instant::now();
    let c2 = tl2.certificates(&nodes[1], &doc);
    let after = t3.elapsed();
    eprintln!(
        "{n} edge writes + {} drops: evaluate {eval:?}, certificates first {first:?} ({} commits), second {second:?} ({}); one more write: extend {ext:?}, certificates {after:?} ({})",
        dropped,
        certs.commits.len(),
        again.commits.len(),
        c2.commits.len()
    );
}
