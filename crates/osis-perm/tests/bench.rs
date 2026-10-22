//! Cost of a 10^4-edge-write history (issues/perm-eval-cost.md): from scratch and incremental. Tier 2:
//! `cargo test -p osis-perm --release --test bench -- --ignored --nocapture`.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

mod common;

use common::*;
use membership_model::Rng;
use osis_core::Role::{Admin, Read, Write};
use osis_core::Tid;
use osis_perm::{At, Timeline, Timelines};
use std::time::Instant;

/// An organization: key actor K owns root actor R (10 admins) owning 20 teams; each team owns
/// 10 docs; 300 member nodes; `n` edge writes (grants, changes, removals on teams and docs)
/// by admins, a few percent received late.
fn org(n: usize, rng: &mut Rng) -> (World, Vec<Tid>) {
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
    let members = &nodes[11..];
    for i in 0..n {
        let t = 1 + i as u64;
        let author = admins[rng.below(admins.len())];
        let target = if rng.below(3) == 0 { teams[rng.below(teams.len())] } else { docs[rng.below(docs.len())] };
        let member = if rng.below(10) == 0 { teams[rng.below(teams.len())] } else { members[rng.below(members.len())] };
        let e = match rng.below(5) {
            0 => None,
            1 => edge(Read),
            2 | 3 => edge(Write),
            _ => edge(Admin),
        };
        let late = rng.below(25) == 0;
        let recv: Vec<(Tid, u64)> = admins.iter().map(|a| (*a, if late { LATE } else { t })).collect();
        w.set(author, target, member, e, t, &recv);
    }
    (w, nodes)
}

// spec: none (cost measurement)
#[test]
#[ignore]
fn bench_10k_edges() {
    let mut rng = Rng(0x5eed_0401);
    // `OSIS_BENCH_N` picks one size (for profiling).
    let sizes: Vec<usize> = std::env::var("OSIS_BENCH_N").ok().and_then(|v| v.parse().ok()).map_or(vec![1_000, 10_000], |n| vec![n]);
    for n in sizes {
        let (w, nodes) = org(n, &mut rng);
        let held = w.held();
        let t0 = Instant::now();
        let tl = Timeline::evaluate(&held);
        let scratch = t0.elapsed();
        let t1 = Instant::now();
        let mut inc = Timelines::new();
        inc.update(&held);
        let first = t1.elapsed();
        let mut w2 = w.clone();
        let doc = *w.created.keys().last().unwrap();
        w2.set(nodes[1], doc, nodes[200], edge(Write), n as u64 + 5, &[]);
        let held2 = w2.held();
        let t2 = Instant::now();
        let evaluated = inc.update(&held2);
        let again = t2.elapsed();
        // a write arriving late, ordered in the middle of the history
        let mut w3 = w2.clone();
        w3.set(nodes[2], doc, nodes[201], edge(Read), n as u64 / 2, &[]);
        let held3 = w3.held();
        let tl3 = Instant::now();
        inc.update(&held3);
        let late = tl3.elapsed();
        let t3 = Instant::now();
        let r = tl.role(&nodes[200], &doc, At::END);
        let query = t3.elapsed();
        // a point query in the middle of the history, and a delta's validity (cold, then memoized)
        let mid = tl.applied().values().nth(tl.applied().len() / 2).map(|a| a.point).unwrap();
        let t4 = Instant::now();
        let _ = tl.role(&nodes[200], &doc, At::before(mid));
        let point_query = t4.elapsed();
        let t5 = Instant::now();
        let v = tl.delta_valid(mid, &doc, "/app/x", osis_perm::Dots::Commit, Write);
        let valid_cold = t5.elapsed();
        let t6 = Instant::now();
        let _ = tl.delta_valid(mid, &doc, "/app/x", osis_perm::Dots::Commit, Write);
        let valid_warm = t6.elapsed();
        // what a node re-judges after a change in this component: one content delta per
        // applied write, by its author on its target, on a fresh timeline (nothing memoized)
        let fresh = Timeline::evaluate(&held);
        let deltas: Vec<_> = fresh.applied().values().take(1000).map(|a| (a.point, a.target)).collect();
        let t7 = Instant::now();
        for (p, t) in &deltas {
            let _ = fresh.delta_valid(*p, t, "/app/x", osis_perm::Dots::Commit, Write);
        }
        let rejudge = t7.elapsed();
        // members' deltas: one by each member granted write or more, just after the grant
        let fresh = Timeline::evaluate(&held);
        let mut by_members = Vec::new();
        for id in fresh.applied().keys() {
            let osis_perm::WriteId::Op(c, k) = id else { continue };
            let cm = fresh.membership_commit(c).unwrap();
            let o = &cm.ops[*k as usize];
            if o.edge.is_some_and(|e| e.role >= Write) && nodes.contains(&o.member) {
                let p = cm.point();
                by_members.push((osis_perm::Point { ts: ts(p.ts.wall_ms().0 + 1), node: o.member, commit: osis_core::CommitId([0x11; 32]) }, o.target));
            }
        }
        by_members.truncate(1000);
        let t7b = Instant::now();
        let mut valid_members = 0;
        for (p, t) in &by_members {
            valid_members += usize::from(fresh.delta_valid(*p, t, "/app/x", osis_perm::Dots::Commit, Write) == osis_perm::Validity::Valid);
        }
        let rejudge_members = t7b.elapsed();
        // what a demotion's frontier lists (§5.1): an admin's chain certificates on a doc, at
        // the end and at the middle
        let end = osis_perm::Point { ts: ts(n as u64 + 10), node: nodes[1], commit: osis_core::CommitId([0xff; 32]) };
        let t8 = Instant::now();
        let certs = tl.certificates(&nodes[1], &doc, end);
        let cert = t8.elapsed();
        let t9 = Instant::now();
        let _ = tl.certificates(&nodes[2], &doc, mid);
        let cert_mid = t9.elapsed();
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
        let mut w4 = w3.clone();
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
        // a new thing (a leaf: only its `/created`) under the team and under the doc with the
        // most demotions recorded
        inc.update(&held4);
        let tl4 = Timeline::evaluate(&held4);
        let most = |things: Vec<Tid>| things.into_iter().map(|t| (nodes.iter().map(|x| tl4.demotions(x, &t).len()).sum::<usize>(), t)).max().unwrap();
        let teams: Vec<Tid> = w.created.iter().filter(|(_, r)| matches!(r, osis_core::CreationRecord::Thing { owner, .. } if w.created.get(owner).is_some_and(|o| matches!(o, osis_core::CreationRecord::Thing { owner: oo, .. } if !w.created.get(oo).is_some_and(|x| matches!(x, osis_core::CreationRecord::Thing { .. })))))).map(|(t, _)| *t).collect();
        let docs: Vec<Tid> = w.created.iter().filter(|(t, r)| !teams.contains(t) && matches!(r, osis_core::CreationRecord::Thing { owner, .. } if teams.contains(owner))).map(|(t, _)| *t).collect();
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
            "{n} edge writes: from scratch {scratch:?} ({} passes, {} dropped), incremental first {first:?}, after one more write {again:?} ({evaluated} components), a late write in the middle {late:?}, one role query {query:?} ({r:?}), role at a mid point {point_query:?}, delta_valid {valid_cold:?} then {valid_warm:?} ({v:?}), {} deltas judged cold {rejudge:?}, {} members' deltas cold {rejudge_members:?} ({valid_members} valid), chain certificates at the end {cert:?} ({} commits, {} snapshots), at the middle {cert_mid:?}",
            tl.passes(),
            tl.dropped().len(),
            deltas.len(),
            by_members.len(),
            certs.commits.len(),
            certs.snapshots.len()
        );
    }
}

// spec: none (cost measurement, issues/perm-eval-cost.md): an owner chain of depth d (each thing
// owned by the previous), one member granted at the top, 100 edge writes at the bottom; evaluate
// and a role query at the leaf.
#[test]
#[ignore]
fn bench_deep_owner_chain() {
    for depth in [10usize, osis_core::format::MAX_OWNER_DEPTH] {
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
