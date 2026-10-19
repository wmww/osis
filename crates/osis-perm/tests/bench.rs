//! Cost of a 10^4-edge-write history (plans/perm.md): from scratch and incremental. Tier 2:
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
    for n in [1_000, 10_000] {
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
        let t3 = Instant::now();
        let r = tl.role(&nodes[200], &doc, At::END);
        let query = t3.elapsed();
        eprintln!(
            "{n} edge writes: from scratch {scratch:?} ({} passes, {} dropped), incremental first {first:?}, after one more write {again:?} ({evaluated} components), one role query {query:?} ({r:?})",
            tl.passes(),
            tl.dropped().len()
        );
    }
}
