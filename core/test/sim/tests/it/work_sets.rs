#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
//! Pass work sets against full passes (spec/sync.md §6, §7): the same scenario and seed run
//! with work sets and with every pass judging everything (`osis_sim::net::with_full_passes`)
//! give the same run: every message, the server logs (uploads and deletes in order, in the
//! report's digest) and the final state. A trigger the work sets miss shows as a divergence.

use osis_sim::net::with_full_passes;
use osis_sim::replay;

fn same(name: &str, seed: u64) {
    // the two runs on two threads (`with_full_passes` is per thread)
    let (work, full) = std::thread::scope(|s| {
        let full = s.spawn(|| with_full_passes(|| replay(name, seed)));
        (replay(name, seed), full.join().unwrap())
    });
    let work = work.unwrap_or_else(|f| panic!("{f}"));
    let full = full.unwrap_or_else(|f| panic!("full passes: {f}"));
    assert_eq!(work, full, "{name} seed {seed}: work sets {work:?}, full passes {full:?}");
}

// spec/sync.md §6, §7: keep-at-most writes, their drops and compaction under crashes: work sets
// give the full passes' run.
#[test]
fn work_sets_keep_at_most_seed_1() {
    same("keep_at_most", 1);
}

// spec/sync.md §6, §7, notes/sync.md Receipts-only reads: a node reading a label for receipts
// only runs no pass there, with work sets or full passes alike.
#[test]
#[ignore = "tier 2"]
fn work_sets_demotion_receipts_seed_1() {
    same("demotion_receipts", 1);
}

// spec/sync.md §6, §7: random writes on two replicating servers, snapshots, keep-at-most,
// expiry, a purge and a demotion: work sets give the full passes' run (about 20 s per run in
// debug).
#[test]
#[ignore = "tier 2"]
fn work_sets_seed_1() {
    same("work_sets", 1);
}

// spec/sync.md §6, §7: every scenario (`OSIS_SIM_ONLY=a,b` narrows them), 20 seeds
// (`OSIS_SIM_SEEDS`) from 0 (`OSIS_SIM_FROM`): work sets give the full passes' run.
#[test]
#[ignore = "tier 2"]
fn work_sets_match_full_passes() {
    let seeds = osis_base::testenv::Seeds::from_env("OSIS_SIM_FROM", "OSIS_SIM_SEEDS", 0..20);
    seeds.announce("work_sets_match_full_passes");
    let only: Vec<String> = std::env::var("OSIS_SIM_ONLY").map(|s| s.split(',').map(String::from).collect()).unwrap_or_default();
    for (name, _) in osis_sim::SCENARIOS.iter().filter(|(n, _)| osis_sim::blocked(n).is_none() && (only.is_empty() || only.iter().any(|o| o == n))) {
        for seed in seeds.range.clone() {
            same(name, seed);
        }
    }
}
