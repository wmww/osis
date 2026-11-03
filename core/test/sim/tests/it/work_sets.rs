#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
//! Pass work sets against full passes (spec/sync.md §6, §7): the same scenario and seed run
//! with work sets and with every pass judging everything (`osis_sim::net::with_full_passes`)
//! end alike: the host logs (uploads and deletes in order, in the report's digest) and the final
//! state. Not every message: a pass the work sets leave out saves what it would have sent again.
//! A trigger the work sets miss shows as a divergence, or as an arrival later than under full
//! passes (`honest_flows_wait_for_no_resync`).

use osis_sim::net::with_full_passes;
use osis_sim::replay;

/// One scenario run with work sets and with full passes.
fn both(name: &str, seed: u64) -> (Result<osis_sim::Report, osis_sim::Failure>, Result<osis_sim::Report, osis_sim::Failure>) {
    // the two runs on two threads (`with_full_passes` is per thread)
    std::thread::scope(|s| {
        let full = s.spawn(|| with_full_passes(|| replay(name, seed)));
        (replay(name, seed), full.join().unwrap())
    })
}

/// Whether the two runs end alike. What the host logs and each node hold is the digest; of the
/// messages only that work sets send no more.
fn alike(name: &str, seed: u64, work: &osis_sim::Report, full: &osis_sim::Report) -> bool {
    let outcome = |r: &osis_sim::Report| osis_sim::Report { sent: 0, delivered: 0, ..r.clone() };
    if outcome(work) != outcome(full) {
        return false;
    }
    assert!(work.sent <= full.sent, "{name} seed {seed}: work sets send more, {work:?}, full passes {full:?}");
    true
}

fn same(name: &str, seed: u64) {
    let (work, full) = both(name, seed);
    let (work, full) = (work.unwrap_or_else(|f| panic!("{f}")), full.unwrap_or_else(|f| panic!("full passes: {f}")));
    assert!(alike(name, seed, &work, &full), "{name} seed {seed}: work sets {work:?}, full passes {full:?}");
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

// spec/sync.md §6, §7: random writes on two replicating hosts, snapshots, keep-at-most,
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
    // a run under faults can part for a harmless reason: a pass left out sends less, so the next
    // message rolls other dice (delays, cuts, the random writes). Rare, or a trigger was missed;
    // `honest_flows_wait_for_no_resync` has no dice.
    let jobs: Vec<(&str, u64)> = osis_sim::SCENARIOS.iter().filter(|(n, _)| osis_sim::blocked(n).is_none() && (only.is_empty() || only.iter().any(|o| o == n))).flat_map(|(n, _)| seeds.range.clone().map(move |s| (*n, s))).collect();
    let runs = jobs.len();
    let jobs = std::sync::Mutex::new(jobs);
    let parted = std::sync::Mutex::new(Vec::new());
    // two threads per job: half a thread per core
    let threads = std::thread::available_parallelism().map_or(1, |n| n.get() / 2).max(1);
    std::thread::scope(|s| {
        for _ in 0..threads {
            s.spawn(|| {
                while let Some((name, seed)) = { jobs.lock().unwrap().pop() } {
                    match both(name, seed) {
                        (Ok(work), Ok(full)) => {
                            if !alike(name, seed, &work, &full) {
                                println!("parted: {name} seed {seed}");
                                parted.lock().unwrap().push((name, seed));
                            }
                        }
                        // the sweep's to report: no difference between the two
                        (Err(_), Err(_)) => println!("failed both ways: {name} seed {seed}"),
                        (work, full) => panic!("{name} seed {seed}: work sets {:?}, full passes {:?}", work.map_err(|f| f.to_string()), full.map_err(|f| f.to_string())),
                    }
                }
            });
        }
    });
    let parted = parted.into_inner().unwrap();
    assert!(parted.len() * 100 <= runs.max(200), "{} of {runs} runs parted: {parted:?}", parted.len());
}

// spec/sync.md §6: honest flows with no faults: everything the full passes' marks send to a host
// goes at the same moment with narrow marks, nothing waits for its label's next resync.
#[test]
#[ignore = "tier 2"]
fn honest_flows_wait_for_no_resync() {
    use osis_sim::net::{library::honest_flows, with_arrivals};
    let seeds = osis_base::testenv::Seeds::from_env("OSIS_SIM_FROM", "OSIS_SIM_SEEDS", 0..2);
    seeds.announce("honest_flows_wait_for_no_resync");
    for seed in seeds.range.clone() {
        let run = |full: bool| {
            std::thread::Builder::new()
                .stack_size(64 << 20)
                .spawn(move || with_arrivals(|| if full { with_full_passes(|| honest_flows(seed)) } else { honest_flows(seed) }))
                .unwrap()
                .join()
                .unwrap()
        };
        let ((work, at), (full, ref_at)) = (run(false), run(true));
        let (work, full) = (work.unwrap_or_else(|f| panic!("{f}")), full.unwrap_or_else(|f| panic!("full passes: {f}")));
        let late: Vec<_> = ref_at.iter().filter(|(k, t)| at.get(*k).is_none_or(|x| x != *t)).map(|(k, t)| (k.0, k.1, k.3, *t, at.get(k).copied())).collect();
        assert!(late.is_empty(), "seed {seed}: (host, label, kind, full passes at, work sets at): {late:?}");
        assert!(alike("honest_flows", seed, &work, &full), "seed {seed}: work sets {work:?}, full passes {full:?}");
    }
}
