#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
//! Pass work sets against full passes (spec/sync.md §6, §7): the same scenario and seed run
//! with work sets and with every pass judging everything (`osis_sim::net::with_full_passes`)
//! end alike: faults and writes, when each upload, deposit and registration first reached each
//! host and when a delete took a host's last copy of a commit (`osis_sim::net::with_arrivals`),
//! and what each node and host ends up with (`Report::parts`). Not every message: a pass the work
//! sets leave out saves what it would have sent again, and the sim's dice do not look at what is
//! sent (`osis_sim::net`). Not blob IDs, the copy of a commit that stayed (the lower ID), how many
//! deletes that took or log order within a moment: all are the luck of the order a pass drew from
//! its random stream. A trigger the work sets miss shows as a later arrival or a later delete.

use osis_sim::net::{Arrivals, with_arrivals, with_full_passes};
use osis_sim::{Failure, Report, replay};
use std::io::Write;

type Run = (Result<Report, Failure>, Arrivals);

/// One scenario run with work sets and with full passes.
fn both(name: &str, seed: u64) -> (Run, Run) {
    // the two runs on two threads (`with_full_passes` is per thread)
    std::thread::scope(|s| {
        let full = s.spawn(|| with_arrivals(|| with_full_passes(|| replay(name, seed))));
        (with_arrivals(|| replay(name, seed)), full.join().unwrap())
    })
}

/// How two runs differ, one line per fact, none when they end alike.
fn parted((work, at): (&Report, &Arrivals), (full, ref_at): (&Report, &Arrivals)) -> Vec<String> {
    let mut out = Vec::new();
    // messages may differ: the counters of what the faults and the scenario did may not
    let counters = |r: &Report| Report { sent: 0, delivered: 0, duplicated: 0, diagnostics: 0, digest: [0; 32], parts: Default::default(), ..r.clone() };
    if counters(work) != counters(full) {
        out.push(format!("counters: work sets {:?}, full passes {:?}", counters(work), counters(full)));
    }
    // only of runs alike to the bit: another seal order alone moves the count, by a hundred
    // messages in a run (`compared_runs_ignore_the_random_stream`)
    if work.digest == full.digest && work.sent > full.sent {
        out.push(format!("work sets send more: {} against {}", work.sent, full.sent));
    }
    let names: std::collections::BTreeSet<_> = work.parts.keys().chain(full.parts.keys()).collect();
    out.extend(names.into_iter().filter(|n| work.parts.get(*n) != full.parts.get(*n)).map(|n| format!("ends apart: {n}")));
    let keys: std::collections::BTreeSet<_> = at.keys().chain(ref_at.keys()).collect();
    for k in keys {
        let (w, f) = (at.get(k), ref_at.get(k));
        if w != f {
            out.push(format!("host {} {:?} {} {}: work sets at {w:?}, full passes at {f:?}", k.0, k.1, k.3, String::from_utf8_lossy(&k.2)));
        }
    }
    out
}

fn same(name: &str, seed: u64) {
    let ((work, at), (full, ref_at)) = both(name, seed);
    let (work, full) = (work.unwrap_or_else(|f| panic!("{f}")), full.unwrap_or_else(|f| panic!("full passes: {f}")));
    let apart = parted((&work, &at), (&full, &ref_at));
    assert!(apart.is_empty(), "{name} seed {seed}: {apart:#?}");
}

// spec/sync.md §6, §7: keep-at-most writes, their drops and compaction under crashes: work sets
// give the full passes' run.
#[test]
fn work_sets_keep_at_most_seed_1() {
    same("keep_at_most", 1);
}

// spec: none (the oracle): what it compares does not see the random stream a pass seals with:
// the same run on another stream is no difference.
#[test]
fn compared_runs_ignore_the_random_stream() {
    let run = |other: bool| with_arrivals(|| if other { osis_sim::net::with_other_stream(|| replay("keep_at_most", 1)) } else { replay("keep_at_most", 1) });
    let ((a, at), (b, bt)) = (run(false), run(true));
    let (a, b) = (a.unwrap_or_else(|f| panic!("{f}")), b.unwrap_or_else(|f| panic!("{f}")));
    assert_ne!(a.digest, b.digest, "the streams differ");
    let apart = parted((&a, &at), (&b, &bt));
    assert!(apart.is_empty(), "{apart:#?}");
}

// spec/sync.md §6: a pass's refetch applied another node's commits at a device back from a crash:
// they go up in the same step, not at the next event (61 s later, at a quiet round). A seed, so it
// lasts until the sim's dice change.
#[test]
fn work_sets_two_devices_host_seed_412300013() {
    same("two_devices_host", 412300013);
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
// (`OSIS_SIM_SEEDS`) from 0 (`OSIS_SIM_FROM`): work sets give the full passes' run. A line to
// stderr gives the count either way.
#[test]
#[ignore = "tier 2"]
fn work_sets_match_full_passes() {
    let seeds = osis_base::testenv::Seeds::from_env("OSIS_SIM_FROM", "OSIS_SIM_SEEDS", 0..20);
    seeds.announce("work_sets_match_full_passes");
    let only: Vec<String> = std::env::var("OSIS_SIM_ONLY").map(|s| s.split(',').map(String::from).collect()).unwrap_or_default();
    let jobs: Vec<(&str, u64)> = osis_sim::SCENARIOS.iter().filter(|(n, _)| osis_sim::blocked(n).is_none() && (only.is_empty() || only.iter().any(|o| o == n))).flat_map(|(n, _)| seeds.range.clone().map(move |s| (*n, s))).collect();
    let runs = jobs.len();
    let jobs = std::sync::Mutex::new(jobs);
    let apart = std::sync::Mutex::new(Vec::new());
    let failed = std::sync::Mutex::new(Vec::new());
    // two threads per job: half a thread per core
    let threads = std::thread::available_parallelism().map_or(1, |n| n.get() / 2).max(1);
    std::thread::scope(|s| {
        for _ in 0..threads {
            s.spawn(|| {
                while let Some((name, seed)) = { jobs.lock().unwrap().pop() } {
                    match both(name, seed) {
                        ((Ok(work), at), (Ok(full), ref_at)) => {
                            let lines = parted((&work, &at), (&full, &ref_at));
                            if !lines.is_empty() {
                                apart.lock().unwrap().push(format!("{name} seed {seed}: {} differences, first {:#?}", lines.len(), &lines[..lines.len().min(5)]));
                            }
                        }
                        // the sweep's to report: no difference between the two
                        ((Err(_), _), (Err(_), _)) => failed.lock().unwrap().push((name, seed)),
                        ((work, _), (full, _)) => panic!("{name} seed {seed}: work sets {:?}, full passes {:?}", work.map_err(|f| f.to_string()), full.map_err(|f| f.to_string())),
                    }
                }
            });
        }
    });
    let (apart, failed) = (apart.into_inner().unwrap(), failed.into_inner().unwrap());
    // past the test harness's capture: a passing run says this too
    let _ = writeln!(std::io::stderr(), "work_sets_match_full_passes: {runs} runs, {} parted, failed both ways {failed:?}", apart.len());
    assert!(apart.is_empty(), "{} of {runs} runs parted:\n{}", apart.len(), apart.join("\n"));
}

// spec/sync.md §6: honest flows with no faults: everything the full passes' marks send to a host
// goes at the same moment with narrow marks, nothing waits for its label's next resync.
#[test]
#[ignore = "tier 2"]
fn honest_flows_wait_for_no_resync() {
    use osis_sim::net::library::honest_flows;
    let seeds = osis_base::testenv::Seeds::from_env("OSIS_SIM_FROM", "OSIS_SIM_SEEDS", 0..2);
    seeds.run(
        "honest_flows_wait_for_no_resync",
        |seed| format!("OSIS_SIM_FROM={seed} OSIS_SIM_SEEDS=1"),
        |seed| {
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
            let apart = parted((&work, &at), (&full, &ref_at));
            assert!(apart.is_empty(), "seed {seed}: {apart:#?}");
        },
    );
}

