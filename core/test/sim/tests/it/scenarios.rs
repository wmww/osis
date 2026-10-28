#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
//! Phase A scenarios, seed 1 each: the quickest in tier 1 (osis-sim's tier 1 stays
//! near 10 s), the rest tier 2 (`-- --ignored`); the sweep is tier 3 (`#[ignore]`, or `sim-sweep`).
//! A failure prints its seed and the `osis_sim::replay` call that reproduces it.

use osis_sim::{Report, SCENARIOS, replay};

fn ok(name: &str, seed: u64) -> Report {
    replay(name, seed).unwrap_or_else(|f| panic!("{f}"))
}

// spec/requirements.md (convergence under any delivery order, duplicates, partial receipt);
// spec/permissions.md §1 (a person's devices as admins of the person actor).
#[test]
fn two_devices_converge() {
    let r = ok("two_devices", 1);
    assert!(r.writes > 20 && r.dropped > 0, "{r:?}");
}

// spec/requirements.md (convergence); spec/crdt.md §2.3 (counters never reused).
#[test]
fn three_nodes_random_delivery() {
    let r = ok("three_random", 1);
    assert!(r.writes > 20 && r.dropped > 0 && r.parked > 0, "{r:?}");
}

// spec/commits.md §4 (atomic apply in one transaction); spec/crdt.md §2.2, §2.3: a crash at any
// durable write recovers, the HLC and counters continue without reuse, nodes converge. Also
// checks seed replay: the same seed gives the same run.
#[test]
#[ignore = "tier 2"]
fn crash_and_restart() {
    let r = ok("crash_restart", 1);
    assert!(r.crashes > 0 && r.restarts > 0, "{r:?}");
    assert_eq!(ok("crash_restart", 1), r);
}

// spec/crdt.md §2.2: commits beyond MAX_DRIFT park until local time catches up.
#[test]
fn drift_parks_until_clock_catches_up() {
    let r = ok("drift_parks", 1);
    assert!(r.parked > 0, "{r:?}");
}

// spec/permissions.md §5 (removal, per-delta validity, un-merge); spec/requirements.md
// (convergence).
#[test]
#[ignore = "tier 2"]
fn revoke_while_writing_converges() {
    ok("revoke_while_writing", 1);
}

// spec/permissions.md §5.2; spec/crdt.md §4.6: sweep seeds that diverge after the removal
// (fixed: un-merge by invalid delta, every body stripped before it joins).
#[test]
#[ignore = "tier 2"]
fn revoke_regression_seeds() {
    for seed in [98, 244, 271] {
        ok("revoke_while_writing", seed);
    }
}

// spec: none (replay by name)
#[test]
fn unknown_scenario_fails() {
    assert!(replay("nope", 1).is_err());
}

// spec/requirements.md (convergence); spec/commits.md §4; spec/crdt.md §2.2, §2.3: a small
// sweep, `OSIS_SIM_SEEDS` seeds per scenario (default 100), `OSIS_SIM_ONLY` a comma list of
// scenario names (default all but the blocked ones). The nightly sweep is the `sim-sweep` binary.
#[test]
#[ignore]
fn sweep() {
    let n: u64 = std::env::var("OSIS_SIM_SEEDS").ok().and_then(|s| s.parse().ok()).unwrap_or(100);
    let mut failed = Vec::new();
    let only: Option<Vec<String>> = std::env::var("OSIS_SIM_ONLY").ok().map(|s| s.split(',').map(str::to_string).collect());
    for (name, _) in SCENARIOS {
        let skip = match &only {
            Some(o) => !o.iter().any(|x| x == name),
            None => osis_sim::blocked(name).is_some(),
        };
        if skip {
            continue;
        }
        for seed in 0..n {
            if let Err(f) = replay(name, seed) {
                eprintln!("{f}");
                failed.push((*name, seed));
            }
        }
    }
    assert!(failed.is_empty(), "failing (scenario, seed): {failed:?}");
}
