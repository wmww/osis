#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
//! Phase A scenarios, one seed each in tier 1 (the engine runs unoptimized in test builds:
//! about 2 s per three-node run); the sweep is tier 3 (`#[ignore]`, run it with `--release`).
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
fn revoke_while_writing_converges() {
    ok("revoke_while_writing", 1);
}

// spec: none (replay by name)
#[test]
fn unknown_scenario_fails() {
    assert!(replay("nope", 1).is_err());
}

// spec/requirements.md (convergence); spec/commits.md §4; spec/crdt.md §2.2, §2.3: the nightly
// sweep's shape, `OSIS_SIM_SEEDS` seeds per scenario (default 100).
#[test]
#[ignore]
fn sweep() {
    let n: u64 = std::env::var("OSIS_SIM_SEEDS").ok().and_then(|s| s.parse().ok()).unwrap_or(100);
    let mut failed = Vec::new();
    for (name, _) in SCENARIOS {
        for seed in 0..n {
            if let Err(f) = replay(name, seed) {
                eprintln!("{f}");
                failed.push((*name, seed));
            }
        }
    }
    assert!(failed.is_empty(), "failing (scenario, seed): {failed:?}");
}
