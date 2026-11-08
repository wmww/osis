#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
//! Phase A: what the gate's sweep (every scenario at 5 seeds) does not check: that a scenario's
//! faults happen, and examples; the sweep here is tier 3 (`#[ignore]`, or `sim-sweep`).
//! A failure prints its seed and the `osis_sim::replay` call that reproduces it.

use osis_base::{CommitId, Role, Value};
use osis_node::Mutation;
use osis_sim::{Config, Report, SCENARIOS, Sim, replay, workload};

fn ok(name: &str, seed: u64) -> Report {
    replay(name, seed).unwrap_or_else(|f| panic!("{f}"))
}

// spec/requirements.md (convergence under any delivery order, duplicates, partial receipt);
// spec/permissions.md §1 (an account's nodes as admins of the account actor).
#[test]
fn two_nodes_converge() {
    let r = ok("two_nodes", 1);
    assert!(r.writes > 20 && r.dropped > 0, "{r:?}");
}

// spec/requirements.md (convergence); spec/crdt.md §2.3 (counters never reused).
#[test]
fn three_nodes_random_delivery() {
    let r = ok("three_random", 1);
    assert!(r.writes > 20 && r.dropped > 0 && r.parked > 0, "{r:?}");
}

// spec/commits.md §4 (a commit applies in one transaction); spec/crdt.md §2.2, §2.3: a crash at any
// durable write recovers, the HLC and counters continue without reuse, nodes converge. Also
// checks seed replay: the same seed gives the same run.
#[test]
#[ignore = "tier 2"]
fn crash_and_restart() {
    let r = ok("crash_restart", 1);
    assert!(r.crashes > 0 && r.restarts > 0, "{r:?}");
    assert_eq!(ok("crash_restart", 1), r);
}

// spec/commits.md §4: a commit on two things, one unknown at node 2, which syncs neither: its part
// there waits alone, the rest applies. Node 2's relay leaves node 1 without that part until a whole copy comes.
#[test]
fn partial_relay_gets_its_rest_spec_commits_4() {
    fn carry(sim: &mut Sim, from: usize, to: usize, ids: &[CommitId]) {
        for id in ids {
            let p = sim.engine(from).unwrap().package(id).unwrap().unwrap();
            sim.deliver(to, &p).unwrap();
        }
    }
    let cfg = Config { nodes: 3, ..Config::default() };
    let mut sim = Sim::new("partial_relay", 1, cfg).unwrap();
    let a = sim.create_thing(0, None).unwrap();
    sim.grant(0, a, 1, Role::Write).unwrap();
    sim.grant(0, a, 2, Role::Write).unwrap();
    let b = sim.create_thing(1, None).unwrap();
    sim.grant(1, b, 0, Role::Write).unwrap();
    sim.grant(1, b, 2, Role::Write).unwrap();
    let (of0, of1) = (sim.engine(0).unwrap().commit_ids(), sim.engine(1).unwrap().commit_ids());
    carry(&mut sim, 0, 1, &of0);
    carry(&mut sim, 0, 2, &of0);
    carry(&mut sim, 1, 0, &of1);

    let word = Value::Str("both".into());
    let mut m = Mutation::new();
    m.set(a, &workload::REG, &word).unwrap();
    m.set(b, &workload::REG, &word).unwrap();
    let id = sim.commit(0, m).unwrap().unwrap();
    carry(&mut sim, 0, 2, &[id]);
    carry(&mut sim, 2, 1, &[id]);
    for n in [1, 2] {
        let e = sim.engine(n).unwrap();
        assert!(e.commit_parts_missing().get(&id).is_some_and(|gaps| gaps.len() == 1), "node {n} holds part of it");
    }
    assert_ne!(sim.read(1, b, "s:reg.0").unwrap(), Some(word.clone()));

    sim.run_until_quiescent(50).unwrap();
    for n in 0..3 {
        assert_eq!(sim.read(n, a, "s:reg.0").unwrap(), Some(word.clone()), "node {n}");
        assert_eq!(sim.read(n, b, "s:reg.0").unwrap(), Some(word.clone()), "node {n}");
    }
}

// spec/crdt.md §2.2: commits beyond MAX_DRIFT park until local time catches up.
#[test]
fn drift_parks_until_clock_catches_up() {
    let r = ok("drift_parks", 1);
    assert!(r.parked > 0, "{r:?}");
}

// spec: none (replay by name)
#[test]
fn unknown_scenario_fails() {
    assert!(replay("nope", 1).is_err());
}

// spec/requirements.md (convergence); spec/commits.md §4; spec/crdt.md §2.2, §2.3: a small
// sweep, `OSIS_SIM_SEEDS` seeds per scenario (default 100) from `OSIS_SIM_FROM` (default 0), `OSIS_SIM_ONLY` a comma list of
// scenario names (default all but the blocked ones). The nightly sweep is the `sim-sweep` binary.
#[test]
#[ignore]
fn sweep() {
    let seeds = osis_base::testenv::Seeds::from_env("OSIS_SIM_FROM", "OSIS_SIM_SEEDS", 0..100);
    seeds.announce("sim sweep");
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
        for seed in seeds.range.clone() {
            if let Err(f) = replay(name, seed) {
                eprintln!("{f}");
                failed.push((*name, seed));
            }
        }
    }
    assert!(failed.is_empty(), "{seeds}: failing (scenario, seed): {failed:?}");
}
