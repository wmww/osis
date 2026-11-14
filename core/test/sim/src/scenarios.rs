//! Named scenarios: each is a function of its seeds (a calm setup of the setup seed, then a
//! random schedule and quiescence of the seed), so every scenario is also a seed family.
//! `replay(name, setup, seed)` reruns one exactly.

use crate::dice::Dice;
use crate::harness::{ClockSpec, Config, Failure, NetFaults, Report, Res, Seeds, Sim, Weights};
use crate::workload;
use osis_base::format::MAX_DRIFT_MS;
use osis_base::{Role, Value};
use osis_engine::{Ingested, Mutation, Reason};
use osis_schema::RawKey;
use std::panic::{AssertUnwindSafe, catch_unwind};

pub type Scenario = fn(Seeds) -> Res<Report>;

/// Every scenario by name: commits carried engine to engine.
pub const SCENARIOS: &[(&str, Scenario)] = &[
    ("two_nodes", two_nodes),
    ("three_random", three_random),
    ("crash_restart", crash_restart),
    ("drift_parks", drift_parks),
    ("revoke_while_writing", revoke_while_writing),
];

/// Scenarios a known engine bug breaks, with the issue: the sweep skips them unless asked;
/// their tests are ignored with the issue's name. Fixing the issue removes the line.
pub const BLOCKED: &[(&str, &str)] = &[];

/// The issue blocking scenario `name`, if any.
pub fn blocked(name: &str) -> Option<&'static str> {
    BLOCKED.iter().find(|b| b.0 == name).map(|b| b.1)
}

/// Runs scenario `name` with seeds `s`; a panic anywhere in node code is a failure. Every failure
/// names `s`, what replays it.
pub fn run(name: &str, s: Seeds, f: Scenario) -> Res<Report> {
    let r = match catch_unwind(AssertUnwindSafe(|| f(s))) {
        Ok(r) => r,
        Err(p) => {
            let msg = p.downcast_ref::<String>().cloned().or_else(|| p.downcast_ref::<&str>().map(|s| s.to_string())).unwrap_or_default();
            Err(Failure { scenario: name.into(), setup: s.setup, seed: s.seed, step: 0, what: format!("panic: {msg}"), trace: Vec::new() })
        }
    };
    r.map_err(|f| Failure { setup: s.setup, seed: s.seed, ..f })
}

/// The setup seed of a by-hand sweep from `from`: `OSIS_SIM_SETUP`, by default `from` (as
/// `sim-sweep --setup`).
#[allow(clippy::panic)] // a by-hand harness's setting: fail loudly
pub fn setup_seed(from: u64) -> u64 {
    std::env::var("OSIS_SIM_SETUP").map_or(from, |v| v.parse().unwrap_or_else(|_| panic!("OSIS_SIM_SETUP={v}: not a number")))
}

/// Reruns scenario `name` with seed `seed` over the setup of seed `setup` (a sweep's `--setup`).
pub fn replay(name: &str, setup: u64, seed: u64) -> Res<Report> {
    let s = Seeds { setup, seed };
    match SCENARIOS.iter().find(|x| x.0 == name) {
        Some((n, f)) => run(n, s, *f),
        None => Err(Failure { scenario: name.into(), setup, seed, step: 0, what: "no such scenario".into(), trace: Vec::new() }),
    }
}

/// Clocks within `skew` ms and `drift` ppm of true time, from the seed.
fn clocks(d: &mut Dice, n: usize, skew: i64, drift: i64) -> Vec<ClockSpec> {
    (0..n).map(|_| ClockSpec { skew_ms: d.range_i64(-skew, skew), drift_ppm: d.range_i64(-drift, drift) }).collect()
}

fn lossy() -> NetFaults {
    NetFaults { drop_pct: 20, dup_pct: 15, max_delay_ms: 30_000, reorder: true }
}

/// Two nodes of one account: an account actor with node 0 as first admin and node 1 as admin
/// (spec/permissions.md §1), a data thing under the account; both write it concurrently under a
/// lossy, reordering, duplicating network; they converge.
pub fn two_nodes(s: Seeds) -> Res<Report> {
    let seed = s.seed;
    let mut d = Dice::new(seed ^ 0xc0f1);
    let cfg = Config { nodes: 2, clocks: clocks(&mut d, 2, 30_000, 100), net: lossy(), ..Config::default() };
    let mut sim = Sim::new("two_nodes", seed, cfg)?;
    let person = sim.create_thing(0, None)?;
    sim.grant(0, person, 1, Role::Admin)?;
    sim.create_thing(0, Some(person))?;
    sim.run(200)?;
    sim.run_until_quiescent(50)?;
    Ok(sim.report.clone())
}

fn three_nodes(name: &str, seed: u64, weights: Weights, steps: u64) -> Res<Report> {
    let mut d = Dice::new(seed ^ 0x7e3);
    let cfg = Config { nodes: 3, clocks: clocks(&mut d, 3, 5 * 60_000, 200), net: lossy(), weights, ..Config::default() };
    let mut sim = Sim::new(name, seed, cfg)?;
    let a = sim.create_thing(0, None)?;
    sim.grant(0, a, 1, Role::Write)?;
    sim.grant(0, a, 2, Role::Write)?;
    let b = sim.create_thing(1, None)?;
    sim.grant(1, b, 0, Role::Admin)?;
    sim.grant(1, b, 2, Role::Write)?;
    sim.run(steps)?;
    sim.run_until_quiescent(50)?;
    Ok(sim.report.clone())
}

/// Three nodes, two shared things, random writes and random delivery with every message fault.
pub fn three_random(s: Seeds) -> Res<Report> {
    three_nodes("three_random", s.seed, Weights::default(), 300)
}

/// `three_random` with crashes (immediate, or at a node's next durable writes: mid-write) and
/// restarts over the same backend: storage recovers, counters are never reused, convergence.
pub fn crash_restart(s: Seeds) -> Res<Report> {
    three_nodes("crash_restart", s.seed, Weights { crash: 1, restart: 2, ..Weights::default() }, 300)
}

/// spec/permissions.md §5: an admin removes a writer while it keeps writing under a lossy
/// network; the removed writer's later deltas are judged invalid everywhere and un-merged, and
/// every node converges, whatever arrived first.
pub fn revoke_while_writing(s: Seeds) -> Res<Report> {
    let seed = s.seed;
    let mut d = Dice::new(seed ^ 0x4e0);
    let cfg = Config { nodes: 3, clocks: clocks(&mut d, 3, 60_000, 100), net: lossy(), ..Config::default() };
    let mut sim = Sim::new("revoke_while_writing", seed, cfg)?;
    let a = sim.create_thing(0, None)?;
    sim.grant(0, a, 1, Role::Write)?;
    sim.grant(0, a, 2, Role::Write)?;
    sim.run(100)?;
    sim.revoke(0, a, 2)?;
    let gone = sim.tid(2)?;
    sim.run(150)?;
    sim.run_until_quiescent(50)?;
    for i in 0..3 {
        if sim.engine(i)?.roster(&a).contains_key(&gone) {
            return Err(sim.fail(format!("node {i} still lists the removed writer")));
        }
    }
    Ok(sim.report.clone())
}

/// spec/crdt.md §2.2: a commit more than MAX_DRIFT ahead of the receiver's clock is parked until
/// local time catches up, then joined; then a random run with one node two hours ahead. The
/// clock jumps after setup (a node whose `created.0` is parked has its commits wait for the chain).
pub fn drift_parks(s: Seeds) -> Res<Report> {
    let seed = s.seed;
    let cfg = Config { nodes: 2, net: lossy(), ..Config::default() };
    let mut sim = Sim::new("drift_parks", seed, cfg)?;
    let t = sim.create_thing(0, None)?;
    sim.grant(0, t, 1, Role::Write)?;
    sim.sync_all()?;
    sim.set_clock(1, ClockSpec { skew_ms: 2 * MAX_DRIFT_MS as i64, drift_ppm: 0 })?;
    let v = Value::Str("ahead".into());
    let mut m = Mutation::new();
    m.set(t, &workload::REG, &v).map_err(|e| sim.fail(e.to_string()))?;
    let id = sim.commit(1, m)?.ok_or_else(|| sim.fail("no commit"))?;
    let pkg = sim.engine(1)?.package(&id).map_err(|e| sim.fail(e.to_string()))?.ok_or_else(|| sim.fail("no package"))?;
    let r = sim.deliver(0, &pkg)?;
    if r != Some(Ingested::Pending(id, Reason::Drift)) {
        return Err(sim.fail(format!("commit 2 h ahead not parked: {r:?}")));
    }
    let read = |sim: &mut Sim| sim.read(0, t, workload::REG.ak());
    if read(&mut sim)? == Some(v.clone()) {
        return Err(sim.fail("parked commit is read"));
    }
    // 2 h ahead: still parked 59 min later, joined once within MAX_DRIFT
    sim.advance(MAX_DRIFT_MS - 60_000)?;
    if read(&mut sim)? == Some(v.clone()) || sim.engine(0)?.header(&id).is_some() {
        return Err(sim.fail("parked commit joined before local time caught up"));
    }
    sim.advance(2 * 60_000)?;
    if read(&mut sim)? != Some(v) {
        return Err(sim.fail("parked commit not joined once local time caught up"));
    }
    sim.check_convergence()?;
    sim.run(150)?;
    sim.run_until_quiescent(50)?;
    Ok(sim.report.clone())
}
