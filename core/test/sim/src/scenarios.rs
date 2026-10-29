//! Named scenarios: each is a function of the seed (setup, a random schedule, quiescence), so
//! every scenario is also a seed family. `replay(name, seed)` reruns one exactly.

use crate::dice::Dice;
use crate::harness::{ClockSpec, Config, Failure, NetFaults, Report, Res, Sim, Weights};
use crate::net::scenarios as net;
use crate::net::ephemeral as net_ephemeral;
use crate::net::{adversary, library, skew};
use crate::workload;
use osis_base::format::MAX_DRIFT_MS;
use osis_base::{Role, Value};
use osis_node::{Ingested, Mutation, Reason};
use osis_schema::AspectKey;
use std::panic::{AssertUnwindSafe, catch_unwind};

pub type Scenario = fn(u64) -> Res<Report>;

/// Every scenario by name: phase A (commits engine to engine), then phase B (sync engines and
/// blind servers, `crate::net`).
pub const SCENARIOS: &[(&str, Scenario)] = &[
    ("two_devices", two_devices),
    ("three_random", three_random),
    ("crash_restart", crash_restart),
    ("drift_parks", drift_parks),
    ("revoke_while_writing", revoke_while_writing),
    ("two_devices_server", net::two_devices_server),
    ("three_persons_two_servers", net::three_persons_two_servers),
    ("removed_writer", net::removed_writer),
    ("compaction", net::compaction),
    ("reader_relays", net::reader_relays),
    ("stranded_reseal", net::stranded_reseal),
    ("server_loses_data", net::server_loses_data),
    ("offline_rotation", net::offline_rotation),
    ("disk_loss", net::disk_loss),
    ("grant_lost_on_crash", net::grant_lost_on_crash),
    ("large_edits", net::large_edits),
    ("work_sets", net::work_sets),
    ("coverer_revoked", net::coverer_revoked),
    ("revocation_bob", library::revocation_bob),
    ("revocation_carol", library::revocation_carol),
    ("stolen_device", library::stolen_device),
    ("demotion_synced", library::demotion_synced),
    ("demotion_unsynced", library::demotion_unsynced),
    ("link_redeem", library::link_redeem),
    ("link_race", library::link_race),
    ("move_import", library::move_import),
    ("chat_join_leave", library::chat_join_leave),
    ("folders", library::folders),
    ("label_replacement", library::label_replacement),
    ("label_replacement_offline", library::label_replacement_offline),
    ("bundles", library::bundles),
    ("disappearing", library::disappearing),
    ("keep_at_most", library::keep_at_most),
    ("concurrent_writers", library::concurrent_writers),
    ("evil_server", adversary::evil_server),
    ("evil_server_drops", adversary::evil_server_drops),
    ("removed_replayer", adversary::removed_replayer),
    ("malformed_blobs", adversary::malformed_blobs),
    ("deposit_flood", adversary::deposit_flood),
    ("equivocating_writer", adversary::equivocating_writer),
    ("tombstone_liar", adversary::tombstone_liar),
    ("future_format", skew::future_format),
    ("newer_schema", skew::newer_schema),
    ("ephemeral", net_ephemeral::ephemeral),
    ("ephemeral_capped", net_ephemeral::ephemeral_capped),
];

/// Scenarios a known engine bug breaks, with the issue: the sweep skips them unless asked;
/// their tests are ignored with the issue's name. Fixing the issue removes the line.
pub const BLOCKED: &[(&str, &str)] = &[
];

/// The issue blocking scenario `name`, if any.
pub fn blocked(name: &str) -> Option<&'static str> {
    BLOCKED.iter().find(|b| b.0 == name).map(|b| b.1)
}

/// Runs scenario `name` with `seed`; a panic anywhere in node code is a failure with the seed.
pub fn run(name: &str, seed: u64, f: Scenario) -> Res<Report> {
    match catch_unwind(AssertUnwindSafe(|| f(seed))) {
        Ok(r) => r,
        Err(p) => {
            let msg = p.downcast_ref::<String>().cloned().or_else(|| p.downcast_ref::<&str>().map(|s| s.to_string())).unwrap_or_default();
            Err(Failure { scenario: name.into(), seed, step: 0, what: format!("panic: {msg}"), trace: Vec::new() })
        }
    }
}

/// Reruns scenario `name` with `seed`.
pub fn replay(name: &str, seed: u64) -> Res<Report> {
    match SCENARIOS.iter().find(|s| s.0 == name) {
        Some((n, f)) => run(n, seed, *f),
        None => Err(Failure { scenario: name.into(), seed, step: 0, what: "no such scenario".into(), trace: Vec::new() }),
    }
}

/// Clocks within `skew` ms and `drift` ppm of true time, from the seed.
fn clocks(d: &mut Dice, n: usize, skew: i64, drift: i64) -> Vec<ClockSpec> {
    (0..n).map(|_| ClockSpec { skew_ms: d.range_i64(-skew, skew), drift_ppm: d.range_i64(-drift, drift) }).collect()
}

fn lossy() -> NetFaults {
    NetFaults { drop_pct: 20, dup_pct: 15, max_delay_ms: 30_000, reorder: true }
}

/// Two devices of one person: a person actor owned by device 0 with device 1 as admin
/// (spec/permissions.md §1), a data thing the person owns; both write it concurrently under a
/// lossy, reordering, duplicating network; they converge.
pub fn two_devices(seed: u64) -> Res<Report> {
    let mut d = Dice::new(seed ^ 0xc0f1);
    let cfg = Config { nodes: 2, clocks: clocks(&mut d, 2, 30_000, 100), net: lossy(), ..Config::default() };
    let mut sim = Sim::new("two_devices", seed, cfg)?;
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
pub fn three_random(seed: u64) -> Res<Report> {
    three_nodes("three_random", seed, Weights::default(), 300)
}

/// `three_random` with crashes (immediate, or at a node's next durable writes: mid-write) and
/// restarts over the same backend: storage recovers, counters are never reused, convergence.
pub fn crash_restart(seed: u64) -> Res<Report> {
    three_nodes("crash_restart", seed, Weights { crash: 1, restart: 2, ..Weights::default() }, 300)
}

/// spec/permissions.md §5: an admin removes a writer while it keeps writing under a lossy
/// network; the removed writer's later deltas are judged invalid everywhere and un-merged, and
/// every node converges, whatever arrived first.
pub fn revoke_while_writing(seed: u64) -> Res<Report> {
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
/// clock jumps after setup (a node whose `/created` is parked has its commits wait for the chain).
pub fn drift_parks(seed: u64) -> Res<Report> {
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
