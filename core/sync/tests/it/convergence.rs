//! The reference-model differential (harness::history): random histories over a few nodes, at
//! quiet every reader reads as a single engine handed every commit directly, and no needed body
//! is deleted everywhere. Fresh worlds per seed; `OSIS_SYNC_SEED`/`OSIS_SYNC_SEEDS` pick the
//! seeds (default: 100 at small size, 1,000 under `OSIS_FULL=1`); a failure prints the history
//! as a script, `OSIS_SYNC_SHRINK=1` shrinks it.

use crate::harness::history::{check, history, world};
use crate::harness::{Step, World, play, shrinking};
use osis_base::testenv::{Seeds, large};

/// Nodes and steps of one history at the default size.
const NODES: usize = 3;
const STEPS: usize = 40;

/// The world a history plays on, the history played, then the checks; replayed by `replay`.
pub(crate) fn converge(seed: u64, n: usize, steps: &[Step], replay: String) {
    let mut w = world(seed, n);
    w.cap = 200_000;
    let _script = play(&mut w, steps, replay);
    check(&mut w);
}

fn converges(seed: u64, n: usize, len: usize, faults: bool) {
    let h = history(seed, n, len, faults);
    let replay = |s: u64| format!("convergence::converge({s}, {n}, &script, String::new())");
    shrinking(|| converge(seed, n, &h, replay(seed)), |steps| converge(seed, n, steps, replay(seed)));
}

// spec: none (property: spec/requirements.md Convergence; spec/sync.md §4 area 4): one node
// alone, through writes, rotations, restarts in place after device crashes, failed writes and
// clock skew, reads as the reference. Every part of the differential but sync runs here.
#[test]
fn one_node_reads_as_the_reference() {
    for seed in 0..4 {
        converges(seed, 1, 30, true);
    }
}

// spec: none (property: spec/sync-ids.md §5, the store is the truth after a crash): one node's
// writes through a crash at a durable write, a write whose sync failed lost at a power loss,
// and a failed write: what it reads is what the reference reads of the commits that stood.
#[test]
fn one_node_through_device_faults_reads_as_the_reference() {
    use crate::harness::DiskFault::*;
    use Step::*;
    let steps = [New(0), Write(0, 0), Disk(0, 0, Crash), Write(0, 0), Write(0, 0), Disk(0, 0, Unsynced), Write(0, 0), PowerOff(0), PowerOn(0), Disk(0, 0, Fail), Write(0, 0), Write(0, 0), Run];
    let mut w = world(0, 1);
    let _script = play(&mut w, &steps, "convergence::one_node_through_device_faults_reads_as_the_reference".into());
    assert_eq!(w.crashes, 1);
    assert_eq!(w.history.values.len(), 4, "the crashed, unsynced and failed writes are not counted");
    check(&mut w);
}

// spec: none (test harness): a history is a function of its seed, and a world of one seed plays
// it the same way twice, faults included.
#[test]
fn a_history_replays_from_its_seed() {
    let h = history(3, 2, 24, true);
    assert_eq!(h, history(3, 2, 24, true));
    assert!(h.iter().any(|s| matches!(s, Step::Grant(..))) && h.iter().any(|s| matches!(s, Step::Lossy(..) | Step::Disk(..) | Step::PowerOff(..))));
    let run = || {
        let mut w: World = world(3, 2);
        w.cap = 200_000;
        w.trace = true;
        let _ = play(&mut w, &h, String::new());
        (w.seen.clone(), w.history.handed.len(), w.now())
    };
    assert_eq!(run(), run());
}

// spec: none (property: spec/requirements.md Convergence, Deterministic; spec/sync.md §2-§3):
// histories of writes, grants of read and sync (nodes keeping a thing unread), removals and
// rotations over three nodes, with power loss, partitions, lost, repeated and held-back
// messages, device faults and clock skew, healed and run to quiet: every reader reads as the
// reference, no needed body is deleted everywhere.
#[test]
#[ignore = "wiring: the driver dials no candidate, and the engine facade's sync_set, deliveries, open_entry and seal_body answer NotBuilt, so no grant or entry reaches another node"]
fn histories_converge() {
    let seeds = Seeds::from_env("OSIS_SYNC_SEED", "OSIS_SYNC_SEEDS", large(0..1000));
    seeds.run("histories_converge", |s| format!("OSIS_SYNC_SEED={s} OSIS_SYNC_SEEDS=1"), |s| converges(s, NODES, STEPS, true));
}

// spec: none (property: as `histories_converge`, no faults): the same histories on a clean
// network, so a failure there is sync's rules, not its recovery.
#[test]
#[ignore = "wiring: the driver dials no candidate, and the engine facade's sync_set, deliveries, open_entry and seal_body answer NotBuilt, so no grant or entry reaches another node"]
fn clean_histories_converge() {
    let seeds = Seeds::from_env("OSIS_SYNC_SEED", "OSIS_SYNC_SEEDS", large(0..1000));
    seeds.run("clean_histories_converge", |s| format!("OSIS_SYNC_SEED={s} OSIS_SYNC_SEEDS=1"), |s| converges(s, NODES, STEPS, false));
}
