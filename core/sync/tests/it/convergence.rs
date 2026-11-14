//! The reference-model differential (harness::history): random histories over a few nodes, at
//! quiet every reader reads as a single engine handed every commit directly, and no needed body
//! is deleted everywhere. Fresh worlds per seed; `OSIS_SYNC_SEED`/`OSIS_SYNC_SEEDS` pick the
//! seeds (default: 20 at small size, 1,000 under `OSIS_FULL=1`: what notes/sync-test-harness.md's
//! differential budget buys, issues/sync-test-cost.md); a failure prints the history as a
//! script, `OSIS_SYNC_SHRINK=1` shrinks it.

use crate::harness::history::{Gives, check, check_readers, hand, hand_all, history, world};
use crate::harness::{Step, World, play, shrinking};
use osis_base::testenv::{Seeds, u64_var};

/// Nodes and steps of one history at the default size.
const NODES: usize = 3;
const STEPS: usize = 40;

/// A default seed range: `full` seeds under `OSIS_FULL=1`, else `small` (the large size stays the
/// release checks' while the small one is cut for cost, issues/sync-test-cost.md).
pub(crate) fn sized(small: u64, full: u64) -> std::ops::Range<u64> {
    0..if u64_var("OSIS_FULL") == Some(1) { full } else { small }
}

/// The world a history plays on, the history played, then the checks; replayed by `replay`.
/// The checks run at quiet: every history ends healed, every node on, faults off, run (so a
/// shrunk history ends so too).
pub(crate) fn converge(seed: u64, n: usize, steps: &[Step], replay: String) {
    let mut w = world(seed, n);
    w.cap = 200_000;
    let _script = play(&mut w, steps, replay);
    let end: Vec<Step> = [Step::Lossy(crate::harness::Loss::NONE), Step::Heal].into_iter().chain((0..n).map(Step::PowerOn)).chain([Step::Run]).collect();
    for s in &end {
        crate::harness::step(&mut w, s);
    }
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
fn histories_converge() {
    let seeds = Seeds::from_env("OSIS_SYNC_SEED", "OSIS_SYNC_SEEDS", sized(20, 1000));
    seeds.run("histories_converge", |s| format!("OSIS_SYNC_SEED={s} OSIS_SYNC_SEEDS=1"), |s| converges(s, NODES, STEPS, true));
}

// spec: none (property: as `histories_converge`, no faults): the same histories on a clean
// network, so a failure there is sync's rules, not its recovery.
#[test]
fn clean_histories_converge() {
    let seeds = Seeds::from_env("OSIS_SYNC_SEED", "OSIS_SYNC_SEEDS", sized(20, 1000));
    seeds.run("clean_histories_converge", |s| format!("OSIS_SYNC_SEED={s} OSIS_SYNC_SEEDS=1"), |s| converges(s, NODES, STEPS, false));
}

/// Plays `steps`, after each handing every node's commits to every other (`hand_all`): perfect
/// delivery without sync, so the oracle is checked on its own.
fn handed(seed: u64, n: usize, steps: &[Step]) -> World {
    let mut w = world(seed, n);
    w.cap = 200_000;
    for s in steps {
        crate::harness::step(&mut w, s);
        hand_all(&mut w);
    }
    w
}

/// The panic message of `f`, which must panic.
fn caught(f: impl FnOnce()) -> String {
    let e = std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)).expect_err("the oracle catches it");
    e.downcast_ref::<String>().cloned().or_else(|| e.downcast_ref::<&str>().map(|s| s.to_string())).unwrap_or_default()
}

// spec: none (test harness): the reader clauses pass what is right. Generated histories over
// three nodes (removals, grants of sync, rotations, writes by nodes that may not, faults)
// delivered to every node by hand pass them, so a reader clause failing with sync wired is
// sync's. (Delivery by hand hands non-readers plaintext too: the other clauses are checked by
// `the_oracle_catches_planted_faults`.)
#[test]
fn handed_histories_pass_the_reader_clauses() {
    for seed in 0..3 {
        let mut w = handed(seed, NODES, &history(seed, NODES, 30, seed % 2 == 1));
        assert!(!w.history.things.is_empty());
        check_readers(&mut w);
    }
}

// spec: none (test harness): the whole oracle passes delivery that keeps content from those that
// may not read it, and catches each planted fault: a write never delivered to a reader; a later
// write delivered to a removed reader; a write delivered to a node keeping the thing unread; the
// body of the value read deleted everywhere.
#[test]
fn the_oracle_catches_planted_faults() {
    use Step::*;
    // node 1 reads until it is removed; node 2 keeps the thing unread (delivery shows it nothing)
    let to1 = |w: &mut World, steps: &[Step]| {
        for s in steps {
            crate::harness::step(w, s);
            hand(w, 0, 1);
        }
    };
    let mut pre = world(0, NODES);
    pre.cap = 200_000;
    to1(&mut pre, &[New(0), Grant(0, 0, 1, Gives::Reads), Grant(0, 0, 2, Gives::Syncs), Write(0, 0)]);
    let mut base = pre.copy();
    to1(&mut base, &[Remove(0, 0, 1)]);
    let mut w = base.copy();
    let _ = play(&mut w, &[Write(0, 0)], String::new());
    check(&mut w);
    assert!(!w.history.hidden.is_empty(), "the write after the removal is hidden from node 1");
    // a write never delivered to reader 1 (before its removal)
    let mut w = pre.copy();
    let _ = play(&mut w, &[Write(0, 0)], String::new());
    assert!(caught(|| check(&mut w)).contains("node 1 reads thing 0 unlike the reference"));
    // the later write delivered to removed reader 1
    let mut w = base.copy();
    to1(&mut w, &[Write(0, 0)]);
    assert!(caught(|| check(&mut w)).contains("node 1, removed from thing 0, reads"));
    // a write delivered to node 2, which keeps the thing unread
    let mut w = base.copy();
    hand(&mut w, 0, 2);
    assert!(caught(|| check(&mut w)).contains("node 2, never granted read on thing 0, reads it"));
    // the value's body gone everywhere (its commit unknown to every node)
    let mut w = base;
    let last = w.history.values.keys().max_by_key(|v| v[1..].parse::<u64>().unwrap_or(0)).cloned().expect("a value");
    w.history.values.insert(last, osis_base::CommitId([0xee; 32]));
    assert!(caught(|| check(&mut w)).contains("is deleted everywhere"));
}

// spec: none (test harness): a differential world's nodes find each other as LAN discovery hands
// them up, and each pair connects (the driver dials discovered candidates).
#[test]
fn a_world_connects_every_pair() {
    let w = world(0, NODES);
    for a in 0..NODES {
        for b in (a + 1)..NODES {
            assert!(w.net.ups.iter().any(|u| *u == (a, b) || *u == (b, a)), "{a} and {b} connected: {:?}", w.net.ups);
        }
    }
}
