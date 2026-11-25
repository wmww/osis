//! The reference-graph differential (harness::history, notes/test-properties.md): random
//! histories over a few nodes of fewer accounts; at quiet every node holds what held-model
//! `closure` says its node closure is, built from the history alone. Fresh worlds per seed;
//! `OSIS_SYNC_START`/`OSIS_SYNC_SEEDS` pick the seeds (`history::size`: 6 at small size, 100
//! under `OSIS_FULL=1`); a failure prints the history as a script, `OSIS_SYNC_SHRINK=1` shrinks
//! it. A failure is a finding: its reproducer is a new hand-written test, never the seed.

use crate::harness::history::{check, history, size, world_of};
use crate::harness::{Step, World, play, shrinking};
use osis_base::testenv::Seeds;

/// The world a history plays on, the history played once (twice when `twice`: its two traces,
/// every delivery and the bytes' digest, must be identical, as a history is a function of its
/// seed), then the checks at quiet. The replay call a failure prints is a debugging aid in a
/// scratch test, never a committed test (notes/principles.md, Never pin a seed).
pub(crate) fn holds(seed: u64, steps: &[Step], replay: String, twice: bool) -> World {
    let (n, accounts, _, _) = size();
    holds_on(seed, accounts, n, steps, replay, twice)
}

/// `holds` on a world of `n` nodes of `accounts` accounts.
fn holds_on(seed: u64, accounts: usize, n: usize, steps: &[Step], replay: String, twice: bool) -> World {
    let played = |replay: String, again: bool| {
        let mut w = world_of(seed, accounts, n);
        if again {
            w.untrace();
        }
        w.cap = crate::harness::STORM_CAP;
        w.trace = twice;
        w.parks = true;
        let script = play(&mut w, steps, replay);
        // every history ends at quiet (a shrunk one too): healed, every node on, faults off, run
        let end: Vec<Step> = [Step::Lossy(crate::harness::Loss::NONE), Step::Heal].into_iter().chain((0..w.len()).map(Step::PowerOn)).chain([Step::Run]).collect();
        for s in &end {
            crate::harness::step(&mut w, s);
        }
        (w, script)
    };
    let (mut w, _script) = played(replay.clone(), false);
    if twice {
        let (again, _) = played(replay, true);
        if let Some(i) = (0..w.seen.len().max(again.seen.len())).find(|&i| w.seen.get(i) != again.seen.get(i)) {
            panic!("not deterministic: replay differs at delivery {i} of {}: {:?} then {:?}", w.seen.len(), w.seen.get(i), again.seen.get(i));
        }
    }
    check(&mut w);
    w
}

/// Every fourth seed's history plays twice (the determinism check: a source of order a run
/// draws from, such as a hashed collection's iteration, reorders any history on its path).
const TWICE_EVERY: u64 = 4;

// spec: none (property: spec/requirements.md Convergence; spec/sync-set.md §1-§4: a node holds
// exactly its node closure): histories of minting things with the account root or other
// things as admin, strongs added and removed from roots and things, grants of sync, read and write to
// accounts and to things (chains), lowering, revoking, rotating, a grantee holding what it is
// granted by a strong (or not), pairing and removing a node, and on every second seed power loss,
// partitions, lost, repeated and held-back messages, device faults and clock skew, healed and run
// to quiet (within the storm cap): each node of an account reads a thing exactly when held-model's
// node closure of the account reads it, then as the reference; its sync set and store hold what
// the model holds; a removed node reads and keeps nothing of the history; no needed body is
// deleted everywhere.
#[test]
#[ignore = "property"]
fn histories_hold_their_closure_plain() {
    let (n, accounts, len, _) = size();
    worlds("histories_hold_their_closure_plain", |seed| history(seed, n, accounts, len, seed % 2 == 1));
}

/// `holds` for each seed of `OSIS_SYNC_START`/`OSIS_SYNC_SEEDS` (default: the size's range) on
/// the history `steps_of(seed)`, each failure shrunk under `OSIS_SYNC_SHRINK=1`. A shrunk script
/// replays over many worlds, or shrinks further from where a seed timeout cut it, in a scratch
/// test: `differential::worlds("scratch", |_| vec![New(2), ..])` (notes/sync-test-harness.md,
/// Replaying a script).
pub(crate) fn worlds(name: &str, steps_of: impl Fn(u64) -> Vec<Step> + Sync) {
    let seeds = Seeds::from_env("OSIS_SYNC_START", "OSIS_SYNC_SEEDS", 0..size().3);
    seeds.run(name, |s| format!("OSIS_SYNC_START={s} OSIS_SYNC_SEEDS=1"), |seed| {
        let h = steps_of(seed);
        let replay = format!("differential::holds({seed}, &script, String::new(), false)");
        let twice = seed.is_multiple_of(TWICE_EVERY);
        shrinking(
            || {
                holds(seed, &h, replay.clone(), twice);
            },
            |steps, again| {
                holds(seed, steps, replay.clone(), again && twice);
            },
        );
    });
}

// spec/sync-set.md §3 (Nothing of R stays): a node's own writes on a thing it releases, not yet
// held elsewhere, go. Node 1 makes a thing and grants node 0's account read; a run connects them
// while no node of that account holds the thing (the grant is an offer); a paired node of the
// account then holds it by a strong and node 1 releases it before any run. The making's value is
// at no node, and the oracle counts it lost: a run gives a node a value write only where its
// account's node closure held the thing then (`harness::history::ran`).
#[test]
fn a_making_released_before_a_grantee_held_it_is_lost_spec_sync_set_3() {
    use crate::harness::history::{Gives, Holder};
    let script = [Step::New(1), Step::NewIn(1, 0), Step::Give(1, 1, Holder::Node(0), Gives::Reads), Step::Run, Step::Strong(2, None, 1), Step::Unstrong(1, Some(0), 1)];
    holds_on(0, 2, 3, &script, String::new(), false);
}

// spec: none (test harness): a history is a function of its seed, faults included, and the
// property's seeds at small size draw every kind of step the oracle judges.
#[test]
fn a_history_is_a_function_of_its_seed() {
    let (n, accounts, len, seeds) = size();
    assert_eq!(history(0, n, accounts, len, true), history(0, n, accounts, len, true));
    let hs: Vec<Vec<Step>> = (0..seeds).map(|seed| history(seed, n, accounts, len, seed % 2 == 1)).collect();
    let drawn = |f: &dyn Fn(&Step) -> bool| hs.iter().flatten().any(f);
    for (name, has) in [
        ("new", drawn(&|s| matches!(s, Step::New(..) | Step::NewIn(..)))),
        ("give", drawn(&|s| matches!(s, Step::Give(..)))),
        ("hold", drawn(&|s| matches!(s, Step::Strong(_, None, _)))),
        ("pair", drawn(&|s| matches!(s, Step::Pair(..)))),
        ("unpair", drawn(&|s| matches!(s, Step::Unpair(..)))),
        ("fault", drawn(&|s| matches!(s, Step::Lossy(..) | Step::Disk(..) | Step::PowerOff(..)))),
    ] {
        assert!(has, "no {name} step");
    }
}
