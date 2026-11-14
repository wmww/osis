//! The simulation set (issues/sync-rewrite.md Phase 4; notes/sync-test-harness.md, Layers):
//! short scripted scenarios with fault schedules, each over 8 seeds at small size (the seed
//! draws the world's IDs, keys and the network's faults), checked at quiet by the
//! differential's oracle (`history::check`) plus the scenario's stated outcome.
//!
//! The common start: node 0 makes thing 0, grants node 1's account write and node 2's sync, so
//! node 2 keeps the thing's sync ID unread; then it runs to quiet.

use crate::harness::history::{Gives, check, reads_as, reference, world};
use crate::harness::lies::Lie;
use crate::harness::{DiskFault, Loss, Step, World, play};
use osis_base::testenv::{Seeds, large};
use crate::harness::Step::*;

/// Every scenario's start.
fn start() -> Vec<Step> {
    vec![New(0), Grant(0, 0, 1, Gives::Writes), Grant(0, 0, 2, Gives::Syncs), Run]
}

/// Writes by nodes 0 and 1, a run after each.
fn writes(n: usize) -> Vec<Step> {
    (0..n).flat_map(|i| [Write(i % 2, 0), Run]).collect()
}

/// Every node on, healed, faults and lies off, run to quiet.
fn end() -> Vec<Step> {
    vec![Lossy(Loss::NONE), Truth(0), Truth(1), Truth(2), Heal, PowerOn(0), PowerOn(1), PowerOn(2), Run]
}

/// Plays `start`, `body`, `end` on a fresh world of three nodes per seed, then the oracle and
/// `outcome`.
fn sim(name: &str, body: impl Fn(u64) -> Vec<Step> + Sync, outcome: impl Fn(&mut World) + Sync) {
    let seeds = Seeds::from_env("OSIS_SYNC_SEED", "OSIS_SYNC_SEEDS", large(0..80));
    seeds.run(name, |s| format!("OSIS_SYNC_SEED={s} OSIS_SYNC_SEEDS=1"), |seed| {
        let steps: Vec<Step> = start().into_iter().chain(body(seed)).chain(end()).collect();
        let mut w = world(seed, 3);
        w.cap = 200_000;
        let _script = play(&mut w, &steps, format!("sims::{name} (seed {seed})"));
        check(&mut w);
        outcome(&mut w);
    });
}

// spec: none (scenario: spec/requirements.md Convergence under duplicates and partial receipt):
// writes over a network losing, repeating and holding back messages converge once it is clean.
#[test]
#[ignore = "wiring: the driver dials no candidate, and the engine facade's sync_set, deliveries, open_entry and seal_body answer NotBuilt, so no grant or entry reaches another node"]
fn lost_and_repeated_messages() {
    sim("lost_and_repeated_messages", |_| [vec![Lossy(Loss { drop: 100, dup: 100, delay: 300, delay_ms: 5_000 })], writes(6)].concat(), |w| assert!(w.net.faulted != (0, 0, 0)));
}

// spec/sync.md §4 (area 8: a peer's word changes only what that peer holds): node 2, keeping the
// thing unread, lies in its own log (shows what it adds as deleted, or hides it) while node 1
// reaches node 0 only through it for a while: no honest node drops or deletes anything for it,
// and after healing node 1 reads every write.
#[test]
#[ignore = "wiring: the driver dials no candidate, and the engine facade's sync_set, deliveries, open_entry and seal_body answer NotBuilt, so no grant or entry reaches another node"]
fn a_peer_lying_in_its_own_log() {
    for lie in [Lie::Forget, Lie::Withhold] {
        sim("a_peer_lying_in_its_own_log", |_| [vec![Lies(2, lie), Partition(0, 1)], writes(4), vec![Heal, Run]].concat(), |_| {});
    }
}

// spec/sync-streams.md §4 (Full): a node keeping the thing unread that says it is full takes
// nothing more as far as its peers know; the readers converge without it.
#[test]
#[ignore = "wiring: the driver dials no candidate, and the engine facade's sync_set, deliveries, open_entry, seal_body and caps answer NotBuilt, so no grant or entry reaches another node"]
fn a_full_peer() {
    sim("a_full_peer", |_| [vec![Lies(2, Lie::Full)], writes(4)].concat(), |_| {});
}

// spec/sync-judgement.md §2 (Role entries first), spec/sync-streams.md §4 (Refused): a node
// keeping the thing unread refuses every role entry; through a removal, a rotation and a grant
// again, node 1 still reads every write, and no delete toward it waits forever.
#[test]
#[ignore = "wiring: the driver dials no candidate, and the engine facade's sync_set, deliveries, open_entry and seal_body answer NotBuilt, so no grant or entry reaches another node"]
fn a_peer_refusing_role_entries() {
    sim("a_peer_refusing_role_entries", |_| [vec![Lies(2, Lie::RefuseRoles)], writes(2), vec![Remove(0, 0, 1), Rotate(0, 0), Run, Grant(0, 0, 1, Gives::Writes)], writes(2)].concat(), |_| {});
}

// spec/sync-streams.md §1 (Stall): a node holding every request open is closed at the stall
// bound; the readers converge through the others.
#[test]
#[ignore = "wiring: the driver dials no candidate, and the engine facade's sync_set, deliveries, open_entry and seal_body answer NotBuilt, so no grant or entry reaches another node"]
fn a_peer_holding_requests_open() {
    sim("a_peer_holding_requests_open", |_| [vec![Lies(2, Lie::Hold)], writes(4)].concat(), |_| {});
}

// spec/sync-ids.md §5 (the store is the truth after a crash): nodes losing power at a durable
// write (drawn per seed) restart in place and converge.
#[test]
#[ignore = "wiring: the driver dials no candidate, and the engine facade's sync_set, deliveries, open_entry and seal_body answer NotBuilt, so no grant or entry reaches another node"]
fn crashes_and_restarts_in_place() {
    sim("crashes_and_restarts_in_place", |seed| [vec![Disk(1, seed % 7, DiskFault::Crash), Disk(2, seed % 5, DiskFault::Crash)], writes(4), vec![Disk(0, seed % 3, DiskFault::Crash)], writes(2)].concat(), |w| assert!(w.crashes > 0));
}

// spec/sync-ids.md §5: a failed durable write, and one whose sync failed followed by a power
// loss, leave every node converging.
#[test]
#[ignore = "wiring: the driver dials no candidate and does not restart in place after a store failure, and the engine facade's sync_set, deliveries, open_entry and seal_body answer NotBuilt"]
fn store_failures() {
    sim("store_failures", |seed| [vec![Disk(1, seed % 6, DiskFault::Fail), Disk(2, seed % 4, DiskFault::Unsynced)], writes(4), vec![PowerOff(2), PowerOn(2)], writes(2)].concat(), |_| {});
}

// spec/requirements.md (a node that cannot read is trusted for availability only; honest nodes
// converge through any route), spec/sync.md §3 (kept unread: it keeps ciphertext and relays it):
// a reader away while the writer writes, back when the writer is gone, reads every write
// through the node keeping the thing unread alone.
#[test]
#[ignore = "wiring: the driver dials no candidate, and the engine facade's sync_set, deliveries, open_entry and seal_body answer NotBuilt, so no grant or entry reaches another node"]
fn a_reader_through_a_node_keeping_it_unread() {
    let seeds = Seeds::from_env("OSIS_SYNC_SEED", "OSIS_SYNC_SEEDS", large(0..80));
    seeds.run("a_reader_through_a_node_keeping_it_unread", |s| format!("OSIS_SYNC_SEED={s} OSIS_SYNC_SEEDS=1"), |seed| {
        let steps: Vec<Step> = [start(), vec![PowerOff(1)], writes(1), vec![Write(0, 0), Run, Write(0, 0), Run, PowerOff(0), PowerOn(1), Run]].concat();
        let mut w = world(seed, 3);
        w.cap = 200_000;
        let _script = play(&mut w, &steps, format!("sims::a_reader_through_a_node_keeping_it_unread (seed {seed})"));
        let mut r = reference(&mut w);
        reads_as(&mut w, &mut r, 0, 1);
    });
}

// spec/sync-streams.md §1 (clock), spec/requirements.md Convergence: nodes whose clocks run ten
// minutes apart converge.
#[test]
#[ignore = "wiring: the driver dials no candidate, and the engine facade's sync_set, deliveries, open_entry and seal_body answer NotBuilt, so no grant or entry reaches another node"]
fn skewed_clocks() {
    sim("skewed_clocks", |_| [vec![Skew(1, 600_000), Skew(2, -600_000)], writes(4)].concat(), |_| {});
}
