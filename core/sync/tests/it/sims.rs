//! The simulation set (notes/test-properties.md, Reference-graph differential and sims): short scripted
//! scenarios with fault schedules over three nodes of three accounts, each over a seed per
//! variant it draws by seed at small size (at least an even and an odd one), 40 under `OSIS_FULL=1` (the seed draws the world's IDs, keys and the network's faults),
//! checked at quiet by the differential's oracle (`history::check`: every node holds its node
//! closure) plus the scenario's stated outcome.
//!
//! The common start: node 0 makes thing 0, gives node 1's account write and node 2's sync, and
//! both hold it, so node 2 keeps the thing's sync ID unread; then it runs to quiet.

use crate::harness::Step::*;
use crate::harness::history::{Gives, check, reads_as, reference, world_of};
use crate::harness::lies::Lie;
use crate::harness::{DiskFault, Loss, Step, World, play};
use osis_base::testenv::Seeds;

/// Seeds `0..variants` at small size (`variants`: the scenario's choices by seed, at least 2).
fn seeds(variants: u64) -> Seeds {
    let n = if osis_base::testenv::u64_var("OSIS_FULL") == Some(1) { 40 } else { variants.max(2) };
    Seeds::from_env("OSIS_SYNC_START", "OSIS_SYNC_SEEDS", 0..n)
}

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

/// Plays `start`, `body(seed)`, `end` on a fresh world of three nodes per seed (`seeds(variants)`),
/// then the oracle and `outcome`.
fn sim(name: &str, variants: u64, body: impl Fn(u64) -> Vec<Step> + Sync, outcome: impl Fn(&mut World) + Sync) {
    seeds(variants).run(name, |s| format!("OSIS_SYNC_START={s} OSIS_SYNC_SEEDS=1"), |seed| {
        let steps: Vec<Step> = start().into_iter().chain(body(seed)).chain(end()).collect();
        let mut w = world_of(seed, 3, 3);
        w.cap = crate::harness::STORM_CAP;
        let _script = play(&mut w, &steps, format!("sims::{name} (seed {seed})"));
        check(&mut w);
        outcome(&mut w);
    });
}

// spec/requirements.md (a node that cannot read is trusted for availability only), spec/sync.md
// §3 (kept unread), spec/sync-set.md §2: a sync grant stores the unit unread; a reader away
// while the writer writes, back when the writer is gone, reads every write through the node
// keeping the thing unread by its sync grant alone.
#[test]
#[ignore = "property"]
fn a_reader_through_a_node_keeping_it_unread_plain() {
    seeds(2).run("a_reader_through_a_node_keeping_it_unread_plain", |s| format!("OSIS_SYNC_START={s} OSIS_SYNC_SEEDS=1"), |seed| {
        let steps: Vec<Step> = [start(), vec![PowerOff(1)], writes(2), vec![PowerOff(0), PowerOn(1), Run]].concat();
        let mut w = world_of(seed, 3, 3);
        w.cap = crate::harness::STORM_CAP;
        let _script = play(&mut w, &steps, format!("sims::a_reader_through_a_node_keeping_it_unread_plain (seed {seed})"));
        let mut r = reference(&mut w, &Default::default());
        reads_as(&mut w, &mut r, 0, 1);
    });
}

// spec/sync-ids.md §5 (the store is the truth for ciphertext), spec/sync-set.md §3,
// spec/sync-inbox.md §3: nodes losing power at a durable write
// (drawn per seed) restart in place and every node holds its closure; a grant made across the
// crashes reaches its grantee.
#[test]
#[ignore = "property"]
fn crashes_and_restarts_in_place_plain() {
    sim(
        "crashes_and_restarts_in_place_plain",
        2,
        |seed| [vec![Disk(1, seed % 7, DiskFault::Crash), Disk(2, seed % 5, DiskFault::Crash)], writes(2), vec![New(0), Disk(0, seed % 3, DiskFault::Crash), Give(0, 1, crate::harness::history::Holder::Node(1), Gives::Reads), PowerOff(1), Run, PowerOn(1), Strong(1, None, 1)], writes(2)].concat(),
        |w| assert!(w.crashes > 0),
    );
}

// spec/requirements.md Decentralization (convergence under duplicates and partial receipt),
// spec/sync-streams.md §1 (Stall): writes over a network losing, repeating and holding back
// messages, and on odd seeds a peer holding every request open, hold their closure once it is
// clean.
#[test]
#[ignore = "property"]
fn lost_and_repeated_messages_plain() {
    sim(
        "lost_and_repeated_messages_plain",
        2,
        |seed| {
            let hold: Vec<Step> = if seed % 2 == 1 { vec![Lies(2, Lie::Hold)] } else { Vec::new() };
            [hold, vec![Lossy(Loss { drop: 100, dup: 100, delay: 300, delay_ms: 5_000 })], writes(4)].concat()
        },
        |w| assert!(w.net.faulted != (0, 0, 0)),
    );
}

// spec/sync-judgement.md §3 (Role entries first), spec/sync-streams.md §4,
// spec/sync.md §4 (a peer's word changes only what that peer holds): the node keeping the thing
// unread refuses every role entry (or, by seed, says it is full, or lies in its own log: shows
// what it adds as deleted, or hides it); through a removal, a rotation and a grant again, node 1
// still reads every write and holds its closure.
#[test]
#[ignore = "property"]
fn a_peer_refusing_role_entries_plain() {
    sim(
        "a_peer_refusing_role_entries_plain",
        4,
        |seed| {
            let lie = [Lie::RefuseRoles, Lie::Full, Lie::Forget, Lie::Withhold][(seed % 4) as usize];
            [vec![Lies(2, lie)], writes(2), vec![Remove(0, 0, 1), Rotate(0, 0), Run, Grant(0, 0, 1, Gives::Writes)], writes(2)].concat()
        },
        |_| {},
    );
}

// spec/sync-ids.md §5: a failed durable write, and one whose sync failed followed by a power
// loss, leave every node holding its closure; clocks skewed by seed.
#[test]
#[ignore = "property"]
fn store_failures_plain() {
    sim(
        "store_failures_plain",
        3,
        |seed| {
            let skew = [0i64, 600_000, -600_000][(seed % 3) as usize];
            [vec![Skew(1, skew), Disk(1, seed % 6, DiskFault::Fail), Disk(2, seed % 4, DiskFault::Unsynced)], writes(4), vec![PowerOff(2), PowerOn(2)], writes(2)].concat()
        },
        |_| {},
    );
}
