#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
//! Phase B scenarios (sync engines and blind servers engine to engine), one seed each in tier 1.
//! Every run ends with the quiescent invariants (sim/src/net/check.rs: convergence by held
//! deltas, member liveness and agreement, label required sets at servers, must-not-hold absent,
//! deposit promotion, tombstones, purges, no ping-pong). A failure prints its seed and the
//! `osis_sim::replay` call that reproduces it. Scenarios an engine bug breaks are ignored with
//! the issue's name.

use osis_sim::{Report, replay};

fn ok(name: &str, seed: u64) -> Report {
    let r = replay(name, seed).unwrap_or_else(|f| panic!("{f}"));
    eprintln!("{name} {seed}: {r:?}");
    r
}

// spec/sync.md §2, §6; spec/commits.md §4: two devices of one person through one blind server
// under cut, delayed, reordered and duplicated messages and crashes mid-write.
#[test]
fn two_devices_server() {
    let r = ok("two_devices_server", 1);
    assert!(r.writes > 10 && r.crashes > 0 && r.dropped > 0 && r.held_checked > 0, "{r:?}");
}

// spec/sync.md §5 (replication, push only), §6; spec/sync.md §3 (grants by inbox): three
// persons share a group through two replicating servers with server crashes and partitions.
#[test]
fn three_persons_two_servers() {
    let r = ok("three_persons_two_servers", 1);
    assert!(r.writes > 10 && r.held_checked > 0 && r.partitions > 0, "{r:?}");
}

// spec/sync.md §5 (deletion by token); spec/commits.md §5 (purge): a removed writer's body
// purged by a remaining writer without the delete key.
#[test]
fn removed_writer() {
    ok("removed_writer", 1);
}

// spec/sync.md §5, §6: a reader relays stamped entries to a server the writer cannot reach;
// the readers' opens race the admin's registrations.
#[test]
fn reader_relays() {
    ok("reader_relays", 1);
}

// spec/permissions.md §3, §4: a device stranded past MEMBERSHIP_KEEP is re-sealed by pairing.
#[test]
fn stranded_reseal() {
    ok("stranded_reseal", 1);
}

// spec/sync.md §6: a server that lost its data gets every must-hold body back from writers.
#[test]
fn server_loses_data() {
    ok("server_loses_data", 1);
}

// spec/sync.md §5 (open by stale sync key, walk); spec/permissions.md §3: a reader offline
// across two rotations walks the steps; removed members hold no later epoch.
#[test]
fn offline_rotation() {
    ok("offline_rotation", 1);
}

// spec: none (replay): the same (scenario, seed) gives the same run, digest included.
#[test]
fn replay_is_exact() {
    assert_eq!(ok("two_devices_server", 2), ok("two_devices_server", 2));
}

// spec/sync.md §7: compaction deletes covered bodies once the snapshot is there; then a purge.
#[test]
fn compaction() {
    ok("compaction", 1);
}

// spec/permissions.md §9: disk loss and recovery from the card.
#[test]
fn disk_loss() {
    ok("disk_loss", 1);
}

// spec/sync.md §3, §5: a grant's inbox deposit survives a crash of the granting device.
#[test]
fn grant_lost_on_crash() {
    ok("grant_lost_on_crash", 1);
}

// spec/sync.md §6; spec/commits.md §4: sweep seed 23, entries whose bytes were never fetched
// freeze the writer's must-hold set; the other device waits for deltas for good.
#[test]
#[ignore = "issues/sync-unopenable-entry-stall.md"]
fn two_devices_server_seed_23() {
    ok("two_devices_server", 23);
}

// spec/sync.md §6: sweep seed 41, a must-hold body never re-uploaded after the wipe and crashes.
#[test]
#[ignore = "issues/sync-lost-upload-after-crash.md"]
fn server_loses_data_seed_41() {
    ok("server_loses_data", 41);
}
