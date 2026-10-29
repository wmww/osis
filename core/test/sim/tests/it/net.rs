#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
//! Phase B scenarios (sync engines and blind servers engine to engine), seed 1 each: the quickest in tier
//! 1 (osis-sim's whole tier 1 stays near 10 s), the rest tier 2 (`-- --ignored`).
//! Every run ends with the quiescent invariants (core/test/sim/src/net/check.rs: convergence by held
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
    assert!(r.writes > 5 && r.crashes > 0 && r.dropped > 0 && r.held_checked > 0, "{r:?}");
}

// spec/sync.md §5 (replication, push only), §6; spec/sync.md §3 (grants by inbox): three
// persons share a group through two replicating servers with server crashes and partitions.
#[test]
#[ignore = "tier 2"]
fn three_persons_two_servers() {
    let r = ok("three_persons_two_servers", 1);
    assert!(r.writes > 10 && r.held_checked > 0 && r.partitions > 0, "{r:?}");
}

// spec/sync.md §5 (deletion by delete key); spec/commits.md §5 (purge): a removed writer's body
// purged by a remaining writer without the delete key.
#[test]
#[ignore = "tier 2"]
fn removed_writer() {
    ok("removed_writer", 1);
}

// spec/sync.md §5, §6: a reader relays stamped entries to a server the writer cannot reach;
// the readers' opens race the admin's registrations.
#[test]
#[ignore = "tier 2"]
fn reader_relays() {
    ok("reader_relays", 1);
}

// spec/permissions.md §3, §4: a device stranded past MEMBERSHIP_KEEP is re-sealed by pairing.
#[test]
#[ignore = "tier 2"]
fn stranded_reseal() {
    ok("stranded_reseal", 1);
}

// spec/sync.md §5 (one step per rotation), spec/permissions.md §3, §4: sweep seed 0, an admin's
// `/label` record of the first step held back the second rotation's step (the settle rule), so
// both rotations shared one step and the stale device claimed through.
#[test]
#[ignore = "tier 2"]
fn stranded_reseal_seed_0() {
    ok("stranded_reseal", 0);
}

// spec/sync.md §6: a server that lost its data gets every must-hold body back from writers.
#[test]
fn server_loses_data() {
    ok("server_loses_data", 1);
}

// spec/sync.md §5 (open by stale sync key, walk); spec/permissions.md §3: a reader offline
// across two rotations walks the steps; removed members hold no later epoch.
#[test]
#[ignore = "tier 2"]
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
#[ignore = "tier 2"]
fn compaction() {
    ok("compaction", 1);
}

// spec/sync.md §6, §7: sweep seed 2887, two writers each dropped what the other's carrier snapshot covered, not what their own did, and deleted each other's bodies of one commit (message storm).
#[test]
#[ignore = "tier 2"]
fn compaction_seed_2887() {
    ok("compaction", 2887);
}

// spec/sync.md §6, §7: sweep seed 3914, the same churn as seed 2887 (not quiescent after 40 rounds).
#[test]
#[ignore = "tier 2"]
fn compaction_seed_3914() {
    ok("compaction", 3914);
}

// spec/permissions.md §9: disk loss and recovery from the card.
#[test]
#[ignore = "tier 2"]
fn disk_loss() {
    ok("disk_loss", 1);
}

// spec/permissions.md §4 (chain certificates, placed whenever they change): sweep seed 3, the
// lost device's copy of the card key's `/created` never reached the server and the remaining
// device's placed copy lacked it, so the recovering device could not verify the person.
#[test]
fn disk_loss_seed_3() {
    ok("disk_loss", 3);
}

// spec/sync.md §6, §8: sweep seed 11, a push during a replay moved the cursor past entries the
// replay had not delivered; a crash then lost them for good.
#[test]
fn two_devices_server_seed_11() {
    ok("two_devices_server", 11);
}

// spec/sync.md §3, §5: a grant's inbox deposit survives a crash of the granting device.
#[test]
fn grant_lost_on_crash() {
    ok("grant_lost_on_crash", 1);
}

// spec/sync.md §6; spec/commits.md §4: sweep seed 23, entries whose bytes were never fetched
// freeze the writer's must-hold set; the other device waits for deltas for good.
#[test]
fn two_devices_server_seed_23() {
    ok("two_devices_server", 23);
}

// spec/sync.md §6: sweep seed 41, a must-hold body never re-uploaded after the wipe and crashes.
#[test]
#[ignore = "tier 2"]
fn server_loses_data_seed_41() {
    ok("server_loses_data", 41);
}

// spec/requirements.md (Scale: a change inside a huge value costs O(change)); spec/sync.md §1
// (chunk reuse): two devices edit an 8 MiB blob in turn through a server; each edit uploads
// within 1.2x of the chunks it changed.
#[test]
#[ignore = "tier 2"]
fn large_edits() {
    ok("large_edits", 1);
}

// spec/sync.md §6, §7: a relayer whose upload of another node's commit was lost later re-uploaded
// its own encryption although the author's was present, so the tiebreak deleted the author's after
// quiescence (fixed: an entry present at the server is the body's entry).
#[test]
#[ignore = "tier 2"]
fn stranded_reseal_seed_23() {
    ok("stranded_reseal", 23);
}

// spec/permissions.md §5.2, spec/commits.md §5: sweep seed 15110 (and 15061 before
// ac49b521), a revoked member's removal un-merged at a node that had applied it valid lost the
// element whose delta its covering snapshot replaced; the tier-1 reduction is
// osis-node `validity::covered_drop_restored_after_remover_revoked_alike_spec_perm_5_2`.
#[test]
#[ignore = "tier 2"]
fn work_sets_seed_15110() {
    ok("work_sets", 15110);
}

// spec/permissions.md §5.2, spec/sync.md §6, §7: a snapshot dropped under a cover that turns
// invalid is missing again; its holder uploads it again and the dropping node fetches it
// (was issues/dropped-voucher-after-cover.md).
#[test]
fn coverer_revoked() {
    ok("coverer_revoked", 1);
}

// notes/ephemeral.md, spec/sync.md §9: ephemeral, presence and signal writes on a window and a
// durable item under faults; holders converge, presence follows its author, signals once.
#[test]
fn ephemeral() {
    let r = ok("ephemeral", 1);
    assert!(r.writes > 20 && r.crashes > 0, "{r:?}");
}

// spec/sync.md §9 (holders upload what a server lacks): a plain entry the capped server refused
// went up again once others' deletions made room (it stayed out for good: divergence at
// quiescence).
#[test]
fn ephemeral_capped_seed_14() {
    ok("ephemeral_capped", 14);
}

// spec/sync.md §9 (compaction on a cap refusal): a refused cover is compacted into a fresh cover
// at every refusal (message storm).
#[test]
#[ignore = "issues/eph-cover-livelock.md"]
fn repro_ephemeral_seed_83() {
    ok("ephemeral", 83);
}
