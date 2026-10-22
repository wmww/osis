#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
//! Phase C: the scenario library, adversaries and version skew (sim/src/net/{library, adversary,
//! skew}.rs), one seed each. Every run ends with the quiescent invariants. Scenarios an engine bug
//! breaks are ignored with the issue's name; all but the quickest few
//! (osis-sim's whole tier 1 stays near 10 s) are tier 2 (`--release -- --ignored`) and swept nightly by `sim-sweep`.

use osis_sim::{Report, replay};

fn ok(name: &str, seed: u64) -> Report {
    let r = replay(name, seed).unwrap_or_else(|f| panic!("{f}"));
    eprintln!("{name} {seed}: {r:?}");
    r
}

// spec/permissions.md §5.1, §5.2: Bob's edits offline around his removal are invalid; re-grant
// restores them.
#[test]
#[ignore = "tier 2"]
fn revocation_bob() {
    ok("revocation_bob", 1);
}

// spec/permissions.md §5.1, §5.2: the Carol variant (Carol synced with Bob directly).
#[test]
#[ignore = "tier 2"]
fn revocation_carol() {
    ok("revocation_carol", 1);
}

// spec/sync.md §6 (clock offset), spec/crdt.md §2.2: sweep seed 12, pings straddling a one-day
// gap set a 12 h offset; once corrected, the node's own commits are refused as drift.
#[test]
#[ignore = "tier 2"]
fn revocation_carol_seed_12() {
    ok("revocation_carol", 12);
}

// spec/permissions.md §5.1, §5.3: a stolen device's backdated edit falls to a backdated revoke.
#[test]
fn stolen_device() {
    ok("stolen_device", 1);
}

// spec/permissions.md §5.3: demotion after the pre-sync keeps the member's edits.
#[test]
fn demotion_synced() {
    ok("demotion_synced", 1);
}

// spec/permissions.md §5.3: demotion without the pre-sync loses the unseen edit.
#[test]
#[ignore = "tier 2"]
fn demotion_unsynced() {
    ok("demotion_unsynced", 1);
}

// spec/sync.md §6, spec/commits.md §4: sweep seed 72, two writers' pending commits stop each
// other's uploads.
#[test]
#[ignore = "tier 2"]
fn move_import_seed_72() {
    ok("move_import", 72);
}

// spec/permissions.md §9: two concurrent redemptions of a multi-use link; then revoked.
#[test]
#[ignore = "tier 2"]
fn link_redeem() {
    ok("link_redeem", 1);
}

// spec/permissions.md §9, §5.1: two concurrent redemptions of a single-use link: one joiner.
#[test]
#[ignore = "tier 2"]
fn link_race() {
    ok("link_race", 1);
}

// spec/permissions.md §3, §9: sweep seed 6, the race's winner misses the loser's rotation of K;
// the sharer's next rotation reaches it by inbox.
#[test]
#[ignore = "tier 2"]
fn link_race_seed_6() {
    ok("link_race", 6);
}

// spec/permissions.md §9, spec/sync.md §7: sweep seed 91, two nodes' certificate copies of one commit churned (one deleted as a strict subset, re-placed each pass).
#[test]
#[ignore = "tier 2"]
fn link_race_seed_91() {
    ok("link_race", 91);
}

// spec/permissions.md §9, spec/sync.md §7: sweep seed 119, two nodes' certificate copies of one commit churned (one deleted as a strict subset, re-placed each pass).
#[test]
#[ignore = "tier 2"]
fn link_race_seed_119() {
    ok("link_race", 119);
}

// spec/permissions.md §9, spec/sync.md §7: sweep seed 164, two nodes' certificate copies of one commit churned (one deleted as a strict subset, re-placed each pass).
#[test]
#[ignore = "tier 2"]
fn link_race_seed_164() {
    ok("link_race", 164);
}

// spec/permissions.md §9, spec/sync.md §7: sweep seed 191, two nodes' certificate copies of one commit churned (one deleted as a strict subset, re-placed each pass).
#[test]
#[ignore = "tier 2"]
fn link_race_seed_191() {
    ok("link_race", 191);
}

// spec/sync.md §3, §7, spec/permissions.md §4: sweep seed 41, the losing redeemer's partial certificate copy promoted alone left the winner pending.
#[test]
#[ignore = "tier 2"]
fn link_race_seed_41() {
    ok("link_race", 41);
}

// spec/sync.md §3, §7, spec/permissions.md §4: sweep seed 107, the losing redeemer's partial certificate copy promoted alone left the winner pending.
#[test]
#[ignore = "tier 2"]
fn link_race_seed_107() {
    ok("link_race", 107);
}

// spec/sync.md §3, §7, spec/permissions.md §4: sweep seed 120, the losing redeemer's partial certificate copy promoted alone left the winner pending.
#[test]
#[ignore = "tier 2"]
fn link_race_seed_120() {
    ok("link_race", 120);
}

// spec/sync.md §3, §7, spec/permissions.md §4: sweep seed 144, the losing redeemer's partial certificate copy promoted alone left the winner pending.
#[test]
#[ignore = "tier 2"]
fn link_race_seed_144() {
    ok("link_race", 144);
}

// spec/sync.md §3, §7, spec/permissions.md §4: sweep seed 197, the losing redeemer's partial certificate copy promoted alone left the winner pending.
#[test]
#[ignore = "tier 2"]
fn link_race_seed_197() {
    ok("link_race", 197);
}

// spec/sync.md §5, §6, spec/permissions.md §4: sweep seed 46, after the chain-completion fix.
#[test]
#[ignore = "tier 2"]
fn link_race_seed_46() {
    ok("link_race", 46);
}

// spec/sync.md §5, spec/permissions.md §4: sweep seed 50 after the chat-cost fix, the loser's promoted `/keys` copy left pending (same cause as seed 41).
#[test]
#[ignore = "tier 2"]
fn link_race_seed_50() {
    ok("link_race", 50);
}

// spec/sync.md §5, spec/permissions.md §3: sweep seed 1792, a redemption reached the sharer without its `/secrets` part (WaitDeltas); passes on main since the sweep (issues/link-race-edge-only-pending.md).
#[test]
#[ignore = "tier 2"]
fn link_race_seed_1792() {
    ok("link_race", 1792);
}

// spec/sync.md §5, spec/permissions.md §3: sweep seed 2255, a redemption reached the sharer without its `/secrets` part (WaitDeltas); passes on main since the sweep (issues/link-race-edge-only-pending.md).
#[test]
#[ignore = "tier 2"]
fn link_race_seed_2255() {
    ok("link_race", 2255);
}

// spec/sync.md §5, spec/permissions.md §3: sweep seed 2898, the losing redeemer forgot K before its deposit of the redemption reached the server; its partial copy under the target left the sharer pending (WaitDeltas).
#[test]
#[ignore = "tier 2"]
fn link_race_seed_2898() {
    ok("link_race", 2898);
}

// spec/sync.md §5, spec/permissions.md §3: sweep seed 3926, a redemption reached the sharer without its `/secrets` part (WaitDeltas); passes on main since the sweep (issues/link-race-edge-only-pending.md).
#[test]
#[ignore = "tier 2"]
fn link_race_seed_3926() {
    ok("link_race", 3926);
}

// spec/permissions.md §7: move with import and re-grant.
#[test]
#[ignore = "tier 2"]
fn move_import() {
    ok("move_import", 1);
}

// spec/permissions.md §3; notes/chat.md: chat join with personas, removal rotates.
#[test]
#[ignore = "tier 2"]
fn chat_join_leave() {
    ok("chat_join_leave", 1);
}

// spec/sync.md §3 (entitlement); spec/permissions.md §1: folder actor with a separately shared
// subfolder.
#[test]
#[ignore = "tier 2"]
fn folders() {
    ok("folders", 1);
}

// spec/sync.md §2: label replacement.
#[test]
#[ignore = "tier 2"]
fn label_replacement() {
    ok("label_replacement", 1);
}

// spec/sync.md §2: label replacement with a member offline; old label cleaned up.
#[test]
#[ignore = "tier 2"]
fn label_replacement_offline() {
    ok("label_replacement_offline", 1);
}

// spec/sync.md §8: bundles carried by hand.
#[test]
#[ignore = "tier 2"]
fn bundles() {
    ok("bundles", 1);
}

// spec/commits.md §5 (expiry): disappearing messages under faults.
#[test]
#[ignore = "tier 2"]
fn disappearing() {
    ok("disappearing", 1);
}

// spec/commits.md §5 (expiry): sweep seed 104, the node is never ticked again, an expired note
// stays readable.
#[test]
fn disappearing_seed_104() {
    ok("disappearing", 104);
}

// spec/commits.md §5 (keep at most): replaced bodies dropped everywhere.
#[test]
fn keep_at_most() {
    ok("keep_at_most", 1);
}

// spec/commits.md §5: sweep seed 6, a dropped body's blob kept at the node.
#[test]
#[ignore = "tier 2"]
fn keep_at_most_seed_6() {
    ok("keep_at_most", 6);
}

// spec/commits.md §5, spec/sync.md §5: sweep seed 42, a timed delete lost on a cut connection.
#[test]
#[ignore = "tier 2"]
fn keep_at_most_seed_42() {
    ok("keep_at_most", 42);
}

// spec/commits.md §5: sweep seed 62, the node is never ticked again, nothing is dropped.
#[test]
#[ignore = "tier 2"]
fn keep_at_most_seed_62() {
    ok("keep_at_most", 62);
}

// spec/crdt.md §4.8, spec/commits.md §5: sweep seed 445, deaths by arrival order: two keep-at-most
// bounds, one node re-uploaded what the other deleted (a storm).
#[test]
#[ignore = "tier 2"]
fn keep_at_most_seed_445() {
    ok("keep_at_most", 445);
}

// spec/crdt.md §4.7, §9: sweep seed 28, an expiring diff lost a heartbeat field; the pass aborted.
#[test]
#[ignore = "tier 2"]
fn revocation_bob_seed_28() {
    ok("revocation_bob", 28);
}

// spec/sync.md §6: a dishonest server; honest nodes converge through the honest one.
#[test]
#[ignore = "tier 2"]
fn evil_server() {
    ok("evil_server", 1);
}

// spec/sync.md §6: sweep seed 134, the sim spun on a message sent after its stream's cut.
#[test]
#[ignore = "tier 2"]
fn evil_server_seed_134() {
    ok("evil_server", 134);
}

// spec/sync.md §6: a dishonest server that also drops replies on open streams.
#[test]
#[ignore = "tier 2"]
fn evil_server_drops() {
    ok("evil_server_drops", 1);
}

// spec/sync.md §2, §5; spec/permissions.md §5: a removed member's replays and deposits.
#[test]
#[ignore = "tier 2"]
fn removed_replayer() {
    ok("removed_replayer", 1);
}

// spec/sync.md §5; spec/commits.md §4; spec/versioning.md §2: malformed blobs are rejected.
#[test]
#[ignore = "tier 2"]
fn malformed_blobs() {
    ok("malformed_blobs", 1);
}

// spec/sync.md §5 (deposit budget): a flooding depositor is bounded.
#[test]
#[ignore = "tier 2"]
fn deposit_flood() {
    ok("deposit_flood", 1);
}

// spec/commits.md §4: an equivocating writer's two counter-reusing commits are both invalid.
#[test]
#[ignore = "tier 2"]
fn equivocating_writer() {
    ok("equivocating_writer", 1);
}

// spec/sync.md §5, §7: a server re-announcing purged entries brings nothing back.
#[test]
#[ignore = "tier 2"]
fn tombstone_liar() {
    ok("tombstone_liar", 1);
}

// spec/versioning.md §1, §2: a newer format version is parked, relayed, never destroyed.
#[test]
#[ignore = "tier 2"]
fn future_format() {
    ok("future_format", 1);
}

// spec/versioning.md §4, §5: a newer schema revision survives an old writer.
#[test]
#[ignore = "tier 2"]
fn newer_schema() {
    ok("newer_schema", 1);
}

// spec/sync.md §5, §6: writers online together upload each body once and promote each deposit
// once.
#[test]
#[ignore = "tier 2"]
fn concurrent_writers() {
    ok("concurrent_writers", 1);
}

// spec/sync.md §6: sweep seeds 804 and 1002, the evil server had nothing to misbehave on in 200 steps (the scenario runs on until it has).
#[test]
#[ignore = "tier 2"]
fn evil_server_seed_804() {
    ok("evil_server", 804);
}

// spec/sync.md §5: sweep seeds 1962, 3237 and 4084, all four writers' promotion points fell in one 1 s sim step for one blob (tolerated once per run).
#[test]
#[ignore = "tier 2"]
fn concurrent_writers_seed_1962() {
    ok("concurrent_writers", 1962);
}
