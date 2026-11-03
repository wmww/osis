#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
//! Phase B scenarios (sync engines and hosts engine to engine), seed 1 each: the quickest in tier
//! 1 (osis-sim's whole tier 1 stays near 10 s), the rest tier 2 (`-- --ignored`).
//! Every run ends with the quiescent invariants (core/test/sim/src/net/check.rs: convergence by held
//! deltas, holder liveness and agreement, label required sets at hosts, must-not-hold absent,
//! deposit promotion, tombstones, purges, no ping-pong). A failure prints its seed and the
//! `osis_sim::replay` call that reproduces it. Scenarios an engine bug breaks are ignored with
//! the issue's name.
//! A `_seed_N` test names what that seed once hit: a seed keeps a run only while the sim's dice and
//! the code it runs stay, so most are plain runs by now, and the fix's own test is what pins it.

use osis_sim::{Report, replay};

fn ok(name: &str, seed: u64) -> Report {
    let r = replay(name, seed).unwrap_or_else(|f| panic!("{f}"));
    eprintln!("{name} {seed}: {r:?}");
    r
}

// spec/sync.md §2, §6; spec/commits.md §4: two devices of one person through one host
// under cut, delayed, reordered and duplicated messages and crashes mid-write.
#[test]
fn two_devices_host() {
    let r = ok("two_devices_host", 1);
    assert!(r.writes > 5 && r.crashes > 0 && r.dropped > 0 && r.held_checked > 0, "{r:?}");
}

// spec/sync.md §5 (replication, push only), §6; spec/sync.md §3 (grants by inbox): three
// persons share a group through two replicating hosts with host crashes and partitions.
#[test]
#[ignore = "tier 2"]
fn three_persons_two_hosts() {
    let r = ok("three_persons_two_hosts", 1);
    assert!(r.writes > 10 && r.held_checked > 0 && r.partitions > 0, "{r:?}");
}

// spec/sync.md §5 (deletion by delete key); spec/commits.md §5 (purge): a removed writer's body
// purged by a remaining writer without the delete key.
#[test]
#[ignore = "tier 2"]
fn removed_writer() {
    ok("removed_writer", 1);
}

// spec/sync.md §5, §6: a reader relays stamped entries to a host the writer cannot reach;
// the readers' opens race the admin's registrations.
#[test]
#[ignore = "tier 2"]
fn reader_relays() {
    ok("reader_relays", 1);
}

// spec/permissions.md §3, §4: a device stranded past ROLE_KEEP is re-sealed by pairing.
#[test]
#[ignore = "tier 2"]
fn stranded_reseal() {
    ok("stranded_reseal", 1);
}

// spec/sync.md §5 (one step per rotation), spec/permissions.md §3, §4: sweep seed 0, an admin's
// `label.0` record of the first step held back the second rotation's step (the settle rule), so
// both rotations shared one step and the stale device claimed through.
#[test]
#[ignore = "tier 2"]
fn stranded_reseal_seed_0() {
    ok("stranded_reseal", 0);
}

// spec/sync.md §6: a host that lost its data gets every must-hold body back from writers.
#[test]
fn host_loses_data() {
    ok("host_loses_data", 1);
}

// spec/sync.md §5 (open by stale sync key, walk); spec/permissions.md §3: a reader offline
// across two rotations walks the steps; removed holders hold no later epoch.
#[test]
#[ignore = "tier 2"]
fn offline_rotation() {
    ok("offline_rotation", 1);
}

// spec: none (replay): the same (scenario, seed) gives the same run, digest included.
#[test]
fn replay_is_exact() {
    assert_eq!(ok("two_devices_host", 2), ok("two_devices_host", 2));
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

// spec/crdt.md §2.1: a device restored from a backup writes before its pass; no commit is void.
#[test]
fn restore_backup() {
    ok("restore_backup", 1);
}

// spec/permissions.md §4 (chain certificates, placed whenever they change): sweep seed 3, the
// lost device's copy of the card key's `created.0` never reached the host and the remaining
// device's placed copy lacked it, so the recovering device could not verify the person.
#[test]
fn disk_loss_seed_3() {
    ok("disk_loss", 3);
}

// spec/sync.md §6, §8: sweep seed 11, a push during a replay moved the cursor past entries the
// replay had not delivered; a crash then lost them for good.
#[test]
fn two_devices_host_seed_11() {
    ok("two_devices_host", 11);
}

// spec/sync.md §3, §5: a grant's inbox deposit survives a crash of the granting device.
#[test]
fn grant_lost_on_crash() {
    ok("grant_lost_on_crash", 1);
}

// spec/sync.md §6; spec/commits.md §4: sweep seed 23, entries whose bytes were never fetched
// freeze the writer's must-hold set; the other device waits for deltas for good.
#[test]
fn two_devices_host_seed_23() {
    ok("two_devices_host", 23);
}

// spec/sync.md §6: sweep seed 41, a must-hold body never re-uploaded after the wipe and crashes.
#[test]
#[ignore = "tier 2"]
fn host_loses_data_seed_41() {
    ok("host_loses_data", 41);
}

// spec/requirements.md (Scale: a change inside a huge value costs O(change)); spec/sync.md §1
// (chunk reuse): two devices edit an 8 MiB blob in turn through a host; each edit uploads
// within 1.2x of the chunks it changed.
#[test]
#[ignore = "tier 2"]
fn large_edits() {
    ok("large_edits", 1);
}

// spec/sync.md §6, §7: a relayer whose upload of another node's commit was lost later re-uploaded
// its own encryption although the author's was present, so the tiebreak deleted the author's after
// quiescence (fixed: an entry present at the host is the body's entry).
#[test]
#[ignore = "tier 2"]
fn stranded_reseal_seed_23() {
    ok("stranded_reseal", 23);
}

// spec/permissions.md §5.2, spec/commits.md §5: sweep seed 15110 (and 15061 before
// ac49b521), a revoked holder's removal un-merged at a node that had applied it valid lost the
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

// spec/commits.md §5, spec/sync.md §6, §7, spec/permissions.md §8: each purge set under a mix of
// compacters, a device coming fresh: kept bodies stay available, reads alike, the labels go quiet.
#[test]
fn snapshot_rights() {
    // 26..: a fresh device's snapshot listing a session short of a body it covered by the join
    for seed in [1, 2, 26, 27, 36, 55, 85, 91, 9021] {
        ok("snapshot_rights", seed);
    }
}

// notes/ephemeral.md, spec/sync.md §9: ephemeral (expiring ones included) and signal writes on a
// window and a durable item under faults; holders converge, a refreshed cursor stays up while its
// author is there and goes by its expiry after, signals once.
#[test]
fn ephemeral() {
    let r = ok("ephemeral", 1);
    assert!(r.writes > 20 && r.crashes > 0, "{r:?}");
}

// spec/sync.md §9 (holders upload what a host lacks): a plain entry the capped host refused
// went up again, at the periodic pass, once others made room (it stayed out for good: divergence at
// quiescence). Seeds of the fixed-cap runs; the cap is random now.
#[test]
fn ephemeral_capped_seed_14() {
    ok("ephemeral_capped", 14);
}

// spec/sync.md §9: a run where compaction of others' commits left one stuck at the full host.
#[test]
fn ephemeral_seed_83() {
    ok("ephemeral", 83);
}

// spec/sync.md §9: a run where the full host held `created.0`-only commits nothing covered.
#[test]
fn ephemeral_capped_seed_2400045() {
    ok("ephemeral_capped", 2400045);
}

// spec/sync.md §9: periodic run 8, node 3 held a commit of node 0 with its e:notes.0 part missing.
#[test]
fn ephemeral_seed_21054() {
    ok("ephemeral", 21054);
}

// spec/sync.md §3, spec/permissions.md §3: a grant to a group reaches its readers with its admin down at the grant, and a later reader; a removal from the group ends the thing's later epochs for the removed reader.
#[test]
#[ignore = "tier 2"]
fn grant_to_group() {
    ok("grant_to_group", 1);
}

// spec/commits.md §4, spec/sync.md §6: what a device does with what phase A's oracle relayed in
// parts: a reader of two labels, one host out of reach, holds the commit back whole (atomic
// apply, things it syncs), across a restart, and applies it whole once that host is back.
#[test]
fn commit_across_labels_waits_whole_across_restart_spec_commits_4() {
    use osis_base::{Role, Value};
    use osis_node::{Mutation, Reason};
    use osis_sim::dice::Dice;
    use osis_sim::net::Party;
    use osis_sim::net::scenarios::{clock, persons, shared_group, sim};
    use osis_sim::workload::REG;

    let mut d = Dice::new(1);
    let mut s = sim("across_labels", 1, Default::default());
    let (s0, s1) = (s.add_host().unwrap(), s.add_host().unwrap());
    let a = s.add_node(&[s0, s1], clock(&mut d)).unwrap();
    let r = s.add_node(&[s0, s1], clock(&mut d)).unwrap();
    // a third reader on one group only: different readers, so a body per label
    let b = s.add_node(&[s0, s1], clock(&mut d)).unwrap();
    let [pa, pr, pb] = persons(&mut s, [a, r, b], [s0, s0, s0]).unwrap();
    let g0 = shared_group(&mut s, a, pa, &[s0], &[(pr, Role::Read)]).unwrap();
    let g1 = shared_group(&mut s, a, pa, &[s1], &[(pr, Role::Read), (pb, Role::Read)]).unwrap();
    let (i0, i1) = (s.item(a, g0).unwrap(), s.item(a, g1).unwrap());
    s.quiet(40).unwrap();
    let before = s.engine(r).unwrap().get_typed(&i0, &REG).unwrap();

    s.partition(Party::N(r), Party::S(s1));
    let word = Value::Str("both".into());
    let mut m = Mutation::new();
    m.set(i0, &REG, &word).unwrap();
    m.set(i1, &REG, &word).unwrap();
    let id = s.commit(a, m).unwrap().unwrap();
    for restart in [false, true] {
        if restart {
            s.restart_node(r).unwrap();
        }
        s.advance(61_000).unwrap();
        s.settle().unwrap();
        let e = s.engine(r).unwrap();
        assert!(e.pending().contains(&(id, Reason::WaitDeltas)), "restart {restart}: waits for the other label");
        assert_eq!(e.get_typed(&i0, &REG).unwrap(), before, "restart {restart}: nothing of it read");
    }

    s.heal(Party::N(r), Party::S(s1));
    s.run_until_quiescent(60).unwrap();
    let e = s.engine(r).unwrap();
    assert_eq!(e.commit_parts_missing().get(&id).map(|g| g.len()), Some(0), "whole");
    assert_eq!(e.get_typed(&i0, &REG).unwrap(), Some(word.clone()));
    assert_eq!(e.get_typed(&i1, &REG).unwrap(), Some(word.clone()));
    s.finish().unwrap();
}
