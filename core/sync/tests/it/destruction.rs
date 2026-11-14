//! Destruction end to end (spec/commits.md §5 Destruction; spec/requirements.md Deletion: purging
//! or expiring a thing's creation destroys it at every node): node 0 makes thing t with a home
//! sync ID S, node 1's account syncs it (kept unread), node 2's writes it; node 0 destroys it.
//! The engine's judgement of a destroyed thing is the engine's and held-model's; these check what
//! crosses nodes: the destruction reaches every node, holds over a restart, a write after it
//! counts nowhere, and S empties once nothing needs it.

use crate::harness::Step::*;
use crate::harness::history::{Gives, value_ak, world};
use crate::harness::{World, play};
use osis_base::format::ROLE_KEEP_MS;
use osis_base::{CommitId, SyncId, Tid, Value};
use osis_commit::PurgeItem;
use osis_engine::Mutation;
use osis_schema::core_types as ct;

/// Node 0 makes thing 0 (a value, filed in its D) and gives it a sync ID of its own, granting
/// node 1's account sync and node 2's write.
fn three() -> (World, Tid, SyncId) {
    let mut w = world(0, 3);
    w.cap = 20_000;
    let _ = play(&mut w, &[New(0), Grant(0, 0, 1, Gives::Syncs), Grant(0, 0, 2, Gives::Writes), Run], String::new());
    let t = w.history.things[0].0;
    let s = w.engine(0).home_sync_id(&t).unwrap().unwrap();
    assert!(w.engine(2).knows(&t) && w.engine(2).get(&t, &value_ak()).unwrap().is_some(), "node 2 reads t");
    assert!(!w.store(1).entries(&s).unwrap().is_empty(), "node 1 keeps S");
    (w, t, s)
}

/// A purge of t's creation by node `by` (an item on `created.0` names every minting).
fn purge_thing(w: &mut World, by: usize, t: Tid) -> CommitId {
    w.write(by, |e| {
        let mut m = Mutation::new();
        let now = e.now();
        m.set(t, &ct::PURGE, &now).unwrap();
        m.purge(PurgeItem::Aspect { tid: t, ak: ct::CREATED.name() });
        e.commit(m).unwrap().unwrap()
    })
}

/// Nothing of t reads as existing at node `i`, and a write to it is refused as unknown.
#[track_caller]
fn gone(w: &mut World, i: usize, t: Tid) {
    let e = w.engine(i);
    assert!(!e.knows(&t), "node {i}: t known");
    assert!(!e.has_content(&t).unwrap(), "node {i}: content");
    assert!(e.roster(&t).is_empty(), "node {i}: roster");
    assert_eq!(e.get(&t, &value_ak()).unwrap(), None, "node {i}: its value");
    let mut m = Mutation::new();
    m.set(t, &value_ak(), &Value::Str("late".into())).unwrap();
    assert!(matches!(e.commit(m), Err(osis_engine::Error::UnknownThing(_))), "node {i}: a write refused as unknown");
}

// spec/commits.md §5 (Destruction: a thing whose every held minting is purged by a request
// holding the right is destroyed; in the same transaction the node drops every part on it), spec/sync-judgement.md §2:
// node 0's purge of t's creation reaches node 2, which reads t absent, also after a restart.
#[test]
#[ignore = "issues/destroying-request-not-under-own-sync-id.md"]
fn repro_a_purged_creation_destroys_the_thing_at_every_node_spec_commits_5() {
    let (mut w, t, _) = three();
    purge_thing(&mut w, 0, t);
    w.run();
    for i in [0, 2] {
        gone(&mut w, i, t);
    }
    w.power_off(2);
    w.power_on(2);
    w.run();
    gone(&mut w, 2, t);
}

// spec/commits.md §5 (Destruction: nobody writes a thing after its destruction: a part stamped
// after it is a part on an unknown thing): node 2, cut off, writes t after node 0 destroyed it;
// back, its write is applied nowhere and t stays destroyed everywhere.
#[test]
#[ignore = "issues/destroying-request-not-under-own-sync-id.md"]
fn repro_a_write_after_the_destruction_counts_nowhere_spec_commits_5() {
    let (mut w, t, _) = three();
    w.partition(0, 2);
    w.partition(1, 2);
    purge_thing(&mut w, 0, t);
    w.run();
    w.advance(10);
    let late = w.write(2, |e| {
        let mut m = Mutation::new();
        m.set(t, &value_ak(), &Value::Str("late".into())).unwrap();
        e.commit(m).unwrap().unwrap()
    });
    w.heal();
    w.run();
    for i in [0, 2] {
        gone(&mut w, i, t);
    }
    assert!(!w.engine(0).commit_ids().contains(&late), "node 0 applied a write after the destruction");
}

// spec/commits.md §5 (Destruction: a release request destroys things as storage reclaim; a
// destroyed thing reads as absent to every read and write), spec/permissions.md §6: node 0's
// release of t reaches node 2, which reads it absent.
#[test]
#[ignore = "issues/destroying-request-not-under-own-sync-id.md"]
fn repro_a_released_thing_reads_absent_at_every_node_spec_commits_5() {
    let (mut w, t, _) = three();
    w.write(0, |e| e.release(&[t])).unwrap().expect("a release request");
    w.run();
    for i in [0, 2] {
        gone(&mut w, i, t);
    }
}

// spec/commits.md §5 (Destruction: once no request is in force and nothing needs it, it keeps
// nothing, and every entry under its own sync IDs is must-not-hold), spec/sync-ids.md §6: past the
// request's window (`ROLE_KEEP`), S's entries leave node 0's and node 2's stores and node 1's,
// which keeps S unread.
#[test]
#[ignore = "issues/destroying-request-not-under-own-sync-id.md"]
fn repro_a_destroyed_things_sync_id_empties_past_its_window_spec_commits_5() {
    let (mut w, t, s) = three();
    purge_thing(&mut w, 0, t);
    w.run();
    w.advance(ROLE_KEEP_MS + 60_000);
    w.run();
    for i in 0..3 {
        let left = w.store(i).entries(&s).unwrap();
        assert!(left.is_empty(), "node {i} holds {} entries under S", left.len());
    }
}
