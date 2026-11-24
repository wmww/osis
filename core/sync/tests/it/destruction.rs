//! Destruction and mintings end to end (spec/commits.md §5 Destruction, A thing's mintings travel
//! with its record; spec/requirements.md Deletion: purging or expiring a thing's creation destroys
//! it at every node): node 0 makes thing t with its sync ID S, node 1's account syncs it (kept
//! unread), node 2's writes it; node 0 destroys it. The engine's judgement of a destroyed thing is
//! the engine's and held-model's; these check what crosses nodes: the destruction reaches every
//! node, holds over a restart, a write after it counts nowhere, a node away past the purge's
//! floor learns it, and the copies of a thing's mintings under a sync ID lacking it converge.

use crate::harness::World;
use crate::harness::history::{self, Gives, value_ak};
use osis_base::format::ROLE_KEEP_MS;
use osis_base::{CommitId, SyncId, Tid, Value};
use osis_commit::PurgeItem;
use osis_engine::Mutation;
use osis_schema::core_types as ct;

/// Node 0 makes thing 0 (a value, held from its D) and gives it a sync ID of its own, granting
/// node 1's account sync and node 2's write; both hold it (after the first run) and sync.
fn three() -> (World, Tid, SyncId) {
    let (mut w, t, s) = history::three(Gives::Writes, 2);
    w.cap = 20_000;
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
// holding the right is destroyed; in the same transaction the node drops its states and every
// part on it), spec/sync-judgement.md §2:
// node 0's purge of t's creation reaches node 2, which reads t absent, also after a restart.
#[test]
#[ignore = "accounts: making an account"]
fn a_purged_creation_destroys_the_thing_at_every_node_spec_commits_5() {
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
#[ignore = "accounts: making an account"]
fn a_write_after_the_destruction_counts_nowhere_spec_commits_5() {
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

// spec/commits.md §5 (Destruction: what stays is held by the ordinary rules alone; a request
// destroying it is a commit carrying a purge request, kept and logged as any), spec/sync-judgement.md §5: past the purge's
// floor (`ROLE_KEEP`; the purge has no expiry) node 1, which keeps S unread and still holds t,
// keeps the request under S, and node 2, away for all of it, learns the destruction from S once
// back.
#[test]
#[ignore = "accounts: making an account"]
fn a_node_away_past_the_floor_learns_the_destruction_spec_commits_5() {
    let (mut w, t, s) = three();
    w.power_off(2);
    let q = purge_thing(&mut w, 0, t);
    w.run();
    w.jump(ROLE_KEEP_MS + 60_000);
    let request = w.engine(0).commit_blobs(&q).unwrap();
    assert!(w.store(1).entries(&s).unwrap().iter().any(|e| request.contains(&e.blob)), "node 1 keeps the request past the floor");
    assert!(w.engine(1).closure_holds(&t), "node 1 keeps t");
    w.power_on(2);
    w.run();
    gone(&mut w, 2, t);
}
