//! Destruction and mintings end to end (spec/commits.md §5 Destruction, A thing's mintings travel
//! with its record; spec/requirements.md Deletion: purging or expiring a thing's creation destroys
//! it at every node): node 0 makes thing t with a home sync ID S, node 1's account syncs it (kept
//! unread), node 2's writes it; node 0 destroys it. The engine's judgement of a destroyed thing is
//! the engine's and held-model's; these check what crosses nodes: the destruction reaches every
//! node, holds over a restart, a write after it counts nowhere, S empties once nothing needs it,
//! and the copies of a thing's mintings under a sync ID lacking it converge.

use crate::harness::Step::*;
use crate::harness::history::{Gives, value_ak, world};
use crate::harness::{World, play};
use osis_base::format::ROLE_KEEP_MS;
use osis_base::{CommitId, SyncId, Tid, Value};
use osis_commit::PurgeItem;
use osis_engine::Mutation;
use osis_schema::core_types as ct;

/// Node 0 makes thing 0 (a value, held from its D) and gives it a sync ID of its own, granting
/// node 1's account sync and node 2's write; both accept (after the first run) and sync.
fn three() -> (World, Tid, SyncId) {
    let mut w = world(0, 3);
    w.cap = 20_000;
    let _ = play(&mut w, &[New(0), Grant(0, 0, 1, Gives::Syncs), Grant(0, 0, 2, Gives::Writes), Run, Run], String::new());
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

// spec/commits.md §5 (Destruction: once no request is in force and nothing needs it, it keeps
// nothing, and every entry under its own sync IDs is must-not-hold), spec/sync-judgement.md §5
// (Emptying: but the destroying requests, which leave at their expiry): past a purge's window
// (`ROLE_KEEP`), S keeps only the request's entries at node 0's, node 2's and node 1's stores
// (node 1 keeps S unread; record blobs gone too, spec/sync-judgement.md §2). The purge has no
// expiry: S stays with it, so a node away for the window learns of the destruction.
#[test]
fn a_destroyed_things_sync_id_empties_but_its_request_past_its_window_spec_sync_judgement_5() {
    let (mut w, t, s) = three();
    let q = purge_thing(&mut w, 0, t);
    w.run();
    w.advance(ROLE_KEEP_MS + 60_000);
    w.run();
    let request = w.engine(0).commit_blobs(&q).unwrap();
    for i in 0..3 {
        let left: Vec<_> = w.store(i).entries(&s).unwrap().into_iter().filter(|e| !request.contains(&e.blob)).collect();
        assert!(left.is_empty(), "node {i} holds {} entries under S but the request's", left.len());
    }
    assert!(w.store(1).entries(&s).unwrap().iter().any(|e| request.contains(&e.blob)), "node 1 lost the request");
    assert!(w.engine(0).destruction(&t).is_some_and(|d| d.requests == vec![q]), "the purge is a destroying request");
}

// spec/sync-judgement.md §6 Closes, spec/sync-set.md §2-§3: a closing step registered at node 1,
// which keeps S unread, takes t out of node 1's node closure while node 1 holds the ticket naming
// S, read from the path its store keeps; a restart judges it so again.
#[test]
#[ignore = "issues/kept-unread-by-ticket.md: a kept-unread thing is held on the ticket's word"]
fn a_closing_head_takes_a_kept_thing_out_spec_sync_judgement_6() {
    let (mut w, t, s) = three();
    assert!(w.engine(1).closure_holds(&t), "node 1 keeps t");
    let head = w.store(1).head(&s).unwrap().unwrap();
    let delete = w.engine(0).head_keys(&t, &head).unwrap().delete.expect("node 0 holds the delete key");
    let mut st = w.store(1).clone();
    assert_eq!(st.take_register(&s, &head.closing(&delete), None).unwrap(), osis_proto::Code::OK);
    w.run();
    assert!(!w.engine(1).closure_holds(&t), "closed: t left");
    let _ = play(&mut w, &[PowerOff(1), PowerOn(1), Run], String::new());
    assert!(!w.engine(1).closure_holds(&t), "closed: t stays out after a restart");
}
