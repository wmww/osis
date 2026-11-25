//! Logged again once (spec/sync-judgement.md §4) at a node keeping S unread, across a restart of
//! the node logging: what it owes a source is judged from that source's saved rows, the deletes it
//! saw there included, so a restart is no change of ground. Node 0 (admin) makes thing 0 and
//! writes its value; node 1's account keeps it unread. The test removes node 1's entries of the
//! write itself (its store deleting them, as a deleter holding a cover node 0 lacks would).

use crate::harness::Step::*;
use crate::harness::history::{Gives, value_ak, world_of};
use crate::harness::lies::Lie;
use crate::harness::{World, edge, fixture_with, play};
use osis_base::{Ak, BlobId, CommitId, Role, SyncId, Tid, Value};
use osis_engine::Mutation;
use osis_engine::flows::Demotion;

/// Thing 0 kept unread at node 1, its value written by node 0 and held at node 1.
fn setup() -> (World, Tid, SyncId, CommitId) {
    let (mut w, (t, s, c)) = fixture_with("again setup", || {
        let mut w = world_of(0, 2, 2);
        let _ = play(&mut w, &[New(0), Grant(0, 0, 1, Gives::Syncs), Run], String::new());
        let t = w.history.things[0].0;
        let s = w.engine(0).sync_id_of(&t).unwrap().unwrap();
        let c = w.write(0, |e| {
            let mut m = Mutation::new();
            m.set(t, &value_ak(), &Value::Str("v".into())).unwrap();
            e.commit(m).unwrap().unwrap()
        });
        w.run();
        (w, (t, s, c))
    });
    assert!(!at_store(&mut w, &s, &c).is_empty(), "node 1 holds the write");
    (w, t, s, c)
}

/// Node 1's entries of `c` under S.
fn at_store(w: &mut World, s: &SyncId, c: &CommitId) -> Vec<BlobId> {
    let es = w.store(1).entries(s).unwrap();
    es.into_iter().filter(|e| w.engine(0).blob_commit(&e.blob) == Some(*c)).map(|e| e.blob).collect()
}

/// Node 1's store deletes its entries of `c` (its stream shows them deleted).
fn store_deletes(w: &mut World, s: &SyncId, c: &CommitId) {
    let mut st = w.node(1).store.clone();
    for b in at_store(w, s, c) {
        assert!(st.drop_entry(s, &b, Vec::new()).unwrap());
    }
    w.write(1, |_| ());
}

/// The encryptions of `c` node 0 made.
fn encryptions(w: &mut World, c: &CommitId) -> usize {
    w.engine(0).commit_blobs(c).unwrap().len()
}

/// Node 0 grants a new actor read on `t` (a role commit, no rotation).
fn grant_reader(w: &mut World, t: Tid) -> Tid {
    w.write(0, |e| {
        let mut m = Mutation::new();
        // minted by the node, not by `t`: a thing of `t`'s made independent makes `t` a holder,
        // due a rotation for KEM keys (spec/crypto.md §3), a second encryption of everything
        let me = e.me();
        let x = e.new_thing(&mut m, me);
        e.commit(m).unwrap();
        e.grant(&t, &x, &edge(Role::Read)).unwrap();
        x
    })
}

fn restart(w: &mut World, i: usize) {
    w.power_off(i);
    w.power_on(i);
}

// spec/sync-judgement.md §4 (logs the body again once; a restart is no change of ground), §3
// (Role entries first: a full source is skipped): node 0 sees its write deleted at node 1
// while node 1 lacks a role commit of node 0's (node 0's stream withheld it), so logging again
// waits; node 0 restarts, then node 1 tells it is full for S, which ends the wait: node 0 logs
// the write there again once.
#[test]
fn a_delete_seen_before_a_restart_is_logged_again_once_after_spec_sync_judgement_4() {
    let (mut w, t, s, c) = setup();
    let before = encryptions(&mut w, &c);
    w.lie(0, Some(Lie::Withhold));
    grant_reader(&mut w, t);
    w.run();
    store_deletes(&mut w, &s, &c);
    w.run();
    assert_eq!(encryptions(&mut w, &c), before, "logging again waits on the role commit");
    // from the restart on node 1 says it is full for S once shown an entry, which ends the wait
    w.lie(0, None);
    w.lie(1, Some(Lie::Full));
    restart(&mut w, 0);
    w.write(0, |e| {
        let mut m = Mutation::new();
        m.set(t, &Ak::new("u:n.0").unwrap(), &Value::Str("w".into())).unwrap();
        e.commit(m).unwrap();
    });
    w.run();
    assert_eq!(encryptions(&mut w, &c), before + 1, "logged again once after the restart");
}

// spec/sync-judgement.md §4 (a restart is no change of ground; Once the head moves): node 0 logged its write again once
// past node 1's delete, node 1 deleted that too, and node 0 restarted: the restart allows nothing,
// and S's head moving there afterwards (a reader removed) allows exactly one more.
#[test]
fn a_head_move_after_a_restart_logs_again_once_more_spec_sync_judgement_4() {
    let (mut w, t, s, c) = setup();
    let x = grant_reader(&mut w, t);
    w.run();
    let before = encryptions(&mut w, &c);
    store_deletes(&mut w, &s, &c);
    w.run();
    assert_eq!(encryptions(&mut w, &c), before + 1, "logged again once");
    store_deletes(&mut w, &s, &c);
    w.run();
    restart(&mut w, 0);
    w.run();
    assert_eq!(encryptions(&mut w, &c), before + 1, "a restart is no change of ground");
    // removing the reader rotates S: its head moves at node 1
    let head = w.store(1).head_id(&s).unwrap();
    w.write(0, |e| e.demote(&t, &Demotion { holder: x, new: None, retain: None })).unwrap();
    w.run();
    assert_ne!(w.store(1).head_id(&s).unwrap(), head, "node 1's head moved");
    assert_eq!(encryptions(&mut w, &c), before + 2, "the head moved: logged again once more");
    assert!(!at_store(&mut w, &s, &c).is_empty(), "node 1 holds the write again");
    store_deletes(&mut w, &s, &c);
    w.run();
    assert_eq!(encryptions(&mut w, &c), before + 2, "once per ground");
}
