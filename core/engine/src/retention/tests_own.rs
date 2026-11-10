//! Own replaces (spec/commits.md §5 Own replaces, Forgetting): what a node judges covered and
//! what it keeps of what it forgot.
#![allow(clippy::unwrap_used, clippy::indexing_slicing)]

use crate::local_peer::LocalPeer;
use crate::Mutation;
use osis_base::{Ak, CommitId, Tid, Value};
use osis_commit::CommitBlob;

const T0: osis_base::WallMs = osis_base::WallMs(1_700_000_000_000);

fn ak(s: &str) -> Ak {
    Ak::new(s).unwrap()
}

/// Two peers sharing a thing of peer 0.
fn thing(seed: u64) -> (LocalPeer, Tid) {
    let mut lp = LocalPeer::new(2, seed, T0).unwrap();
    lp.sync_all().unwrap();
    let me = lp.peers[0].engine.me();
    let mut m = Mutation::new();
    let t = lp.peers[0].engine.new_thing(&mut m, me);
    lp.peers[0].commit(m).unwrap();
    lp.sync_all().unwrap();
    (lp, t)
}

/// Peer 0's whole replaces of `a`, one a second apart.
fn replaces(lp: &mut LocalPeer, t: Tid, a: &Ak, vs: std::ops::Range<i64>) -> Vec<CommitId> {
    vs.map(|v| {
        lp.advance(1000);
        let mut m = Mutation::new();
        m.set(t, a, &Value::Int(v)).unwrap();
        lp.peers[0].commit(m).unwrap().unwrap()
    })
    .collect()
}

// spec/commits.md §5 Own replaces: a part not fetched yet is not established as covered,
// whatever the replaces wrote (it may be a set add or map put); once it arrives the join
// decides, and once dropped it is covered.
#[test]
fn missing_part_is_not_established_spec_commits_5() {
    let (mut lp, t) = thing(11);
    let (a, b) = (ak("x:a.0"), ak("x:b.0"));
    lp.advance(1000);
    let mut m = Mutation::new();
    m.set(t, &a, &Value::Int(1)).unwrap();
    m.set(t, &b, &Value::Int(1)).unwrap();
    let c = lp.peers[0].commit(m).unwrap().unwrap();
    let qs = replaces(&mut lp, t, &a, 2..4);
    // peer 1 gets `c` without its part on `a`, and both replaces
    let pk = lp.peers[0].engine.package(&c).unwrap().unwrap();
    let mut blob = CommitBlob::decode(&pk.bytes).unwrap();
    let ai = blob.header.aspects.iter().position(|x| x.ak == a).unwrap();
    blob.parts.retain(|p| p.ai != ai);
    lp.peers[1].receive(&blob.encode(), pk.blobs.clone()).unwrap();
    for q in &qs {
        let p = lp.peers[0].engine.package(q).unwrap().unwrap();
        lp.deliver(1, &p).unwrap();
    }
    let e1 = &mut lp.peers[1].engine;
    assert!(e1.core.ix.commits.get(&c).unwrap().missing.contains(&ai));
    for q in &qs {
        assert_eq!(e1.covered(q, &c, &t, &a).unwrap(), None, "a part not fetched is not established");
    }
    lp.deliver(1, &pk).unwrap();
    let e1 = &mut lp.peers[1].engine;
    assert_eq!(e1.covered(&qs[1], &c, &t, &a).unwrap(), Some(true), "held: two later own replaces cover it");
    e1.drop_body(&c, &t, &a).unwrap();
    assert_eq!(e1.covered(&qs[1], &c, &t, &a).unwrap(), Some(true), "dropped: covered");
}

// spec/commits.md §5 Own replaces: which own replaces cover a commit depends on what is held,
// never on how many newer commits of the author came after (any later whole replace counts).
#[test]
fn every_later_own_replace_covers_spec_commits_5() {
    let (mut lp, t) = thing(12);
    let a = ak("x:a.0");
    let c = replaces(&mut lp, t, &a, 0..1)[0];
    let qs = replaces(&mut lp, t, &a, 1..6);
    let e = &mut lp.peers[0].engine;
    for q in &qs {
        assert_eq!(e.covered(q, &c, &t, &a).unwrap(), Some(true), "{q:?}");
    }
    // the newest alone has no second later one
    let last = *qs.last().unwrap();
    assert_eq!(e.covered(&last, &qs[3], &t, &a).unwrap(), Some(false));
}

// spec/commits.md §5 Forgetting, §7: what a forgotten durable commit stands for (`ix.forgotten`,
// read by `undo::replaced_kept`) is the same after a restart and after an index rebuild.
#[test]
fn forgotten_survives_restart_spec_commits_5() {
    let (mut lp, t) = thing(13);
    let a = ak("x:a.0");
    let c = replaces(&mut lp, t, &a, 0..1)[0];
    replaces(&mut lp, t, &a, 1..3);
    let e = &mut lp.peers[0].engine;
    e.drop_body(&c, &t, &a).unwrap();
    assert!(e.forgettable(&c));
    e.forget_commit(&c).unwrap();
    let before = e.core.ix.forgotten.get(&(t, a.clone())).copied();
    assert!(before.is_some());
    lp.peers[0].restart(5).unwrap();
    assert_eq!(lp.peers[0].engine.core.ix.forgotten.get(&(t, a.clone())).copied(), before, "after a restart");
    lp.peers[0].engine.rebuild_index().unwrap();
    assert_eq!(lp.peers[0].engine.core.ix.forgotten.get(&(t, a.clone())).copied(), before, "after a rebuild");
}

// spec/commits.md §5 Forgetting: what a node keeps of a forgotten commit goes with its thing, as
// at a node that never held it (no row per ended thing).
#[test]
fn forgotten_goes_with_its_thing_spec_commits_5() {
    let mut lp = LocalPeer::new(1, 14, T0).unwrap();
    let e = &mut lp.peers[0].engine;
    let me = e.me();
    let mut m = Mutation::new();
    let t = e.new_thing(&mut m, me);
    // the creating commit's expiry is its thing's (spec/commits.md §6)
    m.set(t, &ak("x:b.0"), &Value::Int(0)).unwrap();
    m.expires_all(osis_base::WallMs(T0.0 + 100_000));
    e.commit(m).unwrap();
    let a = ak("x:a.0");
    let c = replaces(&mut lp, t, &a, 0..1)[0];
    replaces(&mut lp, t, &a, 1..3);
    let e = &mut lp.peers[0].engine;
    e.drop_body(&c, &t, &a).unwrap();
    e.forget_commit(&c).unwrap();
    assert!(e.local_census().unwrap().contains_key("f/"), "the forgotten row");
    lp.advance(200_000);
    let e = &mut lp.peers[0].engine;
    e.tick().unwrap();
    assert_eq!(e.get(&t, &a).unwrap(), None, "ended");
    assert!(!e.core.ix.forgotten.contains_key(&(t, a.clone())));
    assert!(!e.local_census().unwrap().contains_key("f/"), "gone with the thing");
}

// spec/commits.md §5 Own replaces, spec/permissions.md §5.2: own replaces that turn invalid give
// nothing: the commit dropped under them alone is missing again, and once it comes back the node
// reads as one that never dropped it. Bob writes C, then two replaces only the reader Eve gets;
// Alice removes Bob without having received them.
#[test]
fn invalid_own_replaces_give_back_what_they_covered_spec_commits_5() {
    let mut lp = LocalPeer::new(3, 15, T0).unwrap();
    lp.sync_all().unwrap();
    let me = lp.peers[0].engine.me();
    let mut m = Mutation::new();
    let t = lp.peers[0].engine.new_thing(&mut m, me);
    lp.peers[0].commit(m).unwrap();
    let edge = |role| osis_schema::core_types::Edge { role, until: None, invite: None, tied: None };
    for (p, r) in [(1, osis_base::Role::Write), (2, osis_base::Role::Read)] {
        let who = lp.peers[p].engine.me();
        lp.peers[0].engine.grant(&t, &who, &edge(r)).unwrap();
    }
    lp.sync_all().unwrap();
    let a = ak("x:a.0");
    let write = |lp: &mut LocalPeer, v: i64| {
        lp.advance(1000);
        let mut m = Mutation::new();
        m.set(t, &a, &Value::Int(v)).unwrap();
        lp.peers[1].commit(m).unwrap().unwrap()
    };
    let c = write(&mut lp, 5);
    lp.sync_all().unwrap();
    write(&mut lp, 6);
    write(&mut lp, 7);
    lp.sync(1, 2).unwrap();
    lp.peers[2].engine.drop_body(&c, &t, &a).unwrap();
    assert_eq!(lp.peers[2].engine.get(&t, &a).unwrap(), Some(Value::Int(7)));
    lp.advance(1000);
    let bob = lp.peers[1].engine.me();
    lp.peers[0].engine.demote(&t, &crate::flows::Demotion { holder: bob, new: None, retain: None }).unwrap();
    lp.advance(1000);
    lp.sync(0, 2).unwrap();
    let e2 = &lp.peers[2].engine;
    let ai = e2.core.ix.commits.get(&c).unwrap().aspect(&t, &a).unwrap();
    assert!(e2.core.ix.commits.get(&c).unwrap().missing.contains(&ai), "C is missing again");
    let pk = lp.peers[0].engine.package(&c).unwrap().unwrap();
    lp.deliver(2, &pk).unwrap();
    assert_eq!(lp.peers[0].engine.get(&t, &a).unwrap(), Some(Value::Int(5)), "Alice never held the replaces");
    assert_eq!(lp.peers[2].engine.get(&t, &a).unwrap(), Some(Value::Int(5)), "Eve reads as Alice");
}

// spec/commits.md §5 Own replaces, spec/permissions.md §5.2: a commit dropped under two own
// replaces is missing again once one of them turns invalid, as one never dropped is uncovered
// then (a single own replace covers nothing). Bob writes C and a replace everyone gets, then a
// second replace only the reader Eve gets; Alice removes Bob without having received it. Eve
// keeping C dropped would delete at hosts what Alice, holding C uncovered, uploads.
#[test]
fn one_own_replace_left_covers_nothing_spec_commits_5() {
    let mut lp = LocalPeer::new(3, 16, T0).unwrap();
    lp.sync_all().unwrap();
    let me = lp.peers[0].engine.me();
    let mut m = Mutation::new();
    let t = lp.peers[0].engine.new_thing(&mut m, me);
    lp.peers[0].commit(m).unwrap();
    let edge = |role| osis_schema::core_types::Edge { role, until: None, invite: None, tied: None };
    for (p, r) in [(1, osis_base::Role::Write), (2, osis_base::Role::Read)] {
        let who = lp.peers[p].engine.me();
        lp.peers[0].engine.grant(&t, &who, &edge(r)).unwrap();
    }
    lp.sync_all().unwrap();
    let a = ak("x:a.0");
    let write = |lp: &mut LocalPeer, v: i64| {
        lp.advance(1000);
        let mut m = Mutation::new();
        m.set(t, &a, &Value::Int(v)).unwrap();
        lp.peers[1].commit(m).unwrap().unwrap()
    };
    let c = write(&mut lp, 5);
    let q1 = write(&mut lp, 6);
    lp.sync_all().unwrap();
    write(&mut lp, 7);
    lp.sync(1, 2).unwrap();
    lp.peers[2].engine.drop_body(&c, &t, &a).unwrap();
    lp.advance(1000);
    let bob = lp.peers[1].engine.me();
    lp.peers[0].engine.demote(&t, &crate::flows::Demotion { holder: bob, new: None, retain: None }).unwrap();
    lp.advance(1000);
    lp.sync(0, 2).unwrap();
    assert_eq!(lp.peers[0].engine.covered(&q1, &c, &t, &a).unwrap(), Some(false), "Alice: one own replace covers nothing");
    let e2 = &lp.peers[2].engine;
    let ai = e2.core.ix.commits.get(&c).unwrap().aspect(&t, &a).unwrap();
    assert!(e2.core.ix.commits.get(&c).unwrap().missing.contains(&ai), "Eve: C is missing again");
    assert_eq!(lp.peers[2].engine.get(&t, &a).unwrap(), Some(Value::Int(6)), "Eve reads as Alice");
    assert_eq!(lp.peers[0].engine.get(&t, &a).unwrap(), Some(Value::Int(6)));
}

// spec/sync.md §6, §7 (only a blob carries a delta kept or holding a live write): a delta's
// liveness is its own writes', not its body's: C writes x:a and x:b in one body; once x:a is
// replaced, C's x:a delta has no live write while the body (x:b) still has one.
#[test]
fn delta_live_is_the_deltas_own_spec_sync_7() {
    let (mut lp, t) = thing(17);
    let (a, b) = (ak("x:a.0"), ak("x:b.0"));
    lp.advance(1000);
    let mut m = Mutation::new();
    m.set(t, &a, &Value::Int(1)).unwrap();
    m.set(t, &b, &Value::Int(1)).unwrap();
    let c = lp.peers[0].commit(m).unwrap().unwrap();
    let e = &mut lp.peers[0].engine;
    assert!(e.delta_live(&c, &t, &a).unwrap() && e.delta_live(&c, &t, &b).unwrap());
    replaces(&mut lp, t, &a, 2..3);
    let e = &mut lp.peers[0].engine;
    assert!(!e.delta_live(&c, &t, &a).unwrap(), "x:a replaced");
    assert!(e.delta_live(&c, &t, &b).unwrap());
    assert!(e.body_live(&c, &t, &a).unwrap(), "the body's x:b write lives");
}
