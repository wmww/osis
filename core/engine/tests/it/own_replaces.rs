//! Own replaces (spec/commits.md §5 Own replaces, Forgetting): what a node judges covered and
//! what it keeps of what it forgot.

use osis_engine::local_peer::LocalPeer;
use osis_engine::Mutation;
use osis_base::{Ak, CommitId, Tid, Value};
use osis_commit::CommitBlob;
use crate::common::{T0, ak};

/// Two peers sharing a thing of peer 0.
fn thing() -> (LocalPeer, Tid) {
    LocalPeer::cached("retention::tests_own::thing", thing_build)
}

fn thing_build() -> (LocalPeer, Tid) {
    let mut lp = LocalPeer::fresh(2, T0);
    lp.sync_all().unwrap();
    let me = lp.peers[0].engine.tid();
    let mut m = Mutation::new();
    let t = lp.peers[0].engine.new_thing(&mut m, me);
    lp.peers[0].commit(m).unwrap();
    // peer 1 reads it: content of a thing outside a node closure waits (spec/commits.md §4)
    lp.share(0, t);
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
    let (mut lp, t) = thing();
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
    assert!(e1.core.ix.commits.get(&c).unwrap().missing(ai));
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
    let (mut lp, t) = thing();
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
    let (mut lp, t) = thing();
    let a = ak("x:a.0");
    let c = replaces(&mut lp, t, &a, 0..1)[0];
    replaces(&mut lp, t, &a, 1..3);
    let e = &mut lp.peers[0].engine;
    e.drop_body(&c, &t, &a).unwrap();
    assert!(e.forgettable(&c).unwrap());
    e.forget_commits(&[c]).unwrap();
    let before = e.core.ix.forgotten.get(&(t, a.clone())).copied();
    assert!(before.is_some());
    lp.peers[0].restart(0).unwrap();
    assert_eq!(lp.peers[0].engine.core.ix.forgotten.get(&(t, a.clone())).copied(), before, "after a restart");
    lp.peers[0].engine.rebuild_index().unwrap();
    assert_eq!(lp.peers[0].engine.core.ix.forgotten.get(&(t, a.clone())).copied(), before, "after a rebuild");
}

// spec/commits.md §5 Forgetting: what a node keeps of a forgotten commit goes with its thing, as
// at a node that never held it (no row per destroyed thing).
#[test]
fn forgotten_goes_with_its_thing_spec_commits_5() {
    let mut lp = LocalPeer::fresh(1, T0);
    let e = &mut lp.peers[0].engine;
    let me = e.tid();
    let mut m = Mutation::new();
    // the creating commit's expiry is its thing's (spec/commits.md §5 Destruction)
    let t = e.new_expiring_thing(&mut m, me, Some(osis_base::WallMs(T0.0 + 100_000)));
    m.set(t, &ak("x:b.0"), &Value::Int(0)).unwrap();
    m.expires_all(osis_base::WallMs(T0.0 + 100_000));
    e.commit(m).unwrap();
    let a = ak("x:a.0");
    let c = replaces(&mut lp, t, &a, 0..1)[0];
    replaces(&mut lp, t, &a, 1..3);
    let e = &mut lp.peers[0].engine;
    e.drop_body(&c, &t, &a).unwrap();
    e.forget_commits(&[c]).unwrap();
    assert!(e.local_census().unwrap().contains_key("f/"), "the forgotten row");
    lp.advance(200_000);
    lp.peers[0].tick().unwrap();
    let e = &mut lp.peers[0].engine;
    assert_eq!(e.get(&t, &a).unwrap(), None, "destroyed");
    assert!(!e.core.ix.forgotten.contains_key(&(t, a.clone())));
    assert!(!e.local_census().unwrap().contains_key("f/"), "gone with the thing");
}

/// Alice's (peer 0's) thing with Bob (1) its writer and Eve (2) its reader. Bob writes C = 5 on
/// `x:a`, then replaces it with 6, 7, ...: `shared` replaces everyone gets, then `only` that only
/// Eve gets, and Eve drops C. Returns the thing, C and the shared replaces.
fn bob_replaces(shared: i64, only: i64) -> (LocalPeer, Tid, CommitId, Vec<CommitId>) {
    let (mut lp, t) = LocalPeer::cached("retention::tests_own::writer_and_reader", || {
        let mut lp = LocalPeer::fresh(3, T0);
        lp.sync_all().unwrap();
        let me = lp.peers[0].engine.tid();
        let mut m = Mutation::new();
        let t = lp.peers[0].engine.new_thing(&mut m, me);
        lp.peers[0].commit(m).unwrap();
        lp.hold(t);
        let edge = |role| osis_schema::core_types::Edge { role, until: None, may_grant: false, retain: false, floor: None };
        for (p, r) in [(1, osis_base::Role::Write), (2, osis_base::Role::Read)] {
            let who = lp.peers[p].engine.tid();
            lp.peers[0].engine.grant(&t, &who, &edge(r)).unwrap();
        }
        lp.sync_all().unwrap();
        (lp, t)
    });
    let a = ak("x:a.0");
    let write = |lp: &mut LocalPeer, v: i64| {
        lp.advance(1000);
        let mut m = Mutation::new();
        m.set(t, &a, &Value::Int(v)).unwrap();
        lp.peers[1].commit(m).unwrap().unwrap()
    };
    let c = write(&mut lp, 5);
    let qs = (6..6 + shared).map(|v| write(&mut lp, v)).collect();
    lp.sync_all().unwrap();
    for v in 6 + shared..6 + shared + only {
        write(&mut lp, v);
    }
    lp.sync(1, 2).unwrap();
    lp.peers[2].engine.drop_body(&c, &t, &a).unwrap();
    (lp, t, c, qs)
}

/// Alice removes Bob, then syncs with Eve.
fn remove_bob(lp: &mut LocalPeer, t: Tid) {
    lp.advance(1000);
    let bob = lp.peers[1].engine.tid();
    lp.peers[0].engine.demote(&t, &osis_engine::flows::Demotion { holder: bob, new: None, retain: None }).unwrap();
    lp.advance(1000);
    lp.sync(0, 2).unwrap();
}

/// Whether C's part on `x:a` is missing at Eve.
fn missing_at_eve(lp: &LocalPeer, t: Tid, c: &CommitId) -> bool {
    let e2 = &lp.peers[2].engine;
    let ai = e2.core.ix.commits.get(c).unwrap().view.aspect(&t, "x:a.0").unwrap();
    e2.core.ix.commits.get(c).unwrap().missing(ai)
}

// spec/commits.md §5 Own replaces, spec/permissions.md §5.2: own replaces that turn invalid give
// nothing: the commit dropped under them alone is missing again, and once it comes back the node
// reads as one that never dropped it. Bob writes C, then two replaces only the reader Eve gets;
// Alice removes Bob without having received them.
#[test]
fn invalid_own_replaces_give_back_what_they_covered_spec_commits_5() {
    let (mut lp, t, c, _) = bob_replaces(0, 2);
    let a = ak("x:a.0");
    assert_eq!(lp.peers[2].engine.get(&t, &a).unwrap(), Some(Value::Int(7)));
    remove_bob(&mut lp, t);
    assert!(missing_at_eve(&lp, t, &c), "C is missing again");
    let pk = lp.peers[0].engine.package(&c).unwrap().unwrap();
    lp.deliver(2, &pk).unwrap();
    assert_eq!(lp.peers[0].engine.get(&t, &a).unwrap(), Some(Value::Int(5)), "Alice never held the replaces");
    assert_eq!(lp.peers[2].engine.get(&t, &a).unwrap(), Some(Value::Int(5)), "Eve reads as Alice");
}

// spec/commits.md §5 Own replaces, spec/permissions.md §5.2: a commit dropped under two own
// replaces is missing again once one of them turns invalid, as one never dropped is uncovered
// then (a single own replace covers nothing). Bob writes C and a replace everyone gets, then a
// second replace only the reader Eve gets; Alice removes Bob without having received it. Eve
// keeping C dropped would delete at peers what Alice, holding C uncovered, logs.
#[test]
fn one_own_replace_left_covers_nothing_spec_commits_5() {
    let (mut lp, t, c, qs) = bob_replaces(1, 1);
    let a = ak("x:a.0");
    remove_bob(&mut lp, t);
    assert_eq!(lp.peers[0].engine.covered(&qs[0], &c, &t, &a).unwrap(), Some(false), "Alice: one own replace covers nothing");
    assert!(missing_at_eve(&lp, t, &c), "Eve: C is missing again");
    assert_eq!(lp.peers[2].engine.get(&t, &a).unwrap(), Some(Value::Int(6)), "Eve reads as Alice");
    assert_eq!(lp.peers[0].engine.get(&t, &a).unwrap(), Some(Value::Int(6)));
}

// spec/sync-judgement.md §2, spec/sync-compaction.md §1 (carriers): only a blob carries a delta kept or holding a live write: a delta's
// liveness is its own writes', whatever its commit's other deltas hold: C writes x:a and x:b in
// one body; once x:a is replaced, C's x:a delta has no live write while its x:b delta still has.
#[test]
fn delta_live_is_the_deltas_own_spec_sync_7() {
    let (mut lp, t) = thing();
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
    assert!(e.delta_live(&c, &t, &b).unwrap(), "the x:b write lives");
}

// spec/commits.md §5 Own replaces: what stays dropped under own replaces is a function of what
// is held, as `covered` judges it, not of which replaces it dropped under. Bob writes C and two
// replaces everyone gets, then a third only the reader Eve gets; Eve drops C under the two
// newest; Alice removes Bob without the third. Two valid later replaces are still held at Eve,
// so C stays dropped there, as Alice, holding C, judges it covered.
#[test]
fn any_two_held_own_replaces_keep_a_drop_spec_commits_5() {
    let (mut lp, t, c, qs) = bob_replaces(2, 1);
    let a = ak("x:a.0");
    remove_bob(&mut lp, t);
    assert_eq!(lp.peers[0].engine.covered(&qs[0], &c, &t, &a).unwrap(), Some(true), "Alice: two own replaces cover C");
    assert_eq!(lp.peers[2].engine.covered(&qs[0], &c, &t, &a).unwrap(), Some(true), "Eve: the same two");
    assert!(!missing_at_eve(&lp, t, &c), "Eve: C stays dropped");
    assert_eq!(lp.peers[2].engine.get(&t, &a).unwrap(), Some(Value::Int(7)), "Eve reads as Alice");
    assert_eq!(lp.peers[0].engine.get(&t, &a).unwrap(), Some(Value::Int(7)));
}
