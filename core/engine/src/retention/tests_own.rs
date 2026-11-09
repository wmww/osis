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
    let me = lp.peers[0].engine.tid();
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
