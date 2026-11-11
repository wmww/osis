//! World copies (notes/testing.md, Copied worlds): a copied `LocalPeer` goes on exactly as the
//! original, and the two share nothing.

#![allow(clippy::unwrap_used, clippy::indexing_slicing)]
use crate::Mutation;
use crate::flows::Demotion;
use crate::local_peer::LocalPeer;
use osis_base::{Ak, CommitId, Role, Tid, Value, WallMs};
use osis_crdt::{Op, PathOp, PathSeg};
use osis_schema::core_types as ct;

fn edge(role: Role) -> ct::Edge {
    ct::Edge { role, until: None, invite: None, tied: None }
}

fn put(lp: &mut LocalPeer, who: usize, t: Tid, x: &Ak, k: &str, v: i64) -> Option<CommitId> {
    lp.advance(7);
    let mut m = Mutation::new();
    m.op(t, x, PathOp { path: vec![PathSeg::Key(Value::Str(k.into()))], op: Op::Put(Value::Int(v)) }).unwrap();
    lp.peers[who].commit(m).ok().flatten()
}

/// Three nodes: 0 admin of `t`, 1 a writer later demoted (a rotation), 2 an admin; writes
/// synced and one left unsynced.
fn history() -> (LocalPeer, Tid, Ak) {
    let mut lp = LocalPeer::new(3, 0, WallMs(1_700_000_000_000)).unwrap();
    lp.sync_all().unwrap();
    let x = Ak::new("x:m.0").unwrap();
    let me = lp.peers[0].engine.me();
    let (t, _) = lp.peers[0].engine.create_with_admin(&me).unwrap();
    let (w, a) = (lp.peers[1].engine.me(), lp.peers[2].engine.me());
    lp.peers[0].engine.grant(&t, &w, &edge(Role::Write)).unwrap();
    lp.peers[0].engine.grant(&t, &a, &edge(Role::Admin)).unwrap();
    lp.sync_all().unwrap();
    put(&mut lp, 0, t, &x, "a", 1);
    put(&mut lp, 1, t, &x, "b", 2);
    lp.sync_all().unwrap();
    lp.peers[0].engine.demote(&t, &Demotion { holder: w, new: None, retain: None }).unwrap();
    lp.sync_all().unwrap();
    put(&mut lp, 2, t, &x, "c", 3);
    put(&mut lp, 0, t, &x, "d", 4);
    lp.sync(0, 1).unwrap();
    (lp, t, x)
}

/// The same further steps: writes, a grant, an undo, a tick, syncs. The commit IDs they made.
fn further(lp: &mut LocalPeer, t: Tid, x: &Ak) -> Vec<Option<CommitId>> {
    let mut ids = vec![put(lp, 0, t, x, "e", 5), put(lp, 2, t, x, "a", 6)];
    let w = lp.peers[1].engine.me();
    ids.extend(lp.peers[2].engine.grant(&t, &w, &edge(Role::Read)).unwrap().commits.into_iter().map(Some));
    lp.sync_all().unwrap();
    if let Some(c) = ids[0] {
        ids.push(lp.peers[0].engine.revert(&c).unwrap());
    }
    lp.advance(90_000_000);
    for p in &mut lp.peers {
        p.tick().unwrap();
    }
    lp.sync_all().unwrap();
    ids.push(put(lp, 2, t, x, "f", 7));
    assert_eq!(put(lp, 1, t, x, "g", 8), None, "1 reads only");
    ids
}

/// Everything a test could compare of each node: indexes, timelines, the aspects of `t` read,
/// events, the store's bytes and the backend's history and counters.
fn observe(lp: &mut LocalPeer, t: Tid) -> Vec<String> {
    let mut out = Vec::new();
    for p in &mut lp.peers {
        let reads: Vec<_> = p.engine.aspects(&t).unwrap().into_iter().map(|ak| (ak.clone(), p.engine.get(&t, &ak).unwrap())).collect();
        out.push(format!("{:?}", p.engine.index_digest()));
        out.push(p.engine.perm_digest(false));
        out.push(format!("{reads:?} {:?} {:?}", p.drain_events(), p.engine.point().3));
        out.push(format!("{:?} {:?} {:?}", p.backend.dump(), p.backend.io(), p.backend.syncs()));
        out.push(format!("{:?}", p.engine.store_dump().unwrap()));
    }
    out
}

/// Each memo's and phase's runs (not their time): a copy's memos hit and miss as the original's.
fn runs() -> Vec<(&'static str, u64)> {
    crate::costs::take().into_iter().map(|(k, _, n)| (k, n)).collect()
}

// spec: none (internal: notes/testing.md, Copied worlds). A copied world goes on exactly as the
// original: the same further steps make the same commits, reads, indexes, timelines, events,
// stored bytes and memo runs.
#[test]
fn a_copied_world_goes_on_as_the_original() {
    let (mut lp, t, x) = history();
    let mut copy = lp.copy().unwrap();
    assert_eq!(observe(&mut lp, t), observe(&mut copy, t), "as copied");
    runs();
    let a = further(&mut lp, t, &x);
    let ran = runs();
    let b = further(&mut copy, t, &x);
    assert_eq!(ran, runs(), "memo and phase runs");
    assert_eq!(a, b);
    assert!(a.iter().filter(|c| c.is_some()).count() >= 4, "{a:?}");
    assert_eq!(observe(&mut lp, t), observe(&mut copy, t), "after the same steps");
}

// spec: none (internal: notes/testing.md, Copied worlds). A copy shares nothing with its
// original: writes and fault plans of either leave the other as it was.
#[test]
fn a_copy_shares_nothing() {
    let (mut lp, t, x) = history();
    let (mut c1, mut c2, mut c3) = (lp.copy().unwrap(), lp.copy().unwrap(), lp.copy().unwrap());
    c1.peers[0].backend.faults().at(0, osis_store::Fault::Crash);
    assert!(put(&mut c1, 2, t, &x, "y", 8).is_some());
    c1.sync(2, 1).unwrap();
    assert_eq!(put(&mut c1, 0, t, &x, "y", 9), None, "crashed");
    assert!(c1.peers[0].backend.faults().crashed());
    assert!(!lp.peers[0].backend.faults().crashed());
    assert_eq!(observe(&mut lp, t), observe(&mut c2, t), "the copy's steps and plan stay in the copy");
    // reads count in the backend's counters: c3 is looked at as often as c2
    observe(&mut c3, t);
    further(&mut lp, t, &x);
    assert_eq!(observe(&mut c2, t), observe(&mut c3, t), "the original's steps stay in it");
    assert!(put(&mut c2, 0, t, &x, "z", 9).is_some(), "the original's plan is not the copy's");
}

