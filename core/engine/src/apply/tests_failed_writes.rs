//! One failed write with the device up (`Fault::Fail`) at any write of an operation: the node
//! reads its store again as an open does (`Engine::reload_owed`), so the operation given again
//! (a peer gives again what failed, a host steps again) and one tick end where a node that never
//! failed ends. spec/commits.md §4 (a node applies in one storage transaction; every arrival that
//! applies examines again what waits for it).
#![allow(clippy::unwrap_used, clippy::indexing_slicing)]

use super::tests_vouches::{grant, remove, role, vouches, world};
use crate::Mutation;
use crate::local_peer::LocalPeer;
use osis_base::{Ak, Role, Tid, Value};
use osis_store::Fault;

/// `op` on the world `make` builds, peer `at`'s store failing at its n-th write, for every n `op`
/// writes; after a failure, `op` again and a tick: `seen` of the world then equals a run where
/// nothing failed (`op` once, a tick).
fn each_failed_write<D>(make: impl Fn() -> (LocalPeer, D), at: usize, op: impl Fn(&mut LocalPeer, &D) -> crate::Result<()>, seen: impl Fn(&mut LocalPeer, &D) -> String) {
    let (mut lp, d) = make();
    op(&mut lp, &d).unwrap();
    lp.peers[at].tick().unwrap();
    let want = seen(&mut lp, &d);
    for n in 0.. {
        let (mut lp, d) = make();
        let f = lp.peers[at].backend.faults().clone();
        f.at(n, Fault::Fail);
        let r = op(&mut lp, &d);
        if f.writes() <= n {
            r.unwrap();
            assert!(n > 0, "the operation writes");
            return;
        }
        f.revive();
        op(&mut lp, &d).unwrap();
        lp.peers[at].tick().unwrap();
        assert_eq!(seen(&mut lp, &d), want, "write {n} (failed: {})", r.is_err());
    }
}

fn pending(lp: &LocalPeer, at: usize) -> Vec<osis_base::CommitId> {
    let mut v: Vec<_> = lp.peers[at].engine.pending().into_iter().map(|(c, _)| c).collect();
    v.sort();
    v
}

const X: &str = "x:m.0";

fn set(lp: &mut LocalPeer, by: usize, t: Tid, v: &str) -> osis_base::CommitId {
    let mut m = Mutation::new();
    m.set(t, &Ak::new(X).unwrap(), &Value::Str(v.into())).unwrap();
    lp.peers[by].commit(m).unwrap().unwrap()
}

// An arrival that wakes a wait: W (peer 2) holds K's write and waits for K's grant; the grant
// arrives. The write applies.
#[test]
fn an_arrival_waking_a_wait() {
    let make = || {
        let (mut lp, t) = world(4);
        let g = grant(&mut lp, 0, t, 3, Role::Write);
        lp.sync(0, 3).unwrap();
        let c = set(&mut lp, 3, t, "written");
        let cp = lp.peers[3].engine.package(&c).unwrap().unwrap();
        lp.peers[2].engine.ingest(&cp.bytes, cp.blobs).unwrap();
        assert_eq!(lp.peers[2].engine.pending().len(), 1, "the write waits");
        let gp = lp.peers[0].engine.package(&g).unwrap().unwrap();
        (lp, (t, gp))
    };
    each_failed_write(
        make,
        2,
        |lp, (_, gp)| lp.peers[2].engine.ingest(&gp.bytes, gp.blobs.clone()).map(drop),
        |lp, (t, _)| format!("{:?} {:?}", pending(lp, 2), lp.peers[2].engine.get(t, &Ak::new(X).unwrap()).unwrap()),
    );
}

// A removal arriving at a witness that owes a vouch: X grants K write, W (peer 2) received it,
// H removes X. W vouches for the grant once, and K keeps its role.
#[test]
fn a_removal_owing_a_vouch() {
    let make = || {
        let (mut lp, t) = world(4);
        grant(&mut lp, 1, t, 3, Role::Write);
        lp.sync(1, 2).unwrap();
        remove(&mut lp, 0, t, 1);
        (lp, t)
    };
    each_failed_write(
        make,
        2,
        |lp, _| lp.sync(0, 2),
        |lp, t| {
            let w = lp.peers[2].engine.me();
            let mine = vouches(lp, 2, *t).iter().filter(|v| v.0 == w).count();
            format!("{:?} vouches {mine} role {:?}", pending(lp, 2), role(lp, 2, 3, *t))
        },
    );
}

// A compaction step with an aspect due: compacted once, its bodies covered.
#[test]
fn a_step_with_compactions_due() {
    let make = || {
        let mut lp = LocalPeer::fresh(1, osis_base::WallMs(1_700_000_000_000));
        let me = lp.peers[0].engine.me();
        let mut m = Mutation::new();
        let t = lp.peers[0].engine.new_thing(&mut m, me);
        lp.peers[0].commit(m).unwrap();
        for i in 0..2 * crate::retention::compact::FACTOR + 2 {
            set(&mut lp, 0, t, &format!("v{i}"));
        }
        (lp, t)
    };
    each_failed_write(
        make,
        0,
        |lp, _| lp.peers[0].engine.compactions().map(drop),
        |lp, t| {
            let n = lp.peers[0].engine.core.ix.by_aspect.get(&(*t, Ak::new(X).unwrap())).map_or(0, |s| s.len());
            format!("{:?} bodies {n}", pending(lp, 0))
        },
    );
}
