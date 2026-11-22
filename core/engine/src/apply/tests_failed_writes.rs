//! One failed write with the device up (`Fault::Fail`) at any write of an operation: the node
//! reads its store again as an open does (`Engine::reload_owed`), so the operation given again
//! (a peer gives again what failed, a host steps again) and one tick end where a node that never
//! failed ends. spec/commits.md §4 (a node applies in one storage transaction; every arrival that
//! applies examines again what waits for it).
#![allow(clippy::unwrap_used, clippy::indexing_slicing)]

use crate::Mutation;
use crate::flows::Demotion;
use crate::local_peer::LocalPeer;
use crate::rotation::tests::edge;
use osis_base::{Ak, CommitId, Role, Tid, Value};
use osis_store::Fault;

const T0: osis_base::WallMs = osis_base::WallMs(1_700_000_000_000);

/// Peer 0 (H) makes thing `t` and grants peers 1 (X) and 2 (W) admin; peers 3.. hold nothing
/// on it. Everyone synced.
fn world(n: usize) -> (LocalPeer, Tid) {
    LocalPeer::cached(&format!("apply::tests_failed_writes::world/{n}"), || {
        let mut lp = LocalPeer::fresh(n, T0);
        lp.sync_all().unwrap();
        let me = lp.peers[0].engine.me();
        let mut m = Mutation::new();
        let t = lp.peers[0].engine.new_thing(&mut m, me);
        lp.peers[0].commit(m).unwrap();
        lp.hold(t);
        for i in [1, 2] {
            let who = lp.peers[i].engine.me();
            lp.peers[0].engine.grant(&t, &who, &edge(Role::Admin)).unwrap();
        }
        lp.sync_all().unwrap();
        lp.advance(1000);
        (lp, t)
    })
}

/// Peer `by` grants peer `to` `role` on `t`: the grant's commit.
fn grant(lp: &mut LocalPeer, by: usize, t: Tid, to: usize, role: Role) -> CommitId {
    let who = lp.peers[to].engine.me();
    let id = *lp.peers[by].engine.grant(&t, &who, &edge(role)).unwrap().commits.last().unwrap();
    lp.advance(1000);
    id
}

/// Peer `by` removes peer `holder` from `t`, a second after everything so far.
fn remove(lp: &mut LocalPeer, by: usize, t: Tid, holder: usize) -> CommitId {
    lp.advance(1000);
    let h = lp.peers[holder].engine.me();
    let id = *lp.peers[by].engine.demote(&t, &Demotion { holder: h, new: None, retain: None }).unwrap().commits.last().unwrap();
    lp.advance(1000);
    id
}

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

// A removal arriving at a witness that owes an addendum: X writes, W (peer 2) received it, H
// removes X. W writes one addendum for the write, and it stays valid.
#[test]
fn a_removal_owing_an_addendum() {
    let make = || {
        let (mut lp, t) = world(4);
        set(&mut lp, 1, t, "by X");
        lp.advance(1000);
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
            let mine = lp.peers[2].engine.core.ix.addenda.iter().filter(|((on, _), a)| on == t && a.point.node == w).count();
            format!("{:?} addenda {mine} {:?}", pending(lp, 2), lp.peers[2].engine.get(t, &Ak::new(X).unwrap()).unwrap())
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

// An arrival waking a wait whose round of examinations fails otherwise than by the store (an
// engine fault erring the round): the arrival is held, and without a restart the next tick
// applies the write it woke (`Engine::run_taken`), as a node opening again would.
#[test]
fn an_arrival_waking_a_wait_whose_round_fails() {
    let (mut lp, t) = world(4);
    let g = grant(&mut lp, 0, t, 3, Role::Write);
    lp.sync(0, 3).unwrap();
    let c = set(&mut lp, 3, t, "written");
    let cp = lp.peers[3].engine.package(&c).unwrap().unwrap();
    lp.peers[2].engine.ingest(&cp.bytes, cp.blobs).unwrap();
    assert_eq!(pending(&lp, 2).len(), 1, "the write waits");
    let gp = lp.peers[0].engine.package(&g).unwrap().unwrap();
    lp.peers[2].engine.fail_round = true;
    assert!(lp.peers[2].engine.ingest(&gp.bytes, gp.blobs.clone()).is_err(), "the round failed");
    lp.peers[2].tick().unwrap();
    assert_eq!(pending(&lp, 2), Vec::new(), "nothing waits");
    assert_eq!(lp.peers[2].engine.get(&t, &Ak::new(X).unwrap()).unwrap(), Some(Value::Str("written".into())));
}

// spec/commits.md §4 (Apply: a transaction that fails or is refused leaves the node as it was,
// waits included): a transaction or step that fails leaves no blob wait due for a commit only it
// brought, so the next timer stays as it was. A wait kept for commit C, unknown here, and its
// trees asked, in a transaction that then fails (a sealed fire applied
// with a part waiting for a page, refused: `Engine::ingest_sealed_fire`), and in a step that fails
// inside one that commits: a round due for C finds nothing, yet put the next timer at now, and
// a driver ticking then tried the refused fire again, refused again: a loop.
#[test]
fn a_failed_transaction_leaves_no_wait_due_for_what_it_brought() {
    let mut lp = LocalPeer::fresh(1, T0);
    let e = &mut lp.peers[0].engine;
    let before = e.next_timer().unwrap();
    let c = CommitId([7; 32]);
    let waits = |tx: &mut crate::engine::Tx<'_>| -> crate::Result<()> {
        crate::apply::reach::wait_part(tx, &c, 0, &[], false)?;
        tx.core.walks.trees_of(c);
        Err(crate::Error::Misuse("fails"))
    };
    assert!(e.run(waits).is_err());
    assert_eq!(e.next_timer().unwrap(), before, "a failed transaction");
    e.run(|tx| {
        assert!(tx.step(crate::engine::Step::Commit, waits).is_err());
        Ok(())
    })
    .unwrap();
    assert_eq!(e.next_timer().unwrap(), before, "a failed step");
}
