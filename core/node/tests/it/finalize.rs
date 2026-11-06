//! Finalizing timed edges (spec/permissions.md §2 Finalize, §5.1; spec/crypto.md §4): an edge
//! past its `until` is no departure for keys until a node with write (an admin for an admin edge)
//! removes it with no frontier, a finalize, carrying the rotation. Peers: 0 owns `t` (account A),
//! 1 and 3 write on it (W, W2), 2 is the timed guest G, whose clock lags: it reads on as long as
//! keys let it, so what it reads shows what the writers' keys gave it.

use crate::flows::{edge_of, newest_read, people, sealed_write, spread, thing_of};
use osis_base::{Clock, CommitId, Role, Tid, Value, WallMs};
use osis_crdt::{Op, PathOp};
use osis_node::local_peer::LocalPeer;
use osis_node::Mutation;
use osis_schema::core_types as ct;
use std::collections::BTreeSet;

struct Pass;
impl osis_node::flows::SyncState for Pass {
    fn complete_pass(&self, _: &Tid) -> bool {
        true
    }
}

/// A timed share: `t` owned by peer 0, write to peers 1 and 3, read to peer 2 until `until`
/// (`role`: G's role). Returns (lp, t, persons, until).
fn shared(seed: u64, role: Role) -> (LocalPeer, Tid, Vec<Tid>, WallMs) {
    let (mut lp, ps) = people(4, seed);
    let t = thing_of(&mut lp, 0, ps[0]);
    for w in [1, 3] {
        lp.peers[0].engine.grant(&t, &ps[w], &edge_of(Role::Write)).unwrap();
    }
    let until = WallMs(lp.peers[0].engine.now().0 + 5_000);
    lp.peers[0].engine.grant(&t, &ps[2], &ct::Edge { until: Some(until), ..edge_of(role) }).unwrap();
    spread(&mut lp);
    assert_eq!(sealed_write(&mut lp, 1, t, "before"), BTreeSet::from([0, 2, 3]));
    (lp, t, ps, until)
}

/// Every peer but G (2) past `until`.
fn past(lp: &mut LocalPeer, until: WallMs, by: u64) {
    for i in [0, 1, 3] {
        lp.peers[i].clock.set(WallMs(until.0 + by));
    }
}

/// A removal of `holder`'s edge on `t` by peer `by` with no frontier (finalize-shaped), past the
/// writer's own rules.
fn raw_finalize(lp: &mut LocalPeer, by: usize, t: Tid, holder: Tid) -> CommitId {
    let mut m = Mutation::new();
    m.op(t, &ct::ROLES, PathOp { path: Vec::new(), op: Op::Remove(Value::Tid(holder)) }).unwrap();
    lp.peers[by].engine.commit_hostile(m).unwrap().unwrap()
}

fn holds(lp: &LocalPeer, i: usize, t: Tid, m: Tid) -> bool {
    lp.peers[i].engine.core.key_holders(&t).iter().any(|(x, _)| *x == m)
}

/// Re-seal rounds by the owner and the writers (spec/permissions.md §3), spread after each.
fn reseal(lp: &mut LocalPeer, t: Tid) {
    for _ in 0..2 {
        for i in [0, 1, 3] {
            lp.peers[i].engine.reseal_due(&t, &Pass).unwrap();
        }
        spread(lp);
    }
}

// spec/permissions.md §2 (finalize), §3; spec/crypto.md §4: a writer about to write after a
// reader's `until` finalizes the edge: its removal, with no frontier, rotates, so the guest
// reads nothing written after it, even holding its old secrets and a clock before `until`. Every
// node applies the finalize from its stamp and held writes alone (the guest's own clock lags), and
// no re-seal brings the guest back.
#[test]
fn a_writer_finalizes_an_ended_reader_edge_spec_permissions_2() {
    let (mut lp, t, ps, until) = shared(5401, Role::Read);
    past(&mut lp, until, 1_000);
    assert!(lp.peers[1].engine.departures(&t).unwrap().is_empty(), "keys read no clock");
    let e0 = newest_read(&lp, 1, t);
    assert_eq!(sealed_write(&mut lp, 1, t, "after"), BTreeSet::from([0, 3]), "the writer finalized first");
    assert_ne!(newest_read(&lp, 1, t), e0);
    let fin: Vec<CommitId> = lp.peers[1].engine.commit_ids().into_iter().filter(|c| lp.peers[1].engine.header(c).is_some_and(|h| h.kind == osis_commit::Kind::Role && h.author == lp.peers[1].engine.tid())).collect();
    assert!(fin.iter().any(|c| lp.peers[1].engine.header(c).unwrap().frontier.is_none()), "a finalize carries no frontier");
    spread(&mut lp);
    assert!(lp.peers[2].clock.now_wall_ms() < until);
    for i in 0..4 {
        assert!(!holds(&lp, i, t, ps[2]), "peer {i}: the finalize applies");
    }
    reseal(&mut lp, t);
    assert_eq!(sealed_write(&mut lp, 0, t, "later"), BTreeSet::from([1, 3]));
}

// spec/permissions.md §2 (Finalize), §5.1: a finalize-shaped removal of an edge not past its
// `until` at the removal's stamp applies nothing, though every receiver's clock is past `until`
// when it arrives: the guest stays, and keeps reading once re-sealed.
#[test]
fn a_finalize_of_an_unended_edge_does_nothing_spec_permissions_2() {
    let (mut lp, t, ps, until) = shared(5402, Role::Read);
    raw_finalize(&mut lp, 1, t, ps[2]);
    past(&mut lp, until, 1_000);
    lp.peers[2].clock.set(WallMs(until.0 + 1_000));
    spread(&mut lp);
    for i in 0..4 {
        assert!(holds(&lp, i, t, ps[2]), "peer {i}: the early removal applies nothing");
    }
    // a renewal keeps it a holder by the clock too
    lp.peers[0].engine.grant(&t, &ps[2], &ct::Edge { until: Some(WallMs(until.0 + 3_600_000)), ..edge_of(Role::Read) }).unwrap();
    spread(&mut lp);
    reseal(&mut lp, t);
    assert!(sealed_write(&mut lp, 0, t, "later").contains(&2));
}

// spec/permissions.md §2: a void finalize resets the guest's entry in the state while its edge
// stands on the timeline; an explicit removal after it still removes the edge.
#[test]
fn an_explicit_removal_after_a_void_finalize_removes_spec_permissions_2() {
    let (mut lp, t, ps, _) = shared(5407, Role::Read);
    raw_finalize(&mut lp, 1, t, ps[2]);
    spread(&mut lp);
    assert!(holds(&lp, 0, t, ps[2]));
    let d = osis_node::flows::Demotion { holder: ps[2], new: None, presync: osis_node::flows::PreSync::Synced, retain: None };
    lp.peers[0].engine.demote(&t, &d).unwrap();
    spread(&mut lp);
    for i in 0..4 {
        assert!(!holds(&lp, i, t, ps[2]), "peer {i}: removed");
    }
}

// spec/permissions.md §2 (Finalize): an ended admin edge needs an admin: a writer neither
// finalizes it nor has a finalize of it apply; the owner's does.
#[test]
fn a_writer_cannot_finalize_an_ended_admin_edge_spec_permissions_2() {
    let (mut lp, t, ps, until) = shared(5403, Role::Admin);
    past(&mut lp, until, 1_000);
    let (w, _) = lp.peers[1].engine.ensure_rotated(&t).unwrap();
    assert!(w.commits.is_empty(), "the writer writes no finalize of it");
    raw_finalize(&mut lp, 1, t, ps[2]);
    spread(&mut lp);
    for i in 0..4 {
        assert!(holds(&lp, i, t, ps[2]), "peer {i}: a writer's finalize of an admin edge applies nothing");
    }
    let (a, _) = lp.peers[0].engine.ensure_rotated(&t).unwrap();
    assert_eq!(a.commits.len(), 1, "the owner finalizes it");
    spread(&mut lp);
    for i in 0..4 {
        assert!(!holds(&lp, i, t, ps[2]), "peer {i}");
    }
}

// spec/permissions.md §2 (Finalize), §3 (re-seal): a renewal ordered before a writer's finalize
// wins: the finalize, made not knowing it, applies nothing, its rotation left the guest out, and
// the re-seal brings it back.
#[test]
fn a_renewal_before_the_finalize_wins_spec_permissions_2() {
    let (mut lp, t, ps, until) = shared(5404, Role::Read);
    past(&mut lp, until, 1_000);
    let renewed = lp.peers[0].engine.grant(&t, &ps[2], &ct::Edge { until: Some(WallMs(until.0 + 3_600_000)), ..edge_of(Role::Read) }).unwrap();
    assert_eq!(renewed.commits.len(), 1, "a renewal finalizes nothing first");
    lp.peers[1].clock.set(WallMs(until.0 + 2_000));
    assert_eq!(sealed_write(&mut lp, 1, t, "unaware"), BTreeSet::from([0, 3]), "the writer finalized, not knowing");
    spread(&mut lp);
    for i in 0..4 {
        assert!(holds(&lp, i, t, ps[2]), "peer {i}: the renewal wins");
    }
    reseal(&mut lp, t);
    assert!(sealed_write(&mut lp, 0, t, "later").contains(&2), "re-sealed");
}

// spec/permissions.md §2 (Finalize), spec/crypto.md §4 (forks): two writers finalizing the same
// ended edge at once fork the rotation; once their commits and re-seals spread, every node reads
// the same roster and current epochs, and the guest reads nothing new.
#[test]
fn concurrent_finalizes_converge_spec_permissions_2() {
    let (mut lp, t, ps, until) = shared(5405, Role::Read);
    past(&mut lp, until, 1_000);
    lp.peers[3].clock.set(WallMs(until.0 + 1_500));
    for w in [1, 3] {
        let (done, _) = lp.peers[w].engine.ensure_rotated(&t).unwrap();
        assert_eq!(done.commits.len(), 1, "peer {w} finalizes, not knowing the other's");
    }
    spread(&mut lp);
    let current = |lp: &LocalPeer, i: usize| -> BTreeSet<osis_crypto::Epoch> { lp.peers[i].engine.epochs(&t).unwrap().read.current().into_iter().collect() };
    assert_eq!(current(&lp, 0).len(), 2, "forked");
    reseal(&mut lp, t);
    let first = current(&lp, 0);
    for i in [1, 3] {
        assert_eq!(current(&lp, i), first, "peer {i}");
    }
    for i in 0..4 {
        assert!(!holds(&lp, i, t, ps[2]), "peer {i}");
        assert_eq!(lp.peers[i].engine.roster(&t), lp.peers[0].engine.roster(&t), "peer {i}");
    }
    for i in [0, 1, 3] {
        let want: BTreeSet<usize> = [0, 1, 3].into_iter().filter(|x| *x != i).collect();
        assert_eq!(sealed_write(&mut lp, i, t, &format!("by {i}")), want, "peer {i}");
    }
}

// spec/permissions.md §2 (an `until` passing, Finalize), §3 (Lost access): a finalize counts as
// the `until` it finalizes at the guest: arriving while the guest hears its labels out, it drops
// nothing at once; an explicit removal would.
#[test]
fn a_finalize_lets_the_guest_hear_out_spec_permissions_2() {
    use osis_node::rotation::LostScope;
    let (mut lp, t, _, until) = shared(5406, Role::Write);
    past(&mut lp, until, 1_000);
    lp.peers[2].clock.set(WallMs(until.0 + 1_000));
    let (done, _) = lp.peers[1].engine.ensure_rotated(&t).unwrap();
    assert_eq!(done.commits.len(), 1, "finalized");
    spread(&mut lp);
    assert!(lp.peers[2].engine.lost_due());
    let r = lp.peers[2].engine.forget_lost(LostScope::Due).unwrap();
    assert!(r.actors.is_empty() && r.leaving, "heard out first");
    assert!(lp.peers[2].engine.lost_leaving().unwrap().timed.contains_key(&t));
}

// spec/commits.md §2, spec/permissions.md §2 (Finalize): a writer never writes a removal of
// another's edge with no frontier unless the edge is past its `until`: that would be a void
// finalize, a revoke by an admin that cuts off nobody.
#[test]
fn a_frontierless_removal_of_an_unended_edge_is_refused_spec_commits_2() {
    let (mut lp, t, ps, _) = shared(5408, Role::Read);
    let mut m = Mutation::new();
    m.op(t, &ct::ROLES, PathOp { path: Vec::new(), op: Op::Remove(Value::Tid(ps[2])) }).unwrap();
    let r = lp.peers[0].engine.commit(m);
    assert!(matches!(r, Err(osis_node::Error::BadInput(e)) if e.contains("not past its until")), "{r:?}");
    assert!(holds(&lp, 0, t, ps[2]));
}
