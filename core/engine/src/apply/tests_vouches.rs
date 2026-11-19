//! Vouches (spec/permissions.md §5.1 Vouches, §4 Vouches travel with their removal): a holder that
//! received a removed party's role write the remover had not keeps it, at every node.
#![allow(clippy::unwrap_used, clippy::indexing_slicing)]

use crate::Mutation;
use crate::flows::Demotion;
use crate::local_peer::LocalPeer;
use crate::rotation::tests::edge;
use osis_base::{CommitId, Role, Tid, Value};
use osis_crdt::{Op, PathOp, PathSeg};
use osis_perm::At;
use osis_schema::Codec;
use osis_schema::core_types as ct;

const T0: osis_base::WallMs = osis_base::WallMs(1_700_000_000_000);

/// Peer 0 (H) makes thing `t` and grants peers 1 (X) and 2 (W) admin; peers 3.. hold nothing
/// on it. Everyone synced.
pub(super) fn world(n: usize) -> (LocalPeer, Tid) {
    LocalPeer::cached(&format!("apply::tests_vouches::world/{n}"), || {
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
pub(super) fn grant(lp: &mut LocalPeer, by: usize, t: Tid, to: usize, role: Role) -> CommitId {
    let who = lp.peers[to].engine.me();
    let id = *lp.peers[by].engine.grant(&t, &who, &edge(role)).unwrap().commits.last().unwrap();
    lp.advance(1000);
    id
}

/// Peer `by` removes peer `holder` from `t`, a second after everything so far.
pub(super) fn remove(lp: &mut LocalPeer, by: usize, t: Tid, holder: usize) -> CommitId {
    lp.advance(1000);
    let h = lp.peers[holder].engine.me();
    let id = *lp.peers[by].engine.demote(&t, &Demotion { holder: h, new: None, retain: None }).unwrap().commits.last().unwrap();
    lp.advance(1000);
    id
}

/// Peer `by` writes a vouch on `t` keyed by `r` listing `lists`, by hand.
pub(super) fn vouch(lp: &mut LocalPeer, by: usize, t: Tid, r: CommitId, lists: &[CommitId]) -> CommitId {
    let mut m = Mutation::new();
    let list = ct::Frontier { commits: lists.iter().copied().collect() };
    m.op(t, &ct::VOUCHES, PathOp { path: vec![PathSeg::Key(Value::bytes(&r.0))], op: Op::Put(list.to_value()) }).unwrap();
    let id = lp.peers[by].commit(m).unwrap().unwrap();
    lp.advance(1000);
    id
}

/// Peer `at`'s role for peer `who` on `t` now.
pub(super) fn role(lp: &LocalPeer, at: usize, who: usize, t: Tid) -> Option<Role> {
    let w = lp.peers[who].engine.me();
    lp.peers[at].engine.core.timelines.role(&w, &t, At::END)
}

// spec/permissions.md §5.1 Vouches (an entry counts; second walk), §4 (Vouches travel with their
// removal): X grants K write, W alone receives it, H removes X without it. W's vouch keyed by
// H's removal listing the grant keeps it at every node, H's and K's included; without it the
// grant falls everywhere.
#[test]
fn a_hand_written_vouch_keeps_a_removed_partys_grant_spec_perm_5_1() {
    for vouched in [true, false] {
        let (mut lp, t) = world(4);
        for p in &mut lp.peers {
            p.engine.write_vouches(false);
        }
        let c = grant(&mut lp, 1, t, 3, Role::Write);
        lp.sync(1, 2).unwrap();
        let r = remove(&mut lp, 0, t, 1);
        assert!(!lp.peers[0].engine.core.ix.commits.get(&r).unwrap().view.frontier.as_ref().unwrap().covers(&c));
        if vouched {
            vouch(&mut lp, 2, t, r, &[c]);
        }
        lp.sync_all().unwrap();
        for p in 0..4 {
            assert_eq!(role(&lp, p, 3, t), vouched.then_some(Role::Write), "peer {p}, vouched {vouched}");
            assert_eq!(role(&lp, p, 1, t), None, "peer {p}: X stays removed");
        }
    }
}

/// The vouches held at peer `at` on `t`: (voucher, commit).
pub(super) fn vouches(lp: &LocalPeer, at: usize, t: Tid) -> Vec<(Tid, CommitId)> {
    lp.peers[at].engine.core.ix.held.vouches_on(&t).map(|v| (v.author, v.id)).collect()
}

// spec/permissions.md §5.1 Vouches (Writing): as above with every node writing by the state rule.
// W, which received X's grant, vouches unasked; H (R's writer), X (in question at R) and K (who
// received nothing) write none; every node, and one that syncs only later, keeps the grant.
#[test]
fn a_witness_vouches_unasked_and_the_grant_stays_everywhere_spec_perm_5_1() {
    let (mut lp, t) = world(5);
    let c = grant(&mut lp, 1, t, 3, Role::Write);
    lp.sync(1, 2).unwrap();
    let r = remove(&mut lp, 0, t, 1);
    for (a, b) in [(0, 1), (0, 2), (0, 3), (1, 2), (2, 3), (1, 3)] {
        lp.sync(a, b).unwrap();
        lp.sync(b, a).unwrap();
    }
    let w = lp.peers[2].engine.me();
    let held = vouches(&lp, 0, t);
    assert_eq!(held.iter().map(|x| x.0).collect::<Vec<_>>(), vec![w], "W alone vouches, once");
    let v = lp.peers[0].engine.core.ix.held.vouches_on(&t).next().unwrap().clone();
    assert_eq!(v.entries.iter().map(|(k, l)| (*k, l.commits().to_vec())).collect::<Vec<_>>(), vec![(r, vec![c])]);
    for p in 0..4 {
        assert_eq!(role(&lp, p, 3, t), Some(Role::Write), "peer {p}");
    }
    // a node syncing later gets the vouch with the removal
    lp.sync_all().unwrap();
    assert_eq!(role(&lp, 4, 3, t), Some(Role::Write), "the late node");
    assert_eq!(vouches(&lp, 4, t).len(), 1, "no node writes a second");
}

// spec/permissions.md §5.1 Vouches (an entry counts while W could write c at each later
// lowering of W whose frontier does not list V): W vouches for X's grant; H then removes W too.
// Where H's removal of W does not list W's vouch, the grant falls again at every node; where
// it lists it, the grant stays.
#[test]
fn a_voucher_removed_without_its_vouch_listed_drops_what_it_kept_spec_perm_5_1() {
    for listed in [false, true] {
        let (mut lp, t) = world(4);
        let c = grant(&mut lp, 1, t, 3, Role::Write);
        lp.sync(1, 2).unwrap();
        let _r = remove(&mut lp, 0, t, 1);
        lp.sync(0, 2).unwrap();
        let w = lp.peers[2].engine.me();
        assert_eq!(vouches(&lp, 2, t).iter().map(|x| x.0).collect::<Vec<_>>(), vec![w], "W vouches on receiving R");
        if listed {
            lp.sync(2, 0).unwrap();
        }
        remove(&mut lp, 0, t, 2);
        lp.sync_all().unwrap();
        for p in 0..4 {
            assert_eq!(role(&lp, p, 3, t), listed.then_some(Role::Write), "peer {p}, listed {listed}");
        }
        let _ = c;
    }
}

// spec/permissions.md §5.1 Vouches ("W could write c": each other role-class part needs the role
// its aspect requires): X's rotation of t's write keys, received by W alone, is invalid once H
// removes X without it, unless W's vouch keeps it; W writes that vouch unasked.
#[test]
fn a_vouched_rotation_stays_valid_spec_perm_5_1() {
    for on in [true, false] {
        let (mut lp, t) = world(4);
        for p in &mut lp.peers {
            p.engine.write_vouches(on);
        }
        let c = lp.peers[1].engine.rotate_leaving_out(&t, &[Role::Write], &[]).unwrap().unwrap();
        lp.advance(1000);
        lp.sync(1, 2).unwrap();
        remove(&mut lp, 0, t, 1);
        lp.sync_all().unwrap();
        for p in [0, 2, 3] {
            let m = lp.peers[p].engine.core.ix.commits.get(&c).unwrap();
            let keys = m.view.aspects.iter().position(|a| a.ak.as_str() == "keys.0" && a.tid == t).unwrap();
            assert_eq!(m.valid_at(keys), on, "peer {p}, vouches written {on}");
        }
    }
}

// spec/permissions.md §5.1 Vouches (Writing; what is owed is re-derived): W holds R and X's
// grant but writes nothing (writing off); after a restart, its next transaction writes the vouch
// it owes, and the grant stands at every node.
#[test]
fn a_vouch_owed_across_a_restart_is_written_spec_perm_5_1() {
    let (mut lp, t) = world(4);
    for p in &mut lp.peers {
        p.engine.write_vouches(false);
    }
    grant(&mut lp, 1, t, 3, Role::Write);
    lp.sync(1, 2).unwrap();
    remove(&mut lp, 0, t, 1);
    lp.sync(0, 2).unwrap();
    assert!(vouches(&lp, 2, t).is_empty(), "nothing written while off");
    lp.peers[2].restart(7).unwrap();
    let mut m = Mutation::new();
    let me = lp.peers[2].engine.me();
    lp.peers[2].engine.new_thing(&mut m, me);
    lp.peers[2].commit(m).unwrap();
    assert_eq!(vouches(&lp, 2, t).len(), 1, "written after the restart");
    lp.sync_all().unwrap();
    for p in 0..4 {
        assert_eq!(role(&lp, p, 3, t), Some(Role::Write), "peer {p}");
    }
}

/// X (peer 1), removed by H, signs a grant to H stamped before R and a flood of `flood` vouches
/// and as many addenda keyed by R listing its own grant of K, which no one else received; the
/// removals W judges as it then writes elsewhere.
fn junk_judged(flood: usize) -> u64 {
    let (mut lp, t) = world(4);
    let c = grant(&mut lp, 1, t, 3, Role::Write);
    let r = remove(&mut lp, 0, t, 1);
    let rts = lp.peers[0].engine.header(&r).unwrap().ts;
    lp.sync_all().unwrap();
    // the junk grant, stamped before R, and the forged vouches
    let h = lp.peers[0].engine.me();
    lp.peers[1].engine.core.skip_writer_rules = true;
    let mut m = Mutation::new();
    crate::flows::put_edge(&mut m, t, h, &edge(Role::Read)).unwrap();
    m.ts = osis_base::Ts::from_u64(rts.to_u64() - 2);
    m.unchecked = true;
    lp.peers[1].commit(m).unwrap();
    for _ in 0..flood {
        let mut m = Mutation::new();
        let list = ct::Frontier { commits: [c].into_iter().collect() };
        m.op(t, &ct::VOUCHES, PathOp { path: vec![PathSeg::Key(Value::bytes(&r.0))], op: Op::Put(list.to_value()) }).unwrap();
        m.unchecked = true;
        lp.peers[1].commit(m).unwrap();
        // and forged addenda keyed by R listing the junk grant
        let mut m = Mutation::new();
        let list = ct::Frontier { commits: [c].into_iter().collect() };
        m.op(t, &ct::ADDENDA, PathOp { path: vec![PathSeg::Key(Value::bytes(&r.0))], op: Op::Put(list.to_value()) }).unwrap();
        m.unchecked = true;
        lp.peers[1].commit(m).unwrap();
        lp.advance(1000);
    }
    lp.sync_all().unwrap();
    osis_base::costs::take();
    let mut m = Mutation::new();
    let me = lp.peers[2].engine.me();
    let u = lp.peers[2].engine.new_thing(&mut m, me);
    lp.peers[2].commit(m).unwrap();
    lp.peers[2].engine.grant(&u, &h, &edge(Role::Read)).unwrap();
    let judged = osis_base::costs::take().into_iter().find(|(k, _, _)| *k == "vouches: removals judged").map_or(0, |x| x.2);
    for p in 0..4 {
        assert_eq!(role(&lp, p, 3, t), None, "peer {p}: K's grant fell");
        assert_eq!(role(&lp, p, 1, t), None, "peer {p}: X removed");
        assert_eq!(role(&lp, p, 0, t), Some(Role::Admin), "peer {p}: H admin");
        assert!(lp.peers[p].engine.core.timelines.get(&t).unwrap().counted().next().is_none(), "peer {p}: no entry counts");
    }
    judged
}

// spec/permissions.md §5.1 Vouches (an entry counts only where W could write c; nothing trusts
// a vouch's word), §5.2 Addenda: a removed party's junk grant and its forged vouches and addenda
// revive nobody and nothing counts, at every node; and a flood of them costs a later write the
// same removals judged as one of each (W's write joins R's component by its author, and R,
// woken by the junk grant ordered before it, is filed there).
#[test]
fn a_removed_partys_junk_grant_and_forged_vouches_change_nothing_spec_perm_5_1() {
    let (one, ten) = (junk_judged(1), junk_judged(10));
    println!("vouches: removals judged by a write after a flood: {one} at 1, {ten} at 10");
    assert_eq!(one, ten);
}

// spec/permissions.md §4 (Vouches travel with their removal), spec/crypto.md §4 (Roles secrets):
// a holder granted without history after the vouch gets it with R and keeps X's grant as every
// other node does.
#[test]
fn a_holder_granted_without_history_keeps_the_vouched_grant_spec_perm_5_1() {
    let (mut lp, t) = world(5);
    grant(&mut lp, 1, t, 3, Role::Write);
    lp.sync(1, 2).unwrap();
    remove(&mut lp, 0, t, 1);
    for (a, b) in [(0, 2), (2, 0), (0, 3)] {
        lp.sync(a, b).unwrap();
    }
    let f = lp.peers[4].engine.me();
    lp.peers[0].engine.grant_with(&t, &f, &edge(Role::Read), crate::flows::edges::History::None).unwrap();
    lp.advance(1000);
    lp.sync(0, 4).unwrap();
    assert_eq!(vouches(&lp, 4, t).len(), 1, "the vouch reached the holder granted without history");
    assert_eq!(role(&lp, 4, 3, t), Some(Role::Write));
    assert_eq!(role(&lp, 4, 1, t), None);
}

/// Peer 2 (W) holding `n` removals on `t` owing nothing (H grants peer 3 write, peer 3 writes on
/// `t` and H, having received it, removes peer 3, `n` times: each demotes below write and its
/// frontier lists everything, so no vouch or addendum is owed): the removals W judges as H then
/// grants on another thing and W syncs, and W receives a later commit of peer 3's.
fn judged_per_step(n: usize) -> u64 {
    let (mut lp, t) = world(4);
    let mut last = None;
    for i in 0..n {
        grant(&mut lp, 0, t, 3, Role::Write);
        lp.sync(0, 3).unwrap();
        let mut m = Mutation::new();
        m.set(t, &osis_base::Ak::new("x:e.0").unwrap(), &Value::Int(i64::try_from(i).unwrap())).unwrap();
        lp.peers[3].commit(m).unwrap();
        lp.sync(3, 0).unwrap();
        lp.sync(3, 2).unwrap();
        last = Some(remove(&mut lp, 0, t, 3));
    }
    lp.sync(0, 2).unwrap();
    let w3 = lp.peers[3].engine.me();
    assert!(last.is_none_or(|r| lp.peers[2].engine.core.timelines.get(&t).unwrap().demoted_by(&r).contains(&(w3, t, Role::Write))), "each removal demotes peer 3 below write");
    let mut m = Mutation::new();
    let me = lp.peers[0].engine.me();
    let u = lp.peers[0].engine.new_thing(&mut m, me);
    lp.peers[0].commit(m).unwrap();
    lp.hold(u);
    grant(&mut lp, 0, u, 2, Role::Read);
    lp.sync(0, 2).unwrap();
    grant(&mut lp, 0, u, 1, Role::Read);
    // and the removed party writing after its removals (a commit by a party filed under each,
    // ordered after them: none due)
    let mut m = Mutation::new();
    let p3 = lp.peers[3].engine.me();
    lp.peers[3].engine.new_thing(&mut m, p3);
    let late = lp.peers[3].commit(m).unwrap().unwrap();
    osis_base::costs::take();
    lp.sync(0, 2).unwrap();
    let pk = lp.peers[3].engine.package(&late).unwrap().unwrap();
    lp.deliver(2, &pk).unwrap();
    osis_base::costs::take().into_iter().find(|(k, _, _)| *k == "vouches: removals judged").map_or(0, |x| x.2)
}

// spec/permissions.md §5.1 Vouches (Writing), §5.2 Addenda (Writing), notes/principles.md (Check
// scaling): an idle node's work per step does not grow with the removals it holds owing nothing.
#[test]
fn removals_owing_nothing_cost_a_step_nothing_spec_perm_5_1() {
    let (small, big) = (judged_per_step(2), judged_per_step(20));
    println!("vouches: removals judged per step: {small} at n, {big} at 10n");
    assert_eq!(small, big);
}

// spec/permissions.md §5.1 Vouches (Writing: R's window, by its `ts` and before R arrived): H's
// clock runs ahead, so R reaches W before its `ts`. X's grant reaching W after R, though before
// R's `ts`, is not vouched for (a thief's backdated write landing on a witness that holds R is
// lost); reaching W before R (a millisecond earlier) it is, and the grant stands at every node.
#[test]
fn a_grant_received_after_an_early_removal_is_not_vouched_for_spec_perm_5_1() {
    for before in [true, false] {
        let (mut lp, t) = world(4);
        let c = grant(&mut lp, 1, t, 3, Role::Write);
        lp.peers[0].clock.advance(10_000);
        let r = remove(&mut lp, 0, t, 1);
        let order = if before { [(1, 2), (0, 2)] } else { [(0, 2), (1, 2)] };
        for (a, b) in order {
            lp.sync(a, b).unwrap();
            lp.advance(1);
        }
        let rts = lp.peers[0].engine.header(&r).unwrap().ts;
        let got = lp.peers[2].engine.core.ix.commits.get(&c).unwrap().received;
        assert!(got.0 <= rts.wall_ms().0, "received by R's ts");
        lp.advance(20_000);
        lp.peers[2].tick().unwrap();
        // an open judges every removal again: owed is a function of what is held and received
        lp.peers[2].restart(7).unwrap();
        let mut m = Mutation::new();
        let me = lp.peers[2].engine.me();
        lp.peers[2].engine.new_thing(&mut m, me);
        lp.peers[2].commit(m).unwrap();
        assert_eq!(vouches(&lp, 2, t).len(), usize::from(before), "W vouches for c only when received before R");
        lp.sync_all().unwrap();
        for p in 0..4 {
            assert_eq!(role(&lp, p, 3, t), before.then_some(Role::Write), "peer {p}, before {before}");
        }
    }
}
