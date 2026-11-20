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

/// X (peer 1), removed by H, signs `flood` grants to H stamped before R and `flood` vouches
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
    for i in 0..flood {
        let mut m = Mutation::new();
        crate::flows::put_edge(&mut m, t, h, &edge(Role::Read)).unwrap();
        m.ts = osis_base::Ts::from_u64(rts.to_u64() - 2 - u64::try_from(i).unwrap());
        m.unchecked = true;
        lp.peers[1].commit(m).unwrap();
    }
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
// a vouch's word), §5.2 Addenda: a removed party's backdated junk grants and its forged vouches and addenda
// revive nobody and nothing counts, at every node; and a later write of W's, moving nothing R's
// judgement reads, judges no removal however large the flood.
#[test]
fn a_removed_partys_junk_grant_and_forged_vouches_change_nothing_spec_perm_5_1() {
    let (one, ten) = (junk_judged(1), junk_judged(10));
    println!("vouches: removals judged by a write after a flood: {one} at 1, {ten} at 10");
    assert_eq!((one, ten), (0, 0));
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

/// H removes X (peer 1); X, not holding the removal, grants K (peer 3) write and removes it
/// again `k` times, all stamped after it: `k` removals never applying at W. The removals W
/// judges as it then grants on `t`, an honest write in their component.
fn unapplied_judged(k: usize) -> u64 {
    let (mut lp, t) = world(4);
    let r = remove(&mut lp, 0, t, 1);
    for p in [2, 3] {
        lp.sync(0, p).unwrap();
    }
    let mut junk = Vec::new();
    for _ in 0..k {
        grant(&mut lp, 1, t, 3, Role::Write);
        junk.push(remove(&mut lp, 1, t, 3));
    }
    lp.sync_all().unwrap();
    let tl = lp.peers[2].engine.core.timelines.get(&t).unwrap();
    assert!(junk.iter().all(|j| !tl.is_applied(&osis_perm::WriteId(*j, 0))), "X's removals apply nowhere");
    assert!(tl.is_applied(&osis_perm::WriteId(r, 0)));
    osis_base::costs::take();
    grant(&mut lp, 2, t, 3, Role::Read);
    osis_base::costs::take().into_iter().find(|(k, _, _)| *k == "vouches: removals judged").map_or(0, |x| x.2)
}

// spec/permissions.md §5.1 Vouches (Writing), notes/principles.md (Fast by construction): a
// removal not applying is judged again only when it starts to (its change enters the walk), so
// a removed party's never-applying removals cost an honest write in their component nothing.
#[test]
fn never_applying_removals_cost_an_honest_write_nothing_spec_perm_5_1() {
    let (small, big) = (unapplied_judged(2), unapplied_judged(20));
    println!("vouches: never-applying removals judged by an honest write: {small} at k = 2, {big} at k = 20");
    assert_eq!((small, big), (0, 0));
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


// notes/engine-store.md Index tables (every row a function of the held commits): a role commit
// forgotten whole takes everything perm read of it along (`apply::unindex`), its vouches and
// other role-class parts as well as its edge writes. W vouches on t by hand; peer 3, holding t
// and the vouch, releases t, which goes whole with the vouch's commit: its live index is the
// store opened and rebuilt afresh, before and after a restart, and holds no vouch.
#[test]
fn a_released_things_vouch_leaves_perm_with_it_spec_perm_5_1() {
    let (mut lp, t) = world(4);
    for p in &mut lp.peers {
        p.engine.write_vouches(false);
    }
    let r = remove(&mut lp, 0, t, 1);
    let v = vouch(&mut lp, 2, t, r, &[]);
    lp.sync_all().unwrap();
    assert_eq!(vouches(&lp, 3, t), vec![(lp.peers[2].engine.me(), v)], "peer 3 holds W's vouch");
    let e = &mut lp.peers[3].engine;
    e.unhold(osis_base::Strong(t)).unwrap();
    e.released(&std::collections::BTreeSet::from([t])).unwrap();
    assert!(!e.core.ix.commits.contains_key(&v), "the vouch's commit went with t");
    assert!(vouches(&lp, 3, t).is_empty(), "perm reads no vouch of a commit not held");
    lp.peers[3].engine.check_index();
    lp.peers[3].restart(7).unwrap();
    assert!(vouches(&lp, 3, t).is_empty(), "nor after a restart");
}

// notes/engine-store.md Index tables: a role commit losing a part re-reads as what stays held
// (`retention::needed::settle` calls `add_role_commit` with the parts left). H writes one commit
// vouching on t and on u; peer 3, holding both, releases t: the commit stays for its part on u,
// its vouch on t goes and the one on u stays, before and after a restart.
#[test]
fn a_role_commit_losing_a_part_reads_as_what_stays_spec_perm_5_1() {
    let (mut lp, t) = world(4);
    for p in &mut lp.peers {
        p.engine.write_vouches(false);
    }
    let h = lp.peers[0].engine.me();
    let mut m = Mutation::new();
    let u = lp.peers[0].engine.new_thing(&mut m, h);
    lp.peers[0].commit(m).unwrap();
    lp.hold(u);
    let r = remove(&mut lp, 0, t, 1);
    let mut m = Mutation::new();
    for x in [t, u] {
        m.op(x, &ct::VOUCHES, PathOp { path: vec![PathSeg::Key(Value::bytes(&r.0))], op: Op::Put(ct::Frontier { commits: Default::default() }.to_value()) }).unwrap();
    }
    let v = lp.peers[0].commit(m).unwrap().unwrap();
    lp.sync_all().unwrap();
    assert_eq!((vouches(&lp, 3, t), vouches(&lp, 3, u)), (vec![(h, v)], vec![(h, v)]), "peer 3 holds both vouches");
    let e = &mut lp.peers[3].engine;
    e.unhold(osis_base::Strong(t)).unwrap();
    e.released(&std::collections::BTreeSet::from([t])).unwrap();
    assert!(e.core.ix.commits.contains_key(&v), "the commit stays for its part on u");
    for restart in [false, true] {
        if restart {
            lp.peers[3].restart(7).unwrap();
        }
        assert!(vouches(&lp, 3, t).is_empty(), "restart {restart}: no vouch on t");
        assert_eq!(vouches(&lp, 3, u), vec![(h, v)], "restart {restart}: the vouch on u");
        lp.peers[3].engine.check_index();
    }
}

// notes/engine-store.md Index tables: what perm reads of a role commit is a function of its held
// parts, whatever order they arrived in (`atomic::join_late` re-derives it whole). H writes one
// commit vouching on t and on u; peer 3 gets it whole, or a part at a time in either order with
// a pass end and a restart between: each ends holding the same vouches, its live index the
// store opened and rebuilt afresh.
#[test]
fn a_role_commit_arriving_in_parts_reads_as_whole_spec_perm_5_1() {
    let (mut lp, t) = world(4);
    for p in &mut lp.peers {
        p.engine.write_vouches(false);
    }
    let h = lp.peers[0].engine.me();
    let mut m = Mutation::new();
    let u = lp.peers[0].engine.new_thing(&mut m, h);
    lp.peers[0].commit(m).unwrap();
    lp.hold(u);
    let r = remove(&mut lp, 0, t, 1);
    lp.sync_all().unwrap();
    let mut m = Mutation::new();
    for x in [t, u] {
        m.op(x, &ct::VOUCHES, PathOp { path: vec![PathSeg::Key(Value::bytes(&r.0))], op: Op::Put(ct::Frontier { commits: Default::default() }.to_value()) }).unwrap();
    }
    let v = lp.peers[0].commit(m).unwrap().unwrap();
    let pk = lp.peers[0].engine.package(&v).unwrap().unwrap();
    let blob = osis_commit::CommitBlob::decode(&pk.bytes).unwrap();
    let ais: Vec<usize> = blob.parts.iter().map(|p| p.ai).collect();
    assert_eq!(ais.len(), 2, "a part on each thing");
    let one = |ai: usize| crate::local_peer::holding(&pk, &blob, &std::collections::BTreeSet::from([ai]));
    for order in [vec![pk.clone()], vec![one(ais[0]), one(ais[1])], vec![one(ais[1]), one(ais[0])]] {
        let mut c = lp.copy().unwrap();
        for (i, p) in order.iter().enumerate() {
            c.deliver(3, p).unwrap();
            c.peers[3].engine.settle_needs().unwrap();
            if i == 0 {
                c.peers[3].restart(7).unwrap();
                let held = vouches(&c, 3, t).len() + vouches(&c, 3, u).len();
                assert_eq!(held, 3 - order.len(), "the first delivery's parts alone are held");
            }
        }
        for x in [t, u] {
            assert_eq!(vouches(&c, 3, x), vec![(h, v)], "{} parts: the vouch on {x:?}", order.len());
        }
        c.peers[3].engine.check_index();
    }
}

// notes/principles.md (scaling by counting): a release forgetting k role commits on a thing
// gives the timelines the change once, not once per commit (each update re-walks the thing's
// component, which holds the k holders): at k and 10k the same number of timeline updates.
#[test]
fn a_release_updates_the_timelines_once_whatever_it_forgets_spec_perm_5_1() {
    let work = |k: usize| {
        let (mut lp, t) = world(4);
        let me = lp.peers[0].engine.me();
        for _ in 0..k {
            let mut m = Mutation::new();
            let u = lp.peers[0].engine.new_thing(&mut m, me);
            lp.peers[0].commit(m).unwrap();
            lp.peers[0].engine.grant(&t, &u, &edge(Role::Read)).unwrap();
        }
        lp.sync_all().unwrap();
        let e = &mut lp.peers[3].engine;
        assert!(e.core.ix.held.commits_on(&t).len() > k, "k {k}: peer 3 holds the grants");
        e.unhold(osis_base::Strong(t)).unwrap();
        osis_base::costs::take();
        e.released(&std::collections::BTreeSet::from([t])).unwrap();
        let c = osis_base::costs::take();
        assert!(e.core.ix.held.commits_on(&t).is_empty(), "k {k}: the grants went with t");
        e.check_index();
        c.into_iter().find(|x| x.0 == "timelines").map_or(0, |x| x.2)
    };
    let (small, large) = (work(3), work(30));
    assert_eq!(small, large, "timeline updates at k, 10k");
}

// notes/engine-store.md Index tables (every row a function of the held commits), spec/permissions.md
// §5.1 Vouches ("W could write c": W holds the role each other role-class part of c requires): X
// rotates the write keys of t and of S, a thing of its own peer 3 reads, in one commit c, which W
// and peer 3 receive; H removes X without c; W vouches c. W holds no role on S, so the vouch keeps
// nothing and c's keys on t are invalid. Peer 3 releases S (its record goes): W's role on S is
// then unknown, still no role, so the verdict stays, live and after a restart (were the part on
// an unknown thing dropped, releasing S would make the vouch count).
#[test]
fn a_vouched_commits_parts_read_alike_across_a_restart_spec_perm_5_1() {
    let (mut lp, t) = world(4);
    for p in &mut lp.peers {
        p.engine.write_vouches(false);
    }
    let x = lp.peers[1].engine.me();
    let mut m = Mutation::new();
    let s = lp.peers[1].engine.new_thing(&mut m, x);
    lp.peers[1].commit(m).unwrap();
    grant(&mut lp, 1, s, 3, Role::Read);
    lp.hold_at(3, s);
    lp.sync(1, 3).unwrap();
    let all: Vec<Tid> = lp.peers.iter().map(|p| p.engine.me()).collect();
    let c = lp.peers[1].engine.rotate_boxing_only(&[t, s], &[Role::Write], &all).unwrap().unwrap();
    lp.advance(1000);
    for i in [2, 3] {
        lp.sync(1, i).unwrap();
    }
    let r = remove(&mut lp, 0, t, 1);
    lp.sync(0, 2).unwrap();
    vouch(&mut lp, 2, t, r, &[c]);
    lp.sync(2, 3).unwrap();
    lp.sync(0, 3).unwrap();
    let valid = |lp: &LocalPeer| {
        let m = lp.peers[3].engine.core.ix.commits.get(&c).unwrap();
        let ai = m.view.aspects.iter().position(|a| a.ak.as_str() == "keys.0" && a.tid == t).unwrap();
        m.valid_at(ai)
    };
    assert!(lp.peers[3].engine.core.ix.held.created(&s).is_some(), "peer 3 holds S's record");
    assert!(!valid(&lp), "W could not write c's keys on S: the vouch keeps nothing");
    let e = &mut lp.peers[3].engine;
    e.unhold(osis_base::Strong(s)).unwrap();
    e.released(&std::collections::BTreeSet::from([s])).unwrap();
    assert!(e.core.ix.held.created(&s).is_none(), "S's record went");
    let live = valid(&lp);
    lp.peers[3].restart(7).unwrap();
    assert_eq!(valid(&lp), live, "c's verdict across a restart");
    assert!(!live, "c's keys on S still need a role W lacks: releasing S keeps nothing");
    lp.peers[3].engine.check_index();
}

// notes/principles.md (scaling by counting): an open rebuilding the index reads each role
// commit's other role-class parts once (`validity::parts_moved`, from `note_required`) and
// updates the timelines a fixed number of times (`rejudge_all` between rounds): at k and 10k
// rotations, the same timeline updates and one more parts read per rotation.
#[test]
fn an_open_reads_each_commits_role_parts_a_bounded_number_of_times_spec_perm_5_1() {
    let work = |k: usize| {
        let (mut lp, t) = world(4);
        let all: Vec<Tid> = lp.peers.iter().map(|p| p.engine.me()).collect();
        for _ in 0..k {
            lp.peers[1].engine.rotate_boxing_only(&[t], &[Role::Write], &all).unwrap().unwrap();
            lp.advance(10);
        }
        lp.sync_all().unwrap();
        let e = &mut lp.peers[3].engine;
        osis_base::costs::take();
        e.rebuild_index().unwrap();
        let c = osis_base::costs::take();
        let get = |n: &str| c.iter().find(|x| x.0 == n).map_or(0, |x| x.2);
        e.check_index();
        (get("timelines"), get("role parts read"))
    };
    let ((t1, p1), (t2, p2)) = (work(3), work(30));
    assert_eq!(t1, t2, "timeline updates at k, 10k");
    assert_eq!(p2 - p1, 27, "parts read at k {p1}, 10k {p2}: once per rotation");
}

/// A team (peer 3's actor) with `members` members holds write on `t`; H removes it and grants
/// it again, 5 times; W syncs. The removals' entries in W's wake index
/// (`Indexes::vouch_wake`).
fn wake_entries(members: usize) -> usize {
    let (mut lp, t) = world(4);
    // the team: an ordinary thing peer 3 makes, its members granted on it
    let me3 = lp.peers[3].engine.me();
    let mut m = Mutation::new();
    let team = lp.peers[3].engine.new_thing(&mut m, me3);
    lp.peers[3].commit(m).unwrap();
    lp.hold(team);
    for i in 0..members {
        let who = Tid::from_bytes([u8::try_from(i + 1).unwrap(); 15]);
        let mut m = Mutation::new();
        m.op(team, &ct::ROLES, PathOp { path: vec![PathSeg::Key(Value::Weak(who))], op: Op::Set(edge(Role::Write).to_value()) }).unwrap();
        lp.peers[3].commit(m).unwrap().unwrap();
    }
    lp.sync_all().unwrap();
    for _ in 0..5 {
        lp.peers[0].engine.grant(&t, &team, &edge(Role::Write)).unwrap();
        lp.advance(1000);
        lp.advance(1000);
        lp.peers[0].engine.demote(&t, &Demotion { holder: team, new: None, retain: None }).unwrap();
        lp.advance(1000);
    }
    lp.sync(0, 2).unwrap();
    lp.peers[2].engine.core.ix.vouch_wake.len()
}

// spec/permissions.md §5.1 Vouches (Writing), notes/principles.md (Fast by construction): a
// removal is filed for wakes under the holders it names and its author, one entry each, so a
// removal of a team costs the same whatever its membership.
#[test]
fn a_removal_of_a_team_is_filed_once_whatever_its_members_spec_perm_5_1() {
    let (small, big) = (wake_entries(2), wake_entries(20));
    println!("vouches: wake entries for 5 removals of a team: {small} at 2 members, {big} at 20");
    assert_eq!((small, big), (10, 10));
}

// spec/permissions.md §5.1 Vouches (Writing: a party comes into question at R by a grant
// ordered before it): a team X (minted by peer 1) holds admin on `t`; peer 1 makes Y (peer 3)
// an admin of X (G), and Y grants K (peer 4) write on `t` (c). W (peer 2) receives c in time
// but not G; H removes X without either. W judges R with Y in question nowhere; then G arrives,
// ordered before R: Y comes into question, c becomes a candidate, W vouches for it and K's
// grant stands at every node.
#[test]
fn a_late_grant_bringing_a_party_into_question_is_vouched_for_spec_perm_5_1() {
    let (mut lp, t) = world(5);
    let x = lp.peers[1].engine.me();
    let mut m = Mutation::new();
    let team = lp.peers[1].engine.new_thing(&mut m, x);
    lp.peers[1].commit(m).unwrap();
    lp.hold(team);
    lp.sync_all().unwrap();
    lp.peers[0].engine.grant(&t, &team, &edge(Role::Admin)).unwrap();
    lp.advance(1000);
    lp.sync_all().unwrap();
    let g = grant(&mut lp, 1, team, 3, Role::Admin);
    lp.sync(1, 3).unwrap();
    let c = grant(&mut lp, 3, t, 4, Role::Write);
    let pk = lp.peers[3].engine.package(&c).unwrap().unwrap();
    lp.deliver(2, &pk).unwrap();
    lp.advance(1000);
    let d = Demotion { holder: team, new: None, retain: None };
    let r = *lp.peers[0].engine.demote(&t, &d).unwrap().commits.last().unwrap();
    lp.advance(1000);
    lp.sync(0, 2).unwrap();
    assert!(vouches(&lp, 2, t).is_empty(), "Y is in question nowhere yet");
    let pk = lp.peers[1].engine.package(&g).unwrap().unwrap();
    lp.deliver(2, &pk).unwrap();
    lp.advance(1000);
    lp.peers[2].tick().unwrap();
    let w = lp.peers[2].engine.me();
    let mine: Vec<CommitId> = vouches(&lp, 2, t).into_iter().filter(|(a, _)| *a == w).map(|(_, v)| v).collect();
    assert_eq!(mine.len(), 1, "W vouches once G brings Y into question at R");
    let tl = lp.peers[2].engine.core.timelines.get(&t).unwrap();
    assert!(tl.counted().any(|(rr, cc)| rr == r && cc == c), "W's vouch keyed by R lists c");
    lp.sync_all().unwrap();
    for p in 0..5 {
        assert_eq!(role(&lp, p, 4, t), Some(Role::Write), "peer {p}: K's grant stands");
    }
}

/// H removes X (peer 1), W (2) holding X's grant of K received in time; X then signs `j`
/// content commits on `t` stamped before R, reaching W after R: the removals W judges.
fn backdated_content_judged(j: usize) -> u64 {
    let (mut lp, t) = world(4);
    grant(&mut lp, 1, t, 3, Role::Write);
    lp.sync(1, 2).unwrap();
    let r = remove(&mut lp, 0, t, 1);
    let rts = lp.peers[0].engine.header(&r).unwrap().ts;
    lp.sync_all().unwrap();
    lp.peers[1].engine.core.skip_writer_rules = true;
    for i in 0..j {
        let mut m = Mutation::new();
        m.set(t, &osis_base::Ak::new("x:j.0").unwrap(), &Value::Int(i64::try_from(i).unwrap())).unwrap();
        m.ts = osis_base::Ts::from_u64(rts.to_u64() - 2 - u64::try_from(i).unwrap());
        m.unchecked = true;
        lp.peers[1].commit(m).unwrap();
    }
    osis_base::costs::take();
    lp.sync(1, 2).unwrap();
    osis_base::costs::take().into_iter().find(|(k, _, _)| *k == "vouches: removals judged").map_or(0, |x| x.2)
}

// spec/permissions.md §5.1 Vouches (Writing: R's window), notes/principles.md (Fast by
// construction): a commit with no edge write moves no walk and is a candidate only of a removal
// it reached a node before, so a removed party's backdated content arriving after R judges
// nothing, however much of it.
#[test]
fn a_removed_partys_backdated_content_judges_nothing_spec_perm_5_1() {
    let (one, ten) = (backdated_content_judged(1), backdated_content_judged(10));
    println!("vouches: removals judged by backdated content after R: {one} at 1, {ten} at 10");
    assert_eq!((one, ten), (0, 0));
}

// spec/permissions.md §5.1 Vouches ("W could write c": W holds the role each part of c needs):
// H makes thing S and team A, gives A admin on `t` and on S, and makes X (peer 1) an admin of A
// (its direct grant on `t` removed). X rotates the write keys of `t` and S in one commit c through
// A, which W (peer 2, admin on `t` alone) receives; H removes X from A without c, and W vouches on
// `t` for c. W could not write c's part on S, so the entry counts for nothing: c's parts fall on
// both things at every node holding it: no vouch on `t` keeps a part on S (stated paths keep the
// part on `t` alone: notes/a1-spec/permissions.md §5.1 Vouches). With W an admin of S too, both
// stay.
#[test]
fn a_vouch_on_one_thing_keeps_nothing_on_another_its_voucher_holds_no_role_on_spec_perm_5_1() {
    for w_on_s in [false, true] {
        let (mut lp, t) = world(4);
        for p in &mut lp.peers {
            p.engine.write_vouches(false);
        }
        let h = lp.peers[0].engine.me();
        let x = lp.peers[1].engine.me();
        let mut m = Mutation::new();
        let s = lp.peers[0].engine.new_thing(&mut m, h);
        let a = lp.peers[0].engine.new_thing(&mut m, h);
        lp.peers[0].commit(m).unwrap();
        lp.hold(s);
        lp.hold(a);
        // X holds admin on `t` only through A
        remove(&mut lp, 0, t, 1);
        for on in [t, s] {
            lp.peers[0].engine.grant(&on, &a, &edge(Role::Admin)).unwrap();
        }
        lp.peers[0].engine.grant(&a, &x, &edge(Role::Admin)).unwrap();
        if w_on_s {
            grant(&mut lp, 0, s, 2, Role::Admin);
        }
        lp.advance(1000);
        lp.sync_all().unwrap();
        let all: Vec<Tid> = lp.peers.iter().map(|p| p.engine.me()).collect();
        let c = lp.peers[1].engine.rotate_boxing_only(&[t, s], &[Role::Write], &all).unwrap().unwrap();
        let pk = lp.peers[1].engine.package(&c).unwrap().unwrap();
        lp.deliver(2, &pk).unwrap();
        lp.advance(1000);
        let r = *lp.peers[0].engine.demote(&a, &Demotion { holder: x, new: None, retain: None }).unwrap().commits.last().unwrap();
        lp.advance(1000);
        lp.sync(0, 2).unwrap();
        vouch(&mut lp, 2, t, r, &[c]);
        lp.sync_all().unwrap();
        // c's write-key rotation on each thing, valid or not, at every node holding it
        let valid = |lp: &LocalPeer, p: usize, on: Tid| {
            let m = lp.peers[p].engine.core.ix.commits.get(&c).unwrap();
            let ai = m.view.aspects.iter().position(|x| x.ak.as_str() == "keys.0" && x.tid == on).unwrap();
            m.valid_at(ai)
        };
        for p in [0, 2, 3] {
            assert_eq!((valid(&lp, p, t), valid(&lp, p, s)), (w_on_s, w_on_s), "peer {p}, W on S {w_on_s}");
        }
    }
}

// issues/voucher-admin-in-first-walk.md under today's rule (spec/permissions.md §5.1 Vouches: "W
// could write c" judged in the first walk, where no vouch counts): K's team A2 holds admin on `t`
// and X (peer 1) admin of A2. X removes A2 from `t`; W (peer 2) alone receives it; H removes X
// from `t` without it, and W vouches for X's removal of A2. X then makes Z (peer 3) an admin of A2
// and backdates a grant of write on `t` to Z, which Z vouches for. In the first walk X's removal of
// A2 is dropped (only W's vouch keeps it), so Z could write the grant there and its entry counts;
// in the reading A2 holds nothing on `t`, so Z never held the right, and the grant must fall, as it
// does without Z's vouch. Today it stands with it at every node.
#[test]
#[ignore = "issues/voucher-admin-in-first-walk.md"]
fn repro_a_voucher_holds_admin_by_a_share_only_a_vouch_removes_spec_perm_5_1() {
    for z_vouches in [false, true] {
        let (mut lp, t) = world(5);
        for p in &mut lp.peers {
            p.engine.write_vouches(false);
        }
        let k = lp.peers[4].engine.me();
        let mut m = Mutation::new();
        let a2 = lp.peers[4].engine.new_thing(&mut m, k);
        lp.peers[4].commit(m).unwrap();
        lp.hold(a2);
        lp.sync_all().unwrap();
        grant(&mut lp, 4, a2, 1, Role::Admin);
        lp.peers[0].engine.grant(&t, &a2, &edge(Role::Admin)).unwrap();
        lp.advance(1000);
        lp.sync_all().unwrap();
        let out = *lp.peers[1].engine.demote(&t, &Demotion { holder: a2, new: None, retain: None }).unwrap().commits.last().unwrap();
        lp.advance(1000);
        lp.sync(1, 2).unwrap();
        let r = remove(&mut lp, 0, t, 1);
        lp.sync(0, 2).unwrap();
        vouch(&mut lp, 2, t, r, &[out]);
        grant(&mut lp, 1, a2, 3, Role::Admin);
        let rts = lp.peers[0].engine.header(&r).unwrap().ts;
        let z = lp.peers[3].engine.me();
        lp.peers[1].engine.core.skip_writer_rules = true;
        let mut m = Mutation::new();
        crate::flows::put_edge(&mut m, t, z, &edge(Role::Write)).unwrap();
        m.ts = osis_base::Ts::from_u64(rts.to_u64() - 2);
        m.unchecked = true;
        let gz = lp.peers[1].commit(m).unwrap().unwrap();
        lp.sync_all().unwrap();
        // Z's vouch, which Z's own reading refuses (it holds no role on `t` there)
        if z_vouches {
            lp.peers[3].engine.core.skip_writer_rules = true;
            let mut m = Mutation::new();
            let list = ct::Frontier { commits: [gz].into_iter().collect() };
            m.op(t, &ct::VOUCHES, PathOp { path: vec![PathSeg::Key(Value::bytes(&r.0))], op: Op::Put(list.to_value()) }).unwrap();
            m.unchecked = true;
            lp.peers[3].commit(m).unwrap();
            lp.advance(1000);
        }
        lp.sync_all().unwrap();
        for p in 0..5 {
            let a2_on_t = lp.peers[p].engine.core.timelines.role(&a2, &t, At::END);
            assert_eq!((a2_on_t, role(&lp, p, 1, t)), (None, None), "peer {p}: A2's removal kept by W's vouch, X removed");
            assert_eq!(role(&lp, p, 3, t), None, "peer {p}, Z vouching {z_vouches}: Z's backdated grant falls");
        }
    }
}
// spec/permissions.md §5.1 Vouches (Writing), spec/sync-set.md §2 (Writing: an owed write
// waits): team N (peer 0's thing) holds admin through `t`'s grant; X (peer 1) grants K (peer 3)
// write on N (c), received by W (peer 2) alone, W not holding N. H removes X from `t` (R): X
// falls on N with it, c is a candidate and W could write it, but N is outside W's node closure,
// so the vouch waits. N then enters it: W vouches, and K's grant stands at every node.
#[test]
fn a_vouch_owed_on_a_thing_outside_the_node_closure_is_written_as_it_enters_spec_perm_5_1() {
    let (mut lp, t) = world(4);
    let h = lp.peers[0].engine.me();
    let mut m = Mutation::new();
    let n = lp.peers[0].engine.new_thing(&mut m, h);
    lp.peers[0].commit(m).unwrap();
    for p in [0, 1, 3] {
        lp.hold_at(p, n);
    }
    lp.peers[0].engine.grant(&n, &t, &edge(Role::Admin)).unwrap();
    lp.advance(1000);
    lp.sync_all().unwrap();
    assert!(!lp.peers[2].engine.closure_holds(&n), "W does not hold N");
    assert_eq!(role(&lp, 2, 2, n), Some(Role::Admin), "W holds admin on N through t");
    let c = grant(&mut lp, 1, n, 3, Role::Write);
    let pk = lp.peers[1].engine.package(&c).unwrap().unwrap();
    lp.deliver(2, &pk).unwrap();
    lp.advance(1000);
    assert!(lp.peers[2].engine.core.ix.commits.contains_key(&c), "W holds c");
    let r = remove(&mut lp, 0, t, 1);
    lp.sync(0, 2).unwrap();
    lp.peers[2].tick().unwrap();
    assert!(vouches(&lp, 2, n).is_empty(), "the vouch waits for N");
    lp.hold_at(2, n);
    lp.advance(1000);
    lp.peers[2].tick().unwrap();
    let w = lp.peers[2].engine.me();
    let mine: Vec<CommitId> = vouches(&lp, 2, n).into_iter().filter(|(a, _)| *a == w).map(|(_, v)| v).collect();
    assert_eq!(mine.len(), 1, "W vouches once N enters its node closure");
    let tl = lp.peers[2].engine.core.timelines.get(&n).unwrap();
    assert!(tl.counted().any(|(rr, cc)| rr == r && cc == c), "W's vouch keyed by R lists c");
    lp.sync_all().unwrap();
    for p in 0..4 {
        assert_eq!(role(&lp, p, 3, n), Some(Role::Write), "peer {p}: K's grant stands");
    }
}

// spec/permissions.md §5.1 Vouches (Writing: R applying in its own first walk): Y (peer 3) is
// made an admin of `t` by G, which W (peer 2) receives only after Y's removal of X (R). X's
// grant of K (peer 4), received by W alone, is a candidate of R; W judges R not applying (Y no
// admin yet), owing nothing. G then arrives, ordered before R: R applies (its own change in the
// walk moved), W vouches, and K's grant stands at every node.
#[test]
fn a_removal_applying_after_it_arrived_is_vouched_for_then_spec_perm_5_1() {
    let (mut lp, t) = world(5);
    let g = grant(&mut lp, 0, t, 3, Role::Admin);
    lp.sync(0, 3).unwrap();
    let c = grant(&mut lp, 1, t, 4, Role::Write);
    let pk = lp.peers[1].engine.package(&c).unwrap().unwrap();
    lp.deliver(2, &pk).unwrap();
    let r = remove(&mut lp, 3, t, 1);
    let pk = lp.peers[3].engine.package(&r).unwrap().unwrap();
    lp.deliver(2, &pk).unwrap();
    lp.advance(1000);
    lp.peers[2].tick().unwrap();
    let tl = lp.peers[2].engine.core.timelines.get(&t).unwrap();
    assert!(!tl.is_applied(&osis_perm::WriteId(r, 0)), "R applies not without G");
    assert!(vouches(&lp, 2, t).is_empty(), "nothing owed while R applies not");
    let pk = lp.peers[0].engine.package(&g).unwrap().unwrap();
    lp.deliver(2, &pk).unwrap();
    lp.advance(1000);
    lp.peers[2].tick().unwrap();
    let w = lp.peers[2].engine.me();
    assert_eq!(vouches(&lp, 2, t).iter().filter(|(a, _)| *a == w).count(), 1, "W vouches once R applies");
    lp.sync_all().unwrap();
    for p in 0..5 {
        assert_eq!(role(&lp, p, 4, t), Some(Role::Write), "peer {p}: K's grant stands");
        assert_eq!(role(&lp, p, 1, t), None, "peer {p}: X removed");
    }
}

// spec/permissions.md §5.1 Vouches (Writing), notes/engine-roles.md (Vouches, Write: R's late
// parts): H's removal of X (R) reaches W (peer 2) first without its `roles.0` part, then the
// part alone. With the part W judges R anew: it vouches for X's grant of K, received in time,
// and the grant stands at every node.
#[test]
fn a_removal_whose_edge_part_arrives_late_is_vouched_for_then_spec_perm_5_1() {
    let (mut lp, t) = world(4);
    let c = grant(&mut lp, 1, t, 3, Role::Write);
    lp.sync(1, 2).unwrap();
    let r = remove(&mut lp, 0, t, 1);
    let pk = lp.peers[0].engine.package(&r).unwrap().unwrap();
    let blob = osis_commit::CommitBlob::decode(&pk.bytes).unwrap();
    let h = lp.peers[0].engine.header(&r).unwrap();
    let edge_ai = h.aspects.iter().position(|a| a.ak.as_str() == "roles.0" && a.tid == t).unwrap();
    let rest: std::collections::BTreeSet<usize> = blob.parts.iter().map(|p| p.ai).filter(|ai| *ai != edge_ai).collect();
    assert!(!rest.is_empty(), "R carries parts beside its edge write");
    lp.deliver(2, &crate::local_peer::holding(&pk, &blob, &rest)).unwrap();
    lp.peers[2].tick().unwrap();
    assert!(vouches(&lp, 2, t).is_empty(), "no edge write held: nothing owed");
    lp.deliver(2, &crate::local_peer::holding(&pk, &blob, &std::collections::BTreeSet::from([edge_ai]))).unwrap();
    lp.advance(1000);
    lp.peers[2].tick().unwrap();
    let w = lp.peers[2].engine.me();
    let mine: Vec<CommitId> = vouches(&lp, 2, t).into_iter().filter(|(a, _)| *a == w).map(|(_, v)| v).collect();
    assert_eq!(mine.len(), 1, "W vouches once R's edge part arrives");
    lp.sync_all().unwrap();
    for p in 0..4 {
        assert_eq!(role(&lp, p, 3, t), Some(Role::Write), "peer {p}: K's grant stands");
    }
    let _ = c;
}

/// Things `n` and `elsewhere` (peer 0's), held through `t`'s admin grant by every peer but W
/// (peer 2). `m` times H grants X (peer 1) admin on `t` again, X grants K (peer 3) write on
/// `elsewhere`, received by W alone, and H removes X: `m` removals filed under `elsewhere`, owing
/// a vouch there that waits. Last X grants K write on `n` the same way and H removes X: one
/// removal filed under `n` (and `elsewhere`). The removals woken as `n` enters W's node closure.
fn woken_on_entry(m: usize) -> u64 {
    let (mut lp, t) = world(4);
    let h = lp.peers[0].engine.me();
    let mut things = Vec::new();
    for _ in 0..2 {
        let mut mu = Mutation::new();
        let n = lp.peers[0].engine.new_thing(&mut mu, h);
        lp.peers[0].commit(mu).unwrap();
        for p in [0, 1, 3] {
            lp.hold_at(p, n);
        }
        lp.peers[0].engine.grant(&n, &t, &edge(Role::Admin)).unwrap();
        things.push(n);
    }
    let (n, elsewhere) = (things[0], things[1]);
    lp.advance(1000);
    lp.sync_all().unwrap();
    for i in 0..=m {
        if i > 0 {
            grant(&mut lp, 0, t, 1, Role::Admin);
            lp.sync(0, 1).unwrap();
        }
        let on = if i == m { n } else { elsewhere };
        let c = grant(&mut lp, 1, on, 3, Role::Write);
        let pk = lp.peers[1].engine.package(&c).unwrap().unwrap();
        lp.deliver(2, &pk).unwrap();
        lp.advance(1000);
        remove(&mut lp, 0, t, 1);
        lp.sync(0, 2).unwrap();
        lp.peers[2].tick().unwrap();
    }
    let ix = &lp.peers[2].engine.core.ix;
    assert_eq!(ix.vouch_watch.get(&elsewhere).map_or(0, |s| s.len()), m + 1, "every removal filed under `elsewhere`");
    assert_eq!(ix.vouch_watch.get(&n).map_or(0, |s| s.len()), 1, "the last filed under `n`");
    assert!(ix.vouches_due.is_empty(), "none polled while it waits");
    osis_base::costs::take();
    lp.hold_at(2, n);
    let woken = osis_base::costs::take().into_iter().find(|(k, _, _)| *k == "vouches: removals woken on entry").map_or(0, |x| x.2);
    let w = lp.peers[2].engine.me();
    assert_eq!(vouches(&lp, 2, n).iter().filter(|(a, _)| *a == w).count(), 1, "W vouches on `n` as it enters");
    assert!(vouches(&lp, 2, elsewhere).is_empty(), "and nothing on `elsewhere`, still outside");
    woken
}

// spec/sync-set.md §2 (Writing: an owed write waits), notes/principles.md (Fast by construction):
// a thing entering the node closure wakes the removals filed under it, whatever is filed
// elsewhere, and none waits polled meanwhile.
#[test]
fn a_thing_entering_wakes_only_the_removals_filed_under_it_spec_perm_5_1() {
    let (small, big) = (woken_on_entry(1), woken_on_entry(10));
    println!("vouches: removals woken as a thing enters: {small} at 1 filed elsewhere, {big} at 10");
    assert_eq!((small, big), (1, 1));
}
