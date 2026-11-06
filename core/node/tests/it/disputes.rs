//! Admin disputes end to end (spec/permissions.md §5.1 Trust set; notes/disputes-plan.md
//! step 4): the backdating attack, default sides, switching, a node joining mid-dispute, the
//! trust store across a restart. Over `LocalPeer`: commits delivered by hand, so who holds what
//! first is the test's.

use crate::flows::{edge_of, people, reopen, send, spread, thing_of};
use osis_base::{CommitId, Role, Tid};
use osis_node::flows::{Demotion, PreSync};
use osis_node::local_peer::LocalPeer;
use osis_node::Event;
use std::collections::BTreeSet;

/// Admins `a` (peer 0) and `b` (peer 1) of thing `t` (first admin `c`, peer 2) remove each
/// other, neither having seen the other's removal: `b` removes `a` at a later time (`w`), `a`
/// removes `b` stamped earlier (`r`: the thief backdating, or a clock behind). Peer 2 and any
/// peers after it hold neither yet.
struct Fight {
    lp: LocalPeer,
    a: Tid,
    b: Tid,
    t: Tid,
    w: Vec<CommitId>,
    r: Vec<CommitId>,
}

fn fight(n: usize, seed: u64) -> Fight {
    let (mut lp, ps) = people(n, seed);
    let (a, b, c) = (ps[0], ps[1], ps[2]);
    let t = thing_of(&mut lp, 2, c);
    lp.peers[2].engine.grant(&t, &a, &edge_of(Role::Admin)).unwrap();
    lp.peers[2].engine.grant(&t, &b, &edge_of(Role::Admin)).unwrap();
    spread(&mut lp);
    lp.advance(1000);
    // b's clock runs ahead; a has not seen b's removal when it writes its own
    lp.peers[1].clock.advance(5000);
    let before = ids(&lp, 1);
    lp.peers[1].engine.demote(&t, &Demotion { holder: a, new: None, presync: PreSync::Synced, retain: None }).unwrap();
    let w = new_ids(&lp, 1, &before);
    let before = ids(&lp, 0);
    lp.peers[0].engine.demote(&t, &Demotion { holder: b, new: None, presync: PreSync::Synced, retain: None }).unwrap();
    let r = new_ids(&lp, 0, &before);
    Fight { lp, a, b, t, w, r }
}

fn ids(lp: &LocalPeer, i: usize) -> BTreeSet<CommitId> {
    lp.peers[i].engine.commit_ids().into_iter().collect()
}

fn new_ids(lp: &LocalPeer, i: usize, before: &BTreeSet<CommitId>) -> Vec<CommitId> {
    lp.peers[i].engine.commit_ids().into_iter().filter(|c| !before.contains(c)).collect()
}

/// Which of `a` and `b` peer `i` reads as admin of `t`.
fn admins(f: &Fight, i: usize) -> (bool, bool) {
    let r = f.lp.peers[i].engine.roster(&f.t);
    (r.contains_key(&f.a), r.contains_key(&f.b))
}

/// The one open dispute at peer `i`: b's removal of a, voided by a's earlier-stamped one.
fn the_dispute(f: &Fight, i: usize) -> osis_node::sides::DisputeInfo {
    let (ds, left) = f.lp.peers[i].engine.disputes(64);
    assert_eq!((ds.len(), left), (1, 0), "{ds:?}");
    let d = ds[0].clone();
    assert_eq!((d.holder, d.author, d.target), (f.a, f.lp.peers[1].engine.tid(), f.t));
    d
}

fn detected(lp: &LocalPeer, i: usize) -> Vec<(Tid, Tid, bool)> {
    lp.peers[i].drain_events().into_iter().filter_map(|e| if let Event::DisputeDetected { holder, author, trust, .. } = e { Some((holder, author, trust)) } else { None }).collect()
}

// spec/permissions.md §5.1 Trust set; notes/disputes-plan.md step 4 (first received): a
// node that held the honest removal first keeps its side when the backdated one arrives (the
// removal it applied stops applying: the dispute is detected, the side taken by default and
// told); one that got the backdated removal first stays with it, warned the same way.
#[test]
fn backdated_removal_loses_where_the_honest_one_was_first_spec_permissions_5_1() {
    let mut f = fight(4, 601);
    let (w, r) = (f.w.clone(), f.r.clone());
    // peer 2: b's removal first, then a's backdated one
    send(&mut f.lp, 1, 2, &w);
    assert_eq!(admins(&f, 2), (false, true));
    f.lp.peers[2].drain_events();
    send(&mut f.lp, 0, 2, &r);
    assert_eq!(admins(&f, 2), (false, true), "the side it had stays");
    assert_eq!(detected(&f.lp, 2), vec![(f.a, f.lp.peers[1].engine.tid(), true)]);
    let d = the_dispute(&f, 2);
    assert_eq!(d.side.map(|s| (s.trust, s.chosen)), Some((true, false)));
    // peer 3: the backdated one first
    send(&mut f.lp, 0, 3, &r);
    assert_eq!(admins(&f, 3), (true, false));
    f.lp.peers[3].drain_events();
    send(&mut f.lp, 1, 3, &w);
    assert_eq!(admins(&f, 3), (true, false), "first received: the thief's side, warned");
    assert_eq!(detected(&f.lp, 3), vec![(f.a, f.lp.peers[1].engine.tid(), false)]);
    let d = the_dispute(&f, 3);
    assert_eq!(d.side.map(|s| (s.trust, s.chosen)), Some((false, false)));
    // each party sides with itself
    send(&mut f.lp, 0, 1, &r);
    send(&mut f.lp, 1, 0, &w);
    assert_eq!((admins(&f, 0), admins(&f, 1)), ((true, false), (false, true)));
    assert_eq!(the_dispute(&f, 0).side.map(|s| s.trust), Some(false));
    assert_eq!(the_dispute(&f, 1).side.map(|s| s.trust), Some(true));
}

// notes/disputes-plan.md step 4 (choices): a chosen side replaces the default, switching
// back and forth reads each side as a node that always stood there, and a choice survives a
// restart as the default does.
#[test]
fn choose_switches_sides_and_persists_spec_permissions_5_1() {
    let mut f = fight(3, 602);
    let (w, r) = (f.w.clone(), f.r.clone());
    send(&mut f.lp, 1, 2, &w);
    send(&mut f.lp, 0, 2, &r);
    assert_eq!(admins(&f, 2), (false, true));
    let d = the_dispute(&f, 2);
    let e = &mut f.lp.peers[2].engine;
    e.choose(d.commit, d.op, d.holder, false).unwrap();
    assert_eq!(admins(&f, 2), (true, false), "a's side: its removal of b counts");
    assert_eq!(the_dispute(&f, 2).side.map(|s| (s.trust, s.chosen)), Some((false, true)));
    let e = &mut f.lp.peers[2].engine;
    e.choose(d.commit, d.op, d.holder, true).unwrap();
    assert_eq!(admins(&f, 2), (false, true));
    let e = &mut f.lp.peers[2].engine;
    e.choose(d.commit, d.op, d.holder, false).unwrap();
    assert_eq!(admins(&f, 2), (true, false));
    reopen(&mut f.lp, 2, 7).unwrap();
    assert_eq!(admins(&f, 2), (true, false), "the choice is durable");
    assert_eq!(the_dispute(&f, 2).side.map(|s| (s.trust, s.chosen)), Some((false, true)));
    // an unknown removal cannot be chosen
    assert!(matches!(f.lp.peers[2].engine.choose(d.commit, 7, d.holder, true), Err(osis_node::Error::UnknownCommit(_))));
}

// notes/disputes-plan.md step 4: the default side is durable: after a restart the node
// reads as before, and the dispute is listed with the side it took.
#[test]
fn default_side_survives_a_restart_spec_permissions_5_1() {
    let mut f = fight(3, 603);
    let (w, r) = (f.w.clone(), f.r.clone());
    send(&mut f.lp, 1, 2, &w);
    send(&mut f.lp, 0, 2, &r);
    assert_eq!(admins(&f, 2), (false, true));
    reopen(&mut f.lp, 2, 8).unwrap();
    assert_eq!(admins(&f, 2), (false, true));
    assert_eq!(the_dispute(&f, 2).side.map(|s| (s.trust, s.chosen)), Some((true, false)));
    assert!(detected(&f.lp, 2).is_empty(), "an open detects nothing anew");
}

// notes/disputes-plan.md step 4 (a new node takes the side its own grant counts on): a
// node granted by the honest admin after the fight, holding the backdated removal and its own
// grant when the honest removal arrives, sides with the honest admin though it got the
// backdated removal first: its grant exists on that side only.
#[test]
fn newcomer_takes_the_side_its_grant_counts_on_spec_permissions_5_1() {
    let mut f = fight(4, 604);
    let (w, r) = (f.w.clone(), f.r.clone());
    let d = f.lp.peers[3].engine.tid();
    let before = ids(&f.lp, 1);
    f.lp.peers[1].engine.grant(&f.t, &d, &edge_of(Role::Write)).unwrap();
    let g = new_ids(&f.lp, 1, &before);
    send(&mut f.lp, 0, 3, &r);
    send(&mut f.lp, 1, 3, &g);
    assert_eq!(f.lp.peers[3].engine.role_on(&f.t), None, "granted by an admin the backdated removal removed");
    send(&mut f.lp, 1, 3, &w);
    assert_eq!(admins(&f, 3), (false, true));
    assert_eq!(f.lp.peers[3].engine.role_on(&f.t), Some(Role::Write));
    assert_eq!(the_dispute(&f, 3).side.map(|s| (s.trust, s.chosen)), Some((true, false)));
    // a peer with no stake and the same order keeps the walk's side
    send(&mut f.lp, 0, 2, &r);
    send(&mut f.lp, 1, 2, &w);
    assert_eq!(admins(&f, 2), (true, false));
}

// notes/disputes-plan.md step 4: a node on neither side of a fight reads the things the
// fight cannot reach alike whichever side it takes, and switching does not touch them.
#[test]
fn sides_leave_other_things_alone_spec_permissions_5_1() {
    let mut f = fight(3, 605);
    let (w, r) = (f.w.clone(), f.r.clone());
    let c = f.lp.peers[2].engine.tid();
    let other = thing_of(&mut f.lp, 2, c);
    f.lp.peers[2].engine.grant(&other, &f.a, &edge_of(Role::Write)).unwrap();
    send(&mut f.lp, 1, 2, &w);
    send(&mut f.lp, 0, 2, &r);
    let d = the_dispute(&f, 2);
    let on_other = |f: &Fight| f.lp.peers[2].engine.roster(&other).get(&f.a).map(|e| e.role);
    assert_eq!(on_other(&f), Some(Role::Write));
    f.lp.peers[2].engine.choose(d.commit, d.op, d.holder, false).unwrap();
    assert_eq!(on_other(&f), Some(Role::Write));
}
