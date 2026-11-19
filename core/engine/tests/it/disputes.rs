//! Admin disputes end to end (spec/permissions.md §5.1 Trust set; notes/disputes.md
//! step 4): the backdating attack, default sides, switching, the
//! trust store across a restart. Over `LocalPeer`: commits delivered by hand, so who holds what
//! first is the test's.

use crate::flows::{edge_of, people, reopen, send_carried, spread, thing_of};
use osis_base::{CommitId, Role, Tid};
use osis_engine::flows::Demotion;
use osis_engine::local_peer::LocalPeer;
use osis_engine::Event;
use osis_schema::core_types as ct;
use std::collections::BTreeSet;

/// Takes the walk's side in every admin dispute `p` detected, as a user choosing it would (the
/// order harness's nodes, `order::deliver_with`); how many disputes `p` holds. A node's default
/// side is the one it received first, so two arrival orders of one held set may rightly differ
/// until the sides agree; under the walk's side everywhere (an empty trust set) every order
/// must judge alike (spec/permissions.md §5.1).
pub(crate) fn walk_sides(p: &mut osis_engine::local_peer::Peer) -> usize {
    let (ds, _) = p.engine.disputes(usize::MAX);
    for d in ds.iter().filter(|d| d.side.is_some_and(|s| s.trust)) {
        p.engine.choose(d.commit, d.op, d.holder, false).unwrap();
    }
    ds.len()
}

/// Admins `a` (peer 0) and `b` (peer 1) of thing `t` (mint admin `c`, peer 2) remove each
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

/// Built once per `n` (`LocalPeer::cached`).
fn fight(n: usize) -> Fight {
    let (lp, (a, b, t, w, r)) = LocalPeer::cached(&format!("disputes::fight/{n}"), || {
        let f = fight_built(n);
        (f.lp, (f.a, f.b, f.t, f.w, f.r))
    });
    Fight { lp, a, b, t, w, r }
}

fn fight_built(n: usize) -> Fight {
    let (mut lp, ps) = people(n);
    let (a, b, c) = (ps[0], ps[1], ps[2]);
    let t = thing_of(&mut lp, 2, c);
    lp.peers[2].engine.grant(&t, &a, &edge_of(Role::Admin)).unwrap();
    lp.peers[2].engine.grant(&t, &b, &edge_of(Role::Admin)).unwrap();
    // the other peers read t: content of a thing outside a node closure waits (spec/commits.md §4)
    for p in &ps[3..] {
        lp.peers[2].engine.grant(&t, p, &edge_of(Role::Read)).unwrap();
    }
    spread(&mut lp);
    lp.advance(1000);
    // b's clock runs ahead; a has not seen b's removal when it writes its own
    lp.peers[1].clock.advance(5000);
    let before = ids(&lp, 1);
    lp.peers[1].engine.demote(&t, &Demotion { holder: a, new: None, retain: None }).unwrap();
    let w = new_ids(&lp, 1, &before);
    let before = ids(&lp, 0);
    lp.peers[0].engine.demote(&t, &Demotion { holder: b, new: None, retain: None }).unwrap();
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
fn the_dispute(f: &Fight, i: usize) -> osis_engine::sides::DisputeInfo {
    let (ds, left) = f.lp.peers[i].engine.disputes(64);
    assert_eq!((ds.len(), left), (1, 0), "{ds:?}");
    let d = ds[0].clone();
    assert_eq!((d.holder, d.author, d.target), (f.a, f.lp.peers[1].engine.me(), f.t));
    d
}

fn detected(lp: &LocalPeer, i: usize) -> Vec<(Tid, Tid, bool)> {
    lp.peers[i].drain_events().into_iter().filter_map(|e| if let Event::DisputeDetected { holder, author, trust, .. } = e { Some((holder, author, trust)) } else { None }).collect()
}

// spec/permissions.md §5.1 Trust set; notes/disputes.md, Detection and sides (first received): a
// node that held the honest removal first keeps its side when the backdated one arrives (the
// removal it applied stops applying: the dispute is detected, the side taken by default and
// told); one that got the backdated removal first stays with it, warned the same way.
#[test]
fn backdated_removal_loses_where_the_honest_one_was_first_spec_permissions_5_1() {
    let mut f = fight(4);
    let (w, r) = (f.w.clone(), f.r.clone());
    // peer 2: b's removal first, then a's backdated one
    send_carried(&mut f.lp, 1, 2, &w);
    assert_eq!(admins(&f, 2), (false, true));
    f.lp.peers[2].drain_events();
    send_carried(&mut f.lp, 0, 2, &r);
    assert_eq!(admins(&f, 2), (false, true), "the side it had stays");
    assert_eq!(detected(&f.lp, 2), vec![(f.a, f.lp.peers[1].engine.me(), true)]);
    let d = the_dispute(&f, 2);
    assert_eq!(d.side.map(|s| (s.trust, s.chosen)), Some((true, false)));
    // peer 3: the backdated one first
    send_carried(&mut f.lp, 0, 3, &r);
    assert_eq!(admins(&f, 3), (true, false));
    f.lp.peers[3].drain_events();
    send_carried(&mut f.lp, 1, 3, &w);
    assert_eq!(admins(&f, 3), (true, false), "first received: the thief's side, warned");
    assert_eq!(detected(&f.lp, 3), vec![(f.a, f.lp.peers[1].engine.me(), false)]);
    let d = the_dispute(&f, 3);
    assert_eq!(d.side.map(|s| (s.trust, s.chosen)), Some((false, false)));
    // each party sides with itself
    send_carried(&mut f.lp, 0, 1, &r);
    send_carried(&mut f.lp, 1, 0, &w);
    assert_eq!((admins(&f, 0), admins(&f, 1)), ((true, false), (false, true)));
    assert_eq!(the_dispute(&f, 0).side.map(|s| s.trust), Some(false));
    assert_eq!(the_dispute(&f, 1).side.map(|s| s.trust), Some(true));
}

// notes/disputes.md, Detection and sides (choices): the default side is durable: after a restart the
// node reads as before, and the dispute is listed with the side it took. A chosen side replaces
// the default, switching back and forth reads each side as a node that always stood there, and a
// choice survives a restart as the default does. A node on neither side of a fight reads the
// things the fight cannot reach alike whichever side it takes, and switching does not touch them.
#[test]
fn choose_switches_sides_and_persists_spec_permissions_5_1() {
    let mut f = fight(3);
    let (w, r) = (f.w.clone(), f.r.clone());
    let c = f.lp.peers[2].engine.me();
    let other = thing_of(&mut f.lp, 2, c);
    f.lp.peers[2].engine.grant(&other, &f.a, &edge_of(Role::Write)).unwrap();
    send_carried(&mut f.lp, 1, 2, &w);
    send_carried(&mut f.lp, 0, 2, &r);
    assert_eq!(admins(&f, 2), (false, true));
    reopen(&mut f.lp, 2).unwrap();
    assert_eq!(admins(&f, 2), (false, true));
    assert_eq!(the_dispute(&f, 2).side.map(|s| (s.trust, s.chosen)), Some((true, false)));
    assert!(detected(&f.lp, 2).is_empty(), "an open detects nothing anew");
    let d = the_dispute(&f, 2);
    let on_other = |f: &Fight| f.lp.peers[2].engine.roster(&other).get(&f.a).map(|e| e.role);
    assert_eq!(on_other(&f), Some(Role::Write));
    let e = &mut f.lp.peers[2].engine;
    e.choose(d.commit, d.op, d.holder, false).unwrap();
    assert_eq!(admins(&f, 2), (true, false), "a's side: its removal of b counts");
    assert_eq!(on_other(&f), Some(Role::Write));
    assert_eq!(the_dispute(&f, 2).side.map(|s| (s.trust, s.chosen)), Some((false, true)));
    let e = &mut f.lp.peers[2].engine;
    e.choose(d.commit, d.op, d.holder, true).unwrap();
    assert_eq!(admins(&f, 2), (false, true));
    let e = &mut f.lp.peers[2].engine;
    e.choose(d.commit, d.op, d.holder, false).unwrap();
    assert_eq!(admins(&f, 2), (true, false));
    reopen(&mut f.lp, 2).unwrap();
    assert_eq!(admins(&f, 2), (true, false), "the choice is durable");
    assert_eq!(the_dispute(&f, 2).side.map(|s| (s.trust, s.chosen)), Some((false, true)));
    // an unknown removal cannot be chosen
    assert!(matches!(f.lp.peers[2].engine.choose(d.commit, 7, d.holder, true), Err(osis_engine::Error::UnknownCommit(_))));
}

// spec/permissions.md §5.1, spec/commits.md §5 Invalid: a side chosen late, after content its
// default dropped as invalid, reads as a node that always stood there once the dropped write
// comes again. `a` writes after b's removal of it; peer 2, on b's side by default, drops the
// write, then takes a's side; peer 3 stood there from the start.
#[test]
fn late_choice_brings_back_what_the_default_dropped_spec_permissions_5_1() {
    let mut f = fight(4);
    let (w, r) = (f.w.clone(), f.r.clone());
    f.lp.peers[0].clock.advance(10_000);
    let mut m = osis_engine::Mutation::new();
    m.set(f.t, &crate::common::REG, &crate::common::s("a's")).unwrap();
    let x = f.lp.peers[0].commit(m).unwrap().unwrap();
    let reg = |f: &mut Fight, i: usize| f.lp.peers[i].engine.get(&f.t, &crate::common::ak("t:reg.0")).unwrap();
    for (i, first, then) in [(2, &w, &r), (3, &r, &w)] {
        send_carried(&mut f.lp, if i == 2 { 1 } else { 0 }, i, first);
        send_carried(&mut f.lp, if i == 2 { 0 } else { 1 }, i, then);
        send_carried(&mut f.lp, 0, i, &[x]);
    }
    assert_eq!(reg(&mut f, 3), Some(crate::common::s("a's")));
    assert_ne!(reg(&mut f, 2), reg(&mut f, 3), "b's side: a's write dropped as invalid");
    let d = the_dispute(&f, 2);
    f.lp.peers[2].engine.choose(d.commit, d.op, d.holder, false).unwrap();
    assert_eq!(admins(&f, 2), (true, false));
    assert!(f.lp.peers[2].engine.commit_parts_missing().iter().any(|(c, m)| *c == x && !m.is_empty()), "valid again: missing");
    send_carried(&mut f.lp, 0, 2, &[x]);
    assert_eq!(reg(&mut f, 2), reg(&mut f, 3));
}

// notes/disputes.md, Detection and sides (first received): a removal waiting for an entry's creation
// (spec/permissions.md §2) counts from when it applies. `a` plants a forward-stamped removal of
// `b` waiting at peer 2 on an entry only `a` holds; `b`'s removal of `a` (stamped earlier)
// applies there; `a` then releases the entry: peer 2 keeps `b`.
#[test]
fn planted_removal_counts_from_when_it_applies_spec_permissions_5_1() {
    let (mut lp, ps) = people(3);
    let (a, b, c) = (ps[0], ps[1], ps[2]);
    let t = thing_of(&mut lp, 2, c);
    lp.peers[2].engine.grant(&t, &a, &edge_of(Role::Admin)).unwrap();
    lp.peers[2].engine.grant(&t, &b, &edge_of(Role::Admin)).unwrap();
    spread(&mut lp);
    lp.advance(1000);
    let before = ids(&lp, 0);
    lp.peers[0].engine.grant(&t, &b, &ct::Edge { invite: Some(Role::Read), ..edge_of(Role::Admin) }).unwrap();
    let e = new_ids(&lp, 0, &before);
    lp.peers[0].clock.advance(5000);
    let before = ids(&lp, 0);
    lp.peers[0].engine.demote(&t, &Demotion { holder: b, new: None, retain: None }).unwrap();
    let p = new_ids(&lp, 0, &before);
    send_carried(&mut lp, 0, 2, &p);
    let adm = |lp: &LocalPeer| { let r = lp.peers[2].engine.roster(&t); (r.contains_key(&a), r.contains_key(&b)) };
    assert_eq!(adm(&lp), (true, true), "a's planted removal waits");
    lp.advance(1000);
    let before = ids(&lp, 1);
    lp.peers[1].engine.demote(&t, &Demotion { holder: a, new: None, retain: None }).unwrap();
    let w = new_ids(&lp, 1, &before);
    send_carried(&mut lp, 1, 2, &w);
    assert_eq!(adm(&lp), (false, true));
    send_carried(&mut lp, 0, 2, &e);
    assert_eq!(adm(&lp), (false, true), "b's removal was first and is earlier: kept");
}

// spec/permissions.md §5.1 Vouches (Writing, the writers' leaving out), §5.1 Trust set: X (peer 1)
// demoted H (peer 0) to write (D) and granted K (peer 3) write (C); W (peer 2) alone received
// both; H removes X (R). D lowers R's author, so R applies only where it is trusted (D a seed);
// W sides with R. Listing D would void R there, so W's vouch lists C alone: at W, K keeps write,
// X stays removed and H admin. (Vouches as written: tests in the engine's `apply::tests_vouches`.)
#[test]
fn a_witness_leaves_out_what_would_void_the_removal_spec_perm_5_1() {
    let (mut lp, ps) = people(4);
    let (h, x, w, k) = (ps[0], ps[1], ps[2], ps[3]);
    let t = thing_of(&mut lp, 0, h);
    for p in [x, w] {
        lp.peers[0].engine.grant(&t, &p, &edge_of(Role::Admin)).unwrap();
    }
    spread(&mut lp);
    lp.advance(1000);
    let d = *lp.peers[1].engine.demote(&t, &Demotion { holder: h, new: Some(edge_of(Role::Write)), retain: None }).unwrap().commits.last().unwrap();
    lp.advance(1000);
    let c = *lp.peers[1].engine.grant(&t, &k, &edge_of(Role::Write)).unwrap().commits.last().unwrap();
    lp.advance(1000);
    lp.sync(1, 2).unwrap();
    lp.advance(1000);
    let r = *lp.peers[0].engine.demote(&t, &Demotion { holder: x, new: None, retain: None }).unwrap().commits.last().unwrap();
    lp.advance(1000);
    lp.sync(0, 2).unwrap();
    let vouches = |lp: &LocalPeer| lp.peers[2].engine.core.ix.held.vouches_on(&t).cloned().collect::<Vec<_>>();
    assert!(vouches(&lp).is_empty(), "R void in W's walk: nothing owed");
    let op = lp.peers[2].engine.core.ix.held.edge_commit(&r).unwrap().ops.iter().position(|o| o.holder == x).unwrap();
    lp.peers[2].engine.choose(r, op as u32, x, true).unwrap();
    let v = vouches(&lp);
    assert_eq!(v.len(), 1, "W vouches once it sides with R");
    assert_eq!(v[0].entries.iter().map(|(key, l)| (*key, l.commits().to_vec())).collect::<Vec<_>>(), vec![(r, vec![c])], "D left out");
    assert!(!v[0].entries.iter().any(|(_, l)| l.covers(&d)));
    let e = &lp.peers[2].engine.core;
    assert_eq!(e.role_now(&k, &t), Some(Role::Write), "C kept");
    assert_eq!(e.role_now(&x, &t), None, "X removed");
    assert_eq!(e.role_now(&h, &t), Some(Role::Admin), "H admin");
}

/// A fight at W (peer 2) over thing `t` H (peer 0) made, X (peer 1) and W its admins: X makes `k`
/// role writes on `t` (granting peer 3 write and lowering it to read in turn), then removes H;
/// H, having received none of it, removes X (R); W receives all, sides with R, and vouches for
/// X's writes on peer 3, leaving out X's removal of H (R does not apply with it listed). The
/// leaving-out walks (`flows::vouches::leaving_out`) of a grant by W on `t` after that.
fn leaving_out_walks_per_write(k: usize) -> u64 {
    let mut lp = LocalPeer::fresh(4, osis_base::WallMs(1_700_000_000_000));
    lp.sync_all().unwrap();
    let [h, x, w, p3] = [0, 1, 2, 3].map(|i| lp.peers[i].engine.me());
    let mut m = osis_engine::Mutation::new();
    let t = lp.peers[0].engine.new_thing(&mut m, h);
    lp.peers[0].commit(m).unwrap();
    lp.hold(t);
    for who in [x, w] {
        lp.peers[0].engine.grant(&t, &who, &edge_of(Role::Admin)).unwrap();
    }
    lp.sync_all().unwrap();
    lp.advance(1000);
    let role = |lp: &LocalPeer, at: usize, who: &Tid| lp.peers[at].engine.core.timelines.role(who, &t, osis_perm::At::END);
    for i in 0..k {
        if i % 2 == 0 {
            lp.peers[1].engine.grant(&t, &p3, &edge_of(Role::Write)).unwrap();
        } else {
            lp.peers[1].engine.demote(&t, &Demotion { holder: p3, new: Some(edge_of(Role::Read)), retain: None }).unwrap();
        }
        lp.advance(1000);
    }
    let lowering = *lp.peers[1].engine.demote(&t, &Demotion { holder: h, new: None, retain: None }).unwrap().commits.last().unwrap();
    lp.advance(1000);
    lp.sync(1, 2).unwrap();
    let r = *lp.peers[0].engine.demote(&t, &Demotion { holder: x, new: None, retain: None }).unwrap().commits.last().unwrap();
    lp.advance(1000);
    lp.sync(0, 2).unwrap();
    assert_eq!(role(&lp, 2, &x), Some(Role::Admin), "R does not apply at W before it sides with it");
    lp.peers[2].engine.choose(r, 0, x, true).unwrap();
    let mut m = osis_engine::Mutation::new();
    lp.peers[2].engine.new_thing(&mut m, w);
    lp.peers[2].commit(m).unwrap();
    assert_eq!(role(&lp, 2, &x), None, "R applies at W");
    let held: Vec<_> = lp.peers[2].engine.core.ix.held.vouches_on(&t).cloned().collect();
    assert_eq!(held.len(), 1, "W vouches once");
    let listed: Vec<CommitId> = held[0].entries.iter().flat_map(|(_, l)| l.commits().to_vec()).collect();
    assert_eq!(listed.len(), k, "every role write of X on peer 3 listed");
    assert!(!listed.contains(&lowering), "X's removal of H left out");
    let write = |lp: &mut LocalPeer| {
        osis_base::costs::take();
        lp.peers[2].engine.grant(&t, &p3, &edge_of(Role::Admin)).unwrap();
        lp.advance(1000);
        osis_base::costs::take().into_iter().find(|(k, _, _)| *k == "vouches: leaving-out walks").map_or(0, |x| x.2)
    };
    // the first write after the vouch may take the leaving out anew (the one taken before the
    // vouch counted); every later one keeps it
    write(&mut lp);
    write(&mut lp)
}

// spec/permissions.md §5.1 Vouches (Writing: the writers' leaving out; "may keep"),
// notes/principles.md (Check scaling): in a fight, a write in R's component costs the witness
// the same leaving-out walks whatever the number of candidates the removed party made (taking
// it anew walks once per candidate).
#[test]
fn a_fights_leaving_out_costs_a_write_the_same_at_k_and_10k_candidates_spec_perm_5_1() {
    let (small, big) = (leaving_out_walks_per_write(2), leaving_out_walks_per_write(20));
    println!("vouches: leaving-out walks per write: {small} at k, {big} at 10k");
    assert_eq!(small, big);
}
