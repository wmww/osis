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

// spec/permissions.md §5.1 (Frontier): nothing but a removal's frontier decides which of the
// removed party's role writes before it survive, whoever received them. H (peer 0) makes `t`
// with X (peer 1) and W (peer 2) its admins; X grants K (peer 3) write, which H and W receive,
// then L (peer 4) write, which W alone receives; H removes X. At W, which held both grants before
// the removal: K's, listed, stands, and L's, unlisted, falls, as at H.
#[test]
fn a_removed_partys_grant_the_removal_does_not_list_falls_where_it_was_held_spec_perm_5_1() {
    let (mut lp, ps) = people(5);
    let (h, x, w, k, l) = (ps[0], ps[1], ps[2], ps[3], ps[4]);
    let t = thing_of(&mut lp, 0, h);
    for p in [x, w] {
        lp.peers[0].engine.grant(&t, &p, &edge_of(Role::Admin)).unwrap();
    }
    spread(&mut lp);
    lp.advance(1000);
    lp.peers[1].engine.grant(&t, &k, &edge_of(Role::Write)).unwrap();
    lp.sync(1, 0).unwrap();
    lp.sync(1, 2).unwrap();
    lp.advance(1000);
    lp.peers[1].engine.grant(&t, &l, &edge_of(Role::Write)).unwrap();
    lp.sync(1, 2).unwrap();
    lp.advance(1000);
    let roles = |lp: &LocalPeer, i: usize| [x, k, l].map(|p| lp.peers[i].engine.core.role_now(&p, &t));
    assert_eq!(roles(&lp, 2), [Some(Role::Admin), Some(Role::Write), Some(Role::Write)], "W holds both grants");
    lp.peers[0].engine.demote(&t, &Demotion { holder: x, new: None, retain: None }).unwrap();
    lp.advance(1000);
    lp.sync(0, 2).unwrap();
    assert_eq!(roles(&lp, 2), [None, Some(Role::Write), None], "at W: X removed, K's listed grant stands, L's falls");
    lp.sync(2, 0).unwrap();
    assert_eq!(roles(&lp, 0), roles(&lp, 2), "H, having received L's grant from W, reads alike");
}

// spec/sync-set.md §3 Release, spec/commits.md §5 A released thing and Invalid,
// spec/sync-judgement.md §3 Dropped bodies: `a`, past its backdated removal of `b`, mints Y under
// `t` (the strong to Y on `t`'s `holds.0` and Y's record in one commit) and writes Y's content.
// Peer 3, given `b`'s removal first, sides with `b`: `a`'s writes are invalid, the pass ends and Y,
// out of the node closure, is released. Taking `a`'s side then makes the minting's part on `t`
// valid again: the node keeps that commit known through the release and fetches it again, and,
// Y's record arriving again, pulls anew what it forgot of Y, so it reads Y as a node that always
// stood on `a`'s side. Fails where a release forgets whole a commit whose other part was dropped
// while invalid (nothing left to fetch), or where a record arriving again counts as new (a strong
// reaching a thing whose record its transaction brought pulls nothing anew).
#[test]
fn a_thing_released_while_its_minting_was_invalid_comes_back_whole_with_the_side_taken_spec_sync_set_3() {
    use crate::common::{ak, s, REG};
    let mut f = fight(4);
    let (w, r) = (f.w.clone(), f.r.clone());
    let before = ids(&f.lp, 0);
    let (y, _) = f.lp.peers[0].engine.create_with_admin(&f.t).unwrap();
    let mut m = osis_engine::Mutation::new();
    m.set(y, &REG, &s("y")).unwrap();
    f.lp.peers[0].commit(m).unwrap().unwrap();
    let ys = new_ids(&f.lp, 0, &before);
    send_carried(&mut f.lp, 1, 3, &w);
    send_carried(&mut f.lp, 0, 3, &r);
    send_carried(&mut f.lp, 0, 3, &ys);
    let p = &mut f.lp.peers[3];
    let pass_end = |e: &mut osis_engine::Engine| {
        e.role_duties().unwrap();
        let left: BTreeSet<Tid> = e.left_closure().into_keys().collect();
        e.released(&left).unwrap();
        e.settle_needs().unwrap();
    };
    pass_end(&mut p.engine);
    assert_eq!(p.engine.get(&y, &ak("t:reg.0")).unwrap(), None, "b's side: Y never applied");
    let (ds, _) = p.engine.disputes(usize::MAX);
    let d = ds.iter().find(|d| d.side.is_some_and(|s| s.trust)).expect("b's side taken by default");
    p.engine.choose(d.commit, d.op, d.holder, false).unwrap();
    // the sync exchange: what the node counts missing, then all again where it pulls anew
    p.pulled_anew.clear();
    let missing: Vec<CommitId> = p.engine.commit_parts_missing().into_iter().filter(|(_, m)| !m.is_empty()).map(|(c, _)| c).collect();
    assert!(missing.contains(&ys[0]), "the minting is fetched again: {missing:?}");
    send_carried(&mut f.lp, 0, 3, &missing);
    assert!(!f.lp.peers[3].pulled_anew.is_empty(), "Y's record arriving again pulls Y anew");
    send_carried(&mut f.lp, 0, 3, &ys);
    pass_end(&mut f.lp.peers[3].engine);
    assert_eq!(f.lp.peers[3].engine.get(&y, &ak("t:reg.0")).unwrap(), Some(s("y")));
}

// spec/commits.md §5 Invalid, What a held thing needs: a part dropped while invalid and made
// valid again (missing, to fetch) that turns invalid again before it arrives is dropped as
// invalid, as one held throughout: neither held nor missing. `a`, past its backdated removal of
// `b`, mints Y with the strong on `t`'s `holds.0`. Peer 3 takes `a`'s side, then `b`'s again
// before the pass ends; peer 2 is given the same and stays on `b`'s side. Both then release Y
// alike. Fails where the part stays missing: a missing part on a held thing keeps its commit's
// other things needed, so peer 3 keeps Y's record and reads its roster.
#[test]
#[ignore = "issues/order-roster-admin-edge.md"]
fn repro_a_part_missing_again_that_turns_invalid_drops_as_invalid() {
    let mut f = fight(4);
    let (w, r) = (f.w.clone(), f.r.clone());
    let before = ids(&f.lp, 0);
    let (y, _) = f.lp.peers[0].engine.create_with_admin(&f.t).unwrap();
    let ys = new_ids(&f.lp, 0, &before);
    for i in [2, 3] {
        send_carried(&mut f.lp, 1, i, &w);
        send_carried(&mut f.lp, 0, i, &r);
        send_carried(&mut f.lp, 0, i, &ys);
    }
    let p = &mut f.lp.peers[3];
    let (ds, _) = p.engine.disputes(usize::MAX);
    let d = ds.iter().find(|d| d.side.is_some_and(|s| s.trust)).expect("b's side taken by default").clone();
    p.engine.choose(d.commit, d.op, d.holder, false).unwrap();
    assert!(p.engine.commit_parts_missing().get(&ys[0]).is_some_and(|m| !m.is_empty()), "a's side: the minting's part on t is fetched again");
    p.engine.choose(d.commit, d.op, d.holder, true).unwrap();
    assert!(p.engine.commit_parts_missing().get(&ys[0]).is_none_or(|m| m.is_empty()), "b's side again: nothing to fetch");
    for i in [2, 3] {
        let e = &mut f.lp.peers[i].engine;
        e.role_duties().unwrap();
        let left: BTreeSet<Tid> = e.left_closure().into_keys().collect();
        e.released(&left).unwrap();
        e.settle_needs().unwrap();
    }
    assert_eq!(f.lp.peers[3].engine.roster(&y), f.lp.peers[2].engine.roster(&y));
}
