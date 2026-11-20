//! Reach and keys-open travel (spec/permissions.md §4, as notes/a2-spec/permissions.md drafts it:
//! the (A3) reach bullet and Role changes travel; notes/a2-spec/README.md OPEN 14): hand worlds per finding
//! (notes/evidence-model-findings.md 1, 3, 17, 18, 19) and per held-model `spec_reach.rs` test (same
//! names), each a differential at every step (`assert_agrees`: A3's rule and brief 3's,
//! `Stage::ReachNoErrand`) plus the copy the draft's words decide, with the switch that decides it
//! off where only it brings that copy. The derivation's own: a removal commit on two things reaches
//! by each copy.
use super::*;
use held_model::evidence::names::*;
use held_model::evidence::State;
use osis_engine::evidence::Reason;

/// The derivation under `cfg` over a held set of `w`'s end state under brief 3's delivery
/// (vouches counting).
fn at_end(w: &World, cfg: Config, held: impl Fn(&State) -> Set) -> (Ev, Set) {
    let mut w = w.clone();
    let rule = brief3(&mut w, true);
    let st = w.run(&rule, |_| {});
    let h = held(&st);
    let mut d = Driver::with(&w, cfg);
    d.step(&w, &h, &st.units);
    (d.ev, h)
}

/// Every commit written (the node holding everything).
fn everything(st: &State) -> Set {
    st.written.clone()
}

const BRIEF3: Config = Config { vouches: true, reach: true, keys_open: true };
const NO_REACH: Config = Config { vouches: true, reach: false, keys_open: true };
const NO_KEYS: Config = Config { vouches: true, reach: true, keys_open: false };

fn removal_of(w: &World, e: (Thing, Thing)) -> Id {
    (0..w.w.commits.len()).find(|&i| w.removes(i) == Some(e)).unwrap()
}

/// Findings 1 and 17: K writes D through [A, O]; X removes K from A; nobody honest syncs A with O or
/// D. The removal is evidence of K's writes on D (on their path, and by its reach: A writes O, O
/// writes D, followed to the end), so the node holding everything requires it under D; D's reader
/// under brief 3 never holds it (only A3's errand carries it there, as today).
#[test]
fn open14_with_no_honest_node_between_only_the_errand_reaches_d() {
    let w = hm::family(Shape { via_org: true, units: 0, listed: false, thief: true, regrant: false, addendum: false, raised: false, q_d: false, q_r: false, y_a: false, org_apart: true, vouch: false });
    assert_agrees("open14 f1", &w);
    let r = removal_of(&w, (K, A));
    let (all, _) = at_end(&w, BRIEF3, everything);
    assert!(all.required(&D).unwrap().contains_key(&(r, A)));
    let (reader, h) = at_end(&w, BRIEF3, |st| st.entries[&D].clone());
    assert!(!h.contains(&r) && !reader.required(&D).unwrap().contains_key(&(r, A)));
}

/// Finding 1, the reach itself: Y grants K write on D directly and K writes D by it (no hop through
/// A); X removes K from A; A writes O (W's grant), O writes D (Y's). No body of D rests on (K, A):
/// the removal is D's by its reach alone, two grants deep, with the grant of A on O.
#[test]
fn f1_reach_follows_write_grants_to_the_end_spec_permissions_4() {
    let pw = paths::World::new(&[(X, A), (W, O), (Y, D)]);
    let mut w = World::new(pw, &[A, O, D]);
    let (x, wn, y, k) = (w.node(true, &[A]), w.node(true, &[O]), w.node(true, &[D]), w.node(false, &[]));
    w.write(x, |p| p.edge(X, 1, &[], A, K, Role::Write, &[]));
    let ao = w.write(wn, |p| p.edge(W, 1, &[], O, A, Role::Write, &[]));
    w.write(y, |p| p.edge(Y, 1, &[], D, O, Role::Write, &[]));
    w.write(y, |p| p.edge(Y, 1, &[], D, K, Role::Write, &[]));
    w.write(k, |p| p.content(K, 2, &[], D));
    let r = w.write(x, |p| p.edge(X, 6, &[], A, K, Role::None, &[]));
    assert_agrees("f1 reach", &w);
    let (ev, _) = at_end(&w, BRIEF3, everything);
    let req = ev.required(&D).unwrap();
    assert_eq!(req.get(&(r, A)), Some(&Reason::Removal), "{req:?}");
    assert_eq!(req.get(&(ao, O)), Some(&Reason::Reach((A, O))), "{req:?}");
    let (ev, _) = at_end(&w, NO_REACH, everything);
    assert!(ev.required(&D).unwrap().is_empty());
}

/// Finding 3: a grant written after the removal shows its reach. X removes K from A while A writes
/// nothing; Y grants A write on D later (the raise). The removal is D's from the raise on, not
/// before: reach follows every later grant.
#[test]
fn f3_a_later_grant_brings_a_removal_its_reach_now_holds_spec_permissions_4() {
    let pw = paths::World::new(&[(X, A), (Y, D)]);
    let mut w = World::new(pw, &[A, D]);
    let (x, y, k) = (w.node(true, &[A, D]), w.node(true, &[D]), w.node(false, &[]));
    w.write(x, |p| p.edge(X, 1, &[], A, K, Role::Write, &[]));
    w.write(y, |p| p.edge(Y, 1, &[], D, K, Role::Write, &[]));
    w.write(k, |p| p.content(K, 2, &[], D));
    let r = w.write(x, |p| p.edge(X, 6, &[], A, K, Role::None, &[]));
    let raise = w.write(y, |p| p.edge(Y, 7, &[], D, A, Role::Write, &[]));
    assert_agrees("f3 reach", &w);
    let mut w2 = w.clone();
    let rule = brief3(&mut w2, true);
    let mut d = Driver::with(&w2, BRIEF3);
    let mut seen = vec![];
    w2.run(&rule, |st| {
        d.step(&w2, &st.written, &st.units);
        d.ev.check().unwrap();
        seen.push((st.written.contains(&raise), d.required(D).contains(&(r, A))));
    });
    assert!(seen.contains(&(false, false)) && seen.contains(&(true, true)) && !seen.contains(&(true, false)), "{seen:?}");
}

/// Reach reads grants at any time: Y grants A write on D, then removes it; the removal of K from A
/// still reaches D (a write K made through A before then is judged by it).
#[test]
fn reach_reads_grants_at_any_time_spec_permissions_4() {
    let pw = paths::World::new(&[(X, A), (Y, D)]);
    let mut w = World::new(pw, &[A, D]);
    let (x, y, k) = (w.node(true, &[A, D]), w.node(true, &[D]), w.node(false, &[]));
    w.write(x, |p| p.edge(X, 1, &[], A, K, Role::Write, &[]));
    w.write(y, |p| p.edge(Y, 1, &[], D, A, Role::Write, &[]));
    w.write(y, |p| p.edge(Y, 1, &[], D, K, Role::Write, &[]));
    w.write(k, |p| p.content(K, 2, &[], D));
    let r = w.write(x, |p| p.edge(X, 6, &[], A, K, Role::None, &[]));
    w.write(y, |p| p.edge(Y, 7, &[], D, A, Role::None, &[]));
    assert_agrees("any time", &w);
    let (ev, _) = at_end(&w, BRIEF3, everything);
    assert_eq!(ev.required(&D).unwrap().get(&(r, A)), Some(&Reason::Removal));
}

/// Finding 18 (`open14_a_removed_writers_other_route_carried_the_removal_today`): Y grants K write
/// on D directly and A write on D and R; K writes D directly; X removes K from A; the stolen K
/// writes R through [A]. X syncs A and D, Y syncs D and R. By stated paths D's evidence holds
/// nothing of (K, A); by reach (A writes D) X requires the removal under D, Y takes it there and
/// requires it under R as evidence of the thief's write.
#[test]
fn open14_a_removed_writers_other_route_carried_the_removal_today() {
    let pw = paths::World::new(&[(X, A), (Y, D), (Y, R)]);
    let mut w = World::new(pw, &[A, D, R]);
    let (x, y, k) = (w.node(true, &[A, D]), w.node(true, &[D, R]), w.node(false, &[]));
    w.write(x, |p| p.edge(X, 1, &[], A, K, Role::Write, &[]));
    w.write(y, |p| p.edge(Y, 1, &[], D, A, Role::Write, &[]));
    w.write(y, |p| p.edge(Y, 1, &[], R, A, Role::Write, &[]));
    w.write(y, |p| p.edge(Y, 1, &[], D, K, Role::Write, &[]));
    w.write(k, |p| p.content(K, 2, &[], D));
    let r = w.write(x, |p| p.edge(X, 6, &[], A, K, Role::None, &[]));
    let late = w.write(k, |p| p.content(K, 8, &[A], R));
    assert_agrees("open14 f18", &w);
    let (ev, _) = at_end(&w, BRIEF3, |st| st.held[x].clone());
    assert_eq!(ev.required(&D).unwrap().get(&(r, A)), Some(&Reason::Removal));
    let (ev, _) = at_end(&w, NO_REACH, |st| st.held[x].clone());
    assert!(!ev.required(&D).unwrap().contains_key(&(r, A)));
    let (ev, h) = at_end(&w, BRIEF3, |st| st.entries[&R].clone());
    assert!(h.contains(&late) && ev.required(&R).unwrap().contains_key(&(r, A)));
}

/// Finding 19 (`open14_keys_open_travel_carries_a_removal_to_the_things_reading_through_it`): K
/// writes R through [A, O, D]; Y removes O from D. A holds write on O, so A's keys open O: the
/// removal naming O travels under A (Role changes travel), where N takes it to R. Reach alone puts
/// it under R only (D writes R); without keys-open travel A requires nothing of it.
#[test]
fn open14_keys_open_travel_carries_a_removal_to_the_things_reading_through_it() {
    const V: Thing = 7;
    let pw = paths::World::new(&[(X, A), (W, O), (Y, D), (V, R)]);
    let mut w = World::new(pw, &[A, O, D, R]);
    let (x, wn, y, v, k) = (w.node(true, &[A]), w.node(true, &[O]), w.node(true, &[D, A]), w.node(true, &[R]), w.node(false, &[]));
    let n = w.node(true, &[A, R]);
    w.write(x, |p| p.edge(X, 1, &[], A, K, Role::Write, &[]));
    w.write(wn, |p| p.edge(W, 1, &[], O, A, Role::Write, &[]));
    w.write(y, |p| p.edge(Y, 1, &[], D, O, Role::Write, &[]));
    w.write(v, |p| p.edge(V, 1, &[], R, D, Role::Write, &[]));
    w.write(k, |p| p.content(K, 2, &[A, O, D], R));
    let r = w.write(y, |p| p.edge(Y, 6, &[], D, O, Role::None, &[]));
    w.write(k, |p| p.content(K, 8, &[A, O, D], R));
    assert_agrees("open14 f19", &w);
    let (ev, _) = at_end(&w, BRIEF3, |st| st.held[y].clone());
    assert_eq!(ev.required(&A).unwrap().get(&(r, D)), Some(&Reason::Travels(O)));
    let (ev, _) = at_end(&w, NO_KEYS, |st| st.held[y].clone());
    assert!(!ev.required(&A).unwrap().contains_key(&(r, D)));
    let (ev, _) = at_end(&w, BRIEF3, |st| st.held[n].clone());
    assert!(ev.required(&R).unwrap().contains_key(&(r, D)));
}

/// The derivation's own: one removal commit on two things (X removes K from A and from B) is two
/// copies; the one on A reaches D (A writes D), the one on B reaches nothing. Each step
/// incremental equals from scratch.
#[test]
fn a_removal_on_two_things_reaches_by_each_copy_spec_permissions_4() {
    type E = Evidence<u32, Thing, u32>;
    const B: Thing = 20;
    let w = |holder: Thing, grant: bool| Kind::Write(Write { holder, grant, removal: !grant, gives_write: grant, gives_read: grant, relies: None, creation: None });
    let rec = |a: Thing, b: Thing| Hop { edge: (a, b), record: true };
    let mut ev = E::new(BRIEF3);
    ev.add_sid(D, D);
    ev.join(&D, D);
    ev.add((1, D), vec![Part { kind: w(A, true), hops: Some(vec![rec(Y, D)]), pos: 1, chained: true }]);
    ev.add((2, A), vec![Part { kind: w(K, true), hops: Some(vec![rec(X, A)]), pos: 2, chained: true }]);
    ev.add((2, B), vec![Part { kind: w(K, true), hops: Some(vec![rec(X, B)]), pos: 2, chained: true }]);
    ev.add((3, A), vec![Part { kind: w(K, false), hops: Some(vec![rec(X, A)]), pos: 3, chained: true }]);
    ev.add((3, B), vec![Part { kind: w(K, false), hops: Some(vec![rec(X, B)]), pos: 3, chained: true }]);
    ev.check().unwrap();
    let req = ev.required(&D).unwrap();
    assert!(req.contains_key(&(3, A)) && !req.contains_key(&(3, B)), "{req:?}");
}

/// Reach reads grants at any time, the converse: Y grants A write on D, then removes it, and only
/// then X removes K from A. The removal still reaches D: a write K made through [A] while A held
/// write on D, stamped before either removal (a stolen key's backdated write), is judged by the
/// removal's frontier, so D's readers need it.
#[test]
fn a_grant_removed_before_the_removal_still_reaches_spec_permissions_4() {
    let pw = paths::World::new(&[(X, A), (Y, D)]);
    let mut w = World::new(pw, &[A, D]);
    let (x, y, k) = (w.node(true, &[A, D]), w.node(true, &[D]), w.node(false, &[]));
    w.write(x, |p| p.edge(X, 1, &[], A, K, Role::Write, &[]));
    w.write(y, |p| p.edge(Y, 1, &[], D, A, Role::Write, &[]));
    w.write(k, |p| p.content(K, 2, &[A], D));
    w.write(y, |p| p.edge(Y, 4, &[], D, A, Role::None, &[]));
    let r = w.write(x, |p| p.edge(X, 6, &[], A, K, Role::None, &[]));
    assert_agrees("removed before", &w);
    let (ev, _) = at_end(&w, BRIEF3, everything);
    assert!(ev.required(&D).unwrap().contains_key(&(r, A)));
}

/// A removal on a thing of the unit is a body: no reach seed, no way taken, nothing required by
/// reach. X removes K from D (D in its own unit), A writes D.
#[test]
fn a_removal_on_a_unit_thing_has_no_reach_spec_permissions_4() {
    let pw = paths::World::new(&[(X, D), (Y, A)]);
    let mut w = World::new(pw, &[A, D]);
    let (x, y) = (w.node(true, &[A, D]), w.node(true, &[A]));
    w.write(y, |p| p.edge(Y, 1, &[], A, K, Role::Write, &[]));
    w.write(x, |p| p.edge(X, 1, &[], D, A, Role::Write, &[]));
    w.write(x, |p| p.edge(X, 1, &[], D, K, Role::Write, &[]));
    w.write(x, |p| p.edge(X, 6, &[], D, K, Role::None, &[]));
    assert_agrees("unit removal", &w);
    let (ev, _) = at_end(&w, BRIEF3, everything);
    assert_eq!(ev.reach_size(&D), Some((0, 0)));
}

/// Reach through a cycle of grants (A writes B, B writes A, B writes D) and by two paths into the
/// unit (A writes O1 and O2, each writes D): every edge of every way is required, the cycle's
/// back edge (B, A) too, since a path from A into D may go round it.
#[test]
fn reach_takes_every_way_through_a_cycle_and_two_paths_spec_permissions_4() {
    const B: Thing = 20;
    const O2: Thing = 21;
    let pw = paths::World::new(&[(X, A), (Y, B), (Y, D), (Y, O), (Y, O2)]);
    let mut w = World::new(pw, &[A, B, O, O2, D]);
    let (x, y) = (w.node(true, &[A]), w.node(true, &[B, O, O2, D]));
    w.write(x, |p| p.edge(X, 1, &[], A, K, Role::Write, &[]));
    let ab = w.write(y, |p| p.edge(Y, 1, &[], B, A, Role::Write, &[]));
    let ba = w.write(x, |p| p.edge(X, 1, &[], A, B, Role::Write, &[]));
    w.write(y, |p| p.edge(Y, 1, &[], D, B, Role::Write, &[]));
    let ao = w.write(y, |p| p.edge(Y, 1, &[], O, A, Role::Write, &[]));
    let ao2 = w.write(y, |p| p.edge(Y, 1, &[], O2, A, Role::Write, &[]));
    w.write(y, |p| p.edge(Y, 1, &[], D, O, Role::Write, &[]));
    w.write(y, |p| p.edge(Y, 1, &[], D, O2, Role::Write, &[]));
    let r = w.write(x, |p| p.edge(X, 6, &[], A, K, Role::None, &[]));
    assert_agrees("cycle and two paths", &w);
    let (ev, _) = at_end(&w, BRIEF3, everything);
    let req = ev.required(&D).unwrap();
    for (c, t) in [(r, A), (ab, B), (ba, A), (ao, O), (ao2, O2)] {
        assert!(req.contains_key(&(c, t)), "{c} on {t}: {req:?}");
    }
}

/// An edge write no chained authority makes (K, no admin of A, "removes" Q from A) is junk: no
/// reach seed and no copy anywhere, though A writes D (P10).
#[test]
fn an_unchained_removal_reaches_nothing_spec_permissions_4() {
    let pw = paths::World::new(&[(X, A), (Y, D)]);
    let mut w = World::new(pw, &[A, D]);
    let (x, y, k) = (w.node(true, &[A, D]), w.node(true, &[D]), w.node(false, &[]));
    w.write(x, |p| p.edge(X, 1, &[], A, K, Role::Write, &[]));
    w.write(x, |p| p.edge(X, 1, &[], A, Q, Role::Write, &[]));
    w.write(y, |p| p.edge(Y, 1, &[], D, A, Role::Write, &[]));
    let junk = w.write(k, |p| p.edge(K, 6, &[], A, Q, Role::None, &[]));
    assert_agrees("junk removal", &w);
    let (ev, _) = at_end(&w, BRIEF3, everything);
    assert!(!ev.required(&D).unwrap().contains_key(&(junk, A)));
    assert_eq!(ev.reach_size(&D), Some((0, 0)));
}

/// A grant of read on a hub is a removal as drafted (it gives below write at its `ts`), so a fresh
/// reader's grant on O, who never held write there, is required under every document O writes,
/// as a removed member's removal is: reach grows a document with every reader added to the hub.
/// The model agrees (`World::removes`); notes/a2-spec/README.md OPEN 16.
#[test]
fn a_fresh_read_grant_on_a_hub_is_required_under_its_documents_spec_permissions_4() {
    let pw = paths::World::new(&[(X, O), (Y, D)]);
    let mut w = World::new(pw, &[O, D]);
    let (x, y) = (w.node(true, &[O, D]), w.node(true, &[D]));
    w.write(y, |p| p.edge(Y, 1, &[], D, O, Role::Write, &[]));
    let g = w.write(x, |p| p.edge(X, 2, &[], O, Q, Role::Read, &[]));
    assert_agrees("fresh read grant", &w);
    let (ev, _) = at_end(&w, BRIEF3, everything);
    assert_eq!(ev.required(&D).unwrap().get(&(g, O)), Some(&Reason::Removal));
}

/// The derivation's own: the last edge of a way is often a body (A's grant on D, on D's unit):
/// forgetting it, no reach seed of D's names it, yet D's reach goes (no way into D is left), and
/// the removal leaves D's evidence.
#[test]
fn forgetting_a_ways_last_edge_held_as_a_body_takes_the_reach_away_spec_permissions_4() {
    type E = Evidence<u32, Thing, u32>;
    let w = |holder: Thing, grant: bool| Kind::Write(Write { holder, grant, removal: !grant, gives_write: grant, gives_read: grant, relies: None, creation: None });
    let rec = |a: Thing, b: Thing| Hop { edge: (a, b), record: true };
    let mut ev = E::new(BRIEF3);
    ev.add_sid(D, D);
    ev.join(&D, D);
    ev.add((1, D), vec![Part { kind: w(A, true), hops: Some(vec![rec(Y, D)]), pos: 1, chained: true }]);
    ev.add((2, A), vec![Part { kind: w(K, true), hops: Some(vec![rec(X, A)]), pos: 2, chained: true }]);
    ev.add((3, A), vec![Part { kind: w(K, false), hops: Some(vec![rec(X, A)]), pos: 3, chained: true }]);
    assert!(ev.required(&D).unwrap().contains_key(&(3, A)));
    ev.forget(&(1, D));
    ev.check().unwrap();
    assert!(ev.required(&D).unwrap().is_empty(), "{:?}", ev.required(&D));
}
