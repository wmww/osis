//! Hand worlds (spec/permissions.md §4, as notes/a2-spec/permissions.md drafts it): each held-model `evidence` hand test that names a rule or finding, as a
//! differential at every step (`assert_agrees`) plus the copy the rule decides (its reason where only that rule brings it);
//! and the derivation's own (a path entry waiting to open).
use super::*;
use held_model::evidence::names::*;
use held_model::evidence::State;
use osis_engine::evidence::{Gives, Need, Reason};
use roles_model::paths::Kind as PKind;

/// The derivation over `held` of the end state of `w`'s run under (iv).
fn at_end(w: &World, held: impl Fn(&State) -> Set) -> (Driver, State) {
    let mut w = w.clone();
    let rule = granted(&mut w);
    let st = w.run(&rule, |_| {});
    let mut d = Driver::new(&w, false);
    d.step(&w, &held(&st), &st.units);
    (d, st)
}

/// D's reader at the end: its required copies with their reasons.
fn reader_of(w: &World, s: Thing) -> BTreeMap<CopyId<Id, Thing>, Reason<Id, Thing>> {
    let (d, _) = at_end(w, |st| st.entries[&s].clone());
    d.ev.required(&s).cloned().unwrap_or_default()
}

/// spec_open10's base: X mints A (K, Q writers), Y mints D (A writes it); X syncs A, Y syncs D,
/// Q syncs A, K (no admin) is hostile.
fn base() -> (World, [usize; 4]) {
    let pw = paths::World::new(&[(X, A), (Y, D)]);
    let mut w = World::new(pw, &[A, D]);
    let n = [w.node(true, &[A]), w.node(true, &[D]), w.node(false, &[A]), w.node(true, &[A])];
    w.write(n[0], |p| p.edge(X, 1, &[], A, K, Role::Write, &[]));
    w.write(n[1], |p| p.edge(Y, 1, &[], D, A, Role::Write, &[]));
    (w, n)
}

/// Finding 9 (`f9_a_removal_of_two_holders_waits_for_each_creation`): X removes K and Q from A in
/// one commit C; K writes D after it. C is on K's edge; the creation of Q's entry (X's grant to Q),
/// on no stated path, is in D's evidence for C's reset.
#[test]
fn f9_the_creation_a_reset_names_is_evidence_spec_permissions_2() {
    let (mut w, [x, _, _, _]) = base();
    let kn = w.node(true, &[A]);
    let gq = w.write(x, |p| p.edge(X, 1, &[], A, Q, Role::Write, &[]));
    let c = w.write_parts(x, |p| p.commit(X, 5, &[], A, vec![PKind::set(K, Role::None), PKind::set(Q, Role::None)]));
    w.write(kn, |p| p.content(K, 6, &[A], D));
    assert_agrees("f9", &w);
    let req = reader_of(&w, D);
    assert!(req.contains_key(&(c[0], A)), "{req:?}");
    assert_eq!(req.get(&(gq, A)), Some(&Reason::Creation((c[0], A))), "{req:?}");
}

const M1: Thing = 30;
const M2: Thing = 31;
const V: Thing = 32;

/// Finding 11 (b) (`f11_a_stated_path_no_grant_joins_leaks_a_roster_unless_paths_must_be_joined`):
/// K states [M1, M2, A] for its write on D, M2 holding nothing on A: the path is not joined, so it
/// brings nothing, and V's grant of M1 on M2 is not copied under D at U (P9).
#[test]
fn f11_a_path_no_chained_grant_joins_brings_nothing_spec_permissions_4() {
    let pw = paths::World::new(&[(X, A), (Y, D), (V, M1), (V, M2)]);
    let mut w = World::new(pw, &[A, D, M1, M2]);
    let (y, v, u, k) = (w.node(true, &[D]), w.node(true, &[M1, M2]), w.node(true, &[M2, D]), w.node(false, &[]));
    w.write(y, |p| p.edge(Y, 1, &[], D, A, Role::Write, &[]));
    let gm = w.write(v, |p| p.edge(V, 1, &[], M2, M1, Role::Write, &[]));
    w.write(v, |p| p.edge(V, 1, &[], M1, K, Role::Write, &[]));
    w.write(k, |p| p.content(K, 2, &[M1, M2, A], D));
    assert_agrees("f11", &w);
    let (d, _) = at_end(&w, |st| st.held[u].clone());
    assert!(d.held.contains_key(&(gm, M2)));
    assert_eq!(d.ev.required(&D).unwrap(), &BTreeMap::new());
}

/// Finding 13 (`f13_a_path_set_only_by_junk_waits_at_the_reader_where_the_draft_refuses`): Q writes
/// D through [A] where (Q, A) holds only K's junk grant: the junk is no copy (P10), and the path
/// it does not join brings nothing.
#[test]
fn f13_junk_on_a_path_edge_is_no_copy_spec_permissions_4() {
    let (mut w, [_, y, k, q]) = base();
    let junk = w.write(k, |p| p.edge(K, 2, &[], A, Q, Role::Admin, &[]));
    w.write(q, |p| p.content(Q, 3, &[A], D));
    assert_agrees("f13", &w);
    let (d, _) = at_end(&w, |st| st.held[q].iter().chain(&st.held[y]).copied().collect());
    assert!(d.held.contains_key(&(junk, A)));
    assert_eq!(d.ev.required(&D).unwrap(), &BTreeMap::new());
}

/// Finding 14 (`f14_a_dropped_grant_is_read_by_the_regrant_so_applied_only_strands_a_write`): Q's
/// grant to K (g1), dropped by X's removal of Q, is chained: D's evidence holds it (the re-grant
/// reads it), on the edge K's write uses.
#[test]
fn f14_a_dropped_chained_grant_is_evidence_spec_permissions_4() {
    let pw = paths::World::new(&[(X, A), (Y, D)]);
    let mut w = World::new(pw, &[A, D]);
    let (x, y, q, k) = (w.node(true, &[A]), w.node(true, &[D]), w.node(true, &[A]), w.node(true, &[A]));
    w.write(y, |p| p.edge(Y, 1, &[], D, A, Role::Write, &[]));
    w.write(x, |p| p.edge(X, 1, &[], A, Q, Role::Admin, &[]));
    let g1 = w.write(q, |p| p.edge(Q, 1, &[], A, K, Role::Write, &[]));
    w.write(k, |p| p.content(K, 2, &[A], D));
    w.write(x, |p| p.edge(X, 3, &[], A, Q, Role::None, &[]));
    let rg = w.write(x, |p| p.edge(X, 5, &[], A, K, Role::Write, &[]));
    assert_agrees("f14", &w);
    let req = reader_of(&w, D);
    assert!(req.contains_key(&(g1, A)), "{req:?}");
    assert!(req.contains_key(&(rg, A)));
}

/// Finding 15 (`f15_a_writers_finalizes_and_an_inviters_grants_are_chained_and_copied`): a
/// writer's finalizes on a used edge are chained, each a copy (27 more for 27 more); an
/// inviter's invite grants likewise. OPEN 10's junk (`open10_junk_by_a_non_admin_adds_no_copy_but_under_the_draft`):
/// a non-admin's grants are none; an admin's (`open10_an_admins_writes_on_a_used_edge_are_copies_in_every_variant`)
/// each one.
#[test]
fn f15_what_a_non_admin_and_an_admin_force_on_a_used_edge_spec_permissions_4() {
    let copies = |w: &World| reader_of(w, D).len();
    let finalizes = |n: u32| {
        let (mut w, [x, _, k, q]) = base();
        w.write(x, |p| p.edge(X, 1, &[], A, Q, Role::Write, &[]));
        for i in 0..n {
            w.write(k, |p| p.push(K, 2 + i, &[], A, PKind::finalize(Q)));
        }
        w.write(q, |p| p.content(Q, 2 + n, &[A], D));
        assert_agrees("f15 finalizes", &w);
        copies(&w)
    };
    assert_eq!(finalizes(30) - finalizes(3), 27);
    let invites = |n: u32| {
        let (mut w, [x, _, k, q]) = base();
        w.write(x, |p| p.push(X, 1, &[], A, PKind::set(K, Role::Write).inviting(Role::Write)));
        w.write(x, |p| p.edge(X, 1, &[], A, Q, Role::Write, &[]));
        for i in 0..n {
            w.write(k, |p| p.push(K, 2 + i, &[], A, PKind::set(Q, Role::Read)));
        }
        w.write(q, |p| p.content(Q, 2 + n, &[A], D));
        copies(&w)
    };
    assert_eq!(invites(30) - invites(3), 27);
    let junk = |n: u32| {
        let (mut w, [x, _, k, q]) = base();
        w.write(x, |p| p.edge(X, 1, &[], A, Q, Role::Write, &[]));
        for i in 0..n {
            w.write(k, |p| p.edge(K, 2 + i, &[], A, Q, Role::Admin, &[]));
        }
        w.write(q, |p| p.content(Q, 2 + n, &[A], D));
        assert_agrees("junk", &w);
        copies(&w)
    };
    assert_eq!(junk(30), junk(3));
    let admin = |n: u32| {
        let (mut w, [x, _, _, q]) = base();
        for i in 0..n {
            w.write(x, |p| p.edge(X, 1 + i, &[], A, Q, Role::Write, &[]));
        }
        w.write(q, |p| p.content(Q, 2 + n, &[A], D));
        copies(&w)
    };
    assert_eq!(admin(30) - admin(3), 27);
}

/// The split form (`split_a_part_on_another_thing_adds_no_evidence_requirement`, finding 8): K
/// writes T1 along [A] and T2 along [B] in one commit; T1's evidence holds nothing of B.
#[test]
fn split_a_part_on_another_thing_brings_nothing_spec_permissions_4() {
    const T1: Thing = 30;
    const T2: Thing = 31;
    const B: Thing = 32;
    let pw = paths::World::new(&[(X, A), (X, T1), (Y, B), (Y, T2)]);
    let mut w = World::new(pw, &[A, B, T1, T2]);
    let (x, y, k) = (w.node(true, &[A, T1]), w.node(true, &[B, T2]), w.node(true, &[]));
    let ga = w.write(x, |p| p.edge(X, 1, &[], A, K, Role::Write, &[]));
    w.write(x, |p| p.edge(X, 1, &[], T1, A, Role::Write, &[]));
    let gb = w.write(y, |p| p.edge(Y, 1, &[], B, K, Role::Write, &[]));
    w.write(y, |p| p.edge(Y, 1, &[], T2, B, Role::Write, &[]));
    w.write_parts(k, |p| p.split(K, 2, K, &[(&[A], T1), (&[B], T2)]));
    w.write(y, |p| p.edge(Y, 6, &[], B, K, Role::None, &[]));
    assert_agrees("split", &w);
    let t1: Copies = reader_of(&w, T1).into_keys().collect();
    assert_eq!(t1, Copies::from([(ga, A)]));
    let t2: Copies = reader_of(&w, T2).into_keys().collect();
    assert!(t2.contains(&(gb, B)) && !t2.contains(&(ga, A)), "{t2:?}");
}

/// P4 (`p4_evidence_leaves_with_the_last_commit_that_needed_it`): Q writes D twice through
/// [A]; forgetting the first keeps X's grant to Q, forgetting the second takes it out of D's
/// evidence, incrementally as from scratch, as the model. (The family's world keeps K's grant
/// under (iv): the listed removal's reset names it as its entry's creation.)
#[test]
fn p4_a_copy_leaves_with_the_last_body_that_needed_it_spec_permissions_4() {
    let (mut w, [x, _, _, q]) = base();
    let gq = w.write(x, |p| p.edge(X, 1, &[], A, Q, Role::Write, &[]));
    let c0 = w.write(q, |p| p.content(Q, 2, &[A], D));
    let c1 = w.write(q, |p| p.content(Q, 3, &[A], D));
    let rule = granted(&mut w);
    let mut st = w.run(&rule, |_| {});
    let mut d = Driver::new(&w, false);
    d.step(&w, &st.entries[&D], &st.units);
    assert_eq!(d.required(D), Copies::from([(gq, A)]));
    for (i, left) in [(c0, true), (c1, false)] {
        w.forget(&rule, &mut st, i);
        d.step(&w, &st.entries[&D], &st.units);
        assert_eq!(d.required(D), model_copies(&w, &rule, D, &st.units, &st.entries[&D]));
        assert_eq!(d.required(D).contains(&(gq, A)), left);
        assert_eq!(d.ev.from_scratch(&D).unwrap().into_keys().collect::<Copies>(), d.required(D));
    }
}

/// Finding 2 (`f2_copies_placed_at_logging_leave_a_sync_id_short_when_a_unit_changes`): O, on
/// K's path, leaves R's unit after K's write: A's grant on O, a body of R before, is a copy of R
/// after, derived again at the retag.
#[test]
fn f2_a_retag_turns_what_bodies_still_need_into_copies_spec_permissions_4() {
    let mut sh = Shape::nth(0);
    (sh.via_org, sh.units, sh.listed) = (true, 4, true);
    let mut w = hm::family(sh);
    assert_agrees("f2", &w);
    let rule = granted(&mut w);
    let go = (0..w.w.commits.len()).find(|&i| w.w.sets(i) == Some((A, O))).unwrap();
    let mut d = Driver::new(&w, false);
    let mut seen = vec![];
    w.run(&rule, |st| {
        d.step(&w, &st.entries[&R], &st.units);
        seen.push((st.units[&R].contains(&O), d.required(R).contains(&(go, O))));
    });
    assert!(seen.contains(&(true, false)) && seen.contains(&(false, true)), "{seen:?}");
}

/// The model's other hand worlds (findings 1 to 6 and 12, risk 3, P2, the addendum, P6's cost
/// worlds): the derivation agrees at every step.
#[test]
fn the_models_other_hand_worlds_agree_spec_permissions_4() {
    let org_apart = Shape { via_org: true, units: 0, listed: false, thief: false, regrant: false, addendum: false, raised: false, q_d: false, q_r: false, y_a: false, org_apart: true, grant: false, mint: 0 };
    assert_agrees("f1", &hm::family(org_apart));
    let mut sh = Shape::nth(0);
    (sh.raised, sh.thief) = (true, true);
    assert_agrees("f3", &hm::family(sh));
    for units in [1, 2, 3] {
        let mut sh = Shape::nth(0);
        (sh.units, sh.thief) = (units, true);
        assert_agrees("p2", &hm::family(sh));
    }
    let two = |c1: u32, listed: bool| {
        let pw = paths::World::new(&[(X, A), (Y, D)]);
        let mut w = World::new(pw, &[A, D]);
        let (x, y, k, q) = (w.node(true, &[A]), w.node(true, &[D]), w.node(true, &[A]), w.node(true, &[A]));
        w.write(x, |p| p.edge(X, 1, &[], A, K, Role::Admin, &[]));
        w.write(x, |p| p.edge(X, 1, &[], A, Q, Role::Write, &[]));
        w.write(y, |p| p.edge(Y, 1, &[], D, A, Role::Write, &[]));
        let gz = w.write(k, |p| p.edge(K, 2, &[], A, Z, Role::Write, &[]));
        let c0 = w.write(k, |p| p.content(K, 2, &[A], D));
        let c = w.write(k, |p| p.content(K, c1, &[A], D));
        let r = w.write(x, |p| p.edge(X, 6, &[], A, K, Role::None, &if listed { vec![c0, gz] } else { vec![c] }));
        w.write(q, |p| p.addendum(Q, 7, &[A], D, r, &[c]));
        w.write(x, |p| p.edge(X, 6, &[], A, K, Role::Write, &[]));
        w
    };
    for (c1, listed) in [(3, true), (7, false)] {
        assert_agrees("f4 f6 addendum f12", &two(c1, listed));
    }
    let pw = paths::World::new(&[(X, A), (Y, R), (R, E)]);
    let mut w = World::new(pw, &[A, R]);
    w.member(E, R);
    let (x, y, k) = (w.node(true, &[A]), w.node(true, &[R]), w.node(false, &[]));
    w.write(x, |p| p.edge(X, 1, &[], A, K, Role::Write, &[]));
    w.write(y, |p| p.edge(Y, 1, &[], R, A, Role::Write, &[]));
    w.write(x, |p| p.edge(X, 6, &[], A, K, Role::None, &[]));
    w.write(k, |p| p.content(K, 8, &[A, R], E));
    assert_agrees("risk3", &w);
}

/// The derivation's own (finding 8, notes/path-form.md): a body whose path entry has not opened
/// here brings nothing; its opening brings the path's edges, and a chained grant arriving later
/// joins it. Each step incremental equals from scratch.
#[test]
fn a_body_whose_path_waits_brings_nothing_until_it_opens_spec_permissions_4() {
    type E = Evidence<u32, Thing, u32>;
    let mut ev = E::new(Config { keys_open: false, leaves: false });
    let check = |ev: &E| {
        let inc: Copies32 = ev.required(&D).unwrap().keys().copied().collect();
        ev.check().unwrap();
        inc
    };
    type Copies32 = BTreeSet<CopyId<u32, Thing>>;
    ev.add_sid(D, D);
    ev.join(&D, D);
    let write = |holder: Thing| Kind::Write(Write { holder, grant: Some(Gives::role(osis_base::Role::Write)), removal: false, gives_write: true, gives_read: true, relies: None, creation: None, leaves: vec![] });
    let rec = |a: Thing, b: Thing| Hop { edge: (a, b), record: true, need: Need::Role(osis_base::Role::Write) };
    let hop = |a: Thing, b: Thing| Hop { edge: (a, b), record: false, need: Need::Role(osis_base::Role::Write) };
    // Y grants A write on D (a body); K writes D along [A], its path waiting; X grants K on A
    // before the write
    ev.add((1, D), vec![Part { kind: write(A), hops: Some(vec![rec(Y, D)]), pos: 1, chained: true }]);
    ev.add((5, D), vec![Part { kind: Kind::Content, hops: None, pos: 5, chained: false }]);
    assert_eq!(check(&ev), Copies32::new());
    ev.add((2, A), vec![Part { kind: write(K), hops: Some(vec![rec(X, A)]), pos: 2, chained: true }]);
    assert_eq!(check(&ev), Copies32::new());
    // the path opens onto a joined path
    ev.open_path(&(5, D), 0, vec![hop(K, A), hop(A, D)]);
    assert_eq!(check(&ev), Copies32::from([(2, A)]));
    assert_eq!(ev.required(&D).unwrap().get(&(2, A)), Some(&Reason::Edge((K, A))));
    ev.forget(&(2, A));
    assert_eq!(check(&ev), Copies32::new());
    // a second write's path opens with no grant on (K, A): not joined; a grant ordered between
    // the two writes joins the later one only
    ev.add((9, D), vec![Part { kind: Kind::Content, hops: None, pos: 9, chained: false }]);
    ev.open_path(&(9, D), 0, vec![hop(K, A), hop(A, D)]);
    assert_eq!(check(&ev), Copies32::new());
    ev.add((7, A), vec![Part { kind: write(K), hops: Some(vec![rec(X, A)]), pos: 7, chained: true }]);
    assert_eq!(check(&ev), Copies32::from([(7, A)]));
}

/// The derivation's own: a path is joined by the first chained grant on each edge (a later one
/// joins nothing), and a member copy forgotten leaves though no body's joined-ness moves. Each
/// step incremental equals from scratch.
#[test]
fn the_first_grant_joins_and_a_forgotten_member_leaves_spec_permissions_4() {
    type E = Evidence<u32, Thing, u32>;
    type Copies32 = BTreeSet<CopyId<u32, Thing>>;
    let check = |ev: &E| {
        let inc: Copies32 = ev.required(&D).unwrap().keys().copied().collect();
        ev.check().unwrap();
        inc
    };
    let write = |holder: Thing| Kind::Write(Write { holder, grant: Some(Gives::role(osis_base::Role::Write)), removal: false, gives_write: true, gives_read: true, relies: None, creation: None, leaves: vec![] });
    let rec = |a: Thing, b: Thing| Hop { edge: (a, b), record: true, need: Need::Role(osis_base::Role::Write) };
    let hop = |a: Thing, b: Thing| Hop { edge: (a, b), record: false, need: Need::Role(osis_base::Role::Write) };
    let mut ev = E::new(Config { keys_open: false, leaves: false });
    ev.add_sid(D, D);
    ev.join(&D, D);
    ev.add((1, D), vec![Part { kind: write(A), hops: Some(vec![rec(Y, D)]), pos: 1, chained: true }]);
    ev.add((2, A), vec![Part { kind: write(K), hops: Some(vec![rec(X, A)]), pos: 2, chained: true }]);
    ev.add((8, A), vec![Part { kind: write(K), hops: Some(vec![rec(X, A)]), pos: 8, chained: true }]);
    ev.add((5, D), vec![Part { kind: Kind::Content, hops: Some(vec![hop(K, A), hop(A, D)]), pos: 5, chained: false }]);
    assert_eq!(check(&ev), Copies32::from([(2, A), (8, A)]));
    ev.forget(&(8, A));
    assert_eq!(check(&ev), Copies32::from([(2, A)]));
}

/// A removal reaches a far thing only with a write it judges there: X removes K on A while A writes
/// D (Y's grant). With no body of D resting on K's edge, D requires nothing of A; K's write on D
/// through [A] (before the removal) brings the removal and the grant it ends.
#[test]
fn a_removal_is_evidence_only_where_a_body_rests_on_its_edge_spec_permissions_4() {
    type E = Evidence<u32, Thing, u32>;
    let rec = |a: Thing, b: Thing| Hop { edge: (a, b), record: true, need: Need::Role(osis_base::Role::Write) };
    let hop = |a: Thing, b: Thing| Hop { edge: (a, b), record: false, need: Need::Role(osis_base::Role::Write) };
    let w = |holder: Thing, grant: bool| Kind::Write(Write { holder, grant: grant.then(|| Gives::role(osis_base::Role::Write)), removal: !grant, gives_write: grant, gives_read: grant, relies: None, creation: None, leaves: vec![] });
    let mut ev = E::new(Config { keys_open: true, leaves: false });
    ev.add_sid(D, D);
    ev.join(&D, D);
    ev.add((1, D), vec![Part { kind: w(A, true), hops: Some(vec![rec(Y, D)]), pos: 1, chained: true }]);
    ev.add((2, A), vec![Part { kind: w(K, true), hops: Some(vec![rec(X, A)]), pos: 2, chained: true }]);
    ev.add((5, A), vec![Part { kind: w(K, false), hops: Some(vec![rec(X, A)]), pos: 5, chained: true }]);
    ev.check().unwrap();
    assert!(ev.required(&D).unwrap().is_empty(), "{:?}", ev.required(&D));
    ev.add((3, D), vec![Part { kind: Kind::Content, hops: Some(vec![hop(K, A), hop(A, D)]), pos: 3, chained: false }]);
    ev.check().unwrap();
    let req: BTreeSet<CopyId<u32, Thing>> = ev.required(&D).unwrap().keys().copied().collect();
    assert_eq!(req, BTreeSet::from([(2, A), (5, A)]));
}

/// Finding 23 (held-model `gaps_a_write_through_a_read_hop_pends_at_a_reader_lacking_the_read_grant`):
/// the stolen K writes R through [A, O], A holding only read on O. A hop joins a part only by a
/// grant giving what the part needs there (write for content), so at a node holding everything
/// the path is not joined and R's evidence takes nothing of it: no copy of X's grant to K, nor of
/// W's read grant. Read as joined by any grant, both would be copies.
#[test]
fn f23_a_read_hop_joins_no_write_spec_permissions_4() {
    let pw = paths::World::new(&[(X, A), (W, O), (Y, R)]);
    let mut w = World::new(pw, &[A, O, R]);
    let (x, wn, y, k) = (w.node(true, &[A]), w.node(true, &[O]), w.node(true, &[R]), w.node(false, &[]));
    let gk = w.write(x, |p| p.edge(X, 1, &[], A, K, Role::Write, &[]));
    let ga = w.write(wn, |p| p.edge(W, 1, &[], O, A, Role::Read, &[]));
    w.write(y, |p| p.edge(Y, 1, &[], R, O, Role::Write, &[]));
    w.write(k, |p| p.content(K, 5, &[A, O], R));
    w.join = Join::Needed;
    assert_agrees("f23", &w);
    let (d, _) = at_end(&w, |st| st.written.clone());
    let req = d.ev.required(&R).cloned().unwrap_or_default();
    assert!(!req.contains_key(&(gk, A)) && !req.contains_key(&(ga, O)), "{req:?}");
}
