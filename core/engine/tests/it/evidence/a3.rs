//! The derivation's leaves (`Config::leaves`; spec/permissions.md §4 as notes/a3-spec/permissions.md
//! drafts it: the leaf bullet, §5.1 Reading a list), built unused and going at A3: the leaf form is not the design
//! (notes/write-path-design.md §2, E4), so held-model has no oracle for them. Worlds for findings 27
//! and 34, each a differential of the copies at every step (`assert_agrees`) plus the leaf the
//! draft's words decide; the derivation's own (an addendum leaving, a late witness, a lowering
//! leaving a set).
use super::*;
use held_model::evidence::names::*;
use held_model::evidence::State;
use osis_engine::evidence::LeafWhy;

/// A3's derivation over a held set of the end state of `w` (set to `rule`).
fn at_end(w: &World, rule: &Rule, held: impl Fn(&State) -> Set) -> Driver {
    let st = w.run(rule, |_| {});
    let h = held(&st);
    let mut d = Driver::a3(w);
    d.step(w, &h, &st.units);
    d.ev.check().unwrap();
    d
}


/// Finding 27: X removes Z from A at 3 though Z held no write there (the removal takes no write
/// away), listing Z's earlier write c0 in D's leaf; X grants Z write; Z writes c1 on D through [A].
/// A leaf is read only where its lowering cuts the part: nothing requires the leaf, c1 waits on
/// nothing. With Z granted write before the removal (the control) the removal cuts both writes:
/// D requires the leaf, and a node lacking it waits.
#[test]
#[ignore = "D2: evidence rebuilt at A2 (notes/redesign-plan.md): held-model carries a lowering's list whole, so no world gives the derivation leaf pairs"]
fn f27_a_leaf_of_a_lowering_that_cuts_nothing_is_waited_on_by_nobody() {
    for granted in [false, true] {
        let pw = paths::World::new(&[(X, A), (Y, D)]);
        let mut w = World::new(pw, &[A, D]);
        let (x, y, z) = (w.node(true, &[A]), w.node(true, &[D]), w.node(true, &[]));
        w.write(y, |p| p.edge(Y, 1, &[], D, A, Role::Write, &[]));
        if granted {
            w.write(x, |p| p.edge(X, 1, &[], A, Z, Role::Write, &[]));
        }
        let c0 = w.write(z, |p| p.content(Z, 2, &[A], D));
        let r = w.write(x, |p| p.edge(X, 3, &[], A, Z, Role::None, &[c0]));
        w.write(x, |p| p.edge(X, 4, &[], A, Z, Role::Write, &[]));
        let c1 = w.write(z, |p| p.content(Z, 5, &[A], D));
        assert_agrees("f27", &w);
        let rule = a2(&mut w);
        let mut d = at_end(&w, &rule, |st| st.written.clone());
        let want = granted.then_some(LeafWhy::Reads);
        assert_eq!(d.ev.leaves(&D).unwrap().get(&(r, D)).copied(), want, "granted {granted}");
        assert_eq!(d.ev.waits(&(c1, D), |_| false), granted.then_some((r, D)), "granted {granted}");
        assert_eq!(d.ev.waits(&(c1, D), |l| *l == (r, D)), None);
    }
}


/// Finding 34: X removes K from A listing K's write c on A (its own thing's leaf). A leaf for the
/// lowering's own thing is read only by bodies there: required while c is held, gone with it (never
/// kept at home).
#[test]
#[ignore = "D2: evidence rebuilt at A2 (notes/redesign-plan.md): held-model carries a lowering's list whole, so no world gives the derivation leaf pairs"]
fn f34_a_removals_leaf_for_its_own_thing_leaves_with_what_it_reads() {
    let pw = paths::World::new(&[(X, A)]);
    let mut w = World::new(pw, &[A]);
    let (x, k) = (w.node(true, &[A]), w.node(true, &[A]));
    w.write(x, |p| p.edge(X, 1, &[], A, K, Role::Write, &[]));
    let c = w.write(k, |p| p.content(K, 2, &[], A));
    let r = w.write(x, |p| p.edge(X, 6, &[], A, K, Role::None, &[c]));
    assert_agrees("f34", &w);
    let rule = a2(&mut w);
    let mut st = w.run(&rule, |_| {});
    let mut d = Driver::a3(&w);
    d.step(&w, &st.held[x], &st.units);
    assert_eq!(d.ev.leaves(&A).unwrap(), BTreeMap::from([((r, A), LeafWhy::Reads)]));
    w.forget(&rule, &mut st, c);
    d.step(&w, &st.held[x], &st.units);
    d.ev.check().unwrap();
    assert_eq!(d.ev.leaves(&A).unwrap(), BTreeMap::new());
}

/// An addendum is a body only while it lists a held commit resting on its removal's edge
/// (held-model `an_addendum_leaves_with_the_last_commit_it_lists`): Q's addendum on D lists K's c1;
/// with c1 forgotten (and c0, which it does not list, held) the addendum brings nothing, so X's grant
/// to Q (on the addendum's path alone) leaves D's evidence, incrementally as from scratch.
#[test]
#[ignore = "D2: evidence rebuilt at A2 (notes/redesign-plan.md): held-model carries a lowering's list whole, so no world gives the derivation leaf pairs"]
fn an_addendum_leaves_with_the_last_commit_it_lists() {
    let pw = paths::World::new(&[(X, A), (Y, D)]);
    let mut w = World::new(pw, &[A, D]);
    let (x, y, k, q) = (w.node(true, &[A]), w.node(true, &[D]), w.node(true, &[A]), w.node(true, &[A]));
    w.write(x, |p| p.edge(X, 1, &[], A, K, Role::Write, &[]));
    let gq = w.write(x, |p| p.edge(X, 1, &[], A, Q, Role::Write, &[]));
    w.write(y, |p| p.edge(Y, 1, &[], D, A, Role::Write, &[]));
    w.write(k, |p| p.content(K, 2, &[A], D));
    let c1 = w.write(k, |p| p.content(K, 3, &[A], D));
    let r = w.write(x, |p| p.edge(X, 6, &[], A, K, Role::None, &[]));
    let ad = w.write(q, |p| p.addendum(Q, 7, &[A], D, r, &[c1]));
    assert_agrees("addendum", &w);
    let rule = a2(&mut w);
    let mut st = w.run(&rule, |_| {});
    let everything = |st: &State| st.written.difference(&st.forgotten).copied().collect::<Set>();
    let mut d = Driver::a3(&w);
    d.step(&w, &everything(&st), &st.units);
    assert!(d.required(D).contains(&(gq, A)));
    w.forget(&rule, &mut st, c1);
    let h = everything(&st);
    assert!(h.contains(&ad));
    d.step(&w, &h, &st.units);
    d.ev.check().unwrap();
    assert!(!d.required(D).contains(&(gq, A)));
    assert_eq!(d.required(D), model_copies(&w, &rule, D, &st.units, &h));
    // the addendum forgotten too: nothing indexes it any more
    w.forget(&rule, &mut st, ad);
    let h = everything(&st);
    d.step(&w, &h, &st.units);
    d.ev.check().unwrap();
    assert_eq!(d.required(D), model_copies(&w, &rule, D, &st.units, &h));
}

/// What a lowering cuts moves after it is held: X removes K from A at 6 listing K's write c on A;
/// X's grant of write to K at 1 arrives after it. Until then the removal cuts nothing (no leaf
/// read); with the grant it cuts c, so A requires its own thing's leaf, incrementally as from scratch.
#[test]
#[ignore = "D2: evidence rebuilt at A2 (notes/redesign-plan.md): held-model carries a lowering's list whole, so no world gives the derivation leaf pairs"]
fn a_late_witness_makes_a_held_removals_leaf_read() {
    let pw = paths::World::new(&[(X, A)]);
    let mut w = World::new(pw, &[A]);
    let (x, k) = (w.node(true, &[A]), w.node(true, &[A]));
    let c = w.write(k, |p| p.content(K, 2, &[], A));
    let r = w.write(x, |p| p.edge(X, 6, &[], A, K, Role::None, &[c]));
    let g = w.write(x, |p| p.edge(X, 1, &[], A, K, Role::Write, &[]));
    assert_agrees("late witness", &w);
    let rule = a2(&mut w);
    let mut d = Driver::a3(&w);
    let mut seen = vec![];
    w.run(&rule, |st| {
        d.step(&w, &st.held[x], &st.units);
        d.ev.check().unwrap();
        if st.held[x].contains(&r) {
            seen.push((st.held[x].contains(&g), d.ev.leaves(&A).unwrap().get(&(r, A)).copied()));
        }
    });
    assert!(seen.contains(&(false, None)) && seen.contains(&(true, Some(LeafWhy::Reads))), "{seen:?}");
}

/// A lowering leaving a set as its closure is rebuilt takes its leaves with it: X grants K write on
/// A, Y grants A write on D, K writes c on D through [A], X removes K listing it; the removal is in
/// D's set as a write on c's path, so D requires its leaf. Forgetting Y's grant unjoins c's path:
/// the removal and its leaf leave D's set, though c still rests on the removal's edge.
#[test]
#[ignore = "D2: evidence rebuilt at A2 (notes/redesign-plan.md): held-model carries a lowering's list whole, so no world gives the derivation leaf pairs"]
fn a_lowering_leaving_a_set_takes_its_leaves() {
    let pw = paths::World::new(&[(X, A), (Y, D)]);
    let mut w = World::new(pw, &[A, D]);
    let (x, y, k) = (w.node(true, &[A]), w.node(true, &[D]), w.node(true, &[]));
    w.write(x, |p| p.edge(X, 1, &[], A, K, Role::Write, &[]));
    let way = w.write(y, |p| p.edge(Y, 1, &[], D, A, Role::Write, &[]));
    let c = w.write(k, |p| p.content(K, 2, &[A], D));
    let r = w.write(x, |p| p.edge(X, 6, &[], A, K, Role::None, &[c]));
    assert_agrees("path member", &w);
    let rule = a2(&mut w);
    let mut st = w.run(&rule, |_| {});
    let everything = |st: &State| st.written.difference(&st.forgotten).copied().collect::<Set>();
    let mut d = Driver::a3(&w);
    d.step(&w, &everything(&st), &st.units);
    d.ev.check().unwrap();
    assert_eq!(d.ev.leaves(&D).unwrap().get(&(r, D)), Some(&LeafWhy::Reads));
    w.forget(&rule, &mut st, way);
    let h = everything(&st);
    assert!(h.contains(&c));
    d.step(&w, &h, &st.units);
    d.ev.check().unwrap();
    assert_eq!(d.ev.leaves(&D).unwrap().get(&(r, D)), None);
}
