//! A3's leaves and duty targets (spec/permissions.md §4, as notes/a3-spec/permissions.md drafts it:
//! the leaf bullet, The delivery duty; §5.1 Reading a list): held-model's hand worlds for findings
//! 27 and 30 to 34 and the lost-remover worlds (same names), each a differential at every step
//! (copies, leaves, waits on a leaf, duty targets: `differ`) plus the leaf or target the draft's
//! words decide; the derivation's own (a later grant opens a target; the runner's mode by its role).
use super::*;
use held_model::evidence::names::*;
use held_model::evidence::{Ev as Event, Runners};
use osis_base::Role as R;
use osis_engine::evidence::{LeafWhy, Mode};

/// A3's rule with the duty run by every holder, only in its runner's passes.
fn lagged(w: &mut World, vouches: bool) -> Rule {
    Rule { runners: Runners::AnyHolder, lag: true, ..a3(w, vouches) }
}

/// The differential over `w` under `lagged` delivery, vouches counting and not.
fn agrees_lagged(name: &str, w: &World) -> Run {
    let r = differ_lagged(w, &[true, false]);
    assert!(r.differ.is_empty(), "{name}: {} disagreements, first: {}", r.differ.len(), r.differ[0]);
    r
}

/// The differential over `w` under `lagged` delivery, vouches counting as `vouches` says.
pub(super) fn differ_lagged(w: &World, vouches: &[bool]) -> Run {
    let mut out = Run::default();
    for &vouches in vouches {
        let mut w = w.clone();
        let rule = lagged(&mut w, vouches);
        let r = differ(&w, &rule, vouches);
        out.add(Run { differ: r.differ.into_iter().map(|d| format!("vouches {vouches}: {d}")).collect(), ..r });
    }
    out
}

/// A3's derivation over a held set of the end state of `w` (set to `rule`), with what its duty
/// reads; `roles` (thing, role), when given, the node's only roles.
fn at_end(w: &World, rule: &Rule, held: impl Fn(&State) -> Set, roles: Option<&[(Thing, R)]>) -> Driver {
    let st = w.run(rule, |_| {});
    let h = held(&st);
    let mut d = Driver::a3(w, true);
    if let Some(roles) = roles {
        for t in 0..=Thing::MAX {
            d.ev.set_role(t, None);
        }
        for &(t, r) in roles {
            d.ev.set_role(t, Some(r));
        }
    }
    d.step(w, &h, &st.units);
    d.feed_duty(w, &h, &st.entries);
    d.ev.check().unwrap();
    d
}

/// The targets (and modes) the node runs removal copy `r` for.
fn targets(d: &Driver, r: CopyId<Id, Thing>) -> BTreeMap<Thing, Mode> {
    d.ev.duty().into_iter().filter(|x| x.removal == r).map(|x| (x.target, x.mode)).collect()
}

/// Finding 27: X removes Z from A at 3 though Z held no write there (the removal takes no write
/// away), listing Z's earlier write c0 in D's leaf; X grants Z write; Z writes c1 on D through [A].
/// A leaf is read only where its lowering cuts the part: nothing requires the leaf, c1 waits on
/// nothing. With Z granted write before the removal (the control) the removal cuts both writes:
/// D requires the leaf, and a node lacking it waits.
#[test]
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
        let rule = a3(&mut w, true);
        let mut d = at_end(&w, &rule, |st| st.written.clone(), None);
        let want = granted.then_some(LeafWhy::Reads);
        assert_eq!(d.ev.leaves(&D).unwrap().get(&(r, D)).copied(), want, "granted {granted}");
        assert_eq!(d.ev.waits(&(c1, D), |_| false), granted.then_some((r, D)), "granted {granted}");
        assert_eq!(d.ev.waits(&(c1, D), |l| *l == (r, D)), None);
    }
}

/// Finding 30: K writes c on D through [A]; X removes K listing c (D's leaf) and its node is
/// destroyed before any pass; Q (syncing A) holds the removal and runs the duty. A leaf for a thing
/// other than its lowering's own stays with it wherever it is a body: under A at Q, which carries it
/// to D, where D's reader requires it for c, which the removal cuts.
#[test]
fn f30_a_leaf_only_the_lost_remover_held_strands_what_it_lists() {
    let pw = paths::World::new(&[(X, A), (Y, D)]);
    let mut w = World::new(pw, &[A, D]);
    let (x, y, q, k) = (w.node(true, &[A]), w.node(true, &[D]), w.node(true, &[A]), w.node(false, &[]));
    w.write(x, |p| p.edge(X, 1, &[], A, K, Role::Write, &[]));
    w.write(y, |p| p.edge(Y, 1, &[], D, A, Role::Write, &[]));
    let c = w.write(k, |p| p.content(K, 2, &[A], D));
    let r = w.write(x, |p| p.edge(X, 6, &[], A, K, Role::None, &[c]));
    w.gone(x);
    w.write(k, |p| p.content(K, 8, &[A], D));
    w.pass(q);
    agrees_lagged("f30", &w);
    let rule = lagged(&mut w, true);
    let dq = at_end(&w, &rule, |st| st.held[q].clone(), None);
    assert_eq!(dq.ev.leaves(&A).unwrap().get(&(r, D)), Some(&LeafWhy::Home));
    assert!(targets(&dq, (r, A)).contains_key(&D));
    let dd = at_end(&w, &rule, |st| st.entries[&D].clone(), None);
    assert_eq!(dd.ev.leaves(&D).unwrap().get(&(r, D)), Some(&LeafWhy::Reads));
    let _ = y;
}

/// Finding 31: K writes R through [A, O, D]; Y (syncing D and A) removes O from D and its node is
/// destroyed at once; W, O's only syncer, is gone too. A reads through O (W granted it write), so
/// the removal travels under A (Role changes travel, its keys-open half); N, syncing A and R, holds
/// it and runs the duty from D to R (V granted D write on R).
#[test]
fn f31_dropping_the_keys_open_half_loses_a_removal_when_its_remover_is_lost() {
    const V: Thing = 7;
    let pw = paths::World::new(&[(X, A), (W, O), (Y, D), (V, R)]);
    let mut w = World::new(pw, &[A, O, D, R]);
    let (x, wn, y, v, k) = (w.node(true, &[A]), w.node(true, &[O]), w.node(true, &[D, A]), w.node(true, &[R]), w.node(false, &[]));
    let n = w.node(true, &[A, R]);
    w.write(x, |p| p.edge(X, 1, &[], A, K, Role::Write, &[]));
    w.write(wn, |p| p.edge(W, 1, &[], O, A, Role::Write, &[]));
    w.gone(wn);
    w.write(y, |p| p.edge(Y, 1, &[], D, O, Role::Write, &[]));
    w.write(v, |p| p.edge(V, 1, &[], R, D, Role::Write, &[]));
    w.write(k, |p| p.content(K, 2, &[A, O, D], R));
    let r = w.write(y, |p| p.edge(Y, 6, &[], D, O, Role::None, &[]));
    w.gone(y);
    w.write(k, |p| p.content(K, 8, &[A, O, D], R));
    for m in [x, v, n] {
        w.pass(m);
    }
    agrees_lagged("f31", &w);
    let rule = lagged(&mut w, true);
    let dn = at_end(&w, &rule, |st| st.held[n].clone(), None);
    assert!(dn.ev.required(&A).unwrap().contains_key(&(r, D)));
    assert!(targets(&dn, (r, D)).contains_key(&R), "{:?}", dn.ev.duty());
}

/// Finding 32: X removes K from A; A writes D, D writes E; Y syncs D alone and holds read on D and
/// E (through D's grant), none on A; X's node is lost. The duty runs per target the runner reads:
/// Y's runs reach E (to the end), never A; it stamps where its role gives write, deposits where
/// read only.
#[test]
fn f32_a_holder_reading_only_a_reached_thing_runs_the_duty_there() {
    let pw = paths::World::new(&[(X, A), (Y, D), (V32, E)]);
    let mut w = World::new(pw, &[A, D, E]);
    let (x, y, v, k) = (w.node(true, &[A, D]), w.node(true, &[D]), w.node(true, &[E]), w.node(false, &[]));
    w.write(x, |p| p.edge(X, 1, &[], A, K, Role::Write, &[]));
    w.write(y, |p| p.edge(Y, 1, &[], D, A, Role::Write, &[]));
    w.write(v, |p| p.edge(V32, 1, &[], E, D, Role::Write, &[]));
    let r = w.write(x, |p| p.edge(X, 6, &[], A, K, Role::None, &[]));
    w.gone(x);
    w.write(k, |p| p.content(K, 8, &[A, D], E));
    w.pass(y);
    agrees_lagged("f32", &w);
    let rule = lagged(&mut w, true);
    // Y minted D (admin there), so it writes E through D's grant
    let dy = at_end(&w, &rule, |st| st.held[y].clone(), Some(&[(D, R::Admin), (E, R::Write)]));
    assert_eq!(targets(&dy, (r, A)), BTreeMap::from([(D, Mode::Stamp), (E, Mode::Stamp)]));
    // a reader of D (read through the way) deposits
    let dy = at_end(&w, &rule, |st| st.held[y].clone(), Some(&[(D, R::Read), (E, R::Read)]));
    assert_eq!(targets(&dy, (r, A)), BTreeMap::from([(D, Mode::Deposit), (E, Mode::Deposit)]));
    // reaching E is to the end: by D's grant, not a grant of A's
    assert_eq!(dy.ev.reached(&(r, A)).unwrap().get(&E), Some(&Some((D, E))));
}

/// E's mint admin in finding 32's world.
const V32: Thing = 7;

/// Finding 33: Q (admin of A by X) removes K at 6, listing nothing; X then removes Q at 5, voiding
/// it. Chained-ness disregards removals: Q's removal stays one with a duty, so X runs both to D.
#[test]
fn f33_a_drop_after_a_complete_pass_is_wrong_while_a_voiding_removal_lags() {
    let pw = paths::World::new(&[(X, A), (Y, D)]);
    let mut w = World::new(pw, &[A, D]);
    let (x, q, y, k) = (w.node(true, &[A]), w.node(true, &[A]), w.node(true, &[D]), w.node(true, &[]));
    w.write(x, |p| p.edge(X, 1, &[], A, Q, Role::Admin, &[]));
    w.write(x, |p| p.edge(X, 1, &[], A, K, Role::Write, &[]));
    w.write(y, |p| p.edge(Y, 1, &[], D, A, Role::Write, &[]));
    w.write(k, |p| p.content(K, 2, &[A], D));
    w.gone(k);
    let rq = w.write(q, |p| p.edge(Q, 6, &[], A, K, Role::None, &[]));
    w.pass(q);
    let rx = w.write(x, |p| p.edge(X, 5, &[], A, Q, Role::None, &[]));
    w.pass(x);
    agrees_lagged("f33", &w);
    let rule = lagged(&mut w, true);
    let dx = at_end(&w, &rule, |st| st.held[x].clone(), None);
    assert!(targets(&dx, (rq, A)).contains_key(&D) && targets(&dx, (rx, A)).contains_key(&D), "{:?}", dx.ev.duty());
}

/// Finding 34: X removes K from A listing K's write c on A (its own thing's leaf). A leaf for the
/// lowering's own thing is read only by bodies there: required while c is held, gone with it (never
/// kept at home).
#[test]
fn f34_a_removals_leaf_for_its_own_thing_leaves_with_what_it_reads() {
    let pw = paths::World::new(&[(X, A)]);
    let mut w = World::new(pw, &[A]);
    let (x, k) = (w.node(true, &[A]), w.node(true, &[A]));
    w.write(x, |p| p.edge(X, 1, &[], A, K, Role::Write, &[]));
    let c = w.write(k, |p| p.content(K, 2, &[], A));
    let r = w.write(x, |p| p.edge(X, 6, &[], A, K, Role::None, &[c]));
    assert_agrees("f34", &w);
    let rule = a3(&mut w, true);
    let mut st = w.run(&rule, |_| {});
    let mut d = Driver::a3(&w, true);
    d.step(&w, &st.held[x], &st.units);
    assert_eq!(d.ev.leaves(&A).unwrap(), BTreeMap::from([((r, A), LeafWhy::Reads)]));
    w.forget(&rule, &mut st, c);
    d.step(&w, &st.held[x], &st.units);
    d.ev.check().unwrap();
    assert_eq!(d.ev.leaves(&A).unwrap(), BTreeMap::new());
    assert_eq!(model_leaves(&w, &rule, A, &st.units, &st.held[x]), BTreeSet::new());
}

/// held-model's `spec_errand::race`: X removes K from A at 6; A writes D; X and Q sync A, Y syncs
/// D; `gone`: X's node destroyed right after; the thief writes D through [A] at 8; then a pass of
/// Q.
fn race(gone: bool) -> (World, Id, usize) {
    let pw = paths::World::new(&[(X, A), (Y, D)]);
    let mut w = World::new(pw, &[A, D]);
    let (x, y, q, k) = (w.node(true, &[A]), w.node(true, &[D]), w.node(true, &[A]), w.node(false, &[]));
    w.write(x, |p| p.edge(X, 1, &[], A, K, Role::Write, &[]));
    w.write(x, |p| p.edge(X, 1, &[], A, Q, Role::Write, &[]));
    w.write(y, |p| p.edge(Y, 1, &[], D, A, Role::Write, &[]));
    let r = w.write(x, |p| p.edge(X, 6, &[], A, K, Role::None, &[]));
    if gone {
        w.gone(x);
    }
    w.write(k, |p| p.content(K, 8, &[A], D));
    w.pass(q);
    (w, r, q)
}

/// No designated device: X's node is destroyed right after removing K; Q, holding the removal (it
/// syncs A), runs the duty to D.
#[test]
fn the_errand_runs_at_any_honest_holder_when_the_removers_node_is_lost() {
    let (mut w, r, q) = race(true);
    agrees_lagged("lost remover", &w);
    let rule = lagged(&mut w, true);
    let dq = at_end(&w, &rule, |st| st.held[q].clone(), None);
    assert_eq!(targets(&dq, (r, A)), BTreeMap::from([(A, Mode::Stamp), (D, Mode::Stamp)]));
}

/// held-model's `spec_errand::remover_lost`: `w` with node `x` destroyed right after its last
/// write (None when none of its writes is a removal), node `q` syncing A, and a pass of every other
/// honest node at the end.
pub(super) fn remover_lost(mut w: World, x: usize, q: usize) -> Option<World> {
    let mine: Vec<usize> = (0..w.events.len()).filter(|&k| matches!(w.events[k], Event::Write(i) if w.by[i] == x)).collect();
    if !mine.iter().any(|&k| matches!(w.events[k], Event::Write(i) if w.removes(i).is_some())) {
        return None;
    }
    w.events.insert(mine.last().unwrap() + 1, Event::Gone(x));
    w.nodes[q].syncs.insert(A);
    for n in (0..w.nodes.len()).filter(|&n| n != x && w.nodes[n].honest) {
        w.events.push(Event::Pass(n));
    }
    Some(w)
}

/// The family's node index of Q (held-model `spec_errand::family_q`).
pub(super) fn family_q(sh: Shape) -> usize {
    if sh.org_apart { 3 } else { 2 }
}

/// Every third world of the family slice with X's node destroyed right after its last write, the
/// duty run by every holder in its passes, vouches counting: the derivation agrees at every step,
/// duty targets included (the whole slice, vouches counting and not: the properties).
#[test]
fn a_lost_removers_duty_falls_to_another_holder_on_a_slice_of_the_family() {
    let mut r = Run::default();
    for i in (0..hm::FAMILY).step_by(97 * 9) {
        let sh = Shape::nth(i);
        let Some(w) = remover_lost(hm::family(sh), 0, family_q(sh)) else { continue };
        let x = differ_lagged(&w, &[true]);
        assert!(x.differ.is_empty(), "{sh:?}: {} disagreements, first: {}", x.differ.len(), x.differ[0]);
        r.add(x);
    }
    assert!(r.duty > 0 && r.leaves > 0, "duty {}, leaves {}", r.duty, r.leaves);
}

/// Finding 3 for the duty (standing): X removes K from A while A writes nothing; Y grants A write
/// on D later. X's duty reaches A alone until the grant, then D too, incrementally as from scratch.
#[test]
fn a_later_grant_opens_a_duty_target() {
    let pw = paths::World::new(&[(X, A), (Y, D)]);
    let mut w = World::new(pw, &[A, D]);
    let (x, y, k) = (w.node(true, &[A]), w.node(true, &[D]), w.node(false, &[]));
    w.write(x, |p| p.edge(X, 1, &[], A, K, Role::Write, &[]));
    w.write(k, |p| p.content(K, 2, &[A], A));
    let r = w.write(x, |p| p.edge(X, 6, &[], A, K, Role::None, &[]));
    let raise = w.write(y, |p| p.edge(Y, 7, &[], D, A, Role::Write, &[]));
    w.nodes[x].syncs.insert(D);
    assert_agrees("f3 duty", &w);
    let rule = a3(&mut w, true);
    let mut d = Driver::a3(&w, true);
    let mut seen = vec![];
    w.run(&rule, |st| {
        d.step(&w, &st.held[x], &st.units);
        d.feed_duty(&w, &st.held[x], &st.entries);
        d.ev.check().unwrap();
        if st.held[x].contains(&r) {
            seen.push((st.held[x].contains(&raise), targets(&d, (r, A)).into_keys().collect::<Vec<_>>()));
        }
    });
    assert!(seen.contains(&(false, vec![A])) && seen.contains(&(true, vec![A, D])), "{seen:?}");
}

/// An addendum is a body only while it lists a held commit resting on its removal's edge
/// (held-model `an_addendum_leaves_with_the_last_commit_it_lists`): Q's addendum on D lists K's c1;
/// with c1 forgotten (and c0, which it does not list, held) the addendum brings nothing, so X's grant
/// to Q (on the addendum's path alone) leaves D's evidence, incrementally as from scratch.
#[test]
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
    let rule = a3(&mut w, true);
    let mut st = w.run(&rule, |_| {});
    let everything = |st: &State| st.written.difference(&st.forgotten).copied().collect::<Set>();
    let mut d = Driver::a3(&w, true);
    d.step(&w, &everything(&st), &st.units);
    assert!(d.required(D).contains(&(gq, A)));
    w.forget(&rule, &mut st, c1);
    let h = everything(&st);
    assert!(h.contains(&ad));
    d.step(&w, &h, &st.units);
    d.ev.check().unwrap();
    assert!(!d.required(D).contains(&(gq, A)));
    assert_eq!(d.required(D), model_copies(&w, &rule, D, &st.units, &h));
}

/// Standing, the shrinking way: X removes K from A; A writes D (held), D writes E (read for the
/// duty under E's own sync ID). Forgetting A's grant on D, or releasing the read of D's grant on E,
/// drops what only it reached, incrementally as from scratch.
#[test]
fn a_forgotten_way_drops_its_targets() {
    type Ev3 = Evidence<u32, Thing, u32>;
    let mut ev = Ev3::new(A3);
    for t in [A, D, E] {
        ev.set_role(t, Some(R::Write));
    }
    let write = |holder: Thing, grant: bool| Kind::Write(Write { holder, grant: grant.then(|| Gives::role(R::Write)), removal: !grant, gives_write: grant, gives_read: grant, relies: None, creation: None, leaves: vec![] });
    let part = |kind, on: Thing, pos| Part { kind, hops: Some(vec![Hop { edge: (X, on), record: true, need: Need::Role(R::Admin) }]), pos, chained: true };
    let ad = || vec![part(write(A, true), D, 2)];
    let de = vec![part(write(D, true), E, 3)];
    ev.add((1, A), vec![part(write(K, true), A, 1)]);
    ev.add((2, D), ad());
    ev.duty_add((3, E), de.clone());
    ev.add((4, A), vec![part(write(K, false), A, 4)]);
    let at = |ev: &Ev3| {
        ev.check().unwrap();
        ev.duty().iter().map(|r| r.target).collect::<Vec<_>>()
    };
    assert_eq!(at(&ev), vec![A, D, E]);
    ev.forget(&(2, D));
    assert_eq!(at(&ev), vec![A]);
    ev.add((2, D), ad());
    assert_eq!(at(&ev), vec![A, D, E]);
    ev.duty_forget(&(3, E));
    assert_eq!(at(&ev), vec![A, D]);
    ev.duty_add((3, E), de);
    assert_eq!(at(&ev), vec![A, D, E]);
}
