//! Keys-open travel (spec/permissions.md §4 Role changes
//! travel): hand worlds per finding (notes/evidence-model-findings.md 19, 21) and per held-model
//! `spec_reach.rs` test (same names), each a differential at every step (`assert_agrees`) plus
//! the copy the spec's words decide, with the switch that decides it off where only
//! it brings that copy.
use super::*;
use held_model::evidence::names::*;
use held_model::evidence::State;
use osis_engine::evidence::Reason;

/// The derivation under `cfg` over a held set of `w`'s end state under the spec's rule.
fn at_end(w: &World, cfg: Config, held: impl Fn(&State) -> Set) -> (Ev, Set) {
    at_end_records(w, cfg, true, held)
}

/// `at_end`, with the world's record edges given to the derivation or not (the control).
fn at_end_records(w: &World, cfg: Config, records: bool, held: impl Fn(&State) -> Set) -> (Ev, Set) {
    let mut w = w.clone();
    let rule = e1(&mut w);
    let st = w.run(&rule, |_| {});
    let h = held(&st);
    let mut d = Driver::with(&w, cfg);
    if !records {
        d.ev = Ev::new(cfg);
        for &s in &w.sids {
            d.ev.add_sid(s, s);
        }
    }
    d.step(&w, &h, &st.units);
    (d.ev, h)
}

/// Every commit written (the node holding everything).
fn everything(st: &State) -> Set {
    st.written.clone()
}

const KEYS: Config = Config { keys_open: true };
const NO_KEYS: Config = Config { keys_open: false };

/// R's mint admin (finding 19's worlds).
const V: Thing = 7;

/// Finding 19 (`reach_keys_open_travel_carries_a_removal_to_the_things_reading_through_it`): K
/// writes R through [A, O, D]; Y removes O from D. A holds write on O, so A's keys open O: the
/// removal naming O travels under A (Role changes travel), where N takes it to R as evidence of K's
/// later write (on its path); without keys-open travel A requires nothing of it.
#[test]
fn reach_keys_open_travel_carries_a_removal_to_the_things_reading_through_it() {
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
    let (ev, _) = at_end(&w, KEYS, |st| st.held[y].clone());
    assert_eq!(ev.required(&A).unwrap().get(&(r, D)), Some(&Reason::Travels(O)));
    let (ev, _) = at_end(&w, NO_KEYS, |st| st.held[y].clone());
    assert!(!ev.required(&A).unwrap().contains_key(&(r, D)));
    let (ev, _) = at_end(&w, KEYS, |st| st.held[n].clone());
    assert!(ev.required(&R).unwrap().contains_key(&(r, D)));
}

/// Keys open through a record edge (held-model `records_keys_open_through_a_mint_admins_record_edge`): finding 19's world
/// with O minted by A. A's keys open O through its record edge, so Y's removal of O from D travels
/// under A (keys-open travel): the derivation takes record edges as standing read edges. Without
/// them (the control) A's evidence lacks it.
#[test]
fn records_keys_open_through_a_mint_admins_record_edge_spec_permissions_4() {
    let pw = paths::World::new(&[(X, A), (A, O), (Y, D), (V, R)]);
    let mut w = World::new(pw, &[A, O, D, R]);
    let (x, y, v, k) = (w.node(true, &[A]), w.node(true, &[D, A]), w.node(true, &[R]), w.node(false, &[]));
    w.node(true, &[A, R]);
    w.write(x, |p| p.edge(X, 1, &[], A, K, Role::Write, &[]));
    w.write(y, |p| p.edge(Y, 1, &[], D, O, Role::Write, &[]));
    w.write(v, |p| p.edge(V, 1, &[], R, D, Role::Write, &[]));
    w.write(k, |p| p.content(K, 2, &[A, O, D], R));
    let r = w.write(y, |p| p.edge(Y, 6, &[], D, O, Role::None, &[]));
    w.write(k, |p| p.content(K, 8, &[A, O, D], R));
    assert_agrees("open17 keys open", &w);
    let (ev, _) = at_end(&w, KEYS, everything);
    assert_eq!(ev.required(&A).unwrap().get(&(r, D)), Some(&Reason::Travels(O)));
    let (control, _) = at_end_records(&w, KEYS, false, everything);
    assert!(!control.required(&A).unwrap().contains_key(&(r, D)));
}

