//! Which things count as independent (held_model::independent; spec/sync-set.md §2 Counts as
//! independent, spec/permissions.md §4 Key part): no party below admin makes a dependent thing
//! count independent at any node, whatever it holds; every honest holding of a box without the
//! keyset counts; each clause is needed (each control fails one of the two).
use held_model::independent::*;

#[test]
fn no_box_below_admin_makes_a_dependent_thing_independent_spec_sync_set_2() {
    assert!(unsafe_case(Rule::Spec).is_none(), "{:?}", unsafe_case(Rule::Spec));
    let (w, n, h) = unsafe_case(Rule::BoxAlone).expect("control: a box alone splits a node off");
    assert!(w.honest.is_empty() && h.iter().any(|p| matches!(p, Part::Box { signer: W, .. })), "{w:?} at {n}: {h:?}");
}

#[test]
fn an_honest_box_counts_before_its_keyset_spec_permissions_4() {
    assert!(stuck(Rule::Spec).is_empty(), "{:?}", stuck(Rule::Spec));
    assert_eq!(stuck(Rule::KeysetOnly).len(), honest_holdings().len());
    assert_eq!(stuck(Rule::NotOpenedDependent), ["key part of the mint admin", "late reader of the mint admin"]);
    assert_eq!(stuck(Rule::BesideEdge), ["key part of the mint admin"]);
    for r in [Rule::KeysetOnly, Rule::BesideEdge] {
        assert!(unsafe_case(r).is_none(), "{r:?}: the control fails liveness alone");
    }
    // the issue's candidate fails both: a writer's box to a grantee reading nothing of P
    let (_, n, _) = unsafe_case(Rule::NotOpenedDependent).expect("a box to a node not opening P");
    assert_eq!(n, G);
}

/// An admin's step is its word (spec/sync-ids.md §4 Owner): A writing a box and a step on Y with
/// no keyset makes Y count independent where both are held. A dispute by an admin, which may
/// make Y independent outright.
#[test]
fn an_admin_step_without_a_keyset_is_its_word_spec_sync_set_2() {
    let h = [Part::Box { signer: A, holder: R, epoch: 9 }, Part::Step { signer: A, epoch: 9 }].into();
    assert!(counts(Rule::Spec, &h, &[R].into()));
}
