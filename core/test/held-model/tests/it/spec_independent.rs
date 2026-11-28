//! Which things count as independent (held_model::independent; spec/sync-set.md §2 Counts as
//! independent): no party below admin makes a dependent thing count independent at any node,
//! whatever it holds; an admin's plant with no keyset counts at no node reading it; every honest
//! holding counts; each clause is needed (each control fails one of these).
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
    assert_eq!(stuck(Rule::KeysetOnly), ["sync-only cut"]);
    assert_eq!(stuck(Rule::BesideGrant), Vec::<&str>::new());
    for r in [Rule::KeysetOnly, Rule::BesideGrant, Rule::StepAnywhere] {
        assert!(unsafe_case(r).is_none(), "{r:?}: the control is safe below admin");
    }
    // the issue's candidate: a writer's box to a grantee reading nothing of P
    let (_, n, _) = unsafe_case(Rule::NotOpenedDependent).expect("a box to a node not opening P");
    assert_eq!(n, G);
}

/// An admin's step is its word (spec/sync-ids.md §4 Owner), but only a node reading none of Y's
/// role commits counts Y independent by it: A planting a box and a step on Y with no keyset
/// (demoted after or not) makes Y count independent at K, keeping Y unread, and at no reader, so
/// it splits no read.
#[test]
fn an_admins_plant_splits_no_reader_spec_sync_set_2() {
    assert_eq!(split_case(Rule::Spec), None);
    let (n, _) = split_case(Rule::StepAnywhere).expect("control: the clause at a reader splits it off");
    assert_eq!(n, R);
    let sync_only = [Part::Box { signer: A, holder: K, epoch: 9, read: false }, Part::Step { signer: A, epoch: 9 }].into();
    assert!(counts(Rule::Spec, &sync_only, &[K].into()));
}
