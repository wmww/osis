//! Admin disputes through the API (notes/disputes-plan.md step 4): two admins of a group remove
//! each other, neither having seen the other's removal; a third account's node takes the side it
//! held first by default, is told, lists it and can switch.

use crate::scenario::{account, introduce, new_tag};
use osis::{Dispute, GrantOpts, Role, Side};
use osis_sim::world::World;
use std::sync::mpsc::channel;

// spec/permissions.md §5.1 Trust set: a node's side is its own; notes/disputes-plan.md step 4
#[test]
fn disputes_listed_told_and_chosen_spec_permissions_5_1() {
    let mut w = World::new();
    let host = w.add_host();
    let [a, b, c] = [1, 2, 3].map(|s| account(&mut w, s, host));
    let ab = introduce(&mut w, &a, &b);
    let ac = introduce(&mut w, &a, &c);
    let g = new_tag(&a, "G").unwrap();
    a.grant(g, ab, Role::Admin, GrantOpts::default()).unwrap();
    a.grant(g, ac, Role::Read, GrantOpts::default()).unwrap();
    w.run();
    w.advance(60_000);
    w.run();
    assert_eq!(c.grants(g).unwrap().len(), 3);
    let opts = osis::SetRoleOpts { retain_copy: None };
    // neither has seen the other's removal
    w.set_online(&a, false);
    w.set_online(&b, false);
    b.set_role(g, a.me(), None, opts).unwrap();
    a.set_role(g, b.me(), None, opts).unwrap();
    let (tx, rx) = channel();
    let _sub = c.on_dispute(move |_, d| tx.send(d).unwrap()).unwrap();
    // c holds b's removal first
    let settle = |w: &mut World| {
        for _ in 0..3 {
            w.advance(60_000);
            w.run();
        }
    };
    w.set_online(&b, true);
    settle(&mut w);
    w.set_online(&a, true);
    settle(&mut w);
    let holds = |db: &osis::Osis, x: osis::Tid| db.grants(g).unwrap().contains_key(&x);
    assert!(!holds(&c, a.me()) && holds(&c, b.me()), "b's removal was here first");
    // the contested write is a's removal of b; c sides with its holder, b
    let told = rx.try_iter().last().unwrap();
    let Dispute::Removal { author, holder, side, chosen, .. } = told.clone() else { panic!("a removal: {told:?}") };
    assert_eq!((author, holder, side, chosen), (a.me(), b.me(), Side::Holder, false));
    let (ds, left) = c.disputes().unwrap();
    assert_eq!((ds.len(), left), (1, 0));
    assert_eq!(ds[0], told);
    let id: osis::DisputeId = told.id().to_string().parse().unwrap();
    assert_eq!(id, told.id());
    assert!(matches!(c.choose_side(id, Side::Line(told_commit(&told))), Err(osis::Error::Invalid(_))), "a line is no side of a removal");
    c.choose_side(id, Side::Author).unwrap();
    assert!(holds(&c, a.me()) && !holds(&c, b.me()), "a's side: its removal of b counts");
    let (ds, _) = c.disputes().unwrap();
    assert_eq!((ds[0].side(), ds[0].chosen()), (Side::Author, true));
    c.choose_side(id, Side::Holder).unwrap();
    assert!(!holds(&c, a.me()) && holds(&c, b.me()));
    // each party stands with itself
    assert_eq!(a.disputes().unwrap().0[0].side(), Side::Author);
    assert_eq!(b.disputes().unwrap().0[0].side(), Side::Holder);
    assert!(matches!("x".parse::<osis::DisputeId>(), Err(osis::Error::Invalid(_))));
    // an account's history names its dispute by the account; its sides are lines of it
    let acct: osis::DisputeId = a.me().to_uri().parse().unwrap();
    assert_eq!(acct.to_string(), a.me().to_uri());
    assert!(matches!(c.choose_side(acct, Side::Author), Err(osis::Error::Invalid(_))), "author is no side of a history");
    assert!(matches!(c.choose_side(acct, Side::Line(told_commit(&told))), Err(osis::Error::Invalid(_))), "no change of the account's ends a version there");
}

fn told_commit(d: &Dispute) -> osis::CommitId {
    let Dispute::Removal { commit, .. } = d else { panic!("a removal") };
    *commit
}
