//! Admin disputes through the API (notes/disputes-plan.md step 4): two nodes of one
//! account remove each other, neither having seen the other's removal; a third node takes the
//! side it held first by default, is told, lists it and can switch.

use crate::common::*;
use osis::{MemStore, Side};
use std::sync::mpsc::channel;

// spec/permissions.md §5.1 Trust set: a node's side is its own; notes/disputes-plan.md step 4
#[test]
#[ignore = "needs step (e): a removed node keeps P's seed until removal rotates P (issues/account-signing.md)"]
fn disputes_listed_told_and_chosen_spec_permissions_5_1() {
    let (ca, cb, cc) = (clock(), clock(), clock());
    let a = osis::internals::create(cfg(1, MemStore::new(), &ca)).unwrap();
    let join = |seed: u64, c: &std::sync::Arc<osis::internals::ManualClock>| {
        let j = osis::internals::pair(cfg(seed, MemStore::new(), c), &a.pair_offer().unwrap()).unwrap();
        let (node, reply) = a.pair_accept(j.request()).unwrap();
        (j.finish(&reply).unwrap(), node)
    };
    let (b, node_b) = join(2, &cb);
    let (c, _) = join(3, &cc);
    let node_a = a.node();
    for (x, y) in [(&a, &b), (&a, &c), (&b, &a), (&b, &c)] {
        deliver(x, y);
    }
    assert_eq!(c.nodes().unwrap().len(), 3);
    let opts = osis::SetRoleOpts { retain_copy: None };
    // b's clock runs ahead; a has not seen b's removal when it removes b
    cb.advance(5000);
    b.set_role(b.home(), node_a, None, opts).unwrap();
    a.set_role(a.home(), node_b, None, opts).unwrap();
    let (tx, rx) = channel();
    let _sub = c.on_dispute(move |_, d| tx.send(d).unwrap()).unwrap();
    deliver(&b, &c);
    deliver(&a, &c);
    let nodes = |db: &osis::Osis| db.nodes().unwrap().iter().map(|n| n.node).collect::<Vec<_>>();
    assert!(!nodes(&c).contains(&node_a) && nodes(&c).contains(&node_b), "b's removal was here first");
    let told = recv(&rx);
    assert_eq!((told.holder, told.side, told.chosen), (node_a, Side::Author, false));
    let (ds, left) = c.disputes().unwrap();
    assert_eq!((ds.len(), left), (1, 0));
    assert_eq!(ds[0], told);
    let id: osis::DisputeId = told.id.to_string().parse().unwrap();
    assert_eq!(id, told.id);
    c.choose_side(id, Side::Holder).unwrap();
    assert!(nodes(&c).contains(&node_a) && !nodes(&c).contains(&node_b), "a's side: its removal of b counts");
    let (ds, _) = c.disputes().unwrap();
    assert_eq!((ds[0].side, ds[0].chosen), (Side::Holder, true));
    c.choose_side(id, Side::Author).unwrap();
    assert!(!nodes(&c).contains(&node_a) && nodes(&c).contains(&node_b));
    // each party stands with itself
    deliver(&b, &a);
    deliver(&a, &b);
    assert_eq!(a.disputes().unwrap().0[0].side, Side::Holder);
    assert_eq!(b.disputes().unwrap().0[0].side, Side::Author);
    assert!(matches!("x".parse::<osis::DisputeId>(), Err(osis::Error::Invalid(_))));
}
