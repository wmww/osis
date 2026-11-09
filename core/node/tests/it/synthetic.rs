#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
//! Synthetic aspects, diagnostics.

use crate::common;
use common::*;
use osis_base::{Tid, Value};
use osis_node::{Event, Mutation};
use osis_schema::core_types as ct;
use std::collections::BTreeSet;

fn group(e: &mut osis_node::Engine, g: Tid, items: &[Tid], subs: &[Tid]) {
    let mut m = Mutation::new();
    m.set(g, &ct::GROUP, &ct::Group { items: items.iter().copied().collect(), subgroups: subs.iter().copied().collect() }).unwrap();
    e.commit(m).unwrap();
}

// spec/data-model.md §8, §9: `tid.0`, `aspects.0`, and `groups.0` as the closure over `group.0`
// (nesting and cycles), kept current as groups change.
#[test]
fn synthetic_aspects_spec_dm_8() {
    let mut lp = net(2, 61);
    let x = new_thing(&mut lp, 0);
    let g1 = new_thing(&mut lp, 0);
    let g2 = new_thing(&mut lp, 0);
    let e = &mut lp.peers[0].engine;
    assert_eq!(e.get(&x, &ak("tid.0")).unwrap(), Some(Value::Tid(x)));
    assert_eq!(e.get(&x, &ak("aspects.0")).unwrap(), Some(Value::Set([s("created.0"), s("t:reg.0")].into_iter().collect())));
    group(e, g1, &[x], &[]);
    group(e, g2, &[], &[g1]);
    group(e, g1, &[x], &[g2]); // a cycle
    assert_eq!(e.groups_of(&x), BTreeSet::from([g1, g2]));
    assert_eq!(e.get(&x, &ak("groups.0")).unwrap(), Some(Value::Set([Value::Tid(g1), Value::Tid(g2)].into_iter().collect())));
    group(e, g1, &[], &[g2]);
    assert!(e.groups_of(&x).is_empty());
    group(e, g1, &[x], &[]);
    sync(&mut lp, 0, 1);
    assert_eq!(lp.peers[1].engine.groups_of(&x), BTreeSet::from([g1, g2]));
    lp.peers[1].restart(610).unwrap();
    assert_eq!(lp.peers[1].engine.groups_of(&x), BTreeSet::from([g1, g2]));
}

// notes/architecture.md §3: diagnostics are deduped.
// spec: none (diagnostics are local, notes/architecture.md)
#[test]
fn diagnostics_deduped() {
    let mut lp = net(2, 63);
    new_thing(&mut lp, 0);
    let pk = lp.packages(0).unwrap().pop().unwrap();
    // malformed: the blob's outer array one short
    let mut bad = pk.bytes.clone();
    bad[0] ^= 1;
    for _ in 0..3 {
        let _ = lp.peers[1].receive(&bad, Vec::new());
    }
    let d = lp.peers[1].drain_events().into_iter().filter(|e| matches!(e, Event::Diagnostic(_))).count();
    assert_eq!(d, 1);
}
