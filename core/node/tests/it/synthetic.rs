#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
//! Synthetic aspects, moving a thing (import, `/was`, `/moved`, resolution), diagnostics.

use crate::common;
use common::*;
use osis_core::{Tid, Value};
use osis_crdt::{Op, PathOp};
use osis_node::{Event, Mutation};
use osis_schema::core_types as ct;
use std::collections::BTreeSet;

fn group(e: &mut osis_node::Engine, g: Tid, items: &[Tid], subs: &[Tid]) {
    let mut m = Mutation::new();
    m.set(g, &ct::GROUP, &ct::Group { items: items.iter().copied().collect(), subgroups: subs.iter().copied().collect() }).unwrap();
    e.commit(m).unwrap();
}

// spec/data-model.md §8, §9: `/tid`, `/aspects`, and `/groups` as the closure over `/group`
// (nesting and cycles), kept current as groups change.
#[test]
fn synthetic_aspects_spec_dm_8() {
    let mut lp = net(2, 61);
    let x = new_thing(&mut lp, 0);
    let g1 = new_thing(&mut lp, 0);
    let g2 = new_thing(&mut lp, 0);
    let e = &mut lp.peers[0].engine;
    assert_eq!(e.get(&x, &ak("/tid")).unwrap(), Some(Value::Tid(x)));
    assert_eq!(e.get(&x, &ak("/aspects")).unwrap(), Some(Value::Set([s("/created"), s("/t/reg")].into_iter().collect())));
    group(e, g1, &[x], &[]);
    group(e, g2, &[], &[g1]);
    group(e, g1, &[x], &[g2]); // a cycle
    assert_eq!(e.groups_of(&x), BTreeSet::from([g1, g2]));
    assert_eq!(e.get(&x, &ak("/groups")).unwrap(), Some(Value::Set([Value::Tid(g1), Value::Tid(g2)].into_iter().collect())));
    group(e, g1, &[], &[g2]);
    assert!(e.groups_of(&x).is_empty());
    group(e, g1, &[x], &[]);
    sync(&mut lp, 0, 1);
    assert_eq!(lp.peers[1].engine.groups_of(&x), BTreeSet::from([g1, g2]));
    lp.peers[1].restart(610).unwrap();
    assert_eq!(lp.peers[1].engine.groups_of(&x), BTreeSet::from([g1, g2]));
}

// spec/permissions.md §7: a move copies T into M under a new owner with T's history imported
// (dots re-sourced, ts kept), `/was` on M; the old owner's `/moved`; reads resolve references
// by the referencing thing's owner chain; a second import is refused.
#[test]
fn move_and_resolve_spec_perm_7() {
    let mut lp = net(3, 62);
    lp.sync_all().unwrap();
    let t = new_thing(&mut lp, 0);
    for tag in ["a", "b", "c"] {
        let mut m = Mutation::new();
        m.op(t, &TAGS, PathOp { path: Vec::new(), op: Op::Add(s(tag)) }).unwrap();
        lp.peers[0].commit(m).unwrap();
    }
    let mut m = Mutation::new();
    m.set(t, &TEXT, &s("hello")).unwrap();
    lp.peers[0].commit(m).unwrap();
    let mut m = Mutation::new();
    m.op(t, &TEXT, PathOp { path: Vec::new(), op: Op::Insert { at: 5, items: vec![s("!")] } }).unwrap();
    lp.peers[0].commit(m).unwrap();
    sync(&mut lp, 0, 1);
    // node 1 moves T to itself
    let b = lp.peers[1].engine.tid();
    let (copy, imports) = lp.peers[1].engine.move_thing(&t, b).unwrap();
    assert!(!imports.is_empty());
    let e1 = &mut lp.peers[1].engine;
    for k in ["/t/tags", "/t/text", "/t/reg"] {
        assert_eq!(e1.get(&copy, &ak(k)).unwrap(), e1.get(&t, &ak(k)).unwrap(), "{k}");
    }
    assert_eq!(e1.get(&copy, &ak("/was")).unwrap(), Some(Value::Tid(t)));
    assert!(matches!(e1.move_thing(&t, b), Err(osis_node::Error::Misuse(_))));
    // the copy continues to accept writes
    let mut m = Mutation::new();
    m.op(copy, &TAGS, PathOp { path: Vec::new(), op: Op::Add(s("d")) }).unwrap();
    e1.commit(m).unwrap().unwrap();
    // a thing of node 1 referencing T resolves to the copy
    let me1 = e1.tid();
    let mut m = Mutation::new();
    let r = e1.new_thing(&mut m, me1);
    m.set(r, &REG, &Value::Tid(t)).unwrap_err();
    m.set(r, &ak("/x/ref"), &Value::Tid(t)).unwrap();
    e1.commit(m).unwrap();
    assert_eq!(e1.get(&r, &ak("/x/ref")).unwrap(), Some(Value::Tid(copy)));
    // the old owner points T at the copy; elsewhere references resolve through `/moved`
    let mut m = Mutation::new();
    m.set(t, &ct::MOVED, &copy).unwrap();
    lp.peers[0].commit(m).unwrap();
    lp.sync_all().unwrap();
    let e2 = &mut lp.peers[2].engine;
    assert_eq!(e2.get(&copy, &ak("/t/tags")).unwrap(), lp.peers[1].engine.get(&copy, &ak("/t/tags")).unwrap());
    assert_eq!(lp.peers[2].engine.resolve(&lp.peers[2].engine.tid(), &t), copy);
    // imports are idempotent: the same dots whoever imports (spec/permissions.md §7)
    assert_eq!(lp.peers[1].engine.state(&copy, &ak("/t/text")).unwrap(), lp.peers[2].engine.state(&copy, &ak("/t/text")).unwrap());
}

// spec/permissions.md §7 (origins: snapshots, whose carried writes are imported): after a
// compaction dropped the bodies a snapshot covers, a move imports those writes from the
// snapshot (ranked dots, ts kept) and the rest from their own commits, with each origin
// delta's schema; the copy reads as T, at the mover and at a node that applies the imports.
#[test]
fn move_imports_from_snapshot_spec_perm_7() {
    let mut lp = net(2, 64);
    lp.sync_all().unwrap();
    let t = new_thing(&mut lp, 0);
    let mut bodies = Vec::new();
    for tag in ["a", "b", "c"] {
        let mut m = Mutation::new();
        m.op(t, &TAGS, PathOp { path: Vec::new(), op: Op::Add(s(tag)) }).unwrap();
        bodies.push(lp.peers[0].commit(m).unwrap().unwrap());
    }
    let mut m = Mutation::new();
    m.op(t, &TAGS, PathOp { path: Vec::new(), op: Op::Remove(s("a")) }).unwrap();
    bodies.push(lp.peers[0].commit(m).unwrap().unwrap());
    let snap = lp.peers[0].engine.snapshot(&t, &ak("/t/tags")).unwrap().unwrap();
    for c in &bodies {
        lp.peers[0].engine.drop_body(c, &t, &ak("/t/tags")).unwrap();
    }
    lp.advance(10);
    let mut m = Mutation::new();
    m.op(t, &TAGS, PathOp { path: Vec::new(), op: Op::Add(s("d")) }).unwrap();
    m.op(t, &TAGS, PathOp { path: Vec::new(), op: Op::Remove(s("b")) }).unwrap();
    lp.peers[0].commit(m).unwrap().unwrap();
    let me = lp.peers[0].engine.tid();
    let (copy, imports) = lp.peers[0].engine.move_thing(&t, me).unwrap();
    let e = &mut lp.peers[0].engine;
    assert_eq!(e.get(&copy, &ak("/t/tags")).unwrap(), e.get(&t, &ak("/t/tags")).unwrap());
    assert_eq!(e.get(&copy, &ak("/t/tags")).unwrap(), Some(Value::Set([s("c"), s("d")].into_iter().collect())));
    let from_snap = imports.iter().find(|i| e.header(i).unwrap().origins.first().map(|o| o.commit) == Some(snap)).expect("an import from the snapshot");
    let h = e.header(from_snap).unwrap();
    assert!(h.aspects[0].schema.is_some() && !h.schemas.is_empty(), "the origin's schema");
    sync(&mut lp, 0, 1);
    assert_eq!(lp.peers[1].engine.get(&copy, &ak("/t/tags")).unwrap(), lp.peers[0].engine.get(&copy, &ak("/t/tags")).unwrap());
    assert_eq!(lp.peers[1].engine.state(&copy, &ak("/t/tags")).unwrap(), lp.peers[0].engine.state(&copy, &ak("/t/tags")).unwrap());
}

// notes/architecture.md §3: diagnostics are deduped.
// spec: none (diagnostics are local, notes/architecture.md)
#[test]
fn diagnostics_deduped() {
    let mut lp = net(2, 63);
    new_thing(&mut lp, 0);
    let pk = lp.packages(0).unwrap().pop().unwrap();
    let mut bad = pk.bytes.clone();
    let n = bad.len();
    bad[n - 1] ^= 1;
    for _ in 0..3 {
        let _ = lp.peers[1].engine.ingest(&bad, Vec::new());
    }
    let d = lp.peers[1].drain_events().into_iter().filter(|e| matches!(e, Event::Diagnostic(_))).count();
    assert_eq!(d, 1);
}
