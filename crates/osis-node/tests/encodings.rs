#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
//! The writing path for every encoding the crdt builds today (sequences land with crdt-seq),
//! concurrent writers converging through `LocalPeer`, and paged deltas.

mod common;
use common::*;
use osis_core::{Role, Value};
use osis_crdt::{Op, PathOp, PathSeg};
use osis_node::Mutation;
use std::collections::BTreeMap;

fn write_all(m: &mut Mutation, t: osis_core::Tid, n: i64, tag: &str) {
    m.set(t, &REG, &s(tag)).unwrap();
    m.op(t, &COUNT, PathOp { path: Vec::new(), op: Op::Inc(Value::Int(n)) }).unwrap();
    m.op(t, &HI, PathOp { path: Vec::new(), op: Op::Inc(Value::Int(n * 10)) }).unwrap();
    m.op(t, &LO, PathOp { path: Vec::new(), op: Op::Inc(Value::Int(-n)) }).unwrap();
    m.set(t, &REC, &item(tag, n)).unwrap();
    m.set(t, &SHAPE, &Value::Enum(1, Some(Box::new(Value::Int(n))))).unwrap();
    m.op(t, &TAGS, PathOp { path: Vec::new(), op: Op::Add(s(tag)) }).unwrap();
    m.op(t, &MAP, PathOp { path: vec![PathSeg::Key(s(tag))], op: Op::Set(item(tag, n)) }).unwrap();
}

// spec/crdt.md §1, §4.1, §5: two writers' concurrent commits on every encoding converge,
// whatever the delivery order; reads agree.
#[test]
fn every_encoding_converges_spec_crdt_5() {
    let mut lp = net(2, 11);
    let t = new_thing(&mut lp, 0);
    let b = lp.peers[1].engine.tid();
    set_edge(&mut lp.peers[0].engine, t, b, Some(edge(Role::Write)), None);
    sync(&mut lp, 0, 1);
    assert_eq!(lp.peers[1].engine.role_on(&t), Some(Role::Write));
    for round in 0..3 {
        let mut m = Mutation::new();
        write_all(&mut m, t, round + 1, &format!("a{round}"));
        lp.peers[0].commit(m).unwrap().unwrap();
        let mut m = Mutation::new();
        write_all(&mut m, t, round + 5, &format!("b{round}"));
        lp.peers[1].commit(m).unwrap().unwrap();
        if round % 2 == 0 {
            sync(&mut lp, 1, 0);
            sync(&mut lp, 0, 1);
        } else {
            sync(&mut lp, 0, 1);
            sync(&mut lp, 1, 0);
        }
    }
    let a = states(&mut lp.peers[0].engine, &[t]);
    let bb = states(&mut lp.peers[1].engine, &[t]);
    assert_eq!(a, bb);
    // counter sums every increment: 1+2+3 + 5+6+7
    let c = a.iter().find(|x| x.1.as_str() == "/t/count").unwrap();
    assert_eq!(c.2, Some(Value::Int(24)));
    let tags = a.iter().find(|x| x.1.as_str() == "/t/tags").unwrap();
    let Some(Value::Set(tags)) = &tags.2 else { panic!() };
    assert_eq!(tags.len(), 6);
    // the states themselves (canonical) agree
    for (tid, ak, _) in &a {
        let x = lp.peers[0].engine.state(tid, ak).unwrap();
        let y = lp.peers[1].engine.state(tid, ak).unwrap();
        assert_eq!(x, y, "{ak:?}");
    }
}

// spec/crdt.md §8; spec/commits.md §1: a delta above PAGE_TARGET pages; its pages travel as
// blobs listed in the chunk list and the receiver applies it identically.
#[test]
fn paged_delta_spec_crdt_8() {
    let mut lp = net(2, 12);
    let t = new_thing(&mut lp, 0);
    let mut big = BTreeMap::new();
    for i in 0..3000 {
        big.insert(s(&format!("key-{i:05}")), s(&"x".repeat(40)));
    }
    let mut m = Mutation::new();
    m.set(t, &BIG, &Value::Map(big.clone())).unwrap();
    let id = lp.peers[0].commit(m).unwrap().unwrap();
    let h = lp.peers[0].engine.header(&id).unwrap();
    assert!(!h.chunks.is_empty(), "paged delta lists its pages");
    assert_eq!(lp.peers[0].engine.get(&t, &ak("/t/big")).unwrap(), Some(Value::Map(big.clone())));
    // without its pages the commit waits; with them it applies
    let pk = lp.packages(0).unwrap().into_iter().find(|p| p.id == id).unwrap();
    for p in lp.packages(0).unwrap() {
        if p.id != id {
            lp.deliver(1, &p).unwrap();
        }
    }
    let r = lp.peers[1].engine.ingest(&pk.bytes, Vec::new()).unwrap();
    assert!(matches!(r, osis_node::Ingested::Pending(_, osis_node::Reason::WaitBlobs)), "{r:?}");
    lp.deliver(1, &pk).unwrap();
    lp.peers[1].engine.reexamine().unwrap();
    assert_eq!(lp.peers[1].engine.get(&t, &ak("/t/big")).unwrap(), Some(Value::Map(big)));
    assert_eq!(lp.peers[0].engine.state(&t, &ak("/t/big")).unwrap(), lp.peers[1].engine.state(&t, &ak("/t/big")).unwrap());
}
