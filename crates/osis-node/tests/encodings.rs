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

// spec/crdt.md §5.7: lists and texts through the write path; concurrent inserts converge.
#[test]
fn sequences_converge_spec_crdt_5_7() {
    let mut lp = net(2, 13);
    let t = new_thing(&mut lp, 0);
    let b = lp.peers[1].engine.tid();
    set_edge(&mut lp.peers[0].engine, t, b, Some(edge(Role::Write)), None);
    let mut m = Mutation::new();
    m.set(t, &LIST, &Value::List(vec![s("a"), s("b"), s("c")])).unwrap();
    m.set(t, &TEXT, &s("hello")).unwrap();
    lp.peers[0].commit(m).unwrap().unwrap();
    sync(&mut lp, 0, 1);
    let mut m = Mutation::new();
    m.op(t, &LIST, PathOp { path: Vec::new(), op: Op::Insert { at: 1, items: vec![s("x")] } }).unwrap();
    m.op(t, &TEXT, PathOp { path: Vec::new(), op: Op::Insert { at: 5, items: vec![s(" world")] } }).unwrap();
    lp.peers[0].commit(m).unwrap().unwrap();
    let mut m = Mutation::new();
    m.op(t, &LIST, PathOp { path: Vec::new(), op: Op::Delete { at: 2, len: 1 } }).unwrap();
    m.op(t, &TEXT, PathOp { path: Vec::new(), op: Op::Insert { at: 0, items: vec![s(">")] } }).unwrap();
    lp.peers[1].commit(m).unwrap().unwrap();
    sync(&mut lp, 0, 1);
    sync(&mut lp, 1, 0);
    let a = states(&mut lp.peers[0].engine, &[t]);
    assert_eq!(a, states(&mut lp.peers[1].engine, &[t]));
    let l = a.iter().find(|x| x.1.as_str() == "/t/list").unwrap();
    assert_eq!(l.2, Some(Value::List(vec![s("a"), s("x"), s("b")])));
    let tx = a.iter().find(|x| x.1.as_str() == "/t/text").unwrap();
    assert_eq!(tx.2, Some(s(">hello world")));
}

// spec/crdt.md §3.3 rule 3, §8; spec/commits.md §1: 65 inline values of 128 KiB inserted in
// one commit (over 8 MiB of content) split into runs that page within blobs; the commit applies,
// travels and reads back.
#[test]
fn big_list_insert_fits_blobs_spec_crdt_3_3() {
    let mut lp = net(2, 15);
    let t = new_thing(&mut lp, 0);
    let n = osis_core::format::CHUNK_THRESHOLD - 8;
    let items: Vec<Value> = (0..65).map(|i| s(&format!("{i:03}{}", "z".repeat(n - 3)))).collect();
    let mut m = Mutation::new();
    m.set(t, &LIST, &Value::List(items.clone())).unwrap();
    lp.peers[0].commit(m).unwrap().unwrap();
    assert_eq!(lp.peers[0].engine.get(&t, &ak("/t/list")).unwrap(), Some(Value::List(items.clone())));
    sync(&mut lp, 0, 1);
    assert_eq!(lp.peers[1].engine.get(&t, &ak("/t/list")).unwrap(), Some(Value::List(items)));
}

// spec/data-model.md §6: a large atomic value is a link to a chunk tree; its chunks travel as
// blobs and read back whole; an equal rewrite changes nothing.
#[test]
fn large_value_spec_dm_6() {
    let mut lp = net(2, 14);
    let t = new_thing(&mut lp, 0);
    let data: Vec<u8> = (0..300_000u32).map(|i| (i.wrapping_mul(2654435761) >> 13) as u8).collect();
    let mut m = Mutation::new();
    m.set(t, &BLOB, &Value::Bytes(data.clone())).unwrap();
    let id = lp.peers[0].commit(m).unwrap().unwrap();
    assert!(!lp.peers[0].engine.header(&id).unwrap().chunks.is_empty());
    assert!(matches!(lp.peers[0].engine.get(&t, &ak("/t/blob")).unwrap(), Some(Value::Link(_))));
    assert_eq!(lp.peers[0].engine.get_full(&t, &ak("/t/blob")).unwrap(), Some(Value::Bytes(data.clone())));
    let mut m = Mutation::new();
    m.set(t, &BLOB, &Value::Bytes(data.clone())).unwrap();
    assert_eq!(lp.peers[0].commit(m).unwrap(), None);
    sync(&mut lp, 0, 1);
    assert_eq!(lp.peers[1].engine.get_full(&t, &ak("/t/blob")).unwrap(), Some(Value::Bytes(data)));
}

// spec/crdt.md §4.1, §8; notes/local-store.md, Units; spec/requirements.md, Scale: a large map in a field of a struct
// aspect is paged too (the struct's other fields in the unit's skeleton). Path edits into the
// map, edits of the other field, a restart, and a second writer's concurrent edits: reads and
// canonical states agree with a model and across peers.
#[test]
fn paged_struct_field_converges() {
    let mut lp = net(2, 21);
    let t = new_thing(&mut lp, 0);
    let b = lp.peers[1].engine.tid();
    set_edge(&mut lp.peers[0].engine, t, b, Some(edge(Role::Write)), None);
    let pad = "y".repeat(40);
    let mut model: BTreeMap<Value, Value> = (0..3000).map(|i| (s(&format!("k{i}")), s(&format!("{pad}{i}")))).collect();
    let book = |m: &BTreeMap<Value, Value>, note: &str| Value::Map([(Value::Int(0), Value::Map(m.clone())), (Value::Int(1), s(note))].into_iter().collect());
    let mut m = Mutation::new();
    m.set(t, &BOOK, &book(&model, "n0")).unwrap();
    lp.peers[0].commit(m).unwrap().unwrap();
    sync(&mut lp, 0, 1);
    let mut note = "n0".to_string();
    for round in 0..12 {
        let w = round % 2;
        let mut m = Mutation::new();
        for j in 0..3 {
            let k = s(&format!("k{}", (round * 37 + j * 101) % 3500));
            let v = s(&format!("r{round}w{w}"));
            m.op(t, &BOOK, PathOp { path: vec![PathSeg::Field(0), PathSeg::Key(k.clone())], op: Op::Set(v.clone()) }).unwrap();
            model.insert(k, v);
        }
        if round % 3 == 0 {
            note = format!("n{round}");
            m.op(t, &BOOK, PathOp { path: vec![PathSeg::Field(1)], op: Op::Set(s(&note)) }).unwrap();
        }
        lp.peers[w].commit(m).unwrap().unwrap();
        sync(&mut lp, w, 1 - w);
        if round == 5 {
            lp.peers[1].restart(77).unwrap();
        }
        for p in 0..2 {
            assert_eq!(lp.peers[p].engine.get(&t, &ak("/t/book")).unwrap(), Some(book(&model, &note)), "round {round} peer {p}");
        }
    }
    let x = lp.peers[0].engine.state(&t, &ak("/t/book")).unwrap();
    assert_eq!(x, lp.peers[1].engine.state(&t, &ak("/t/book")).unwrap());
    let k = s("k5");
    assert_eq!(lp.peers[1].engine.get_at(&t, &ak("/t/book"), &[PathSeg::Field(0), PathSeg::Key(k.clone())]).unwrap(), model.get(&k).cloned());
}

// spec/crdt.md §8 (the join of a state's pages is the state), notes/local-store.md Units: a
// received delete arrives as one range record spanning many pages of a paged text; every page
// it covers is rewritten, so the state survives a restart.
#[test]
#[ignore = "tier 2: ~20 s"]
fn range_delta_rewrites_its_pages_spec_crdt_8() {
    let mut lp = net(2, 14);
    let t = new_thing(&mut lp, 0);
    let b = lp.peers[1].engine.tid();
    set_edge(&mut lp.peers[0].engine, t, b, Some(edge(Role::Write)), None);
    let text: String = (0..70_000u32).map(|i| char::from(b'a' + (i % 26) as u8)).collect();
    let mut m = Mutation::new();
    m.set(t, &TEXT, &s(&text)).unwrap();
    lp.peers[0].commit(m).unwrap().unwrap();
    sync(&mut lp, 0, 1);
    let mut m = Mutation::new();
    m.op(t, &TEXT, PathOp { path: Vec::new(), op: Op::Delete { at: 5_000, len: 50_000 } }).unwrap();
    lp.peers[1].commit(m).unwrap().unwrap();
    sync(&mut lp, 1, 0);
    let want: String = text.chars().take(5_000).chain(text.chars().skip(55_000)).collect();
    assert_eq!(lp.peers[0].engine.get(&t, &ak("/t/text")).unwrap(), Some(s(&want)));
    // pages hold what a snapshot carries (deleted chars dropped): compare those bytes
    let carried = |f: Option<osis_crdt::Fragment>| {
        let cx = osis_crdt::DeltaCtx { ts: osis_core::Ts::from_u64(1 << 40).unwrap(), own: osis_crdt::Source::node(b), range: osis_crdt::CounterRange::EMPTY, kind: osis_crdt::DeltaKind::Snapshot };
        let snap = osis_crdt::Snapshot { nonce: [0; 16], fragment: f.unwrap(), frontiers: Default::default() };
        osis_crdt::encode_snapshot(&snap, &cx, None).unwrap()
    };
    let before = carried(lp.peers[0].engine.state(&t, &ak("/t/text")).unwrap());
    lp.peers[0].restart(140).unwrap();
    assert!(carried(lp.peers[0].engine.state(&t, &ak("/t/text")).unwrap()) == before, "state after restart");
    assert_eq!(lp.peers[0].engine.get(&t, &ak("/t/text")).unwrap(), Some(s(&want)));
}
