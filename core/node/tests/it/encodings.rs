#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
//! The writing path for every encoding the crdt builds today (sequences land with crdt-seq),
//! concurrent writers converging through `LocalPeer`, and paged deltas.

use crate::common;
use common::*;
use osis_base::{Role, Value};
use osis_crdt::{Op, PathOp, PathSeg};
use osis_node::Mutation;
use osis_schema::core_types as ct;
use std::collections::BTreeMap;

fn write_all(m: &mut Mutation, t: osis_base::Tid, n: i64, tag: &str) {
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
    let c = a.iter().find(|x| x.1.as_str() == "t:count.0").unwrap();
    assert_eq!(c.2, Some(Value::Int(24)));
    let tags = a.iter().find(|x| x.1.as_str() == "t:tags.0").unwrap();
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
    m.set(t, &BIG, &Value::Map(big.clone().into_iter().collect())).unwrap();
    let id = lp.peers[0].commit(m).unwrap().unwrap();
    let h = lp.peers[0].engine.header(&id).unwrap();
    assert!(!h.chunks.is_empty(), "paged delta lists its pages");
    assert_eq!(lp.peers[0].engine.get(&t, &ak("t:big.0")).unwrap(), Some(Value::Map(big.clone().into_iter().collect())));
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
    assert_eq!(lp.peers[1].engine.get(&t, &ak("t:big.0")).unwrap(), Some(Value::Map(big.into_iter().collect())));
    assert_eq!(lp.peers[0].engine.state(&t, &ak("t:big.0")).unwrap(), lp.peers[1].engine.state(&t, &ak("t:big.0")).unwrap());
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
    let l = a.iter().find(|x| x.1.as_str() == "t:list.0").unwrap();
    assert_eq!(l.2, Some(Value::List(vec![s("a"), s("x"), s("b")])));
    let tx = a.iter().find(|x| x.1.as_str() == "t:text.0").unwrap();
    assert_eq!(tx.2, Some(s(">hello world")));
}

// spec/crdt.md §3.3 rule 3, §8; spec/commits.md §1: 65 inline values of 128 KiB inserted in
// one commit (over 8 MiB of content) split into runs that page within blobs; the commit applies,
// travels and reads back.
#[test]
fn big_list_insert_fits_blobs_spec_crdt_3_3() {
    let mut lp = net(2, 15);
    let t = new_thing(&mut lp, 0);
    let n = osis_base::format::CHUNK_THRESHOLD - 8;
    let items: Vec<Value> = (0..65).map(|i| s(&format!("{i:03}{}", "z".repeat(n - 3)))).collect();
    let mut m = Mutation::new();
    m.set(t, &LIST, &Value::List(items.clone())).unwrap();
    lp.peers[0].commit(m).unwrap().unwrap();
    assert_eq!(lp.peers[0].engine.get(&t, &ak("t:list.0")).unwrap(), Some(Value::List(items.clone())));
    sync(&mut lp, 0, 1);
    assert_eq!(lp.peers[1].engine.get(&t, &ak("t:list.0")).unwrap(), Some(Value::List(items)));
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
    assert!(matches!(lp.peers[0].engine.get(&t, &ak("t:blob.0")).unwrap(), Some(Value::Link(_))));
    assert_eq!(lp.peers[0].engine.get_full(&t, &ak("t:blob.0")).unwrap(), Some(Value::Bytes(data.clone())));
    let mut m = Mutation::new();
    m.set(t, &BLOB, &Value::Bytes(data.clone())).unwrap();
    assert_eq!(lp.peers[0].commit(m).unwrap(), None);
    sync(&mut lp, 0, 1);
    assert_eq!(lp.peers[1].engine.get_full(&t, &ak("t:blob.0")).unwrap(), Some(Value::Bytes(data)));
}

// spec/crdt.md §3.3 rule 7, spec/data-model.md §6: a core-aspect delta must fit the core type. An
// element of `group.0`'s `set<tid>` that is a link (the type takes none) or an int is bad input:
// that delta never applies (its commit stalls alone, spec/commits.md §4) and the group reads whole,
// later writes too. Before, one such element made `group.0` unreadable for every reader (`blob
// missing`, or a decode failure: no group, no membership, nothing to sync).
#[test]
fn ill_typed_core_element_refused_spec_crdt_3_3() {
    let bogus = Value::link(osis_base::Link { hash: [3; 32], blob: osis_base::BlobId([4; 32]), suite: 1, key: [5; 32] });
    for bad in [bogus, Value::Int(5)] {
        let mut lp = net(2, 15);
        let t = new_thing(&mut lp, 0);
        let (x, y) = (lp.peers[0].engine.tid(), lp.peers[1].engine.tid());
        let mut m = Mutation::new();
        m.set(t, &ct::GROUP, &ct::Group { items: [x].into(), subgroups: Default::default() }).unwrap();
        lp.peers[0].commit(m).unwrap().unwrap();
        let add = |v: Value| PathOp { path: vec![PathSeg::Field(0)], op: Op::Add(v) };
        // a writer's own node refuses it too; a hostile one writes it anyway
        lp.peers[0].engine.core.skip_writer_rules = true;
        let mut m = Mutation::new();
        m.op(t, &ct::GROUP, add(bad.clone())).unwrap();
        lp.peers[0].commit(m).unwrap().unwrap();
        lp.peers[0].engine.core.skip_writer_rules = false;
        let mut m = Mutation::new();
        m.op(t, &ct::GROUP, add(Value::Tid(y))).unwrap();
        lp.peers[0].commit(m).unwrap().unwrap();
        sync(&mut lp, 0, 1);
        let e = &mut lp.peers[1].engine;
        assert_eq!(e.get_typed(&t, &ct::GROUP).unwrap(), Some(ct::Group { items: [x, y].into(), subgroups: Default::default() }), "{bad:?}");
        assert_eq!(e.get_full(&t, &ak("group.0")).unwrap(), e.get(&t, &ak("group.0")).unwrap());
        assert!(e.listed_in(&y).0.contains(&t), "{bad:?}: the group's members are known");
    }
}

// spec/data-model.md §6, spec/commits.md §4: the reader's untyped check of what must be chunked
// (`Fragment::holds_unchunked`) passes what a writer writes, in every position: text is not
// chunked, a register's string, a set element and a map key are.
#[test]
fn large_values_of_a_writer_pass_the_reader_spec_dm_6() {
    let mut lp = net(2, 22);
    let t = new_thing(&mut lp, 0);
    let big = "z".repeat(osis_base::format::CHUNK_THRESHOLD + 1);
    // as many bytes in a quarter of the chars: a text costs per char
    let text = "\u{1F600}".repeat(osis_base::format::CHUNK_THRESHOLD / 4 + 1);
    let mut m = Mutation::new();
    m.set(t, &TEXT, &s(&text)).unwrap();
    m.set(t, &ak("t:reg.0"), &s(&big)).unwrap();
    m.op(t, &ak("t:docs.0"), PathOp { path: vec![PathSeg::Key(s("k"))], op: Op::Set(s(&big)) }).unwrap();
    m.op(t, &ak("t:docs.0"), PathOp { path: vec![PathSeg::Key(s(&big))], op: Op::Set(s("v")) }).unwrap();
    m.op(t, &ak("t:tags.0"), PathOp { path: Vec::new(), op: Op::Add(s(&big)) }).unwrap();
    // a large key with a large value at it
    m.set(t, &BIG, &Value::Map([(s(&big), s(&big))].into_iter().collect())).unwrap();
    lp.peers[0].commit(m).unwrap().unwrap();
    sync(&mut lp, 0, 1);
    assert!(lp.peers[1].engine.pending().is_empty());
    for a in ["t:text.0", "t:reg.0", "t:docs.0", "t:tags.0", "t:big.0"] {
        assert!(lp.peers[1].engine.get(&t, &ak(a)).unwrap().is_some(), "{a}");
    }
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
    let mut model: osis_base::ValueMap = (0..3000).map(|i| (s(&format!("k{i}")), s(&format!("{pad}{i}")))).collect();
    let book = |m: &osis_base::ValueMap, note: &str| Value::Map([(Value::Int(0), Value::Map(m.clone())), (Value::Int(1), s(note))].into_iter().collect());
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
            assert_eq!(lp.peers[p].engine.get(&t, &ak("t:book.0")).unwrap(), Some(book(&model, &note)), "round {round} peer {p}");
        }
    }
    let x = lp.peers[0].engine.state(&t, &ak("t:book.0")).unwrap();
    assert_eq!(x, lp.peers[1].engine.state(&t, &ak("t:book.0")).unwrap());
    let k = s("k5");
    assert_eq!(lp.peers[1].engine.get_at(&t, &ak("t:book.0"), &[PathSeg::Field(0), PathSeg::Key(k.clone())]).unwrap(), model.get(&k).cloned());
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
    assert_eq!(lp.peers[0].engine.get(&t, &ak("t:text.0")).unwrap(), Some(s(&want)));
    // pages hold what a snapshot carries (deleted chars dropped): compare those bytes
    let carried = |f: Option<osis_crdt::Fragment>| {
        let cx = osis_crdt::DeltaCtx { ts: osis_base::Ts::from_u64(1 << 40).unwrap(), own: osis_crdt::Source::session(osis_crdt::Session { node: b, nonce: [0; osis_crdt::SESSION_NONCE_LEN] }), range: osis_crdt::CounterRange::EMPTY, kind: osis_crdt::DeltaKind::Snapshot };
        let snap = osis_crdt::Snapshot { absorbed: Default::default(), nonce: [0; 16], fragment: f.unwrap(), frontiers: Default::default() };
        osis_crdt::encode_snapshot(&snap, &cx, None).unwrap()
    };
    let before = carried(lp.peers[0].engine.state(&t, &ak("t:text.0")).unwrap());
    lp.peers[0].restart(140).unwrap();
    assert!(carried(lp.peers[0].engine.state(&t, &ak("t:text.0")).unwrap()) == before, "state after restart");
    assert_eq!(lp.peers[0].engine.get(&t, &ak("t:text.0")).unwrap(), Some(s(&want)));
}

// spec/crdt.md §5.7 (Read: the visible elements in placement order), §6, §8: a read by index
// range of a paged list (its placement kept with its pages, and through the edits) and of a
// small text, in new sessions, after a concurrent writer's insert and a move: what the whole
// read holds there, clamped to the length, loading a few pages; absent or not a sequence reads
// `None`.
#[test]
fn range_reads_by_index_spec_crdt_5_7() {
    let mut lp = net(2, 23);
    let t = new_thing(&mut lp, 0);
    let b = lp.peers[1].engine.tid();
    set_edge(&mut lp.peers[0].engine, t, b, Some(edge(Role::Write)), None);
    let items: Vec<Value> = (0..2500).map(|i| s(&format!("item-{i:06}-padding-padding"))).collect();
    let mut m = Mutation::new();
    m.set(t, &LIST, &Value::List(items)).unwrap();
    m.set(t, &TEXT, &s("hello world")).unwrap();
    lp.peers[0].commit(m).unwrap().unwrap();
    sync(&mut lp, 0, 1);
    let mut m = Mutation::new();
    m.op(t, &LIST, PathOp { path: vec![], op: Op::Insert { at: 1200, items: vec![s("from b")] } }).unwrap();
    lp.peers[1].commit(m).unwrap().unwrap();
    let mut m = Mutation::new();
    m.op(t, &LIST, PathOp { path: vec![], op: Op::Move { at: 10, len: 5, to: 1500 } }).unwrap();
    lp.peers[0].commit(m).unwrap().unwrap();
    sync(&mut lp, 1, 0);
    sync(&mut lp, 0, 1);
    for p in 0..2 {
        let Some(Value::List(all)) = lp.peers[p].engine.get(&t, &ak("t:list.0")).unwrap() else { panic!() };
        assert_eq!(all.len(), 2501);
        assert!(all.contains(&s("from b")));
        // the edits kept the stored placement: no read lays it out anew
        lp.peers[p].restart(59).unwrap();
        osis_node::costs::take();
        assert_eq!(lp.peers[p].engine.get_range(&t, &ak("t:list.0"), &[], 0..2).unwrap(), Some(Value::List(all[0..2].to_vec())));
        let loads = osis_node::costs::take().iter().find(|x| x.0 == "state page load").map_or(0, |x| x.2);
        assert!((1..=3).contains(&loads), "kept through the edits: {loads} pages");
        for r in [1195..1210, 1490..1510, 0..3, 2495..2600] {
            // a new session: nothing loaded
            lp.peers[p].restart(60 + r.start as u64).unwrap();
            let want = all.get(r.start.min(all.len())..r.end.min(all.len())).unwrap().to_vec();
            osis_node::costs::take();
            assert_eq!(lp.peers[p].engine.get_range(&t, &ak("t:list.0"), &[], r.clone()).unwrap(), Some(Value::List(want)), "peer {p} {r:?}");
            let loads = osis_node::costs::take().iter().find(|x| x.0 == "state page load").map_or(0, |x| x.2);
            assert!((1..=3).contains(&loads), "peer {p} {r:?}: {loads} pages loaded");
        }
        lp.peers[p].restart(70).unwrap();
        osis_node::costs::take();
        lp.peers[p].engine.get(&t, &ak("t:list.0")).unwrap();
        let loads = osis_node::costs::take().iter().find(|x| x.0 == "state page load").map_or(0, |x| x.2);
        assert!(loads >= 6, "the whole list: {loads} pages");
        let e = &mut lp.peers[p].engine;
        assert_eq!(e.get_range(&t, &ak("t:text.0"), &[], 6..20).unwrap(), Some(s("world")));
        assert_eq!(e.get_range(&t, &ak("t:reg.0"), &[], 0..2).unwrap(), None);
        assert_eq!(e.get_range(&t, &ak("t:gone.0"), &[], 0..2).unwrap(), None);
    }
}

// spec/crdt.md §5.7 (Read by index): a reversed range reads empty, from the whole sequence and
// through a paged one's stored placement in a new session.
#[test]
fn reversed_range_reads_empty_spec_crdt_5_7() {
    let mut lp = net(1, 31);
    let t = new_thing(&mut lp, 0);
    let items: Vec<Value> = (0..2500).map(|i| s(&format!("item-{i:06}-padding-padding"))).collect();
    let mut m = Mutation::new();
    m.set(t, &LIST, &Value::List(items)).unwrap();
    lp.peers[0].commit(m).unwrap().unwrap();
    let reversed = std::ops::Range { start: 10, end: 5 };
    assert_eq!(lp.peers[0].engine.get_range(&t, &ak("t:list.0"), &[], reversed.clone()).unwrap(), Some(Value::List(Vec::new())));
    lp.peers[0].restart(7).unwrap();
    assert_eq!(lp.peers[0].engine.get_range(&t, &ak("t:list.0"), &[], reversed.clone()).unwrap(), Some(Value::List(Vec::new())));
}

// spec/crdt.md §5.6 (a removed key reads absent), §5.7: a range read under a removed map key
// holding a paged text reads absent, as a read at that key does, in the session and a new one.
#[test]
fn range_under_removed_key_absent_spec_crdt_5_6() {
    let mut lp = net(1, 29);
    let t = new_thing(&mut lp, 0);
    let big = |c: char| s(&std::iter::repeat_n(c, 30_000).collect::<String>());
    let mut m = Mutation::new();
    m.op(t, &DOCS, PathOp { path: vec![PathSeg::Key(s("a"))], op: Op::Set(big('a')) }).unwrap();
    m.op(t, &DOCS, PathOp { path: vec![PathSeg::Key(s("b"))], op: Op::Set(big('b')) }).unwrap();
    lp.peers[0].commit(m).unwrap().unwrap();
    lp.peers[0].restart(5).unwrap();
    assert_eq!(lp.peers[0].engine.get_range(&t, &ak("t:docs.0"), &[PathSeg::Key(s("a"))], 0..5).unwrap(), Some(s("aaaaa")));
    let mut m = Mutation::new();
    m.op(t, &DOCS, PathOp { path: vec![], op: Op::Remove(s("a")) }).unwrap();
    lp.peers[0].commit(m).unwrap().unwrap();
    for session in 0..2 {
        if session == 1 {
            lp.peers[0].restart(6).unwrap();
        }
        let e = &mut lp.peers[0].engine;
        assert_eq!(e.get_at(&t, &ak("t:docs.0"), &[PathSeg::Key(s("a"))]).unwrap(), None);
        assert_eq!(e.get_range(&t, &ak("t:docs.0"), &[PathSeg::Key(s("a"))], 0..5).unwrap(), None, "session {session}");
        assert_eq!(e.get_range(&t, &ak("t:docs.0"), &[PathSeg::Key(s("b"))], 0..5).unwrap(), Some(s("bbbbb")), "session {session}");
    }
}

// spec/data-model.md §6: role-class values stay inline whatever their size. A label's claim set for
// 2049-4096 readers passes `CHUNK_THRESHOLD`; its `label.0` write applies at its writer and reader.
#[test]
fn label_claim_set_above_the_threshold_stays_inline_spec_dm_6() {
    let mut lp = net(2, 25);
    let t = new_thing(&mut lp, 0);
    let claims = osis_label::ClaimSet { claims: vec![[1; 32]; 4096], entries: Default::default() }.to_bytes();
    assert!(claims.len() > osis_base::format::CHUNK_THRESHOLD);
    let l = ct::Label { index: 0, steps: [([9; 32], ct::StepRecord { step: vec![1; 200], claims: Some(claims) })].into_iter().collect(), hosts: Vec::new(), replaced: false };
    let mut m = Mutation::new();
    m.op(t, &ct::LABEL, PathOp { path: vec![PathSeg::Key(Value::Bytes(vec![5; 16]))], op: Op::Set(osis_schema::Codec::to_value(&l)) }).unwrap();
    lp.peers[0].commit(m).unwrap().unwrap();
    assert!(lp.peers[0].engine.get(&t, &ak("label.0")).unwrap().is_some(), "held by its writer");
    sync(&mut lp, 0, 1);
    assert!(lp.peers[1].engine.get(&t, &ak("label.0")).unwrap().is_some(), "held by the reader");
}
