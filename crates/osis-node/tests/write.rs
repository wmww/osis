#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
//! Writing path end to end: identity, creation, ops to commits, local apply, events, restart.

mod common;
use osis_core::{Ak, Value, WallMs};
use osis_crdt::{Op, PathOp, PathSeg};
use osis_node::local_peer::Peer;
use osis_node::{Event, Mutation, Origin};
use osis_schema::core_types as ct;
use std::collections::BTreeMap;

fn ak(s: &str) -> Ak {
    Ak::new(s).unwrap()
}

fn peer(seed: u64) -> Peer {
    Peer::new(seed, WallMs(1_700_000_000_000)).unwrap()
}

// spec/data-model.md §1, §9; spec/permissions.md §4: a new node holds its own thing with
// `/created`, `/node` and `/keys`.
#[test]
fn node_identity_spec_dm_1() {
    let mut p = peer(1);
    let me = p.engine.tid();
    let rec = p.engine.get_typed(&me, &ct::CREATED).unwrap().unwrap();
    assert_eq!(rec.tid(), me);
    assert!(p.engine.get_typed(&me, &ct::NODE).unwrap().is_some());
    let keys = p.engine.get_typed(&me, &ct::KEYS).unwrap().unwrap();
    assert!(keys.key.is_some());
    assert_eq!(p.engine.get(&me, &ak("/tid")).unwrap(), Some(Value::Tid(me)));
    let aspects = p.engine.aspects(&me).unwrap();
    assert!(aspects.contains(&ak("/created")) && aspects.contains(&ak("/node")) && aspects.contains(&ak("/keys")));
    assert_eq!(p.engine.role_on(&me), Some(osis_core::Role::Admin));
}

// spec/crdt.md §4.5, §9; spec/commits.md §1: ops become one commit, applied locally, with an
// event naming the changed aspects (notes/api.md: listeners fire for local writes too).
#[test]
fn write_and_read_spec_crdt_4_5() {
    let mut p = peer(2);
    let me = p.engine.tid();
    p.drain_events();
    let mut m = Mutation::new();
    let t = p.engine.new_thing(&mut m, me);
    let a = ak("/app/title");
    m.set(t, &a, &Value::Str("hello".into())).unwrap();
    let mut map = BTreeMap::new();
    map.insert(Value::Str("x".into()), Value::Int(1));
    m.set(t, &ak("/app/map"), &Value::Map(map)).unwrap();
    let id = p.commit(m).unwrap().unwrap();
    assert_eq!(p.engine.get(&t, &a).unwrap(), Some(Value::Str("hello".into())));
    let ev = p.drain_events();
    let Some(Event::Applied { id: eid, origin, changed, .. }) = ev.iter().find(|e| matches!(e, Event::Applied { .. })) else { panic!("{ev:?}") };
    assert_eq!((*eid, *origin), (id, Origin::Local));
    assert!(changed.contains(&(t, a.clone())) && changed.contains(&(t, ak("/created"))));
    // path op into the map, then a no-op set writes nothing
    let mut m = Mutation::new();
    m.op(t, &ak("/app/map"), PathOp { path: vec![PathSeg::Key(Value::Str("y".into()))], op: Op::Set(Value::Int(2)) }).unwrap();
    p.commit(m).unwrap().unwrap();
    let v = p.engine.get(&t, &ak("/app/map")).unwrap().unwrap();
    let Value::Map(v) = v else { panic!() };
    assert_eq!(v.len(), 2);
    let mut m = Mutation::new();
    m.set(t, &a, &Value::Str("hello".into())).unwrap();
    assert_eq!(p.commit(m).unwrap(), None);
    // remove
    let mut m = Mutation::new();
    m.remove_aspect(t, &a).unwrap();
    p.commit(m).unwrap().unwrap();
    assert_eq!(p.engine.get(&t, &a).unwrap(), None);
}

// spec/crdt.md §2.1, §2.3: node-form counters per (aspect, node) are contiguous from 1.
#[test]
fn counters_contiguous_spec_crdt_2_3() {
    let mut p = peer(3);
    let me = p.engine.tid();
    let mut m = Mutation::new();
    let t = p.engine.new_thing(&mut m, me);
    m.set(t, &ak("/app/n"), &Value::Int(0)).unwrap();
    p.commit(m).unwrap();
    let mut ranges = Vec::new();
    for i in 1..5 {
        let mut m = Mutation::new();
        m.set(t, &ak("/app/n"), &Value::Int(i)).unwrap();
        let id = p.commit(m).unwrap().unwrap();
        let h = p.engine.header(&id).unwrap();
        let a = h.aspects.iter().find(|a| a.ak.as_str() == "/app/n").unwrap();
        ranges.push((a.lo, a.hi));
    }
    assert_eq!(ranges, vec![(2, 3), (3, 4), (4, 5), (5, 6)]);
}

// spec/commits.md §3: commit-form dots carry the commit ID as their source.
#[test]
fn commit_form_spec_commits_3() {
    let mut p = peer(4);
    let me = p.engine.tid();
    let mut m = Mutation::new();
    let t = p.engine.new_thing(&mut m, me);
    m.commit_form();
    m.set(t, &ak("/app/x"), &Value::Int(7)).unwrap();
    let id = p.commit(m).unwrap().unwrap();
    assert_eq!(p.engine.header(&id).unwrap().form, osis_commit::Form::Commit);
    assert_eq!(p.engine.get(&t, &ak("/app/x")).unwrap(), Some(Value::Int(7)));
}

// spec/permissions.md §1: writing a thing needs write on it; an unknown thing is refused.
#[test]
fn authority_checked_before_signing_spec_perm_1() {
    let mut a = peer(5);
    let mut b = peer(6);
    let ta = {
        let me = a.engine.tid();
        let mut m = Mutation::new();
        let t = a.engine.new_thing(&mut m, me);
        m.set(t, &ak("/app/x"), &Value::Int(1)).unwrap();
        a.commit(m).unwrap();
        t
    };
    let mut m = Mutation::new();
    m.set(ta, &ak("/app/x"), &Value::Int(2)).unwrap();
    assert!(matches!(b.commit(m), Err(osis_node::Error::UnknownThing(_))));
    // after receiving the thing, b still holds no role on it
    for id in a.engine.commit_ids() {
        let pk = a.engine.package(&id).unwrap().unwrap();
        b.engine.ingest(&pk.bytes, pk.blobs).unwrap();
    }
    assert_eq!(b.engine.get(&ta, &ak("/app/x")).unwrap(), Some(Value::Int(1)));
    let mut m = Mutation::new();
    m.set(ta, &ak("/app/x"), &Value::Int(2)).unwrap();
    assert!(matches!(b.commit(m), Err(osis_node::Error::Permission { .. })));
}

// notes/local-store.md: everything survives a restart (reload from the store).
// spec/commits.md §4 (one storage transaction per apply: state survives a reopen)
#[test]
fn restart_keeps_state() {
    let mut p = peer(7);
    let me = p.engine.tid();
    let mut m = Mutation::new();
    let t = p.engine.new_thing(&mut m, me);
    m.set(t, &ak("/app/x"), &Value::Str("kept".into())).unwrap();
    p.commit(m).unwrap();
    let n = p.engine.commit_ids().len();
    p.restart(70).unwrap();
    assert_eq!(p.engine.tid(), me);
    assert_eq!(p.engine.commit_ids().len(), n);
    assert_eq!(p.engine.get(&t, &ak("/app/x")).unwrap(), Some(Value::Str("kept".into())));
    let mut m = Mutation::new();
    m.set(t, &ak("/app/x"), &Value::Str("again".into())).unwrap();
    let id = p.commit(m).unwrap().unwrap();
    let h = p.engine.header(&id).unwrap();
    assert_eq!(h.aspects[0].lo, 2);
}

// spec/crdt.md §4.1, §8 (a large state pages; the join of its pages is the state); notes/local-store.md,
// Units: a large state is kept as pages and an edit rewrites only the pages
// it touched; spec/requirements.md, Scale (a change inside a huge value costs O(change)). Seeded
// random puts, removals and bulk inserts (page splits) into a paged map and a paged set, checked
// against a model across restarts, plus an undo of an edit inside the paged map.
#[test]
fn paged_state_edits_and_restart() {
    let mut p = peer(11);
    let me = p.engine.tid();
    let mut m = Mutation::new();
    let t = p.engine.new_thing(&mut m, me);
    let (am, aset) = (ak("/app/big"), ak("/app/bigset"));
    let pad = "x".repeat(40);
    let mut model: BTreeMap<Value, Value> = (0..3000i64).map(|i| (Value::Int(i), Value::Str(format!("{pad}{i}")))).collect();
    let mut smodel: std::collections::BTreeSet<Value> = (0..3000i64).map(|i| Value::Str(format!("{pad}{i}"))).collect();
    m.set(t, &am, &Value::Map(model.clone())).unwrap();
    m.set(t, &aset, &Value::Set(smodel.clone())).unwrap();
    p.commit(m).unwrap().unwrap();
    let mut r = 0x9e37_79b9_7f4a_7c15u64;
    let mut next = || {
        r ^= r << 13;
        r ^= r >> 7;
        r ^= r << 17;
        r
    };
    let mut last_edit = None;
    for round in 0..40 {
        let mut m = Mutation::new();
        let k = Value::Int((next() % 4000) as i64);
        match next() % 4 {
            0 if model.contains_key(&k) => {
                m.op(t, &am, PathOp { path: vec![], op: Op::Remove(k.clone()) }).unwrap();
                model.remove(&k);
            }
            1 => {
                // a bulk insert lands in the last page and splits it
                for j in 0..300 {
                    let k = Value::Int(10_000 + round * 300 + j);
                    let v = Value::Str(format!("{pad}{round}"));
                    m.op(t, &am, PathOp { path: vec![PathSeg::Key(k.clone())], op: Op::Set(v.clone()) }).unwrap();
                    model.insert(k, v);
                }
            }
            _ => {
                let v = Value::Int(round);
                m.op(t, &am, PathOp { path: vec![PathSeg::Key(k.clone())], op: Op::Set(v.clone()) }).unwrap();
                model.insert(k, v);
            }
        }
        let s = Value::Str(format!("{pad}{}", next() % 4000));
        if smodel.contains(&s) {
            m.op(t, &aset, PathOp { path: vec![], op: Op::Remove(s.clone()) }).unwrap();
            smodel.remove(&s);
        } else {
            m.op(t, &aset, PathOp { path: vec![], op: Op::Add(s.clone()) }).unwrap();
            smodel.insert(s);
        }
        last_edit = p.commit(m).unwrap();
        if round % 10 == 9 {
            p.restart(100 + round as u64).unwrap();
        }
        assert_eq!(p.engine.get(&t, &am).unwrap(), Some(Value::Map(model.clone())), "round {round}");
        assert_eq!(p.engine.get(&t, &aset).unwrap(), Some(Value::Set(smodel.clone())), "round {round}");
        let k = Value::Int((next() % 4000) as i64);
        assert_eq!(p.engine.get_at(&t, &am, &[PathSeg::Key(k.clone())]).unwrap(), model.get(&k).cloned());
    }
    // a path edit, then its undo (the undo buffer keeps only the edited entry)
    let before = p.engine.get(&t, &am).unwrap();
    let mut m = Mutation::new();
    m.op(t, &am, PathOp { path: vec![PathSeg::Key(Value::Int(5))], op: Op::Set(Value::Int(-5)) }).unwrap();
    let id = p.commit(m).unwrap().unwrap();
    assert_ne!(p.engine.get(&t, &am).unwrap(), before);
    p.engine.undo(&id).unwrap();
    assert_eq!(p.engine.get(&t, &am).unwrap(), before);
    assert!(last_edit.is_some());
}

/// Seeded pseudo-random bytes.
fn noise(n: usize, seed: u64) -> Vec<u8> {
    let mut v = vec![0u8; n];
    osis_crypto::RngCore::fill_bytes(&mut osis_crypto::SeededRng::from_u64(seed), &mut v);
    v
}

/// Bytes of the chunks of `new`'s canonical encoding whose content `old`'s lacks: what any
/// content-defined writer must write for the edit.
fn new_chunk_bytes(old: &[u8], new: &[u8]) -> usize {
    let cuts = |d: &[u8]| -> Vec<Vec<u8>> {
        let e = osis_core::encode(&Value::Bytes(d.to_vec()));
        let mut out = Vec::new();
        let mut at = 0;
        for n in osis_core::chunker::chunk_lengths(&e, osis_core::ChunkParams::FORMAT) {
            out.push(e[at..at + n].to_vec());
            at += n;
        }
        out
    };
    let have: std::collections::BTreeSet<Vec<u8>> = cuts(old).into_iter().collect();
    cuts(new).into_iter().filter(|c| !have.contains(c)).map(|c| c.len()).sum()
}

// spec/requirements.md (Scale: a change inside a huge value costs O(change)); spec/sync.md §1
// (a chunk reused by a later delta keeps its blob and prefix); spec/commits.md §1 (the chunk list
// holds the blobs the deltas introduce): editing a value of many chunks writes, and lists for
// upload, only the chunks the edit changed plus the tree's root node.
#[test]
fn large_edit_reuses_chunks_spec_sync_1() {
    let mut p = peer(12);
    let me = p.engine.tid();
    let a = ak("/app/file");
    let mut m = Mutation::new();
    let t = p.engine.new_thing(&mut m, me);
    let mut cur = noise(4 << 20, 1);
    m.set(t, &a, &Value::Bytes(cur.clone())).unwrap();
    let first = p.commit(m).unwrap().unwrap();
    let blobs = |p: &mut Peer, c| p.engine.package(&c).unwrap().unwrap().blobs.iter().map(|(_, b)| b.len()).sum::<usize>();
    let whole = blobs(&mut p, first);
    let chunks = osis_core::chunker::chunk_lengths(&osis_core::encode(&Value::Bytes(cur.clone())), osis_core::ChunkParams::FORMAT).len();
    assert!(chunks > 30, "{chunks} chunks");
    for name in ["insert 100 B", "overwrite 256 KiB", "append 10 KB", "delete 50 KB"] {
        let old = cur.clone();
        match name {
            "insert 100 B" => drop(cur.splice(2 << 20..2 << 20, noise(100, 2))),
            "overwrite 256 KiB" => cur[1 << 20..(1 << 20) + (256 << 10)].copy_from_slice(&noise(256 << 10, 3)),
            "append 10 KB" => cur.extend(noise(10_000, 4)),
            _ => drop(cur.drain(3 << 20..(3 << 20) + 50_000)),
        }
        let mut m = Mutation::new();
        m.set(t, &a, &Value::Bytes(cur.clone())).unwrap();
        let c = p.commit(m).unwrap().unwrap();
        let wrote = blobs(&mut p, c);
        let need = new_chunk_bytes(&old, &cur);
        // the root node: one link (about 100 B) per chunk
        let node = chunks * 120 + 4096;
        eprintln!("{name}: {wrote} B of blobs ({need} B of new chunks, whole value {whole} B)");
        assert!(wrote * 10 <= need * 12 + node * 10, "{name}: wrote {wrote}, new chunks {need}");
        assert_eq!(p.engine.get_full(&t, &a).unwrap(), Some(Value::Bytes(cur.clone())), "{name}");
    }
    // the same value again changes nothing
    let mut m = Mutation::new();
    m.set(t, &a, &Value::Bytes(cur.clone())).unwrap();
    assert_eq!(p.commit(m).unwrap(), None);
}

// spec/data-model.md §6: a list item above CHUNK_THRESHOLD is chunked when inserted, as when set.
#[test]
fn large_list_insert_chunked_spec_dm_6() {
    let mut p = peer(13);
    let me = p.engine.tid();
    let (key, a) = (&common::LIST, ak("/t/list"));
    let mut m = Mutation::new();
    let t = p.engine.new_thing(&mut m, me);
    m.set(t, key, &Value::List(vec![common::s("a")])).unwrap();
    p.commit(m).unwrap().unwrap();
    let big = Value::Str("large ".repeat(50_000));
    let mut m = Mutation::new();
    m.op(t, key, PathOp { path: vec![], op: Op::Insert { at: 1, items: vec![big.clone(), common::s("b")] } }).unwrap();
    p.commit(m).unwrap().unwrap();
    let Some(Value::List(l)) = p.engine.get(&t, &a).unwrap() else { panic!() };
    assert!(matches!(l.as_slice(), [Value::Str(_), Value::Link(_), Value::Str(_)]), "{l:?}");
    assert_eq!(p.engine.get_full(&t, &a).unwrap(), Some(Value::List(vec![common::s("a"), big, common::s("b")])));
}

/// A struct of 65 string registers: each field just under `CHUNK_THRESHOLD` stays inline, and
/// together they exceed `MAX_BLOB`.
static WIDE: osis_schema::StaticSchema = osis_schema::StaticSchema::new("wide.osis", WIDE_SRC);
const WIDE_SRC: &str = concat!(
    "schema 0x0123456789abcdef0123456789abcd02;\nrevision 1;\ntype wide = struct { ",
    "0 f0: string, 1 f1: string, 2 f2: string, 3 f3: string, 4 f4: string, 5 f5: string, 6 f6: string, 7 f7: string, 8 f8: string, 9 f9: string, ",
    "10 f10: string, 11 f11: string, 12 f12: string, 13 f13: string, 14 f14: string, 15 f15: string, 16 f16: string, 17 f17: string, 18 f18: string, 19 f19: string, ",
    "20 f20: string, 21 f21: string, 22 f22: string, 23 f23: string, 24 f24: string, 25 f25: string, 26 f26: string, 27 f27: string, 28 f28: string, 29 f29: string, ",
    "30 f30: string, 31 f31: string, 32 f32: string, 33 f33: string, 34 f34: string, 35 f35: string, 36 f36: string, 37 f37: string, 38 f38: string, 39 f39: string, ",
    "40 f40: string, 41 f41: string, 42 f42: string, 43 f43: string, 44 f44: string, 45 f45: string, 46 f46: string, 47 f47: string, 48 f48: string, 49 f49: string, ",
    "50 f50: string, 51 f51: string, 52 f52: string, 53 f53: string, 54 f54: string, 55 f55: string, 56 f56: string, 57 f57: string, 58 f58: string, 59 f59: string, ",
    "60 f60: string, 61 f61: string, 62 f62: string, 63 f63: string, 64 f64: string };\naspect /w/wide: wide;\n"
);
const WIDE_AK: osis_schema::Aspect<Value> = osis_schema::Aspect::new("/w/wide", &WIDE);

// spec/commits.md §1 (delta fits a blob): a struct of many near-`CHUNK_THRESHOLD` registers (no
// field chunked, a struct not paged) makes one delta over `MAX_BLOB`: the writer refuses it and
// nothing is applied; the same struct with two fields empty is written.
#[test]
fn wide_struct_over_max_blob_refused_spec_commits_1() {
    use osis_core::format::{CHUNK_THRESHOLD, MAX_BLOB};
    let mut p = peer(14);
    let me = p.engine.tid();
    let mut m = Mutation::new();
    let t = p.engine.new_thing(&mut m, me);
    m.set(t, &ak("/app/x"), &Value::Int(1)).unwrap();
    p.commit(m).unwrap().unwrap();
    let field = "w".repeat(CHUNK_THRESHOLD - 16);
    let wide = |n: i64| Value::Map((0..65).map(|i| (Value::Int(i), Value::Str(if i < n { field.clone() } else { String::new() }))).collect());
    assert!(65 * field.len() > MAX_BLOB && 63 * field.len() < MAX_BLOB);
    let mut m = Mutation::new();
    m.set(t, &WIDE_AK, &wide(65)).unwrap();
    let e = p.commit(m).unwrap_err();
    assert!(matches!(e, osis_node::Error::Commit(osis_commit::Error::Build(_))), "{e}");
    assert_eq!(p.engine.get(&t, &ak("/w/wide")).unwrap(), None);
    let mut m = Mutation::new();
    m.set(t, &WIDE_AK, &wide(63)).unwrap();
    p.commit(m).unwrap().unwrap();
    let Some(Value::Map(got)) = p.engine.get(&t, &ak("/w/wide")).unwrap() else { panic!() };
    assert_eq!(got.values().filter(|v| **v == Value::Str(field.clone())).count(), 63);
}

// spec/data-model.md §6: a list `edit` chunks the items it inserts as an insert does; base items
// match the list's links by content hash (so the edit lands in place), and an item the list
// holds already keeps its tree (nothing of it is written again).
#[test]
fn large_list_edit_chunked_spec_dm_6() {
    let mut p = peer(14);
    let me = p.engine.tid();
    let (key, a) = (&common::LIST, ak("/t/list"));
    let mut m = Mutation::new();
    let t = p.engine.new_thing(&mut m, me);
    let big1 = Value::Str("first ".repeat(50_000));
    m.set(t, key, &Value::List(vec![common::s("a"), big1.clone()])).unwrap();
    let first = p.commit(m).unwrap().unwrap();
    let blobs = |p: &mut Peer, c| p.engine.package(&c).unwrap().unwrap().blobs.iter().map(|(_, b)| b.len()).sum::<usize>();
    assert!(blobs(&mut p, first) > 300_000);
    let big2 = Value::Str("second ".repeat(50_000));
    let base = Value::List(vec![common::s("a"), big1.clone()]);
    let new = Value::List(vec![common::s("a"), big1.clone(), big2.clone(), common::s("b")]);
    let mut m = Mutation::new();
    m.op(t, key, PathOp { path: vec![], op: Op::Edit { base, new: new.clone() } }).unwrap();
    let c = p.commit(m).unwrap().unwrap();
    let Some(Value::List(l)) = p.engine.get(&t, &a).unwrap() else { panic!() };
    assert!(matches!(l.as_slice(), [Value::Str(_), Value::Link(_), Value::Link(_), Value::Str(_)]), "{l:?}");
    assert_eq!(p.engine.get_full(&t, &a).unwrap(), Some(new.clone()));
    // only big2's tree is new (350 000 bytes; with big1's it would be 650 000)
    let wrote = blobs(&mut p, c);
    assert!((350_000..430_000).contains(&wrote), "edit wrote {wrote} B");
    // a new item twice: one tree
    let big3 = Value::Str("third ".repeat(50_000));
    let base = new.clone();
    let Value::List(mut items) = new else { panic!() };
    items.extend([big3.clone(), common::s("c"), big3]);
    let new = Value::List(items);
    let mut m = Mutation::new();
    m.op(t, key, PathOp { path: vec![], op: Op::Edit { base, new: new.clone() } }).unwrap();
    let c = p.commit(m).unwrap().unwrap();
    assert_eq!(p.engine.get_full(&t, &a).unwrap(), Some(new));
    let wrote = blobs(&mut p, c);
    assert!((300_000..380_000).contains(&wrote), "duplicate items wrote {wrote} B");
}

// spec/commits.md §1 (the chunk list holds the blobs the deltas introduce): an edit replacing a
// large item the list no longer holds (deleted concurrently) changes nothing there; the tree
// written for the replacement is neither listed nor kept.
#[test]
fn edit_of_gone_item_lists_nothing_spec_commits_1() {
    let mut p = peer(15);
    let me = p.engine.tid();
    let (key, a) = (&common::LIST, ak("/t/list"));
    let mut m = Mutation::new();
    let t = p.engine.new_thing(&mut m, me);
    m.set(t, key, &Value::List(vec![common::s("a"), common::s("x"), common::s("b")])).unwrap();
    p.commit(m).unwrap().unwrap();
    let mut m = Mutation::new();
    m.op(t, key, PathOp { path: vec![], op: Op::Delete { at: 1, len: 1 } }).unwrap();
    p.commit(m).unwrap().unwrap();
    // an editor that still sees "x" replaces it by a large item, and edits "b"
    let base = Value::List(vec![common::s("a"), common::s("x"), common::s("b")]);
    let new = Value::List(vec![common::s("a"), Value::Str("large ".repeat(50_000)), common::s("c")]);
    let mut m = Mutation::new();
    m.op(t, key, PathOp { path: vec![], op: Op::Edit { base, new } }).unwrap();
    let c = p.commit(m).unwrap();
    let listed = c.map_or(0, |c| p.engine.package(&c).unwrap().unwrap().blobs.len());
    let got = p.engine.get_full(&t, &a).unwrap();
    let large = matches!(&got, Some(Value::List(l)) if l.iter().any(|v| matches!(v, Value::Str(s) if s.len() > 1000)));
    assert!(large || listed == 0, "{listed} blobs listed for a value the list does not hold: {got:?}");
}
