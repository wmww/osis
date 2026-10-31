//! Wire tests (spec/crdt.md §3.2, §3.3, §8): byte identity with core/test/crdt-model, round trips, and
//! every §3.3 rule 7 rejection.

use crate::codec::{decode_delta, decode_snapshot, encode_delta, encode_snapshot};
use crate::stamp::{CounterRange, Interner, Source};
use crate::testutil::{frag, history_with, mapply, sink_no_seq, source, ts};
use crate::wire::{Delta, DeltaCtx, DeltaKind, Frontiers, Snapshot};
use crdt_model::ops::Ty;
use crdt_model::stamp::Source as MSource;
use crdt_model::wire::{Ctx, encode_delta as m_encode_delta};
use osis_base::{Classified, ErrorClass, Tid, Value};
use proptest::prelude::*;
use std::collections::BTreeMap;

pub(crate) fn writer_cx(w: &crdt_model::ops::Writer) -> DeltaCtx {
    DeltaCtx { ts: ts(w.ts), own: source(&w.source), range: CounterRange { lo: w.lo, hi: w.hi() }, kind: DeltaKind::Writer }
}

pub(crate) fn snap_cx() -> DeltaCtx {
    DeltaCtx { ts: ts(1 << 40), own: source(&MSource::node(250)), range: CounterRange::EMPTY, kind: DeltaKind::Snapshot }
}

/// Every delta of a random history, node or commit form, encodes byte-identically with the model
/// and decodes back to itself under the writer's header; snapshots of the joined state likewise.
fn wire_matches(seed: u64, types: &[Ty], sources: Vec<MSource>) {
    let mut r = crate::testutil::rng(seed | 1);
    // commit-form sources get an author (§8 `Authors`)
    let mau: crdt_model::wire::Authors = sources.iter().filter_map(|s| if let MSource::Commit(c) = s { Some((*c, ([1; 15], 5u64 << 16))) } else { None }).collect();
    let authors: BTreeMap<osis_base::CommitId, (osis_base::Tid, osis_base::Ts)> = mau.iter().map(|(c, (t, ts))| (osis_base::CommitId(*c), (osis_base::Tid::from_bytes(*t), osis_base::Ts::from_u64(*ts).unwrap()))).collect();
    let commits = history_with(&mut r, types, sources, 5);
    let mut state = None;
    for c in &commits {
        let mut mcx = Ctx::new(c.w.ts, c.w.source.clone(), c.w.lo);
        let mbytes = m_encode_delta(&c.delta, [7; 16], &mut mcx);
        let cx = writer_cx(&c.w);
        let d = Delta { nonce: [7; 16], fragment: frag(&c.delta) };
        let bytes = encode_delta(&d, &cx, None).unwrap();
        assert_eq!(bytes, mbytes, "delta bytes equal the model's");
        let back = decode_delta(&bytes, &cx, &mut Interner::new(), None).unwrap();
        crate::testutil::check_bound(&bytes, &back.fragment);
        assert_eq!(back, d, "delta round trip");
        mapply(&mut state, c.delta.clone());
        let st = state.as_ref().unwrap();
        let mut fr = crdt_model::received::Received::default();
        fr.add(&c.w.source, 1, c.w.hi());
        let mfr: Vec<(MSource, u64)> = fr.frontiers().into_iter().filter(|(s, _)| matches!(s, MSource::Node(_))).collect();
        let msnap = crdt_model::wire::encode_snapshot_authors(st, &mfr, &mau, [3; 16], &mut Ctx::new(1 << 40, MSource::node(250), 1));
        let frontiers = Frontiers(mfr.iter().map(|(s, c)| (source(s).as_node().unwrap(), *c)).collect());
        let s = Snapshot { absorbed: Default::default(), nonce: [3; 16], fragment: frag(st), frontiers, authors: authors.clone() };
        let sbytes = encode_snapshot(&s, &snap_cx(), None).unwrap();
        assert_eq!(sbytes, msnap, "snapshot bytes equal the model's");
        let mut back = decode_snapshot(&sbytes, &snap_cx(), &mut Interner::new(), None).unwrap();
        crate::testutil::check_bound(&sbytes, &back.fragment);
        // the authors of the sources the fragment holds, those of others not carried
        assert!(back.authors.iter().all(|(c, v)| s.authors.get(c) == Some(v)));
        back.authors = s.authors.clone();
        assert_eq!(back, s, "snapshot round trip");
    }
}

proptest! {
    /// §3.2, §3.3 rules 1–6: node form.
    #[test]
    fn wire_matches_model_spec_3(seed in any::<u64>()) {
        let sources = (1..=3).map(MSource::node).collect();
        wire_matches(seed, &[sink_no_seq()], sources);
    }

    /// §3.3 rule 2: commit form, own source sorting below the other commits.
    #[test]
    fn wire_commit_form_spec_3_3(seed in any::<u64>()) {
        let sources = [0x80u8, 0x10, 0xf0].iter().map(|b| MSource::Commit([*b; 32])).collect();
        wire_matches(seed, &[sink_no_seq()], sources);
    }

    /// §7 snapshots carry slots.
    #[test]
    fn wire_slots_spec_7(seed in any::<u64>()) {
        let set = Ty::Set(Box::new(Ty::Register));
        let sources = (1..=4).map(MSource::node).collect();
        wire_matches(seed, &[Ty::Register, Ty::Counter, set, Ty::Max], sources);
    }

    /// §3.3 rule 7: the decoder never panics on arbitrary input.
    #[test]
    fn decoder_never_panics_spec_3_3(bytes in proptest::collection::vec(any::<u8>(), 0..300)) {
        let _ = decode_delta(&bytes, &wcx(), &mut Interner::new(), None);
        let _ = decode_snapshot(&bytes, &snap_cx(), &mut Interner::new(), None);
    }

    /// §3.3 rule 7: mutated valid deltas are rejected or decode, never panic.
    #[test]
    fn mutated_delta_never_panics_spec_3_3(seed in any::<u64>(), pos in any::<usize>(), byte in any::<u8>()) {
        let mut r = crate::testutil::rng(seed | 1);
        let commits = history_with(&mut r, &[sink_no_seq()], vec![MSource::node(1)], 2);
        for c in &commits {
            let cx = writer_cx(&c.w);
            let mut bytes = encode_delta(&Delta { nonce: [1; 16], fragment: frag(&c.delta) }, &cx, None).unwrap();
            let p = pos % bytes.len();
            bytes[p] = byte;
            if let Ok(d) = decode_delta(&bytes, &cx, &mut Interner::new(), None) {
                let mut s = crate::Fragment::default();
                s.join(d.fragment);
                let _ = s.read();
            }
        }
    }
}

// ---- negative tests (§2.3, §3.3 rule 7)

fn tid(n: u8) -> Tid {
    let mut b = [0u8; 15];
    b[14] = n;
    Tid::from_bytes(b)
}

/// Writer of node 1 at ts 5·2^16 with range [3, 6).
pub(crate) fn wcx() -> DeltaCtx {
    DeltaCtx { ts: ts(5 << 16), own: Source::node(tid(1)), range: CounterRange { lo: 3, hi: 6 }, kind: DeltaKind::Writer }
}

pub(crate) fn i(n: i64) -> Value {
    Value::Int(n)
}
pub(crate) fn l(v: Vec<Value>) -> Value {
    Value::List(v)
}
pub(crate) fn delta(sources: Vec<Value>, commits: Vec<Value>, f: Value) -> Vec<u8> {
    osis_base::encode(&l(vec![Value::Bytes(vec![0; 16]), l(sources), l(commits), f]))
}
fn set_with(elems: Vec<Value>) -> Value {
    l(vec![i(6), l(vec![]), l(vec![]), l(elems)])
}
fn elem(dot: Value, v: i64) -> Value {
    l(vec![dot, l(vec![]), l(vec![l(vec![i(0), l(vec![]), i(0), i(v)])])])
}

pub(crate) fn rejects(bytes: &[u8], cx: &DeltaCtx, class: ErrorClass) {
    match decode_delta(bytes, cx, &mut Interner::new(), None) {
        Ok(d) => panic!("accepted {d:?}"),
        Err(e) => assert_eq!(e.class(), class, "{e}"),
    }
}

#[test]
fn accepts_a_valid_delta_spec_3_2() {
    let b = delta(vec![], vec![], set_with(vec![elem(i(3), 1), elem(i(4), 2)]));
    let d = decode_delta(&b, &wcx(), &mut Interner::new(), None).unwrap();
    let mut s = crate::Fragment::default();
    s.join(d.fragment);
    assert_eq!(s.read(), Some(Value::Set([i(1), i(2)].into_iter().collect())));
}

#[test]
fn rejects_non_canonical_cbor_spec_3_3() {
    let mut b = delta(vec![], vec![], l(vec![i(0), l(vec![]), i(0), i(1)]));
    // replace the final int 1 by its non-shortest form 0x18 0x01
    b.pop();
    b.extend([0x18, 0x01]);
    rejects(&b, &wcx(), ErrorClass::BadInput);
}

#[test]
fn rejects_out_of_range_indices_spec_3_3() {
    // Src 1 with an empty Sources table
    rejects(&delta(vec![], vec![], set_with(vec![elem(l(vec![i(1), i(2)]), 1)])), &wcx(), ErrorClass::BadInput);
    // Ci 1 in a writer's delta
    rejects(&delta(vec![], vec![], l(vec![i(0), l(vec![]), i(1), i(1)])), &wcx(), ErrorClass::BadInput);
    // counter 0
    rejects(&delta(vec![], vec![], set_with(vec![elem(i(0), 1)])), &wcx(), ErrorClass::BadInput);
}

#[test]
fn rejects_own_counters_out_of_range_spec_2_3() {
    // a stamp above hi
    rejects(&delta(vec![], vec![], l(vec![i(0), l(vec![]), l(vec![i(0), i(6)]), i(1)])), &wcx(), ErrorClass::BadInput);
    // a stamp below lo
    rejects(&delta(vec![], vec![], l(vec![i(0), l(vec![]), l(vec![i(0), i(2)]), i(1)])), &wcx(), ErrorClass::BadInput);
    // an own element dot at hi
    rejects(&delta(vec![], vec![], set_with(vec![elem(i(6), 1)])), &wcx(), ErrorClass::BadInput);
    // two creations taking one counter
    let s = l(vec![i(4), l(vec![]), l(vec![]), Value::Map([(i(1), set_with(vec![elem(i(3), 1)])), (i(2), set_with(vec![elem(i(3), 2)]))].into_iter().collect())]);
    rejects(&delta(vec![], vec![], s), &wcx(), ErrorClass::BadInput);
}

#[test]
fn rejects_non_canonical_forms_spec_3_3() {
    // stamp in array form at its base
    rejects(&delta(vec![], vec![], l(vec![i(0), l(vec![]), l(vec![i(0), i(3)]), i(1)])), &wcx(), ErrorClass::BadInput);
    // own dot in array form
    rejects(&delta(vec![], vec![], set_with(vec![elem(l(vec![i(0), i(3)]), 1)])), &wcx(), ErrorClass::BadInput);
    // unsorted elements
    rejects(&delta(vec![], vec![], set_with(vec![elem(i(4), 1), elem(i(3), 2)])), &wcx(), ErrorClass::BadInput);
    // a source the fragment does not use
    rejects(&delta(vec![Value::Bytes(vec![9; 15])], vec![], set_with(vec![elem(i(3), 1)])), &wcx(), ErrorClass::BadInput);
    // the own source repeated in Sources
    let own = Value::Bytes(tid(1).as_bytes().to_vec());
    rejects(&delta(vec![own], vec![], set_with(vec![elem(i(3), 1)])), &wcx(), ErrorClass::BadInput);
    // a bad nonce
    let b = osis_base::encode(&l(vec![Value::Bytes(vec![0; 15]), l(vec![]), l(vec![]), set_with(vec![])]));
    rejects(&b, &wcx(), ErrorClass::BadInput);
}

#[test]
fn rejects_foreign_stamps_in_writer_delta_spec_3_3() {
    let src = Value::Bytes(vec![9; 15]);
    let commits = vec![l(vec![i(1), l(vec![l(vec![i(1), i(0), i(1)])])])];
    let f = l(vec![i(0), l(vec![]), i(1), i(1)]);
    rejects(&delta(vec![src], commits, f), &wcx(), ErrorClass::BadInput);
}

#[test]
fn rejects_nested_register_reset_spec_3_3() {
    let s = l(vec![i(4), l(vec![]), l(vec![]), Value::Map([(i(1), l(vec![i(0), l(vec![i(0)]), i(0), i(1)]))].into_iter().collect())]);
    rejects(&delta(vec![], vec![], s), &wcx(), ErrorClass::BadInput);
}

/// §3.2, §3.3 rule 2, §5.6: a removal record carries its entry's key; records of one dot sort
/// by key, the key-less one first, each (dot, key) once.
#[test]
fn keyed_tombstones_spec_3_3() {
    let tomb = |k: Option<i64>| l([vec![i(3), l(vec![i(0)])], k.map(i).into_iter().collect(), vec![l(vec![])]].concat());
    let map = |es: Vec<Value>| delta(vec![], vec![], l(vec![i(7), l(vec![]), l(vec![]), l(es)]));
    let d = decode_delta(&map(vec![tomb(None), tomb(Some(5)), tomb(Some(7))]), &wcx(), &mut Interner::new(), None).unwrap();
    let crate::Fragment::Map(m) = &d.fragment else { panic!("map") };
    assert_eq!(m.entries().map(|(_, _, k, _)| k.cloned()).collect::<Vec<_>>(), vec![None, Some(i(5)), Some(i(7))]);
    rejects(&map(vec![tomb(Some(7)), tomb(Some(5))]), &wcx(), ErrorClass::BadInput);
    rejects(&map(vec![tomb(Some(5)), tomb(None)]), &wcx(), ErrorClass::BadInput);
    rejects(&map(vec![tomb(Some(5)), tomb(Some(5))]), &wcx(), ErrorClass::BadInput);
}

#[test]
fn rejects_bad_slots_spec_3_3() {
    let reg = l(vec![i(0), l(vec![]), i(0), i(1)]);
    let set = set_with(vec![elem(i(3), 1)]);
    // any slots in a writer's delta
    rejects(&delta(vec![], vec![], l(vec![i(10), l(vec![reg.clone()]), l(vec![set.clone()])])), &wcx(), ErrorClass::BadInput);
    // in a snapshot (stamps foreign: the snapshotter is node 2, writes by node 1)
    let scx = DeltaCtx { ts: ts(9 << 16), own: Source::node(tid(2)), range: CounterRange::EMPTY, kind: DeltaKind::Snapshot };
    let srcs = vec![Value::Bytes(tid(1).as_bytes().to_vec())];
    let commits = vec![l(vec![i(1), l(vec![l(vec![i(5), i(0), i(3)])])])];
    let reg = l(vec![i(0), l(vec![]), i(1), i(1)]);
    let set = l(vec![i(6), l(vec![]), l(vec![]), l(vec![l(vec![l(vec![i(1), i(3)]), l(vec![]), l(vec![l(vec![i(0), l(vec![]), i(1), i(1)])])])])]);
    let ok = |members: Value, reg: Value| delta(srcs.clone(), commits.clone(), l(vec![i(10), reg, members]));
    // one member only
    rejects(&ok(l(vec![]), l(vec![reg.clone()])), &scx, ErrorClass::BadInput);
    // a register among the non-register members
    rejects(&ok(l(vec![set.clone(), reg.clone()]), l(vec![])), &scx, ErrorClass::BadInput);
    // a non-register first member
    rejects(&ok(l(vec![set.clone()]), l(vec![set.clone()])), &scx, ErrorClass::BadInput);
    // repeated encodings
    rejects(&ok(l(vec![set.clone(), set.clone()]), l(vec![reg.clone()])), &scx, ErrorClass::BadInput);
}

// spec/versioning.md §2 (park unknown)
#[test]
fn parks_unknown_encoding_spec_3_1() {
    rejects(&delta(vec![], vec![], l(vec![i(42), l(vec![])])), &wcx(), ErrorClass::Parked);
}

#[test]
fn rejects_deep_values_spec_3_3() {
    let mut v = i(1);
    for _ in 0..70 {
        v = l(vec![v]);
    }
    rejects(&delta(vec![], vec![], l(vec![i(0), l(vec![]), i(0), v])), &wcx(), ErrorClass::BadInput);
}

#[test]
fn snapshot_frontiers_spec_8() {
    let scx = DeltaCtx { ts: ts(9 << 16), own: Source::node(tid(2)), range: CounterRange::EMPTY, kind: DeltaKind::Snapshot };
    let s = Snapshot { absorbed: Default::default(), authors: Default::default(), nonce: [0; 16], fragment: crate::Fragment::default(), frontiers: Frontiers(BTreeMap::from([(tid(5), 7), (tid(2), 3)])) };
    let b = encode_snapshot(&s, &scx, None).unwrap();
    // own (Src 0) first; the frontier-only source last in Sources
    let back = decode_snapshot(&b, &scx, &mut Interner::new(), None).unwrap();
    assert_eq!(back, s);
    let top = osis_base::decode(&b, &osis_base::Limits::DEFAULT).unwrap();
    let Value::List(a) = top else { panic!() };
    assert_eq!(a[4], l(vec![l(vec![i(0), i(3)]), l(vec![i(1), i(7)])]));
    // a commit-form writer (own a commit) cannot be named by a frontier; a zero counter is refused
    let bad = Snapshot { frontiers: Frontiers(BTreeMap::from([(tid(5), 0)])), ..s };
    assert!(encode_snapshot(&bad, &scx, None).is_err());
}

/// spec/crdt.md §3.2 (set elements), §3.3 rule 7, §5.5: a set element of a struct type is one
/// register holding the whole value, byte-identical with the model; a set element that is a
/// nested fragment is bad input; a link fits only a register position.
#[test]
fn set_element_is_a_register_spec_3_2() {
    use crate::fragment::{Elem, Fragment, Meta, Set};
    use crate::ops::{Writer, create};
    use crate::testutil::{TyView, writer};
    let pair = Ty::Struct([(1, Ty::Register), (2, Ty::Register)].into_iter().collect());
    let v = Value::Map([(Value::Int(1), Value::Int(1)), (Value::Int(2), Value::Int(2))].into());
    let mw = crdt_model::ops::Writer::new(MSource::node(1), 3 << 16, 1);
    let mut w: Writer = writer(&mw);
    let f = create(&mut w, &TyView(Ty::Set(Box::new(pair.clone()))), &Value::Set([v.clone()].into())).unwrap();
    let Fragment::Set(s) = &f else { panic!("set") };
    assert!(s.elems.values().all(|e| matches!(e.frag.as_deref(), Some(Fragment::Register(_)))));
    let mut mw2 = mw.clone();
    let mf = crdt_model::ops::create(&mut mw2, &Ty::Set(Box::new(pair.clone())), &crdt_model::value::Value::set(vec![crdt_model::value::Value::fields(vec![(1, crdt_model::value::Value::Int(1)), (2, crdt_model::value::Value::Int(2))])]));
    assert_eq!(f, frag(&mf));
    let cx = writer_cx(&mw2);
    let bytes = encode_delta(&Delta { nonce: [1; 16], fragment: f }, &cx, None).unwrap();
    assert!(decode_delta(&bytes, &cx, &mut Interner::new(), None).is_ok());
    // the element as a nested struct fragment
    let mut w = writer(&mw);
    let d = w.fresh().dot;
    let nested = create(&mut w, &TyView(pair.clone()), &v).unwrap();
    let bad = Fragment::Set(Set { meta: Meta::default(), elems: BTreeMap::from([(d, Elem { reset: None, frag: Some(Box::new(nested)) })]) });
    let bytes = encode_delta(&Delta { nonce: [1; 16], fragment: bad }, &cx, None).unwrap();
    let e = decode_delta(&bytes, &cx, &mut Interner::new(), None).unwrap_err();
    assert_eq!(e.class(), ErrorClass::BadInput);
    // a link at a struct, list, set or counter position is refused
    let link = Value::Link(osis_base::Link { hash: [1; 32], blob: osis_base::BlobId([2; 32]), suite: 1, key: [0; 32] });
    for ty in [pair, Ty::List(Box::new(Ty::Register)), Ty::Set(Box::new(Ty::Register)), Ty::Counter] {
        assert!(create(&mut writer(&mw), &TyView(ty), &link).is_err());
    }
}

/// §3.2 `PosW`, §3.3 rule 7, §5.7: a writer's position write may carry a sibling key naming
/// another commit (the only use of a writer's commit table), its `ts` below its stamp's; a write
/// stamp naming a table commit is foreign. Model and implementation agree on each.
#[test]
fn position_write_sibling_keys_spec_3_3() {
    let n2 = Value::Bytes(tid(2).as_bytes().to_vec());
    // node 2's commit at wall 1, base counter 7 (Ci 1)
    let table = || vec![l(vec![i(1), l(vec![l(vec![i(1), i(0), i(7)])])])];
    // a position write on node 2's element 7: `[i, Stamp, HEAD, key?]`
    let posw = |w: Vec<Value>| l(vec![i(9), l(vec![]), l(vec![]), l(vec![l(vec![l(vec![i(1), i(7)]), i(1), l(vec![]), l(vec![]), l(vec![l(w)]), l(vec![])])])]);
    let alike = |b: &[u8]| {
        let mut mcx = Ctx::writer(5 << 16, MSource::node(1), 3, 6);
        let m = crdt_model::wire::decode_delta(b, &mut mcx);
        let d = decode_delta(b, &wcx(), &mut Interner::new(), None);
        assert_eq!(m.is_ok(), d.is_ok(), "model {m:?}, implementation {d:?}");
        if let (Ok(m), Ok(d)) = (&m, &d) {
            assert_eq!(frag(m), d.fragment);
        }
        d
    };
    let ok = alike(&delta(vec![n2.clone()], table(), posw(vec![i(0), i(0), i(0), i(1)]))).unwrap();
    let crate::Fragment::Seq(s) = &ok.fragment else { panic!("text") };
    let e = s.elems().values().next().unwrap();
    assert_eq!(e.pos.first().and_then(|p| p.2.as_ref()), Some(&crate::stamp::Stamp::new(ts(1 << 16), Source::node(tid(2)), 7)));
    // the key equal to or above the stamp (own commit: counter 3 is the base), or below it at
    // the same ts (imports re-source both, which may reorder them)
    for k in [i(0), l(vec![i(0), i(4)]), l(vec![i(0), i(2)])] {
        assert!(alike(&delta(vec![n2.clone()], vec![], posw(vec![i(0), i(0), i(0), k]))).is_err());
    }
    // the write stamp naming the table's commit
    assert!(alike(&delta(vec![n2.clone()], table(), posw(vec![i(0), i(1), i(0)]))).is_err());
    // a table entry nothing names
    assert!(alike(&delta(vec![n2], table(), posw(vec![i(0), i(0), i(0)]))).is_err());
}
