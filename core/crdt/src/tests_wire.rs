//! Wire tests (spec/crdt.md §3.2, §3.3, §8): byte identity with core/test/crdt-model, round trips, and
//! every §3.3 rule 7 rejection.

use crate::codec::{decode_delta, decode_snapshot, encode_delta, encode_snapshot};
use crate::fragment::{Elem, Fragment, Meta, RegWrite, Register, Set};
use crate::stamp::{CounterRange, Dot, Interner, Source, Stamp};
use crate::testutil::{frag, history_with, mapply, sess, sess_value, sink_no_seq, source, ts};
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
    DeltaCtx { ts: ts(1 << 40), own: source(&MSource::session(250, 0)), range: CounterRange::EMPTY, kind: DeltaKind::Snapshot }
}

/// Every delta of a random history, node or commit form, encodes byte-identically with the model
/// and decodes back to itself under the writer's header; snapshots of the joined state likewise.
fn wire_matches(seed: u64, types: &[Ty], sources: Vec<MSource>) {
    let mut r = crate::testutil::rng(seed | 1);
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
        // a snapshot lists frontiers for the sources of its fragment only (§8)
        let traced = crate::sources_of(&frag(st), &snap_cx()).unwrap();
        let mfr: Vec<(MSource, u64)> = fr.frontiers().into_iter().filter(|(s, _)| traced.contains(&source(s))).collect();
        let msnap = crdt_model::wire::encode_snapshot(st, &mfr, [3; 16], &mut Ctx::new(1 << 40, MSource::session(250, 0), 1));
        let mut frontiers = Frontiers::default();
        for (s, c) in &mfr {
            assert!(frontiers.insert(&source(s), *c), "a session frontier");
        }
        let s = Snapshot { absorbed: Default::default(), nonce: [3; 16], fragment: frag(st), frontiers };
        let sbytes = encode_snapshot(&s, &snap_cx(), None).unwrap();
        assert_eq!(sbytes, msnap, "snapshot bytes equal the model's");
        let mut back = decode_snapshot(&sbytes, &snap_cx(), &mut Interner::new(), None).unwrap();
        crate::testutil::check_bound(&sbytes, &back.fragment);
        back.frontiers = back.frontiers.without_zeros();
        assert_eq!(back, s, "snapshot round trip");
        // what a snapshot carries of an expiring delta (§4.7: value-less writes and `W`, map
        // writes key-erased): the commits of the first source
        let gone = &commits[0].w.source;
        let mut mst = st.clone();
        mst.strip(&|d| d.source == *gone);
        let mut ours = frag(st);
        ours.strip(&|d| d.src == source(gone));
        assert_eq!(ours, frag(&mst), "strip equals the model");
        let msnap = crdt_model::wire::encode_snapshot(&mst, &[], [3; 16], &mut Ctx::new(1 << 40, MSource::session(250, 0), 1));
        let s = Snapshot { absorbed: Default::default(), nonce: [3; 16], fragment: ours, frontiers: Frontiers::default() };
        let sbytes = encode_snapshot(&s, &snap_cx(), None).unwrap();
        assert_eq!(sbytes, msnap, "a stripped snapshot's bytes equal the model's");
        let mut back = decode_snapshot(&sbytes, &snap_cx(), &mut Interner::new(), None).unwrap();
        back.frontiers = back.frontiers.without_zeros();
        assert_eq!(back, s, "stripped snapshot round trip");
    }
}

proptest! {
    /// §3.2, §3.3 rules 1–6: session form.
    #[test]
    fn wire_matches_model_spec_3(seed in any::<u64>()) {
        let sources = (1..=3).map(|n| MSource::session(n, 0)).collect();
        wire_matches(seed, &[sink_no_seq()], sources);
    }

    /// §2.1, §2.2, §8: two sessions of one node beside other nodes': 31-byte `Source`, order by
    /// tid then nonce, frontiers per session.
    #[test]
    fn wire_matches_model_sessions_spec_2_1(seed in any::<u64>()) {
        let sources = vec![MSource::session(1, 0xf0), MSource::session(2, 0), MSource::session(1, 0x10), MSource::session(3, 0x80)];
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
        let sources = (1..=4).map(|n| MSource::session(n, 0)).collect();
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
        let commits = history_with(&mut r, &[sink_no_seq()], vec![MSource::session(1, 0)], 2);
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
    DeltaCtx { ts: ts(5 << 16), own: sess(tid(1)), range: CounterRange { lo: 3, hi: 6 }, kind: DeltaKind::Writer }
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
    rejects(&delta(vec![Value::Bytes(vec![9; 31])], vec![], set_with(vec![elem(i(3), 1)])), &wcx(), ErrorClass::BadInput);
    // a source entry of neither 31 nor 32 bytes (a bare tid)
    let e = decode_delta(&delta(vec![Value::Bytes(vec![9; 15])], vec![], set_with(vec![elem(i(3), 1)])), &wcx(), &mut Interner::new(), None).unwrap_err();
    assert!(e.to_string().contains("source length"), "{e}");
    // the own source repeated in Sources
    let own = sess_value(tid(1));
    rejects(&delta(vec![own], vec![], set_with(vec![elem(i(3), 1)])), &wcx(), ErrorClass::BadInput);
    // a bad nonce
    let b = osis_base::encode(&l(vec![Value::Bytes(vec![0; 15]), l(vec![]), l(vec![]), set_with(vec![])]));
    rejects(&b, &wcx(), ErrorClass::BadInput);
}

#[test]
fn rejects_foreign_stamps_in_writer_delta_spec_3_3() {
    let src = sess_value(tid(9));
    let commits = vec![l(vec![i(1), l(vec![l(vec![i(1), i(0), i(1)])])])];
    let f = l(vec![i(0), l(vec![]), i(1), i(1)]);
    let e = decode_delta(&delta(vec![src], commits, f), &wcx(), &mut Interner::new(), None).unwrap_err();
    assert!(e.to_string().contains("foreign stamps"), "{e}");
}

#[test]
fn rejects_nested_register_reset_spec_3_3() {
    let s = l(vec![i(4), l(vec![]), l(vec![]), Value::Map([(i(1), l(vec![i(0), l(vec![i(0)]), i(0), i(1)]))].into_iter().collect())]);
    rejects(&delta(vec![], vec![], s), &wcx(), ErrorClass::BadInput);
}

/// §3.2, §3.3 rule 2, §5.6: a removal record carries its entry's key; records of one dot sort
/// by key, the key-less one first, each (dot, key) once. The records of an own earlier entry
/// (dot 1): a removal, key-less or keyed, or a keyed record writing struct field `k` (each
/// write in one record, §3.3 rule 7 Prune; one record of the dot carries content, its counter
/// claimed once).
#[test]
fn keyed_tombstones_spec_3_3() {
    let tomb = |k: Option<i64>| l([vec![i(1), l(vec![i(0)])], k.map(i).into_iter().collect(), vec![l(vec![])]].concat());
    let rec = |k: i64| l(vec![i(1), l(vec![]), i(k), l(vec![l(vec![i(4), l(vec![]), l(vec![]), Value::Map([(i(k), l(vec![i(0), l(vec![]), i(0), i(1)]))].into_iter().collect())])])]);
    let map = |es: Vec<Value>| delta(vec![], vec![], l(vec![i(7), l(vec![]), l(vec![]), l(es)]));
    decode_delta(&map(vec![tomb(Some(5))]), &wcx(), &mut Interner::new(), None).unwrap();
    let d = decode_delta(&map(vec![tomb(None), rec(5)]), &wcx(), &mut Interner::new(), None).unwrap();
    let crate::Fragment::Map(m) = &d.fragment else { panic!("map") };
    assert_eq!(m.entries().map(|(_, _, k, _)| k.cloned()).collect::<Vec<_>>(), vec![None, Some(i(5))]);
    rejects(&map(vec![rec(5), tomb(None)]), &wcx(), ErrorClass::BadInput);
    rejects(&map(vec![tomb(Some(7)), tomb(Some(5))]), &wcx(), ErrorClass::BadInput);
    rejects(&map(vec![tomb(Some(5)), tomb(Some(5))]), &wcx(), ErrorClass::BadInput);
}

#[test]
fn rejects_bad_slots_spec_3_3() {
    let reg = l(vec![i(0), l(vec![]), i(0), i(1)]);
    let set = set_with(vec![elem(i(3), 1)]);
    // any slots in a writer's delta
    rejects(&delta(vec![], vec![], l(vec![i(10), l(vec![reg.clone()]), l(vec![set.clone()])])), &wcx(), ErrorClass::BadInput);
    // in a snapshot (stamps foreign: the snapshotter is node 2, writes by node 1)
    let scx = DeltaCtx { ts: ts(9 << 16), own: sess(tid(2)), range: CounterRange::EMPTY, kind: DeltaKind::Snapshot };
    let srcs = vec![sess_value(tid(1))];
    let commits = vec![l(vec![i(1), l(vec![l(vec![i(5), i(0), i(3)])])])];
    let reg = l(vec![i(0), l(vec![]), i(1), i(1)]);
    let set = l(vec![i(6), l(vec![]), l(vec![]), l(vec![l(vec![l(vec![i(1), i(3)]), l(vec![]), l(vec![l(vec![i(0), l(vec![]), i(1), i(1)])])])])]);
    let ok = |slots: Value, reg: Value| delta(srcs.clone(), commits.clone(), l(vec![i(10), reg, slots]));
    // one slot only
    rejects(&ok(l(vec![]), l(vec![reg.clone()])), &scx, ErrorClass::BadInput);
    // a register among the non-register slots
    rejects(&ok(l(vec![set.clone(), reg.clone()]), l(vec![])), &scx, ErrorClass::BadInput);
    // a non-register first slot
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

// §8: one frontier entry per session source of the fragment, in table order, 0 where
// the writer claims nothing; a source of the fragment without an entry, an entry for a source
// not in the fragment, or one for a commit source is bad input.
#[test]
fn snapshot_frontiers_spec_8() {
    let scx = DeltaCtx { ts: ts(9 << 16), own: Source::commit(osis_base::CommitId([0; 32])), range: CounterRange::EMPTY, kind: DeltaKind::Snapshot };
    let session = crate::Session { node: tid(5), nonce: [1; crate::SESSION_NONCE_LEN] };
    // a set with elements of two sessions of one node and a commit source
    let mut elems = BTreeMap::new();
    for (k, src) in [(1u8, sess(tid(5))), (2, Source::session(session)), (3, Source::commit(osis_base::CommitId([7; 32])))] {
        let dot = Dot::new(src, 4);
        elems.insert(dot.clone(), Elem { reset: None, frag: Some(Box::new(Fragment::Register(Register { reset: None, write: Some(RegWrite { stamp: Stamp { ts: ts((u64::from(k) + 1) << 16), dot }, value: Some(Value::Int(i64::from(k))) }) }))) });
    }
    let fragment = Fragment::Set(Set { meta: Meta::default(), elems });
    let first = crate::Session { node: tid(5), nonce: [0; crate::SESSION_NONCE_LEN] };
    let frontiers = Frontiers { sessions: BTreeMap::from([(first, 7)]) };
    let s = Snapshot { absorbed: Default::default(), nonce: [0; 16], fragment, frontiers };
    let b = encode_snapshot(&s, &scx, None).unwrap();
    let back = decode_snapshot(&b, &scx, &mut Interner::new(), None).unwrap();
    assert!(back.frontiers.lists(&Source::session(session)) && back.frontiers.of(&Source::session(session)) == 0, "the session is listed with 0");
    assert_eq!(Snapshot { frontiers: back.frontiers.clone().without_zeros(), ..back.clone() }, s);
    let top = osis_base::decode(&b, &osis_base::Limits::DEFAULT).unwrap();
    let Value::List(a) = top else { panic!() };
    assert_eq!(a[1], l(vec![Value::Bytes(first.to_bytes().to_vec()), Value::Bytes(session.to_bytes().to_vec()), Value::Bytes(vec![7; 32])]));
    assert_eq!(a[4], l(vec![l(vec![i(1), i(7)]), l(vec![i(2), i(0)])]));
    let bad = |fr: Value| {
        let mut a = a.clone();
        a[4] = fr;
        decode_snapshot(&osis_base::encode(&Value::List(a)), &scx, &mut Interner::new(), None).unwrap_err().class()
    };
    assert_eq!(bad(l(vec![l(vec![i(1), i(7)])])), ErrorClass::BadInput, "the session's entry missing");
    assert_eq!(bad(l(vec![l(vec![i(1), i(7)]), l(vec![i(2), i(0)]), l(vec![i(3), i(1)])])), ErrorClass::BadInput, "a commit source");
    assert_eq!(bad(l(vec![l(vec![i(2), i(0)]), l(vec![i(1), i(7)])])), ErrorClass::BadInput, "out of table order");
    // a frontier for a source outside the fragment is refused at the encoder
    let extra = Snapshot { frontiers: Frontiers { sessions: BTreeMap::from([(first, 7), (crate::Session { node: tid(2), ..first }, 3)]) }, ..s.clone() };
    assert!(encode_snapshot(&extra, &scx, None).is_err());
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
    let mw = crdt_model::ops::Writer::new(MSource::session(1, 0), 3 << 16, 1);
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
    let link = Value::link(osis_base::Link { hash: [1; 32], blob: osis_base::BlobId([2; 32]), suite: 1, key: [0; 32] });
    for ty in [pair, Ty::List(Box::new(Ty::Register)), Ty::Set(Box::new(Ty::Register)), Ty::Counter] {
        assert!(create(&mut writer(&mw), &TyView(ty), &link).is_err());
    }
}

/// §3.2 `PosW`, §3.3 rule 7, §5.7: a writer's position write may carry a sibling key naming
/// another commit (the only use of a writer's commit table), its `ts` below its stamp's; a write
/// stamp naming a table commit is foreign. Model and implementation agree on each.
#[test]
fn position_write_sibling_keys_spec_3_3() {
    let n2 = sess_value(tid(2));
    // node 2's commit at wall 1, base counter 7 (Ci 1)
    let table = || vec![l(vec![i(1), l(vec![l(vec![i(1), i(0), i(7)])])])];
    // a position write on node 2's element 7: `[i, Stamp, HEAD, key?]`
    let posw = |w: Vec<Value>| l(vec![i(9), l(vec![]), l(vec![]), l(vec![l(vec![l(vec![i(1), i(7)]), i(1), l(vec![]), l(vec![]), l(vec![l(w)]), l(vec![])])])]);
    let alike = |b: &[u8]| {
        let mut mcx = Ctx::writer(5 << 16, MSource::session(1, 0), 3, 6);
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
    assert_eq!(e.pos.first().and_then(|p| p.2.as_ref()), Some(&crate::stamp::Stamp::new(ts(1 << 16), sess(tid(2)), 7)));
    // the key equal to or above the stamp (own commit: counter 3 is the base), or below it at
    // the same ts (`ts` alone is compared)
    for k in [i(0), l(vec![i(0), i(4)]), l(vec![i(0), i(2)])] {
        assert!(alike(&delta(vec![n2.clone()], vec![], posw(vec![i(0), i(0), i(0), k]))).is_err());
    }
    // the write stamp naming the table's commit
    assert!(alike(&delta(vec![n2.clone()], table(), posw(vec![i(0), i(1), i(0)]))).is_err());
    // a table entry nothing names
    assert!(alike(&delta(vec![n2], table(), posw(vec![i(0), i(0), i(0)]))).is_err());
}

// ---- spec audit rules (§2.3, §3.3 rules 2, 5, 7, §5.5)

/// Snapshot by node 2 at ts 9·2^16 of node 1's commit at ts 5·2^16 (base 3), plus `more`
/// sources and commit entries.
fn snap(more_src: Vec<Value>, more_commits: Vec<Value>, f: Value) -> (Vec<u8>, DeltaCtx) {
    let scx = DeltaCtx { ts: ts(9 << 16), own: sess(tid(2)), range: CounterRange::EMPTY, kind: DeltaKind::Snapshot };
    let srcs = [vec![sess_value(tid(1))], more_src].concat();
    let commits = [vec![l(vec![i(1), l(vec![l(vec![i(5), i(0), i(3)])])])], more_commits].concat();
    // one frontier entry per session source of the table (§8), claiming nothing
    let fr: Vec<Value> = srcs.iter().enumerate().filter(|(_, s)| matches!(s, Value::Bytes(b) if b.len() == 15 || b.len() == 31)).map(|(k, _)| l(vec![i(k as i64 + 1), i(0)])).collect();
    let b = osis_base::encode(&l(vec![Value::Bytes(vec![0; 16]), l(srcs), l(commits), f, l(fr), l(vec![])]));
    (b, scx)
}

fn snap_ok(b: &[u8], cx: &DeltaCtx) -> bool {
    decode_snapshot(b, cx, &mut Interner::new(), None).is_ok()
}

/// §2.3, §3.3 rule 7: in a writer's delta every commit-level write (register value, reset, `W`,
/// element reset) has the delta stamp, counter `lo`; only creations and position writes take the
/// other counters of `[lo, hi)`.
#[test]
fn rejects_commit_level_off_delta_stamp_spec_2_3() {
    let at4 = || l(vec![i(0), i(4)]);
    rejects(&delta(vec![], vec![], l(vec![i(0), l(vec![]), at4(), i(1)])), &wcx(), ErrorClass::BadInput);
    rejects(&delta(vec![], vec![], l(vec![i(6), l(vec![at4()]), l(vec![]), l(vec![])])), &wcx(), ErrorClass::BadInput);
    rejects(&delta(vec![], vec![], l(vec![i(6), l(vec![]), l(vec![at4()]), l(vec![])])), &wcx(), ErrorClass::BadInput);
    rejects(&delta(vec![], vec![], set_with(vec![l(vec![i(4), l(vec![at4()]), l(vec![])])])), &wcx(), ErrorClass::BadInput);
    // element 4 created, its value at the delta stamp
    assert!(decode_delta(&delta(vec![], vec![], set_with(vec![elem(i(4), 1)])), &wcx(), &mut Interner::new(), None).is_ok());
}

/// §3.3 rules 5, 7, §4.2, §5.1: a delta carries no write its own resets prune: a register's reset
/// below its write, a child below its struct's reset, a set element below the set's reset.
#[test]
fn rejects_writes_own_resets_prune_spec_3_3() {
    let reg = |r: Value, s: Value| l(vec![i(0), l(vec![r]), s, i(7)]);
    let (b, cx) = snap(vec![], vec![], reg(i(1), i(1)));
    assert!(snap_ok(&b, &cx), "a replace: reset and write share a stamp");
    let (b, cx) = snap(vec![], vec![], reg(i(1), l(vec![i(1), i(4)])));
    assert!(!snap_ok(&b, &cx), "reset below the register's write");
    let child = l(vec![i(0), l(vec![]), i(1), i(7)]);
    let st = |r: Value| l(vec![i(4), l(vec![r]), l(vec![]), Value::Map([(i(1), child.clone())].into_iter().collect())]);
    let (b, cx) = snap(vec![], vec![], st(i(1)));
    assert!(snap_ok(&b, &cx));
    let (b, cx) = snap(vec![], vec![], st(l(vec![i(1), i(4)])));
    assert!(!snap_ok(&b, &cx), "child below the struct's reset");
    let set = l(vec![i(6), l(vec![l(vec![i(1), i(4)])]), l(vec![]), l(vec![l(vec![l(vec![i(1), i(3)]), l(vec![]), l(vec![l(vec![i(0), l(vec![]), i(1), i(1)])])])])]);
    let (b, cx) = snap(vec![], vec![], set);
    assert!(!snap_ok(&b, &cx), "element below the set's reset");
}

/// §3.3 rule 7, §5.5: a set or bag element's value register is written only by its creation, so
/// by its dot's source.
#[test]
fn rejects_set_value_of_another_source_spec_5_5() {
    let set = |ci: i64| l(vec![i(6), l(vec![]), l(vec![]), l(vec![l(vec![l(vec![i(1), i(3)]), l(vec![]), l(vec![l(vec![i(0), l(vec![]), i(ci), i(1)])])])])]);
    let (b, cx) = snap(vec![], vec![], set(1));
    assert!(snap_ok(&b, &cx));
    // node 1's element 3 holding a value stamped by node 3 (the encoder writes it canonically)
    use crate::fragment::{Elem, Fragment, Meta, RegWrite, Register, Set};
    use crate::stamp::{Dot, Stamp};
    let reg = Fragment::Register(Register { reset: None, write: Some(RegWrite { stamp: Stamp::new(ts(5 << 16), sess(tid(3)), 1), value: Some(i(1)) }) });
    let f = Fragment::Set(Set { meta: Meta::default(), elems: BTreeMap::from([(Dot::new(sess(tid(1)), 3), Elem { reset: None, frag: Some(Box::new(reg)) })]) });
    let b = encode_snapshot(&Snapshot { absorbed: Default::default(), nonce: [0; 16], fragment: f, frontiers: Frontiers::default() }, &cx, None).unwrap();
    assert!(!snap_ok(&b, &cx), "node 3 wrote node 1's element value");
}

/// §3.3 rule 7, spec/data-model.md §5: a fragment reads at most 64 deep from the aspect root: a
/// struct field adds one level, an enum payload two.
#[test]
fn rejects_fragments_reading_too_deep_spec_3_3() {
    let nested = |n: usize| (0..n).fold(i(1), |v, _| l(vec![v]));
    let reg = |n: usize| l(vec![i(0), l(vec![]), i(0), nested(n)]);
    let ok = |f: Value| decode_delta(&delta(vec![], vec![], f), &wcx(), &mut Interner::new(), None).is_ok();
    assert!(ok(reg(64)));
    assert!(!ok(reg(65)));
    let st = |n: usize| l(vec![i(4), l(vec![]), l(vec![]), Value::Map([(i(1), reg(n))].into_iter().collect())]);
    assert!(ok(st(63)));
    assert!(!ok(st(64)), "64 below a struct reads 65 deep");
    let en = |n: usize| l(vec![i(5), l(vec![]), l(vec![]), l(vec![]), Value::Map([(i(1), reg(n))].into_iter().collect())]);
    assert!(ok(en(62)));
    assert!(!ok(en(63)), "63 below an enum payload reads 65 deep");
}

/// spec/data-model.md §5, §3.3 rule 7: a writer refuses what a reader would reject: a case step
/// counts two levels, a list item one below its list; an enum case above 2^63 - 1.
#[test]
fn writer_refuses_out_of_profile_values_spec_3_3() {
    use crate::batch::Batch;
    use crate::ops::{Op, PathOp, PathSeg, Writer};
    use crate::view::AnyView;
    let nested = |n: usize| (0..n).fold(i(1), |v, _| l(vec![v]));
    let apply = |path: Vec<PathSeg>, op: Op| {
        let state = crate::Fragment::default();
        let mut b = Batch::new(&state, Writer::new(ts(5 << 16), sess(tid(1)), 3));
        b.apply(&PathOp { path, op }, &AnyView).err().map(|e| e.to_string())
    };
    let deep = |e: Option<String>| e.is_some_and(|e| e.contains("MAX_VALUE_DEPTH"));
    assert!(deep(apply(vec![PathSeg::Case(1)], Op::Set(nested(63)))));
    assert!(!deep(apply(vec![PathSeg::Case(1)], Op::Set(nested(62)))));
    assert!(deep(apply(vec![], Op::Insert { at: 0, items: vec![nested(64)] })));
    assert!(!deep(apply(vec![], Op::Insert { at: 0, items: vec![nested(63)] })));
    assert!(deep(apply(vec![], Op::Set(Value::Enum(1 << 63, None)))));
    assert!(apply(vec![], Op::Set(Value::Enum(i64::MAX as u64, None))).is_none());
}

/// spec/data-model.md §5, §3.3 rule 7: writer and reader draw the depth line at the same
/// place: under `n` struct levels each op shape is written iff its read value nests at most 64
/// deep, and what it writes decodes (a text's chars read at the text's depth, a list's items one
/// below).
#[test]
fn writer_and_reader_depth_agree_spec_3_3() {
    use crate::batch::Batch;
    use crate::ops::{Op, PathOp, PathSeg, Writer};
    use crate::testutil::TyView;
    let s = |x: &str| Value::Str(x.into());
    let reg = || Box::new(Ty::Register);
    // (leaf type, path below it, op, the value the leaf then reads as)
    let shapes: Vec<(Ty, Vec<PathSeg>, Op, Value)> = vec![
        (Ty::Register, vec![], Op::Set(l(vec![i(1)])), l(vec![i(1)])),
        (Ty::Text, vec![], Op::Insert { at: 0, items: vec![s("ab")] }, s("ab")),
        (Ty::List(reg()), vec![], Op::Insert { at: 0, items: vec![s("ab")] }, l(vec![s("ab")])),
        (Ty::List(Box::new(Ty::Text)), vec![], Op::Insert { at: 0, items: vec![s("ab")] }, l(vec![s("ab")])),
        (Ty::Set(reg()), vec![], Op::Add(i(1)), Value::Set([i(1)].into_iter().collect())),
        (Ty::Map(reg(), reg()), vec![PathSeg::Key(s("k"))], Op::Set(i(1)), Value::Map([(s("k"), i(1))].into_iter().collect())),
        (Ty::Enum([(2, Some(Ty::Register))].into_iter().collect()), vec![], Op::Set(Value::Enum(2, Some(Box::new(i(1))))), Value::Enum(2, Some(Box::new(i(1))))),
    ];
    for (leaf, below, op, read) in shapes {
        for n in 58..=66usize {
            let ty = (0..n).fold(leaf.clone(), |t, _| Ty::Struct([(1, t)].into_iter().collect()));
            let want = (0..n).fold(read.clone(), |v, _| Value::Map([(i(1), v)].into_iter().collect())).depth() <= 64;
            let path: Vec<PathSeg> = std::iter::repeat_n(PathSeg::Field(1), n).chain(below.iter().cloned()).collect();
            let state = crate::Fragment::default();
            let mut b = Batch::new(&state, Writer::new(ts(5 << 16), sess(tid(1)), 3));
            let r = b.apply(&PathOp { path, op: op.clone() }, &TyView(ty));
            let wrote = match r {
                Ok(()) => true,
                Err(e) if e.to_string().contains("MAX_VALUE_DEPTH") => false,
                Err(e) => panic!("{leaf:?} under {n}: {e}"),
            };
            assert_eq!(wrote, want, "{leaf:?} under {n}: writer");
            if let Some((f, range)) = b.finish() {
                let cx = DeltaCtx { range, ..wcx() };
                let bytes = encode_delta(&Delta { nonce: [0; 16], fragment: f }, &cx, None).unwrap();
                let read = decode_delta(&bytes, &cx, &mut Interner::new(), None);
                assert!(read.is_ok(), "{leaf:?} under {n}: reader {read:?}");
            }
        }
    }
}

/// §3.3 rule 2, §4.1 copy order: values holding links compare by canonical bytes, not by
/// `Value` order (links by content hash): of two copies of one write the bytewise greater wins,
/// and two map keys of one dot differing only in link bytes are two records in byte order.
#[test]
fn links_compare_by_bytes_spec_3_3() {
    use crate::fragment::{Eid, Entry, Fragment, Key, Map, Meta, RegWrite, Register};
    use crate::stamp::{Dot, Stamp};
    use std::cmp::Ordering;
    let link = |blob: u8| Value::link(osis_base::Link { hash: [1; 32], blob: osis_base::BlobId([blob; 32]), suite: 1, key: [0; 32] });
    // `Value` order puts [l3, 3] first (equal hashes, then 3 < 5); bytes put [l2, 5] first
    let (a, b) = (l(vec![link(2), i(5)]), l(vec![link(3), i(3)]));
    assert_eq!(a.cmp(&b), Ordering::Greater);
    assert!(osis_base::encode(&a) < osis_base::encode(&b));
    assert!(Key(a.clone()) < Key(b.clone()));
    let src = sess(tid(1));
    let s = Stamp::new(ts(5 << 16), src.clone(), 3);
    let reg = |v: &Value| Fragment::Register(Register { reset: None, write: Some(RegWrite { stamp: s.clone(), value: Some(v.clone()) }) });
    for (x, y) in [(&a, &b), (&b, &a)] {
        let mut f = reg(x);
        f.join(reg(y));
        assert_eq!(f.read().map(|v| osis_base::encode(&v)), Some(osis_base::encode(&b)), "the bytewise greater copy");
    }
    let dot = Dot::new(src, 3);
    // each write in one record (§3.3 rule 7 Prune): the creation in one, the value in the other
    let created = Entry { reset: None, frag: None, created: Some(s.clone()) };
    let valued = Entry { reset: None, frag: Some(Box::new(reg(&i(1)))), created: None };
    let entries: BTreeMap<Eid, Entry> = [(Eid::new(dot.clone(), Some(b.clone())), valued), (Eid::new(dot, Some(a.clone())), created)].into_iter().collect();
    assert_eq!(entries.keys().map(|e| e.key().cloned()).collect::<Vec<_>>(), vec![Some(a), Some(b)]);
    let scx = DeltaCtx { ts: ts(9 << 16), own: sess(tid(2)), range: CounterRange::EMPTY, kind: DeltaKind::Snapshot };
    let snap = Snapshot { absorbed: Default::default(), nonce: [0; 16], fragment: Fragment::Map(Map::new(Meta::default(), entries)), frontiers: Frontiers::default() };
    let bytes = encode_snapshot(&snap, &scx, None).unwrap();
    let mut back = decode_snapshot(&bytes, &scx, &mut Interner::new(), None).unwrap();
    back.frontiers = back.frontiers.without_zeros();
    assert_eq!(back, snap);
}

/// §2.4, §8: a snapshot commit carries only foreign writes and consumes no counters: a write of
/// this commit (`Ci` 0) is bad input there, while the same fragment is a writer's delta.
#[test]
fn snapshot_carries_no_own_writes_spec_2_4() {
    let f = l(vec![i(0), l(vec![]), i(0), i(1)]);
    assert!(decode_delta(&delta(vec![], vec![], f.clone()), &wcx(), &mut Interner::new(), None).is_ok());
    let scx = DeltaCtx { ts: ts(5 << 16), own: sess(tid(1)), range: CounterRange::EMPTY, kind: DeltaKind::Snapshot };
    let b = osis_base::encode(&l(vec![Value::Bytes(vec![0; 16]), l(vec![]), l(vec![]), f, l(vec![]), l(vec![])]));
    assert!(decode_snapshot(&b, &scx, &mut Interner::new(), None).is_err());
}
