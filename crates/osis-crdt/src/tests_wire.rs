//! Wire tests (spec/crdt.md §3.2, §3.3, §8): byte identity with models/crdt, round trips, and
//! every §3.3 rule 7 rejection.

use crate::codec::{decode_delta, decode_snapshot, encode_delta, encode_snapshot};
use crate::error::Error;
use crate::stamp::{CounterRange, Interner, Source};
use crate::testutil::{frag, history_with, mapply, sink_no_seq, source, ts};
use crate::wire::{Delta, DeltaCtx, DeltaKind, Frontiers, Snapshot};
use crdt_model::r#gen::Rng;
use crdt_model::ops::Ty;
use crdt_model::stamp::Source as MSource;
use crdt_model::wire::{Ctx, encode_delta as m_encode_delta, encode_snapshot as m_encode_snapshot};
use osis_core::{Classified, ErrorClass, Tid, Value};
use proptest::prelude::*;
use std::collections::BTreeMap;

fn writer_cx(w: &crdt_model::ops::Writer) -> DeltaCtx {
    DeltaCtx { ts: ts(w.ts), own: source(&w.source), range: CounterRange { lo: w.lo, hi: w.hi() }, kind: DeltaKind::Writer }
}

fn snap_cx() -> DeltaCtx {
    DeltaCtx { ts: ts(1 << 40), own: source(&MSource::node(250)), range: CounterRange::EMPTY, kind: DeltaKind::Snapshot }
}

/// Every delta of a random history, node or commit form, encodes byte-identically with the model
/// and decodes back to itself under the writer's header; snapshots of the joined state likewise.
fn wire_matches(seed: u64, types: &[Ty], sources: Vec<MSource>) {
    let mut r = Rng(seed | 1);
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
        assert_eq!(back, d, "delta round trip");
        mapply(&mut state, c.delta.clone());
        let st = state.as_ref().unwrap();
        let mut fr = crdt_model::received::Received::default();
        fr.add(&c.w.source, 1, c.w.hi());
        let mfr: Vec<(MSource, u64)> = fr.frontiers().into_iter().filter(|(s, _)| matches!(s, MSource::Node(_))).collect();
        let msnap = m_encode_snapshot(st, &mfr, [3; 16], &mut Ctx::new(1 << 40, MSource::node(250), 1));
        let frontiers = Frontiers(mfr.iter().map(|(s, c)| (source(s).as_node().unwrap(), *c)).collect());
        let s = Snapshot { nonce: [3; 16], fragment: frag(st), frontiers };
        let sbytes = encode_snapshot(&s, &snap_cx(), None).unwrap();
        assert_eq!(sbytes, msnap, "snapshot bytes equal the model's");
        assert_eq!(decode_snapshot(&sbytes, &snap_cx(), &mut Interner::new(), None).unwrap(), s, "snapshot round trip");
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
        let mut r = Rng(seed | 1);
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
fn wcx() -> DeltaCtx {
    DeltaCtx { ts: ts(5 << 16), own: Source::node(tid(1)), range: CounterRange { lo: 3, hi: 6 }, kind: DeltaKind::Writer }
}

fn i(n: i64) -> Value {
    Value::Int(n)
}
fn l(v: Vec<Value>) -> Value {
    Value::List(v)
}
fn delta(sources: Vec<Value>, commits: Vec<Value>, f: Value) -> Vec<u8> {
    osis_core::encode(&l(vec![Value::Bytes(vec![0; 16]), l(sources), l(commits), f]))
}
fn set_with(elems: Vec<Value>) -> Value {
    l(vec![i(6), l(vec![]), l(vec![]), l(elems)])
}
fn elem(dot: Value, v: i64) -> Value {
    l(vec![dot, l(vec![]), l(vec![l(vec![i(0), l(vec![]), i(0), i(v)])])])
}

fn rejects(bytes: &[u8], cx: &DeltaCtx, class: ErrorClass) {
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
    let b = osis_core::encode(&l(vec![Value::Bytes(vec![0; 15]), l(vec![]), l(vec![]), set_with(vec![])]));
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

#[test]
fn rejects_keyed_tombstone_spec_3_3() {
    let entry = l(vec![i(3), l(vec![i(0)]), i(7), l(vec![])]);
    rejects(&delta(vec![], vec![], l(vec![i(7), l(vec![]), l(vec![]), l(vec![entry])])), &wcx(), ErrorClass::BadInput);
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

#[test]
fn parks_unknown_encoding_spec_3_1() {
    rejects(&delta(vec![], vec![], l(vec![i(42), l(vec![])])), &wcx(), ErrorClass::Parked);
}

#[test]
fn sequences_unsupported_until_crdt_seq() {
    let r = decode_delta(&delta(vec![], vec![], l(vec![i(9), l(vec![]), l(vec![]), l(vec![])])), &wcx(), &mut Interner::new(), None);
    assert!(matches!(r, Err(Error::Unsupported(_))));
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
    let s = Snapshot { nonce: [0; 16], fragment: crate::Fragment::default(), frontiers: Frontiers(BTreeMap::from([(tid(5), 7), (tid(2), 3)])) };
    let b = encode_snapshot(&s, &scx, None).unwrap();
    // own (Src 0) first; the frontier-only source last in Sources
    let back = decode_snapshot(&b, &scx, &mut Interner::new(), None).unwrap();
    assert_eq!(back, s);
    let top = osis_core::decode(&b, &osis_core::Limits::DEFAULT).unwrap();
    let Value::List(a) = top else { panic!() };
    assert_eq!(a[4], l(vec![l(vec![i(0), i(3)]), l(vec![i(1), i(7)])]));
    // a commit-form writer (own a commit) cannot be named by a frontier; a zero counter is refused
    let bad = Snapshot { frontiers: Frontiers(BTreeMap::from([(tid(5), 0)])), ..s };
    assert!(encode_snapshot(&bad, &scx, None).is_err());
}
