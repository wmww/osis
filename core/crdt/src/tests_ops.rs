//! Ops, diff, net effect and undo (spec/crdt.md §2.3, §4.5, §4.6, §5, §9).

use crate::batch::Batch;
use crate::fragment::Fragment;
use crate::ops::{Op, PathOp, PathSeg, Writer, create, diff, diff_values};
use crate::stamp::{CounterRange, Dot, Source};
use crate::testutil::{TyView, frag, history, mapply, ostate, sink_no_seq, source, ts, value, writer};
use crate::undo::{Undone, undo};
use crate::view::AnyView;
use crdt_model::r#gen::{Rng, random_op, random_value};
use crdt_model::ops::{Ty, Writer as MWriter};
use osis_base::{Tid, Value};
use proptest::prelude::*;

fn read(f: &Fragment) -> Option<Value> {
    f.read()
}

proptest! {
    /// §9: the structural diff equals the model's write for write (same dots, same stamps) and
    /// reaches the value; creation likewise.
    #[test]
    fn diff_matches_model_spec_9(seed in any::<u64>()) {
        let ty = sink_no_seq();
        let mut r = crate::testutil::rng(seed | 1);
        let commits = history(&mut r, std::slice::from_ref(&ty), 2, 3);
        let mut mstate = None;
        for c in &commits {
            mapply(&mut mstate, c.delta.clone());
        }
        let state = ostate(&mstate);
        for k in 0..4u64 {
            let mv = random_value(&mut r, &ty, 0);
            let v = value(&mv);
            let mut mw = MWriter::new(crdt_model::stamp::Source::node(9), ((100 + k) << 16) + 9, 1);
            let mut w = writer(&mw);
            let md = crdt_model::diff::diff(&mut mw, mstate.as_ref(), &ty, &mv);
            let d = diff(&mut w, Some(&state), &TyView(ty.clone()), &v).unwrap();
            prop_assert_eq!(d.clone(), md.as_ref().map(frag));
            prop_assert_eq!(w.range(), CounterRange { lo: mw.lo, hi: mw.hi() });
            let mut s = state.clone();
            if let Some(d) = d {
                s.join(d);
            }
            prop_assert_eq!(read(&s), Some(v.clone()));
            let mut mw = MWriter::new(crdt_model::stamp::Source::node(9), 1 << 16, 1);
            let mut w = writer(&mw);
            prop_assert_eq!(create(&mut w, &TyView(ty.clone()), &v).unwrap(), frag(&crdt_model::ops::create(&mut mw, &ty, &mv)));
        }
    }

    /// §4.5: a batch of path ops in one commit reads like the same ops committed one by one.
    #[test]
    fn batch_is_net_effect_spec_4_5(seed in any::<u64>()) {
        let ty = sink_no_seq();
        let view = TyView(ty.clone());
        let mut r = crate::testutil::rng(seed | 1);
        let commits = history(&mut r, std::slice::from_ref(&ty), 1, 3);
        let mut mstate = None;
        for c in &commits {
            mapply(&mut mstate, c.delta.clone());
        }
        let base = ostate(&mstate);
        let ops = random_path_ops(&mut r, &ty, 6);
        let node = Source::node(Tid::from_bytes([7; 15]));
        // one by one
        let mut seq_state = base.clone();
        let mut lo = 1;
        for (k, op) in ops.iter().enumerate() {
            let mut b = Batch::new(&seq_state, Writer::new(ts((50 + k as u64) << 16), node.clone(), lo));
            if b.apply(op, &view).is_err() {
                continue;
            }
            if let Some((d, range)) = b.finish() {
                lo = range.hi;
                seq_state.join(d);
            }
        }
        // one batch
        let mut b = Batch::new(&base, Writer::new(ts(90 << 16), node, 1));
        for op in &ops {
            let _ = b.apply(op, &view);
        }
        let mut batch_state = base.clone();
        if let Some((d, _)) = b.finish() {
            batch_state.join(d);
        }
        prop_assert_eq!(read(&batch_state), read(&seq_state));
    }

    /// §4.6: undoing a single writer's last commit restores the previous read.
    #[test]
    fn undo_restores_spec_4_6(seed in any::<u64>()) {
        let ty = sink_no_seq();
        let mut r = crate::testutil::rng(seed | 1);
        let commits = history(&mut r, std::slice::from_ref(&ty), 1, 3);
        let mut mstate = None;
        for c in &commits {
            mapply(&mut mstate, c.delta.clone());
        }
        let Some(ms) = mstate.clone() else { return Ok(()) };
        let mut mw = MWriter::new(crdt_model::stamp::Source::node(1), 80 << 16, 40);
        mw.next_commit(81 << 16);
        let Some(md) = random_op(&mut r, &mut mw, &ty, Some(&ms)) else { return Ok(()) };
        let s0 = frag(&ms);
        let d = frag(&md);
        // exact: a spot absent before is absent again (§4.6 "Absent before")
        let cmp = |s: &Fragment| read(s);
        let mut s1 = s0.clone();
        s1.join(d.clone());
        let src = source(&mw.source);
        let u = Undone { delta: &d, source: &src, range: CounterRange { lo: mw.lo, hi: mw.hi() }, restored: &|_| false };
        let mut w = Writer::new(ts(82 << 16), Source::node(Tid::from_bytes([1; 15])), mw.hi());
        let full = undo(&mut w, &u, &s1, &s0, &TyView(ty.clone())).unwrap();
        // the node keeps only the footprint of the delta as its undo buffer
        let mut w2 = Writer::new(ts(82 << 16), Source::node(Tid::from_bytes([1; 15])), mw.hi());
        prop_assert_eq!(undo(&mut w2, &u, &s1, &s0.footprint(&d), &TyView(ty.clone())).unwrap(), full.clone());
        let Some(ud) = full else {
            prop_assert_eq!(cmp(&s1), cmp(&s0));
            return Ok(());
        };
        let mut s2 = s1.clone();
        s2.join(ud);
        prop_assert_eq!(cmp(&s2), cmp(&s0));
    }

    /// notes/api.md `edit`: the value diff applied to the base reaches the new value, and a
    /// concurrent change to a field the edit did not touch survives.
    #[test]
    fn diff_values_spec_9(seed in any::<u64>()) {
        let ty = sink_no_seq();
        let view = TyView(ty.clone());
        let mut r = crate::testutil::rng(seed | 1);
        let base = value(&random_value(&mut r, &ty, 0));
        let new = value(&random_value(&mut r, &ty, 0));
        let node = Source::node(Tid::from_bytes([3; 15]));
        let mut w = Writer::new(ts(1 << 16), node.clone(), 1);
        let mut state = create(&mut w, &view, &base).unwrap();
        let ops = diff_values(Some(&base), &new, &view).unwrap();
        let mut b = Batch::new(&state, Writer::new(ts(2 << 16), node, w.range().hi));
        for op in &ops {
            b.apply(op, &view).unwrap();
        }
        if let Some((d, _)) = b.finish() {
            state.join(d);
        }
        prop_assert_eq!(read(&state), Some(new));
    }
}

/// Random path ops over the sink type: field sets, set add/remove, map put/remove, inc.
fn random_path_ops(r: &mut Rng, ty: &Ty, n: usize) -> Vec<PathOp> {
    let Ty::Struct(fields) = ty else { return vec![] };
    let mut out = Vec::new();
    for _ in 0..n {
        let ids: Vec<&u64> = fields.keys().collect();
        let id = *ids[r.below(ids.len())];
        let ft = &fields[&id];
        let path = vec![PathSeg::Field(id)];
        let op = match (ft, r.below(3)) {
            (Ty::Set(et), 0) => Op::Add(value(&random_value(r, et, 1))),
            (Ty::Set(et), 1) => Op::Remove(value(&random_value(r, et, 1))),
            (Ty::Map(kt, _), 0) => Op::Remove(value(&random_value(r, kt, 1))),
            (Ty::Map(kt, vt), 1) => {
                let k = value(&random_value(r, kt, 1));
                out.push(PathOp { path: vec![PathSeg::Field(id), PathSeg::Key(k)], op: Op::Set(value(&random_value(r, vt, 1))) });
                continue;
            }
            (Ty::Counter | Ty::Max | Ty::Min, 0) => Op::Inc(Value::Int(r.below(5) as i64 - 2)),
            (_, 2) => Op::Replace(value(&random_value(r, ft, 1))),
            _ => Op::Set(value(&random_value(r, ft, 1))),
        };
        out.push(PathOp { path, op });
    }
    out
}

/// §4.5: an element created and removed in one commit is omitted from the delta.
#[test]
fn created_and_removed_is_omitted_spec_4_5() {
    let state = Fragment::default();
    let node = Source::node(Tid::from_bytes([2; 15]));
    let view = AnyView;
    let mut b = Batch::new(&state, Writer::new(ts(1 << 16), node, 1));
    b.apply(&PathOp { path: vec![], op: Op::Set(Value::Set([Value::Int(1)].into_iter().collect())) }, &view).unwrap();
    b.apply(&PathOp { path: vec![], op: Op::Add(Value::Int(2)) }, &view).unwrap();
    b.apply(&PathOp { path: vec![], op: Op::Remove(Value::Int(2)) }, &view).unwrap();
    let (d, range) = b.finish().unwrap();
    let Fragment::Set(s) = &d else { panic!("set") };
    assert_eq!(s.elems.len(), 1);
    // both creations consumed counters (§2.3)
    assert_eq!(range, CounterRange { lo: 1, hi: 3 });
    let mut st = Fragment::default();
    st.join(d);
    assert_eq!(st.read(), Some(Value::Set([Value::Int(1)].into_iter().collect())));
}

/// §4.5: a register written twice in one commit carries the last value; a later replace drops
/// earlier writes of the commit.
#[test]
fn last_write_and_replace_win_spec_4_5() {
    let state = Fragment::default();
    let node = Source::node(Tid::from_bytes([2; 15]));
    let view = AnyView;
    let m = |kv: &[(i64, i64)]| Value::Map(kv.iter().map(|(k, v)| (Value::Int(*k), Value::Int(*v))).collect());
    let mut b = Batch::new(&state, Writer::new(ts(1 << 16), node, 1));
    b.apply(&PathOp { path: vec![], op: Op::Set(m(&[(1, 1), (2, 2)])) }, &view).unwrap();
    b.apply(&PathOp { path: vec![PathSeg::Key(Value::Int(1))], op: Op::Set(Value::Int(5)) }, &view).unwrap();
    assert_eq!(b.view().read(), Some(m(&[(1, 5), (2, 2)])));
    b.apply(&PathOp { path: vec![], op: Op::Replace(m(&[(3, 3)])) }, &view).unwrap();
    let (d, _) = b.finish().unwrap();
    let mut st = Fragment::default();
    st.join(d);
    assert_eq!(st.read(), Some(m(&[(3, 3)])));
}

/// §5.6: a put into a live key writes into the lowest live dot; a remove resets every live dot.
#[test]
fn map_put_lowest_dot_spec_5_6() {
    let view = AnyView;
    let a = Source::node(Tid::from_bytes([1; 15]));
    let b = Source::node(Tid::from_bytes([2; 15]));
    let put = |src: &Source, t: u64, v: i64| {
        let mut w = Writer::new(ts(t << 16), src.clone(), 1);
        create(&mut w, &view, &Value::Map([(Value::Int(0), Value::Int(v))].into_iter().collect())).unwrap()
    };
    let mut st = put(&a, 1, 1);
    st.join(put(&b, 1, 2));
    let mut batch = Batch::new(&st, Writer::new(ts(5 << 16), a.clone(), 2));
    batch.apply(&PathOp { path: vec![PathSeg::Key(Value::Int(0))], op: Op::Set(Value::Int(9)) }, &view).unwrap();
    let (d, _) = batch.finish().unwrap();
    let Fragment::Map(m) = &d else { panic!("map") };
    assert_eq!(m.entries.keys().map(|id| id.dot.src.clone()).collect::<Vec<_>>(), vec![a.clone()]);
    st.join(d);
    assert_eq!(st.read(), Some(Value::Map([(Value::Int(0), Value::Int(9))].into_iter().collect())));
    let mut batch = Batch::new(&st, Writer::new(ts(6 << 16), a, 3));
    batch.apply(&PathOp { path: vec![], op: Op::Remove(Value::Int(0)) }, &view).unwrap();
    let (d, _) = batch.finish().unwrap();
    let Fragment::Map(m) = &d else { panic!("map") };
    assert_eq!(m.entries.len(), 2);
    st.join(d);
    assert_eq!(st.read(), Some(Value::Map(Default::default())));
}

/// §5.6: a path op into a key with no live entry creates the entry holding the op's writes; two
/// writers doing so concurrently make two entries that read as one joined value; an op that
/// writes nothing creates nothing.
#[test]
fn path_op_into_absent_key_spec_5_6() {
    let view = AnyView;
    let st = Fragment::default();
    let add = |src: u8, v: i64| {
        let mut b = Batch::new(&st, Writer::new(ts(1 << 16), Source::node(Tid::from_bytes([src; 15])), 1));
        b.apply(&PathOp { path: vec![PathSeg::Key(Value::Int(0))], op: Op::Add(Value::Int(v)) }, &view).unwrap();
        b.finish().unwrap().0
    };
    let mut s = add(1, 1);
    assert_eq!(s.read(), Some(Value::Map([(Value::Int(0), Value::Set([Value::Int(1)].into_iter().collect()))].into_iter().collect())));
    s.join(add(2, 2));
    assert_eq!(s.read(), Some(Value::Map([(Value::Int(0), Value::Set([Value::Int(1), Value::Int(2)].into_iter().collect()))].into_iter().collect())));
    let mut b = Batch::new(&st, Writer::new(ts(1 << 16), Source::node(Tid::from_bytes([3; 15])), 1));
    // untyped, a remove from an absent value fails; typed, it is a no-op: either way no entry
    let _ = b.apply(&PathOp { path: vec![PathSeg::Key(Value::Int(0))], op: Op::Remove(Value::Int(1)) }, &view);
    assert!(b.finish().is_none());
}

/// §5.6, spec/versioning.md §5: typed, a path op into an absent key that writes nothing creates
/// no entry and consumes no counter; one going on through a struct field is refused (it would
/// create a partial struct).
#[test]
fn absent_key_typed_spec_5_6() {
    let inner = Ty::Struct([(1, Ty::Register), (2, Ty::Set(Box::new(Ty::Register)))].into_iter().collect());
    let sets = TyView(Ty::Map(Box::new(Ty::Register), Box::new(Ty::Set(Box::new(Ty::Register)))));
    let structs = TyView(Ty::Map(Box::new(Ty::Register), Box::new(inner)));
    let st = Fragment::default();
    let node = Source::node(Tid::from_bytes([4; 15]));
    let mut b = Batch::new(&st, Writer::new(ts(1 << 16), node.clone(), 1));
    b.apply(&PathOp { path: vec![PathSeg::Key(Value::Int(0))], op: Op::Remove(Value::Int(1)) }, &sets).unwrap();
    b.apply(&PathOp { path: vec![PathSeg::Key(Value::Int(0))], op: Op::Add(Value::Int(2)) }, &sets).unwrap();
    let (d, range) = b.finish().unwrap();
    assert_eq!(range, CounterRange { lo: 1, hi: 3 }, "entry and element only: the no-op took no counter");
    let mut s = st.clone();
    s.join(d);
    assert_eq!(s.read(), Some(Value::Map([(Value::Int(0), Value::Set([Value::Int(2)].into_iter().collect()))].into_iter().collect())));
    let mut b = Batch::new(&st, Writer::new(ts(1 << 16), node, 1));
    let partial = PathOp { path: vec![PathSeg::Key(Value::Int(0)), PathSeg::Field(1)], op: Op::Set(Value::Int(5)) };
    assert!(b.apply(&partial, &structs).is_err());
    assert!(b.finish().is_none());
}


/// §5.5, §5.6, §9, spec/data-model.md §6: large values compare by keyed content hash: two writes
/// of one content (other blob and key) are one set element, one map key, an unchanged register;
/// the read shows the lowest live dot's link (§5.5, §5.6).
#[test]
fn large_values_equal_by_hash_spec_5_5() {
    use osis_base::{BlobId, Link};
    let view = AnyView;
    let link = |blob: u8| Value::Link(Link { hash: [9; 32], blob: BlobId([blob; 32]), suite: 1, key: [blob; 32] });
    let a = Source::node(Tid::from_bytes([1; 15]));
    let b = Source::node(Tid::from_bytes([2; 15]));
    // Set: concurrent adds of one content read once; an add of it again writes nothing.
    let set = |src: &Source, blob: u8| create(&mut Writer::new(ts(1 << 16), src.clone(), 1), &view, &Value::Set([link(blob)].into_iter().collect())).unwrap();
    let mut st = set(&a, 1);
    st.join(set(&b, 2));
    assert_eq!(st.read(), Some(Value::Set([link(3)].into_iter().collect())));
    // The read shows the link of the lowest live element in dot order, whatever the join order.
    let blob_of = |v: Option<Value>| match v {
        Some(Value::Set(s)) => s.iter().next().and_then(|v| if let Value::Link(l) = v { Some(l.blob) } else { None }),
        Some(Value::Map(m)) => m.keys().next().and_then(|v| if let Value::Link(l) = v { Some(l.blob) } else { None }),
        _ => None,
    };
    let Fragment::Set(s) = &st else { panic!("set") };
    let lowest = s.elems.values().next().and_then(|e| e.frag.as_ref()?.read());
    let mut st2 = set(&b, 2);
    st2.join(set(&a, 1));
    assert_eq!(blob_of(st.read()), blob_of(lowest.map(|v| Value::Set([v].into_iter().collect()))));
    assert_eq!(blob_of(st.read()), blob_of(st2.read()));
    let mut batch = Batch::new(&st, Writer::new(ts(5 << 16), a.clone(), 2));
    batch.apply(&PathOp { path: vec![], op: Op::Add(link(4)) }, &view).unwrap();
    assert!(batch.finish().is_none());
    // Map: a put under an equal-hash key writes into the live entry.
    let m = |blob: u8, v: i64| Value::Map([(link(blob), Value::Int(v))].into_iter().collect());
    let mut st = create(&mut Writer::new(ts(1 << 16), a.clone(), 1), &view, &m(1, 1)).unwrap();
    st.join(create(&mut Writer::new(ts(1 << 16), b.clone(), 1), &view, &m(2, 2)).unwrap());
    assert_eq!(st.read().map(|v| if let Value::Map(m) = v { m.len() } else { 0 }), Some(1));
    let Fragment::Map(mf) = &st else { panic!("map") };
    let lowest = mf.entries.keys().next().and_then(|id| id.key().cloned());
    assert_eq!(blob_of(st.read()), blob_of(lowest.map(|k| Value::Map([(k, Value::Int(0))].into_iter().collect()))));
    let mut st2 = create(&mut Writer::new(ts(1 << 16), b.clone(), 1), &view, &m(2, 2)).unwrap();
    st2.join(create(&mut Writer::new(ts(1 << 16), a.clone(), 1), &view, &m(1, 1)).unwrap());
    assert_eq!(blob_of(st.read()), blob_of(st2.read()));
    // Register: a set to an equal-hash link is no write.
    let reg = create(&mut Writer::new(ts(1 << 16), a.clone(), 1), &view, &link(1)).unwrap();
    assert_eq!(diff(&mut Writer::new(ts(2 << 16), a, 2), Some(&reg), &view, &link(2)).unwrap(), None);
}

/// spec/crdt.md §5.6, §3.3: a remove and a put of one live map key in one batch (flows rewrite a
/// history box as remove + put) encodes canonically.
#[test]
fn remove_then_put_same_key_round_trips_spec_5_6() {
    use crate::codec::{decode_delta, encode_delta};
    use crate::stamp::Interner;
    use crate::wire::{Delta, DeltaCtx, DeltaKind};
    let view = AnyView;
    let a = Source::node(Tid::from_bytes([1; 15]));
    let key = Value::Int(0);
    let mk = |v: u8| Value::Map([(key.clone(), Value::Bytes(vec![v; 4]))].into_iter().collect());
    let mut w = Writer::new(ts(1 << 16), a.clone(), 1);
    let st = create(&mut w, &view, &mk(1)).unwrap();
    for (src, lo) in [(a.clone(), 2), (Source::node(Tid::from_bytes([2; 15])), 1), (Source::commit(osis_base::CommitId([9; 32])), 1)] {
        let mut batch = Batch::new(&st, Writer::new(ts(5 << 16), src.clone(), lo));
        batch.apply(&PathOp { path: vec![], op: Op::Remove(key.clone()) }, &view).unwrap();
        batch.apply(&PathOp { path: vec![PathSeg::Key(key.clone())], op: Op::Set(Value::Bytes(vec![1; 4])) }, &view).unwrap();
        let (d, range) = batch.finish().unwrap();
        let cx = DeltaCtx { ts: ts(5 << 16), own: src.clone(), range, kind: DeltaKind::Writer };
        let delta = Delta { nonce: [7; 16], fragment: d };
        let bytes = encode_delta(&delta, &cx, None).unwrap();
        let back = decode_delta(&bytes, &cx, &mut Interner::new(), None);
        assert_eq!(back.as_ref().ok(), Some(&delta), "{back:?}");
    }
}


/// §9, §4.7: S is the state as read now. A struct field whose only write went value-less reads
/// as absent, so the diff writes it again; a field whose value is still live is matched and not
/// rewritten (it keeps its expiry).
#[test]
fn diff_rewrites_value_less_field_spec_9() {
    let ty = Ty::Struct([(0, Ty::Register), (1, Ty::Register)].into_iter().collect());
    let view = TyView(ty);
    let v = |a: i64, b: Option<i64>| Value::Map([(Value::Int(0), Value::Int(a))].into_iter().chain(b.map(|b| (Value::Int(1), Value::Int(b)))).collect());
    let first = Source::node(Tid::from_bytes([1; 15]));
    let mut w1 = Writer::new(ts(1 << 16), first.clone(), 1);
    let mut st = create(&mut w1, &view, &v(1, Some(7))).unwrap();
    let mut w2 = Writer::new(ts(2 << 16), Source::node(Tid::from_bytes([2; 15])), 1);
    let d = diff(&mut w2, Some(&st), &view, &v(2, Some(7))).unwrap().unwrap();
    let Fragment::Struct(s) = &d else { panic!("struct delta") };
    assert_eq!(s.fields.keys().copied().collect::<Vec<_>>(), vec![0], "the live field 1 is not rewritten");
    st.join(d);
    // the first delta expires: field 1 goes, field 0 keeps the second delta's value
    st.strip(&|d: &crate::stamp::Dot| d.src == first);
    assert_eq!(read(&st), Some(v(2, None)));
    let mut w3 = Writer::new(ts(3 << 16), Source::node(Tid::from_bytes([3; 15])), 1);
    let d = diff(&mut w3, Some(&st), &view, &v(2, Some(7))).unwrap().unwrap();
    let Fragment::Struct(s) = &d else { panic!("struct delta") };
    assert_eq!(s.fields.keys().copied().collect::<Vec<_>>(), vec![1]);
    st.join(d);
    assert_eq!(read(&st), Some(v(2, Some(7))));
}

proptest! {
    /// §5.6: the local key index finds a key's live entries as a scan of the joined map does,
    /// after any sequence of joins (several writers, removals, resets).
    #[test]
    fn key_index_matches_scan_spec_5_6(seed in any::<u64>()) {
        let ty = sink_no_seq();
        let mut r = crate::testutil::rng(seed | 1);
        let commits = history(&mut r, std::slice::from_ref(&ty), 3, 4);
        let mut s = Fragment::default();
        for c in &commits {
            s.join(frag(&c.delta));
            let Fragment::Struct(st) = &s else { continue };
            let Some(Fragment::Map(m)) = st.fields.get(&7) else { continue };
            let scan = crate::ops::live_entries(m);
            let keys: std::collections::BTreeSet<&Value> = m.entries.keys().filter_map(|id| id.key()).collect();
            for k in keys {
                let want: Vec<&crate::fragment::Eid> = scan.get(k).cloned().unwrap_or_default();
                prop_assert_eq!(m.live_ids(k), want);
            }
        }
    }
}

/// §5.6 `put_new`: a new entry whatever is live, carrying the value whole (an unchanged value
/// too) and resetting nothing; the key reads as the join of its live entries. A set into a live
/// key is no put (its entry is not the delta's own).
#[test]
fn map_put_new_spec_5_6() {
    let view = AnyView;
    let a = Source::node(Tid::from_bytes([1; 15]));
    let one = |v: i64| Value::Map([(Value::Int(0), Value::Int(v))].into_iter().collect());
    let mut w = Writer::new(ts(1 << 16), a.clone(), 1);
    let mut st = create(&mut w, &view, &one(1)).unwrap();
    for (t, v) in [(2u64, 1i64), (3, 7)] {
        let mut batch = Batch::new(&st, Writer::new(ts(t << 16), a.clone(), t));
        batch.apply(&PathOp { path: vec![PathSeg::Key(Value::Int(0))], op: Op::Put(Value::Int(v)) }, &view).unwrap();
        let (d, range) = batch.finish().unwrap();
        let own = |x: &Dot| x.src == a && range.lo <= x.ctr && x.ctr < range.hi;
        assert!(d.is_put_only_map(&own));
        // a set into the live key writes into an existing entry: not a put
        let mut batch = Batch::new(&st, Writer::new(ts(t << 16), a.clone(), t));
        batch.apply(&PathOp { path: vec![PathSeg::Key(Value::Int(0))], op: Op::Set(Value::Int(v + 100)) }, &view).unwrap();
        let (s, range) = batch.finish().unwrap();
        let own = |x: &Dot| x.src == a && range.lo <= x.ctr && x.ctr < range.hi;
        assert!(!s.is_put_only_map(&own));
        st.join(d);
        assert_eq!(st.read(), Some(one(v)));
    }
    let Fragment::Map(m) = &st else { panic!("map") };
    assert_eq!(m.entries.len(), 3);
    let mut batch = Batch::new(&st, Writer::new(ts(4 << 16), a, 4));
    batch.apply(&PathOp { path: vec![], op: Op::Remove(Value::Int(0)) }, &view).unwrap();
    assert!(!batch.finish().unwrap().0.is_put_only_map(&|_| true));
}

/// §5.6 `put_new` away from a map key: a register is written again; a composite (it would merge
/// with what is there) is refused.
#[test]
fn put_new_register_only_spec_5_6() {
    let view = AnyView;
    let a = Source::node(Tid::from_bytes([1; 15]));
    let st = Fragment::default();
    let mut b = Batch::new(&st, Writer::new(ts(1 << 16), a.clone(), 1));
    assert!(b.apply(&PathOp { path: vec![], op: Op::Put(Value::Int(3)) }, &view).is_ok());
    for v in [Value::Set([Value::Int(1)].into_iter().collect()), Value::List(vec![Value::Int(1)]), Value::Map([(Value::Int(1), Value::Int(1))].into_iter().collect())] {
        let mut b = Batch::new(&st, Writer::new(ts(2 << 16), a.clone(), 1));
        assert!(b.apply(&PathOp { path: vec![], op: Op::Put(v) }, &view).is_err());
    }
}

/// spec/commits.md §2: a reset-plus-full-state delta of a map or set split per entry gives
/// deltas sharing the commit-level stamp whose join is the whole, each encoding on its own
/// under the commit's range.
#[test]
fn split_entries_join_back_spec_commits_2() {
    use crate::codec::{decode_delta, encode_delta};
    use crate::stamp::Interner;
    use crate::wire::{Delta, DeltaCtx, DeltaKind};
    let map = Value::Map((0..3i64).map(|i| (Value::Int(i), Value::Str(format!("v{i}")))).collect());
    let set = Value::Set((0..3i64).map(Value::Int).collect());
    for v in [map, set] {
        let node = Source::node(Tid::from_bytes([5; 15]));
        let mut w = crate::ops::Writer::new(ts(70 << 16), node.clone(), 1);
        let whole = crate::ops::replace(&mut w, &AnyView, &v).unwrap();
        let parts = whole.clone().split_entries();
        assert_eq!(parts.len(), 4, "the reset alone, then one per entry");
        let cx = DeltaCtx { ts: ts(70 << 16), own: node.clone(), range: w.range(), kind: DeltaKind::Writer };
        let mut joined = Fragment::empty(whole.encoding()).unwrap();
        for p in parts {
            let d = Delta { nonce: [1; 16], fragment: p.clone() };
            let bytes = encode_delta(&d, &cx, None).unwrap();
            assert_eq!(decode_delta(&bytes, &cx, &mut Interner::new(), None).unwrap(), d);
            joined.join(p);
        }
        assert_eq!(joined, whole);
        assert_eq!(read(&joined), Some(v));
    }
}

/// Two writers' concurrent puts of key `k` (two live entries), joined in either order.
fn concurrent_key() -> Vec<(TyView, Fragment, Value)> {
    let ty = Ty::Map(Box::new(Ty::Register), Box::new(Ty::Struct([(1, Ty::Register), (2, Ty::Register)].into_iter().collect())));
    let view = TyView(ty);
    let (na, nb) = (Source::node(Tid::from_bytes([1; 15])), Source::node(Tid::from_bytes([2; 15])));
    let k = Value::Str("k".into());
    let st = |a: (u64, &str)| Value::Map([(Value::Int(a.0 as i64), Value::Str(a.1.into()))].into_iter().collect());
    let mut w = Writer::new(ts(1 << 16), na.clone(), 1);
    let base = create(&mut w, &view, &Value::Map(Default::default())).unwrap();
    let put = |w: Writer, v: Value| {
        let mut b = Batch::new(&base, w);
        b.apply(&PathOp { path: vec![PathSeg::Key(k.clone())], op: Op::Set(v) }, &view).unwrap();
        b.finish().unwrap().0
    };
    let da = put(Writer::new(ts(2 << 16), na, 10), st((1, "a")));
    let db = put(Writer::new(ts(2 << 16), nb, 1), st((2, "b")));
    let both = Value::Map([(k.clone(), Value::Map([(Value::Int(1), Value::Str("a".into())), (Value::Int(2), Value::Str("b".into()))].into_iter().collect()))].into_iter().collect());
    [(&da, &db), (&db, &da)]
        .into_iter()
        .map(|(x, y)| {
            let mut s = base.clone();
            s.join(x.clone());
            s.join(y.clone());
            assert_eq!(s.read(), Some(both.clone()));
            (TyView(view.0.clone()), s, both.clone())
        })
        .collect()
}

/// Commits `op` on `s` as node 1 at ts 5, undoes it (full state and footprint as the buffer);
/// returns the undo delta and the state after it.
fn commit_and_undo(view: &TyView, s: &Fragment, op: PathOp) -> (Fragment, Fragment, Fragment) {
    let node = Source::node(Tid::from_bytes([1; 15]));
    let mut b = Batch::new(s, Writer::new(ts(5 << 16), node.clone(), 20));
    b.apply(&op, view).unwrap();
    let (d, range) = b.finish().unwrap();
    let mut s1 = s.clone();
    s1.join(d.clone());
    let u = Undone { delta: &d, source: &node, range, restored: &|_| false };
    let ud = undo(&mut Writer::new(ts(6 << 16), node.clone(), 40), &u, &s1, s, view).unwrap().unwrap();
    assert_eq!(undo(&mut Writer::new(ts(6 << 16), node.clone(), 40), &u, &s1, &s.footprint(&d), view).unwrap().as_ref(), Some(&ud));
    let mut s2 = s1.clone();
    s2.join(ud.clone());
    (s1, ud, s2)
}

/// §4.6: removing a key two writers put concurrently and undoing it re-adds the key as one
/// entry holding the joined value, in either join order.
#[test]
fn undo_remove_of_concurrent_key_spec_4_6() {
    for (view, s, both) in concurrent_key() {
        let (s1, ud, s2) = commit_and_undo(&view, &s, PathOp { path: vec![], op: Op::Remove(Value::Str("k".into())) });
        assert_eq!(s1.read(), Some(Value::Map(Default::default())));
        let Fragment::Map(m) = &ud else { panic!("map") };
        assert_eq!(m.entries.keys().filter(|id| id.key() == Some(&Value::Str("k".into()))).count(), 1);
        assert_eq!(s2.read(), Some(both));
    }
}

/// §4.6, §5.6: an edit into a key with two live entries goes to the lowest one; undoing it
/// restores what the key read before (the join of its entries), in either join order.
#[test]
fn undo_edit_of_concurrent_key_spec_4_6() {
    for (view, s, both) in concurrent_key() {
        for field in [1, 2] {
            let path = vec![PathSeg::Key(Value::Str("k".into())), PathSeg::Field(field)];
            let (s1, _, s2) = commit_and_undo(&view, &s, PathOp { path, op: Op::Set(Value::Str("c".into())) });
            assert_ne!(s1.read(), Some(both.clone()));
            assert_eq!(s2.read(), Some(both.clone()), "field {field}");
        }
    }
}

/// A struct whose set, enum-payload set, list, text and counter fields start absent.
fn absent_spots() -> (TyView, Fragment) {
    let set = || Ty::Set(Box::new(Ty::Register));
    let inner = Ty::Struct([(1, Ty::Register), (2, set())].into_iter().collect());
    let cases = [(0, None), (1, Some(inner))].into_iter().collect();
    let ty = Ty::Struct(
        [(1, Ty::Register), (2, set()), (3, Ty::Enum(cases)), (4, Ty::List(Box::new(Ty::Register))), (5, Ty::Text), (6, Ty::Counter)].into_iter().collect(),
    );
    let view = TyView(ty);
    let mut w = Writer::new(ts(1 << 16), Source::node(Tid::from_bytes([1; 15])), 1);
    let payload = Value::Map([(Value::Int(1), Value::Str("p".into()))].into_iter().collect());
    let v = Value::Map([(Value::Int(1), Value::Str("x".into())), (Value::Int(3), Value::Enum(1, Some(Box::new(payload))))].into_iter().collect());
    let s = create(&mut w, &view, &v).unwrap();
    assert_eq!(s.read(), Some(v));
    (view, s)
}

fn absent_spot_ops() -> Vec<(&'static str, PathOp)> {
    absent_spot_ops_of("a")
}

fn absent_spot_ops_of(item: &str) -> Vec<(&'static str, PathOp)> {
    let one = || Value::Str(item.into());
    vec![
        ("struct field set", PathOp { path: vec![PathSeg::Field(2)], op: Op::Add(one()) }),
        ("enum payload set", PathOp { path: vec![PathSeg::Field(3), PathSeg::Case(1), PathSeg::Field(2)], op: Op::Add(one()) }),
        ("list", PathOp { path: vec![PathSeg::Field(4)], op: Op::Insert { at: 0, items: vec![one()] } }),
        ("text", PathOp { path: vec![PathSeg::Field(5)], op: Op::Insert { at: 0, items: vec![one()] } }),
        ("counter", PathOp { path: vec![PathSeg::Field(6)], op: Op::Inc(Value::Int(2)) }),
    ]
}

/// §4.6 "Absent before": undoing the first write into a spot that did not exist makes it absent
/// again (a set, an enum payload's field, a list, a text, a counter).
#[test]
fn undo_makes_absent_again_spec_4_6() {
    let (view, s) = absent_spots();
    for (name, op) in absent_spot_ops() {
        let (s1, ud, s2) = commit_and_undo(&view, &s, op);
        assert_ne!(s1.read(), s.read(), "{name}");
        assert_eq!(s2.read(), s.read(), "{name}: {ud:?}");
    }
}

/// §4.6 "Absent before": the reset also drops a concurrent older write into the spot arriving
/// later; a write newer than the undo survives, and one already held blocks the reset.
#[test]
fn undo_absent_before_wipes_concurrent_spec_4_6() {
    let (view, s) = absent_spots();
    let other = Source::node(Tid::from_bytes([2; 15]));
    for ((name, op), (_, op_b)) in absent_spot_ops().into_iter().zip(absent_spot_ops_of("b")) {
        let (_, ud, _) = commit_and_undo(&view, &s, op.clone());
        for (at, survives) in [(4u64, false), (7, true)] {
            // node 2 writes into the same spot without seeing node 1's commit
            let mut b = Batch::new(&s, Writer::new(ts(at << 16), other.clone(), 1));
            b.apply(&op, &view).unwrap();
            let d2 = b.finish().unwrap().0;
            let node = Source::node(Tid::from_bytes([1; 15]));
            let mut b = Batch::new(&s, Writer::new(ts(5 << 16), node, 20));
            b.apply(&op, &view).unwrap();
            let d1 = b.finish().unwrap().0;
            let mut only2 = s.clone();
            only2.join(d2.clone());
            let mut all = s.clone();
            for d in [d1, d2, ud.clone()] {
                all.join(d);
            }
            let want = if survives { only2.read() } else { s.read() };
            assert_eq!(all.read(), want, "{name} at {at}");
            // node 2's write already here when undoing: not wiped, only node 1's write goes
            let (_, _, s2) = commit_and_undo(&view, &only2, op_b.clone());
            assert_eq!(s2.read(), only2.read(), "{name} at {at}, seen");
        }
    }
}

/// `approx_bytes` (a memory bound's measure, not a spec rule): it grows with the content and
/// stays within a small factor of the encoded size. spec: none (resource bound)
#[test]
fn approx_bytes_tracks_content() {
    let mut r = crate::testutil::rng(7);
    let ty = sink_no_seq();
    for _ in 0..50 {
        let v = value(&random_value(&mut r, &ty, 0));
        let mut w = Writer::new(osis_base::Ts::default(), Source::node(Tid::from_bytes([1; 15])), 1);
        let f = create(&mut w, &AnyView, &v).unwrap();
        let enc = osis_base::encode(&v).len();
        assert!(f.approx_bytes() >= enc / 2, "{} vs {enc}", f.approx_bytes());
    }
    let mut w = Writer::new(osis_base::Ts::default(), Source::node(Tid::from_bytes([1; 15])), 1);
    let small = create(&mut w, &AnyView, &Value::Str("a".into())).unwrap();
    let big = create(&mut w, &AnyView, &Value::Str("a".repeat(10_000))).unwrap();
    assert!(big.approx_bytes() > small.approx_bytes() + 9_000);
}

/// `decoded_bound` (a memory bound's measure, not a spec rule) holds for the shapes that take
/// most per encoded byte: many tiny map entries, set elements, list elements, struct fields,
/// text. spec: none (resource bound)
#[test]
fn decoded_bound_holds_dense_shapes() {
    use crate::codec::{decode_snapshot, encode_snapshot};
    use crate::wire::{DeltaCtx, DeltaKind, Snapshot};
    let ints = |n: i64| (0..n).map(Value::Int);
    let shapes = [
        Value::Map(ints(2000).map(|i| (i.clone(), i)).collect()),
        Value::Map(ints(2000).map(|i| (i, Value::Map(Default::default()))).collect()),
        Value::Map((0..2000).map(|i| (Value::Str(format!("{i}")), Value::Bool(true))).collect()),
        Value::Set(ints(2000).collect()),
        Value::List(ints(2000).collect()),
        Value::List(ints(2000).map(|_| Value::Map(Default::default())).collect()),
        Value::Str("a".repeat(5000)),
        Value::Map([(Value::Int(1), Value::Int(1))].into_iter().collect()),
        Value::Int(1),
        Value::Map(ints(500).map(|i| (i, Value::Map([(Value::Int(0), Value::Map([(Value::Int(0), Value::Int(0))].into_iter().collect()))].into_iter().collect()))).collect()),
        Value::List(ints(500).map(|_| Value::List(vec![Value::List(vec![Value::Int(0)])])).collect()),
        Value::Set(ints(500).map(|i| Value::Set([i].into_iter().collect())).collect()),
    ];
    let cx = DeltaCtx { ts: ts(1 << 40), own: Source::node(Tid::from_bytes([9; 15])), range: CounterRange::EMPTY, kind: DeltaKind::Snapshot };
    for v in shapes {
        let mut w = Writer::new(ts(1 << 30), Source::node(Tid::from_bytes([1; 15])), 1);
        let f = create(&mut w, &AnyView, &v).unwrap();
        let s = Snapshot { absorbed: Default::default(), authors: Default::default(), nonce: [0; 16], fragment: f, frontiers: Default::default() };
        let bytes = encode_snapshot(&s, &cx, None).unwrap();
        let back = decode_snapshot(&bytes, &cx, &mut crate::stamp::Interner::new(), None).unwrap();
        crate::testutil::check_bound(&bytes, &back.fragment);
    }
    // a text: one record per character
    let mut w = Writer::new(ts(1 << 30), Source::node(Tid::from_bytes([1; 15])), 1);
    let f = create(&mut w, &crate::fuzzing::TextView, &Value::Str("a".repeat(5000))).unwrap();
    let s = Snapshot { absorbed: Default::default(), authors: Default::default(), nonce: [0; 16], fragment: f, frontiers: Default::default() };
    let bytes = encode_snapshot(&s, &cx, None).unwrap();
    let back = decode_snapshot(&bytes, &cx, &mut crate::stamp::Interner::new(), None).unwrap();
    crate::testutil::check_bound(&bytes, &back.fragment);
}
