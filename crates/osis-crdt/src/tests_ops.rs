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
use osis_core::{Tid, Value};
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
        let mut r = Rng(seed | 1);
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
        let mut r = Rng(seed | 1);
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
        let mut r = Rng(seed | 1);
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
        // undo restores values, not absence: a register cannot be written "absent" and a
        // collection emptied by an undo stays present (§4.3, §4.6); only fully present states
        let Some(Value::Map(fields)) = s0.read() else { return Ok(()) };
        let Ty::Struct(tf) = &ty else { return Ok(()) };
        if fields.len() != tf.len() {
            return Ok(());
        }
        let d = frag(&md);
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
            prop_assert_eq!(read(&s1), read(&s0));
            return Ok(());
        };
        let mut s2 = s1.clone();
        s2.join(ud);
        prop_assert_eq!(read(&s2), read(&s0));
    }

    /// notes/api.md `edit`: the value diff applied to the base reaches the new value, and a
    /// concurrent change to a field the edit did not touch survives.
    #[test]
    fn diff_values_spec_9(seed in any::<u64>()) {
        let ty = sink_no_seq();
        let view = TyView(ty.clone());
        let mut r = Rng(seed | 1);
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
    assert_eq!(m.entries.keys().map(|d| d.src.clone()).collect::<Vec<_>>(), vec![a.clone()]);
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


/// §5.5, §5.6, §9, spec/data-model.md §6: large values compare by keyed content hash: two writes
/// of one content (other blob and key) are one set element, one map key, an unchanged register;
/// the read shows the lowest live dot's link (§5.5, §5.6).
#[test]
fn large_values_equal_by_hash_spec_5_5() {
    use osis_core::{BlobId, Link};
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
    let lowest = mf.entries.values().next().and_then(|e| e.key.clone());
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
    for (src, lo) in [(a.clone(), 2), (Source::node(Tid::from_bytes([2; 15])), 1), (Source::commit(osis_core::CommitId([9; 32])), 1)] {
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
        let mut r = Rng(seed | 1);
        let commits = history(&mut r, std::slice::from_ref(&ty), 3, 4);
        let mut s = Fragment::default();
        for c in &commits {
            s.join(frag(&c.delta));
            let Fragment::Struct(st) = &s else { continue };
            let Some(Fragment::Map(m)) = st.fields.get(&7) else { continue };
            let scan = crate::ops::live_entries(&m.entries);
            let keys: std::collections::BTreeSet<&Value> = m.entries.values().filter_map(|e| e.key.as_ref()).collect();
            for k in keys {
                let want: Vec<&crate::stamp::Dot> = scan.get(k).cloned().unwrap_or_default();
                prop_assert_eq!(m.live_dots(k), want);
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
