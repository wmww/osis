//! Ops, diff, net effect and undo (spec/crdt.md §2.3, §4.5, §4.6, §5, §9).

use crate::batch::Batch;
use crate::fragment::Fragment;
use crate::ops::{Op, PathOp, PathSeg, Writer, create, diff, diff_values};
use crate::stamp::{CounterRange, Source};
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
        let u = Undone { delta: &d, source: &src, range: CounterRange { lo: mw.lo, hi: mw.hi() } };
        let mut w = Writer::new(ts(82 << 16), Source::node(Tid::from_bytes([1; 15])), mw.hi());
        let Some(ud) = undo(&mut w, &u, &s1, &s0, &TyView(ty.clone())).unwrap() else {
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

