//! Sequence ops, net effect, undo, cut/paste, diff and `edit` (spec/crdt.md §4.5, §4.6, §5.7, §9).

use crate::batch::Batch;
use crate::codec::{decode_delta, encode_delta};
use crate::fragment::Fragment;
use crate::ops::{Op, PathOp, PathSeg, Writer, create, diff, diff_values};
use crate::seq::visible;
use crate::stamp::{CounterRange, Interner, Source};
use crate::testutil::{TyView, frag, mapply, ostate, ts, value, writer};
use crate::undo::{Undone, undo};
use crate::wire::{Delta, DeltaCtx, DeltaKind};
use crdt_model::r#gen::{Rng, random_value};
use crdt_model::ops::{self as mops, Ty, Writer as MWriter};
use crdt_model::state::Content;
use osis_core::{Tid, Value};
use proptest::prelude::*;

fn node(n: u8) -> Source {
    Source::node(Tid::from_bytes([n; 15]))
}
fn s(x: &str) -> Value {
    Value::Str(x.into())
}
fn read_str(f: &Fragment) -> String {
    match f.read() {
        Some(Value::Str(x)) => x,
        _ => String::new(),
    }
}
fn list_ty() -> Ty {
    Ty::List(Box::new(Ty::Struct([(1, Ty::Register), (2, Ty::Register)].into_iter().collect())))
}
fn text_view() -> TyView {
    TyView(Ty::Text)
}

/// One replica: state, writer source, next counter, clock.
struct Replica {
    state: Fragment,
    src: Source,
    lo: u64,
}

impl Replica {
    fn new(n: u8) -> Replica {
        Replica { state: Fragment::default(), src: node(n), lo: 1 }
    }
    /// Applies `ops` as one commit at time `t`; the delta goes through the wire as a writer's.
    fn commit(&mut self, t: u64, ops: &[PathOp], view: &TyView) -> Option<(Fragment, Source, CounterRange)> {
        let mut b = Batch::new(&self.state, Writer::new(ts(t << 16), self.src.clone(), self.lo));
        for op in ops {
            b.apply(op, view).unwrap();
        }
        let (d, range) = b.finish()?;
        self.lo = range.hi;
        let cx = DeltaCtx { ts: ts(t << 16), own: self.src.clone(), range, kind: DeltaKind::Writer };
        let bytes = encode_delta(&Delta { nonce: [0; 16], fragment: d.clone() }, &cx, None).unwrap();
        let back = decode_delta(&bytes, &cx, &mut Interner::new(), None).unwrap().fragment;
        assert_eq!(back, d, "a writer's delta round-trips");
        self.state.join(back);
        crate::testutil::check_lin(&self.state);
        Some((d, self.src.clone(), range))
    }
}

/// `f` through a snapshot: deleted chars dropped, uniform stretches as range records (§3.3).
fn rebooted(f: &Fragment) -> Fragment {
    let cx = crate::tests_wire::snap_cx();
    let snap = crate::wire::Snapshot { nonce: [0; 16], fragment: f.clone(), frontiers: Default::default() };
    let bytes = crate::encode_snapshot(&snap, &cx, None).unwrap();
    crate::decode_snapshot(&bytes, &cx, &mut Interner::new(), None).unwrap().fragment
}

fn op(o: Op) -> PathOp {
    PathOp { path: vec![], op: o }
}

/// A random text op against the current read of length `n`.
fn random_text_op(r: &mut Rng, n: usize, st: &Fragment) -> Op {
    match r.below(7) {
        0 | 1 => Op::Insert { at: r.below(n + 1), items: vec![s(&(crdt_model::r#gen::random_text(r, 3) + "z"))] },
        2 if n > 0 => {
            let at = r.below(n);
            Op::Delete { at, len: (1 + r.below(3)).min(n - at) }
        }
        3 | 4 if n > 1 => {
            let at = r.below(n);
            let len = (1 + r.below(3)).min(n - at);
            Op::Move { at, len, to: r.below(n - len + 1) }
        }
        5 => Op::Set(s(&crdt_model::r#gen::random_text(r, 6))),
        6 => {
            // paste a run of cut (deleted) text, adjacent in placement order
            let Fragment::Seq(sq) = st else { return Op::Insert { at: 0, items: vec![s("a")] } };
            let mut runs: Vec<Vec<crate::Dot>> = vec![vec![]];
            for d in crate::linearize::place(sq.elems(), sq.text).iter().map(|r| r.dot.clone()) {
                let e = crate::seq_span::elem(sq.elems(), &d).unwrap();
                match (e.flag(), &e.content) {
                    (true, crate::seq::SeqContent::Char(_)) => runs.last_mut().unwrap().push(d),
                    (true, _) => {}
                    _ => runs.push(vec![]),
                }
            }
            runs.retain(|x| !x.is_empty());
            if runs.is_empty() {
                return Op::Insert { at: 0, items: vec![s("b")] };
            }
            let dots = runs.swap_remove(r.below(runs.len()));
            Op::Paste { dots, at: r.below(n + 1) }
        }
        _ => Op::Insert { at: 0, items: vec![s("a")] },
    }
}

/// What `o` does to a plain string (the sequential model); `st` is the state it applies to.
fn apply_text(model: &mut Vec<char>, o: &Op, st: &Fragment) {
    match o {
        Op::Insert { at, items } => {
            let cs: Vec<char> = items.iter().flat_map(|i| if let Value::Str(x) = i { x.chars().collect::<Vec<_>>() } else { vec![] }).collect();
            model.splice(*at..*at, cs);
        }
        Op::Delete { at, len } => {
            model.drain(*at..*at + *len);
        }
        Op::Move { at, len, to } => {
            let m: Vec<char> = model.drain(*at..*at + *len).collect();
            model.splice(*to..*to, m);
        }
        Op::Paste { dots, at } => {
            let Fragment::Seq(sq) = st else { return };
            let cs: Vec<char> = dots.iter().filter_map(|d| if let crate::seq::SeqContent::Char(c) = sq.elems()[d].content { Some(c) } else { None }).collect();
            model.splice(*at..*at, cs);
        }
        Op::Set(Value::Str(x)) => *model = x.chars().collect(),
        _ => {}
    }
}

proptest! {
    /// §5.7 Ops: a single writer's text ops (insert, delete, move, set by diff), committed one
    /// by one through the wire, read like the same ops on a plain string.
    #[test]
    fn single_writer_text_spec_5_7(seed in any::<u64>()) {
        let mut r = Rng(seed | 1);
        let mut a = Replica::new(1);
        let mut model: Vec<char> = Vec::new();
        for k in 0..30u64 {
            let o = random_text_op(&mut r, model.len(), &a.state);
            apply_text(&mut model, &o, &a.state);
            a.commit(k + 1, &[op(o.clone())], &text_view());
            prop_assert_eq!(read_str(&a.state), model.iter().collect::<String>(), "after {:?}", o);
            if r.chance(1, 3) {
                // ops then meet range records
                a.state = rebooted(&a.state);
            }
        }
    }

    /// §4.5: several ops in one commit read like the same ops committed one by one.
    #[test]
    fn text_batch_is_net_effect_spec_4_5(seed in any::<u64>()) {
        let mut r = Rng(seed | 1);
        let mut a = Replica::new(1);
        a.commit(1, &[op(Op::Set(s("hello world")))], &text_view());
        let base = a.state.clone();
        let mut model: Vec<char> = read_str(&base).chars().collect();
        let mut ops = Vec::new();
        for _ in 0..6 {
            let o = random_text_op(&mut r, model.len(), &base);
            if matches!(o, Op::Paste { .. }) {
                continue;
            }
            apply_text(&mut model, &o, &base);
            ops.push(op(o));
        }
        a.commit(2, &ops, &text_view());
        prop_assert_eq!(read_str(&a.state), model.iter().collect::<String>());
    }

    /// §5.7, §6: replicas applying random text ops (paste included) and exchanging deltas in
    /// random order converge to equal states.
    #[test]
    fn text_ops_converge_spec_5_7(seed in any::<u64>()) {
        let mut r = Rng(seed | 1);
        let mut reps: Vec<Replica> = (1..=3).map(Replica::new).collect();
        let mut log: Vec<Fragment> = Vec::new();
        for round in 0..6u64 {
            for (i, rep) in reps.iter_mut().enumerate() {
                // catch up on a random part of the log
                for d in &log {
                    if r.chance(1, 2) {
                        rep.state.join(d.clone());
                    }
                }
                let n = read_str(&rep.state).chars().count();
                let o = random_text_op(&mut r, n, &rep.state);
                if let Some((d, _, _)) = rep.commit(round * 10 + i as u64 + 1, &[op(o)], &text_view()) {
                    log.push(d);
                }
            }
        }
        let mut finals = Vec::new();
        for rep in &mut reps {
            let mut order: Vec<usize> = (0..log.len()).collect();
            for k in (1..order.len()).rev() {
                order.swap(k, r.below(k + 1));
            }
            for k in order {
                rep.state.join(log[k].clone());
            }
            finals.push(rep.state.clone());
        }
        prop_assert_eq!(&finals[0], &finals[1]);
        prop_assert_eq!(&finals[1], &finals[2]);
    }

    /// §4.6, §5.7 Undo: undoing a single writer's last text commit restores the previous read.
    #[test]
    fn text_undo_restores_spec_4_6(seed in any::<u64>()) {
        let mut r = Rng(seed | 1);
        let mut a = Replica::new(1);
        a.commit(1, &[op(Op::Set(s("the quick brown fox")))], &text_view());
        for k in 0..4 {
            let n = read_str(&a.state).chars().count();
            let o = random_text_op(&mut r, n, &a.state);
            a.commit(2 + k, &[op(o)], &text_view());
        }
        let before = a.state.clone();
        let n = read_str(&a.state).chars().count();
        let o = random_text_op(&mut r, n, &a.state);
        // a move undoes with fresh stamps: newer siblings of the old anchor may then follow it (notes/crdt.md)
        if matches!(o, Op::Move { .. } | Op::Paste { .. }) {
            return Ok(());
        }
        let Some((d, src, range)) = a.commit(10, &[op(o)], &text_view()) else { return Ok(()) };
        let u = Undone { delta: &d, source: &src, range, restored: &|_| false };
        let mut w = Writer::new(ts(11 << 16), node(1), a.lo);
        let full = undo(&mut w, &u, &a.state, &before, &text_view()).unwrap();
        // the node keeps only the footprint of the delta as its undo buffer
        let mut w2 = Writer::new(ts(11 << 16), node(1), a.lo);
        prop_assert_eq!(undo(&mut w2, &u, &a.state, &before.footprint(&d), &text_view()).unwrap(), full.clone());
        if let Some(ud) = full {
            a.state.join(ud);
        }
        prop_assert_eq!(read_str(&a.state), read_str(&before));
    }

    /// §4.6, §5.7 Undo: list insert, delete (re-insert), move and nested edits undo.
    #[test]
    fn list_undo_restores_spec_4_6(seed in any::<u64>()) {
        let ty = list_ty();
        let view = TyView(ty.clone());
        let mut r = Rng(seed | 1);
        let mut a = Replica::new(1);
        let v = value(&random_value(&mut r, &ty, 0));
        a.commit(1, &[op(Op::Set(v))], &view);
        for k in 0..3 {
            let o = random_list_op(&mut r, &a.state, &ty);
            a.commit(2 + k, &[o], &view);
        }
        let before = a.state.clone();
        let o = random_list_op(&mut r, &a.state, &ty);
        if matches!(o.op, Op::Move { .. }) {
            return Ok(());
        }
        let Some((d, src, range)) = a.commit(10, &[o], &view) else { return Ok(()) };
        let u = Undone { delta: &d, source: &src, range, restored: &|_| false };
        let mut w = Writer::new(ts(11 << 16), node(1), a.lo);
        let full = undo(&mut w, &u, &a.state, &before, &view).unwrap();
        let mut w2 = Writer::new(ts(11 << 16), node(1), a.lo);
        prop_assert_eq!(undo(&mut w2, &u, &a.state, &before.footprint(&d), &view).unwrap(), full.clone());
        if let Some(ud) = full {
            a.state.join(ud);
        }
        prop_assert_eq!(a.state.read(), before.read());
    }

    /// §9: the structural diff reaches the value, text and list, from random states.
    #[test]
    fn seq_diff_reaches_value_spec_9(seed in any::<u64>()) {
        let mut r = Rng(seed | 1);
        for ty in [Ty::Text, list_ty()] {
            let commits = crate::testutil::history(&mut r, std::slice::from_ref(&ty), 2, 4);
            let mut m = None;
            for c in &commits {
                mapply(&mut m, c.delta.clone());
            }
            let st = ostate(&m);
            for k in 0..3u64 {
                let v = value(&random_value(&mut r, &ty, 0));
                let mut w = Writer::new(ts((100 + k) << 16), node(9), 1);
                let d = diff(&mut w, Some(&st), &TyView(ty.clone()), &v).unwrap();
                let mut s2 = st.clone();
                if let Some(d) = d {
                    s2.join(d);
                }
                prop_assert_eq!(s2.read(), Some(v));
            }
        }
    }

    /// notes/api.md `edit`: with no concurrent change the edit reaches the new value; with a
    /// concurrent remote edit outside the edited ranges, the remote content survives.
    #[test]
    fn text_edit_rebases_spec_9(seed in any::<u64>()) {
        let mut r = Rng(seed | 1);
        let mut a = Replica::new(1);
        let base = "alpha beta gamma delta";
        a.commit(1, &[op(Op::Set(s(base)))], &text_view());
        // the user edits inside "beta", a remote appends after "delta"
        let new = base.replacen("beta", if r.chance(1, 2) { "BETA!" } else { "bet" }, 1);
        let ops = diff_values(Some(&s(base)), &s(&new), &text_view()).unwrap();
        let mut plain = a.state.clone();
        let mut b = Batch::new(&plain, Writer::new(ts(3 << 16), node(1), a.lo));
        for o in &ops {
            b.apply(o, &text_view()).unwrap();
        }
        plain.join(b.finish().unwrap().0);
        prop_assert_eq!(read_str(&plain), new.clone());
        let mut remote = Replica::new(2);
        remote.state = a.state.clone();
        let (rd, _, _) = remote.commit(2, &[op(Op::Insert { at: base.len(), items: vec![s(" epsilon")] })], &text_view()).unwrap();
        a.state.join(rd);
        a.commit(3, &ops, &text_view());
        prop_assert_eq!(read_str(&a.state), format!("{new} epsilon"));
    }

    /// §4.5: list ops (nested ones through `PathSeg::Index` included) in one commit read like
    /// the same ops committed one by one; replicas exchanging them converge.
    #[test]
    fn list_batch_and_convergence_spec_4_5(seed in any::<u64>()) {
        let ty = list_ty();
        let view = TyView(ty.clone());
        let mut r = Rng(seed | 1);
        let mut a = Replica::new(1);
        a.commit(1, &[op(Op::Set(value(&random_value(&mut r, &ty, 0))))], &view);
        let mut one = Replica { state: a.state.clone(), src: node(1), lo: a.lo };
        let mut ops = Vec::new();
        for k in 0..5u64 {
            let o = random_list_op(&mut r, &one.state, &ty);
            one.commit(2 + k, std::slice::from_ref(&o), &view);
            ops.push(o);
        }
        a.commit(20, &ops, &view);
        prop_assert_eq!(a.state.read(), one.state.read());
        // two replicas editing concurrently converge
        let mut b = Replica { state: a.state.clone(), src: node(2), lo: 1 };
        let mut log = Vec::new();
        for k in 0..4u64 {
            for rep in [&mut a, &mut b] {
                let o = random_list_op(&mut r, &rep.state, &ty);
                if let Some((d, _, _)) = rep.commit(30 + k, &[o], &view) {
                    log.push(d);
                }
            }
        }
        for d in &log {
            a.state.join(d.clone());
        }
        for d in log.iter().rev() {
            b.state.join(d.clone());
        }
        prop_assert_eq!(&a.state, &b.state);
    }

    /// notes/api.md `edit` on a list: changed elements are edited in place (nested), so a
    /// concurrent edit to another field of the same element survives.
    #[test]
    fn list_edit_rebases_spec_9(seed in any::<u64>()) {
        let ty = list_ty();
        let view = TyView(ty.clone());
        let mut r = Rng(seed | 1);
        let item = |a: i64, b: i64| Value::Map([(Value::Int(1), Value::Int(a)), (Value::Int(2), Value::Int(b))].into_iter().collect());
        let base = Value::List((0..4).map(|k| item(k, 10 + k)).collect());
        let mut a = Replica::new(1);
        a.commit(1, &[op(Op::Set(base.clone()))], &view);
        let k = r.below(4);
        let Value::List(mut items) = base.clone() else { panic!() };
        items[k] = item(100, 10 + k as i64);
        let new = Value::List(items.clone());
        let ops = diff_values(Some(&base), &new, &view).unwrap();
        // remote: field 2 of element k
        let mut b = Replica { state: a.state.clone(), src: node(2), lo: 1 };
        let (rd, _, _) = b.commit(2, &[PathOp { path: vec![PathSeg::Index(k), PathSeg::Field(2)], op: Op::Set(Value::Int(-1)) }], &view).unwrap();
        a.state.join(rd);
        a.commit(3, &ops, &view);
        items[k] = item(100, -1);
        prop_assert_eq!(a.state.read(), Some(Value::List(items)));
    }
}

/// Tier 2 timing: a 10^5-char text built from ~5000 insert runs; read, a small join, one op
/// through `Batch`, joins of decoded deltas (insert, delete, older concurrent insert, move),
/// snapshot encode/decode.
#[test]
#[ignore = "tier 2"]
fn budget_big_text_spec_6() {
    use std::time::Instant;
    let mut r = Rng(5);
    let mut a = Replica::new(1);
    let mut len = 0usize;
    let t = Instant::now();
    let run: String = "abcdefghij".repeat(10);
    for k in 0..1000u64 {
        let at = r.below(len + 1);
        len += 100;
        a.commit(k + 1, &[op(Op::Insert { at, items: vec![s(&run)] })], &text_view());
    }
    let build = t.elapsed();
    let t = Instant::now();
    let v = a.state.read();
    let read = t.elapsed();
    assert_eq!(read_str(&a.state).len(), 100_000);
    let t = Instant::now();
    let Fragment::Seq(sq) = &a.state else { panic!() };
    let p = crate::linearize::place(sq.elems(), sq.text);
    let place = t.elapsed();
    let mut b = Replica { state: a.state.clone(), src: node(2), lo: 1 };
    let t = Instant::now();
    let (d, src, range) = b.commit(1000, &[op(Op::Insert { at: 5000, items: vec![s("x")] })], &text_view()).unwrap();
    let d = wired(&d, &src, range, 1000);
    let one_op = t.elapsed();
    let t = Instant::now();
    a.state.join(d);
    let small_join = t.elapsed();
    let t = Instant::now();
    let two = [op(Op::Insert { at: 10, items: vec![s("y")] }), op(Op::Delete { at: 50_000, len: 3 })];
    b.commit(1001, &two, &text_view()).unwrap();
    let two_ops = t.elapsed();
    // joins with no read between follow the cache too
    let (d, src, range) = b.commit(1002, &[op(Op::Insert { at: 7000, items: vec![s("w")] })], &text_view()).unwrap();
    let d = wired(&d, &src, range, 1002);
    let t = Instant::now();
    a.state.join(d);
    let unread_join = t.elapsed();
    // a delete
    let (d, src, range) = b.commit(1003, &[op(Op::Delete { at: 9000, len: 5 })], &text_view()).unwrap();
    let d = wired(&d, &src, range, 1003);
    let t = Instant::now();
    a.state.join(d);
    let delete_join = t.elapsed();
    // an older concurrent insert at the anchor of a newer one, below it and its subtree
    let mut c = Replica { state: a.state.clone(), src: node(3), lo: 1 };
    let (older, src, range) = c.commit(1004, &[op(Op::Insert { at: 20_000, items: vec![s("old")] })], &text_view()).unwrap();
    let older = wired(&older, &src, range, 1004);
    let (newer, _, _) = a.commit(1005, &[op(Op::Insert { at: 20_000, items: vec![s("new")] })], &text_view()).unwrap();
    let _ = newer;
    let t = Instant::now();
    a.state.join(older);
    let older_join = t.elapsed();
    // a move: the next use places from scratch
    let (d, src, range) = b.commit(1006, &[op(Op::Move { at: 100, len: 10, to: 60_000 })], &text_view()).unwrap();
    let d = wired(&d, &src, range, 1006);
    let t = Instant::now();
    a.state.join(d);
    let _ = a.state.read();
    let move_join = t.elapsed();
    let snap = crate::wire::Snapshot { nonce: [0; 16], fragment: a.state.clone(), frontiers: Default::default() };
    let cx = DeltaCtx { ts: ts(1 << 40), own: node(9), range: CounterRange::EMPTY, kind: DeltaKind::Snapshot };
    let mut pages = crate::MemoryPages::new();
    let t = Instant::now();
    let bytes = crate::encode_snapshot(&snap, &cx, Some(&mut pages)).unwrap();
    let encode = t.elapsed();
    let t = Instant::now();
    crate::decode_snapshot(&bytes, &cx, &mut Interner::new(), Some(&mut pages)).unwrap();
    let decode = t.elapsed();
    eprintln!("10^5 text ({} elems): build {build:?}, read {read:?}, place {place:?}, one op {one_op:?}, two-op batch {two_ops:?}, small join {small_join:?}, join without a read {unread_join:?}, delete join {delete_join:?}, older concurrent insert join {older_join:?}, move join and read {move_join:?}, encode {encode:?}, decode {decode:?}", p.iter().count());
    let _ = v;
}

/// §6 (`seq_lin`): typing and deleting at random places, joined by another replica, keeps the
/// cached placement (no whole pass) and it equals a whole pass.
#[test]
fn cached_placement_follows_typing_spec_6() {
    let mut r = Rng(11);
    let mut a = Replica::new(1);
    let mut b = Replica::new(2);
    let mut kept = 0;
    for k in 0..200u64 {
        let n = read_str(&a.state).chars().count();
        let o = if n > 0 && r.chance(1, 4) { Op::Delete { at: r.below(n), len: 1 } } else { Op::Insert { at: r.below(n + 1), items: vec![s("xy")] } };
        let (d, _, _) = a.commit(k + 1, &[op(o)], &text_view()).unwrap();
        let before = read_str(&b.state);
        b.state.join(d);
        crate::testutil::check_lin(&b.state);
        if matches!(&b.state, Fragment::Seq(x) if x.lin_check() == Some(true)) {
            kept += 1;
        }
        assert_eq!(read_str(&a.state), read_str(&b.state), "after {before:?}");
    }
    assert!(kept >= 199, "kept {kept}");
    // joins without a read in between follow it too
    let cached = |b: &Replica| matches!(&b.state, Fragment::Seq(x) if x.lin_check() == Some(true));
    for k in 200..203u64 {
        let (d, _, _) = a.commit(k + 1, &[op(Op::Insert { at: 0, items: vec![s("z")] })], &text_view()).unwrap();
        b.state.join(d);
        assert!(cached(&b));
    }
    assert_eq!(read_str(&a.state), read_str(&b.state));
}

/// §6.1 sibling order (`seq_lin`): two writers typing at one place concurrently (each insert
/// lands next to the other's, older ones below newer siblings and their subtrees) keep the
/// cached placement of a third replica receiving both, equal to a whole pass.
#[test]
fn cached_placement_follows_concurrent_typing_spec_6() {
    let mut r = Rng(13);
    let mut a = Replica::new(1);
    a.commit(1, &[op(Op::Set(s(&"base text ".repeat(20))))], &text_view());
    let mut b = Replica { state: a.state.clone(), src: node(2), lo: 1 };
    let mut c = Replica { state: a.state.clone(), src: node(3), lo: 1 };
    let (mut kept, mut joins) = (0, 0);
    for k in 0..60u64 {
        // both type a word at the same visible index; b's write is older
        let n = read_str(&a.state).chars().count();
        let at = r.below(n + 1);
        let (db, _, _) = b.commit(2 * k + 2, &[op(Op::Insert { at, items: vec![s("bb")] })], &text_view()).unwrap();
        let (da, _, _) = a.commit(2 * k + 3, &[op(Op::Insert { at, items: vec![s("aaa")] })], &text_view()).unwrap();
        for d in if r.chance(1, 2) { [da.clone(), db.clone()] } else { [db.clone(), da.clone()] } {
            let _ = read_str(&c.state);
            c.state.join(d);
            crate::testutil::check_lin(&c.state);
            joins += 1;
            if matches!(&c.state, Fragment::Seq(x) if x.lin_check() == Some(true)) {
                kept += 1;
            }
        }
        a.state.join(db);
        b.state.join(da);
        assert_eq!(read_str(&a.state), read_str(&b.state));
        assert_eq!(read_str(&a.state), read_str(&c.state));
    }
    assert!(kept * 10 >= joins * 9, "kept {kept} of {joins}");
}

/// notes/api.md `edit`: a base element changed concurrently (and a remote insert beside it) is
/// never deleted or edited through a guessed pairing.
#[test]
fn list_edit_never_deletes_through_a_pair_spec_9() {
    let view = TyView(list_ty());
    let item = |a: i64, b: i64| Value::Map([(Value::Int(1), Value::Int(a)), (Value::Int(2), Value::Int(b))].into_iter().collect());
    let base = Value::List(vec![item(1, 1)]);
    for new in [Value::List(vec![]), Value::List(vec![item(2, 1)])] {
        let mut a = Replica::new(1);
        a.commit(1, &[op(Op::Set(base.clone()))], &view);
        let mut b = Replica { state: a.state.clone(), src: node(2), lo: 1 };
        let (z, _, _) = b.commit(2, &[op(Op::Insert { at: 0, items: vec![item(7, 7)] })], &view).unwrap();
        let (ch, _, _) = b.commit(3, &[PathOp { path: vec![PathSeg::Index(1), PathSeg::Field(2)], op: Op::Set(Value::Int(5)) }], &view).unwrap();
        a.state.join(z);
        a.state.join(ch);
        let ops = diff_values(Some(&base), &new, &view).unwrap();
        a.commit(4, &ops, &view);
        assert_eq!(a.state.read(), Some(Value::List(vec![item(7, 7), item(1, 5)])), "edit to {new:?}");
    }
}

/// §5.7 paste: the clipboard no longer matches when visible text lies inside its range.
#[test]
fn paste_refuses_a_range_with_visible_text_spec_5_7() {
    let mut a = Replica::new(1);
    a.commit(1, &[op(Op::Set(s("abcdef")))], &text_view());
    let dots = crate::cut_dots(&a.state, 1, 3).unwrap(); // "bcd"
    a.commit(2, &[op(Op::Delete { at: 1, len: 3 })], &text_view());
    // someone types inside the cut range (anchored at the hidden "c")
    let mut b = Replica { state: a.state.clone(), src: node(2), lo: 1 };
    let mut d = crate::seq::Seq::empty(true);
    let st = crate::stamp::Stamp::new(ts(3 << 16), node(2), 1);
    d.elems_mut().insert(st.dot.clone(), crate::seq::SeqElem { created: Some((st.clone(), crate::seq::Anchor::Dot(dots[1].clone()))), content: crate::seq::SeqContent::Char('X'), pos: vec![(st, crate::seq::Anchor::Dot(dots[1].clone()))], deleted: None, span: 1 });
    b.state.join(Fragment::Seq(d));
    assert_eq!(read_str(&b.state), "aXef");
    let mut bt = Batch::new(&b.state, Writer::new(ts(5 << 16), node(2), 2));
    assert!(bt.apply(&op(Op::Paste { dots, at: 3 }), &text_view()).is_err());
}

/// §9 identity rule: a list diff keeps the dot of an element it edits (paired in order), so a
/// concurrent nested write into that element survives.
#[test]
fn list_diff_keeps_dots_spec_9() {
    let view = TyView(list_ty());
    let item = |a: i64, b: i64| Value::Map([(Value::Int(1), Value::Int(a)), (Value::Int(2), Value::Int(b))].into_iter().collect());
    let mut a = Replica::new(1);
    a.commit(1, &[op(Op::Set(Value::List(vec![item(1, 1), item(2, 2)])))], &view);
    let mut b = Replica { state: a.state.clone(), src: node(2), lo: 1 };
    let (bd, _, _) = b.commit(2, &[PathOp { path: vec![PathSeg::Index(1), PathSeg::Field(2)], op: Op::Set(Value::Int(7)) }], &view).unwrap();
    a.commit(3, &[op(Op::Set(Value::List(vec![item(1, 1), item(9, 2), item(3, 3)])))], &view);
    a.state.join(bd);
    assert_eq!(a.state.read(), Some(Value::List(vec![item(1, 1), item(9, 7), item(3, 3)])));
}

/// §5.7 Undo: a move undoes by writing the old anchors back (notes/crdt.md worked example).
#[test]
fn move_undo_spec_5_7() {
    let mut a = Replica::new(1);
    a.commit(1, &[op(Op::Set(s("FOOBAR")))], &text_view());
    let before = a.state.clone();
    let (d, src, range) = a.commit(2, &[op(Op::Move { at: 0, len: 3, to: 3 })], &text_view()).unwrap();
    assert_eq!(read_str(&a.state), "BARFOO");
    let u = Undone { delta: &d, source: &src, range, restored: &|_| false };
    let mut w = Writer::new(ts(3 << 16), node(1), a.lo);
    let full = undo(&mut w, &u, &a.state, &before, &text_view()).unwrap().unwrap();
    let mut w2 = Writer::new(ts(3 << 16), node(1), a.lo);
    assert_eq!(undo(&mut w2, &u, &a.state, &before.footprint(&d), &text_view()).unwrap(), Some(full.clone()), "the footprint as the buffer");
    a.state.join(full);
    assert_eq!(read_str(&a.state), "FOOBAR");
    // a later move of the same element makes the undo a no-op for it
    let mut b = Replica::new(2);
    b.state = before.clone();
    b.state.join(d.clone());
    b.commit(4, &[op(Op::Move { at: 3, len: 1, to: 0 })], &text_view());
    let mut w = Writer::new(ts(5 << 16), node(1), a.lo);
    let x = undo(&mut w, &u, &b.state, &before, &text_view()).unwrap();
    assert!(x.is_some_and(|x| match x {
        Fragment::Seq(sq) => sq.elems().len() == 1,
        _ => false,
    }));
}

/// A random list op: insert, delete, move, or a nested field set through `PathSeg::Index`.
fn random_list_op(r: &mut Rng, st: &Fragment, ty: &Ty) -> PathOp {
    let Ty::List(et) = ty else { panic!() };
    let n = match st.read() {
        Some(Value::List(l)) => l.len(),
        _ => 0,
    };
    let o = match r.below(4) {
        0 => Op::Insert { at: r.below(n + 1), items: vec![value(&random_value(r, et, 1))] },
        1 if n > 0 => Op::Delete { at: r.below(n), len: 1 },
        2 if n > 1 => {
            let at = r.below(n);
            Op::Move { at, len: 1, to: r.below(n) }
        }
        3 if n > 0 => {
            let i = r.below(n);
            return PathOp { path: vec![PathSeg::Index(i), PathSeg::Field(1 + r.below(2) as u64)], op: Op::Set(Value::Int(r.below(5) as i64)) };
        }
        _ => Op::Insert { at: 0, items: vec![value(&random_value(r, et, 1))] },
    };
    op(o)
}

/// §5.7 Ops: create equals the model's write for write; move and insert likewise.
#[test]
fn ops_match_model_spec_5_7() {
    let mut r = Rng(7);
    for _ in 0..20 {
        let mut mw = MWriter::new(crdt_model::stamp::Source::node(1), 1 << 16, 1);
        let text = crdt_model::r#gen::random_text(&mut r, 8) + "xyz";
        let mv = crdt_model::value::Value::Str(text.clone());
        let mut w = writer(&mw);
        let m = mops::create(&mut mw, &Ty::Text, &mv);
        assert_eq!(create(&mut w, &text_view(), &s(&text)).unwrap(), frag(&m));
        let mut ms = m.clone();
        ms.prune(None);
        let st = frag(&ms);
        let n = text.chars().count();
        // move
        let (at, len) = (r.below(n - 1), 2);
        let to = r.below(n - len + 1);
        mw.next_commit(2 << 16);
        let mut w = writer(&mw);
        let md = mops::seq_move(&mut mw, &ms, at, len, to).unwrap();
        let d = crate::ops::leaf(&mut w, Some(&st), &text_view(), &Op::Move { at, len, to }, true).unwrap().unwrap();
        assert_eq!(d, frag(&md));
        // insert
        mw.next_commit(3 << 16);
        let mut w = writer(&mw);
        let at = r.below(n + 1);
        let md = mops::seq_insert(&mut mw, Some(&ms), true, at, vec![Content::Char('q')]);
        let d = crate::ops::leaf(&mut w, Some(&st), &text_view(), &Op::Insert { at, items: vec![s("q")] }, true).unwrap().unwrap();
        assert_eq!(d, frag(&md));
    }
}

/// §5.7 cut, paste: a paste of cut text moves the original elements back and undeletes them, so
/// concurrent edits anchored inside the cut text follow it.
#[test]
fn cut_and_paste_keeps_identity_spec_5_7() {
    let mut a = Replica::new(1);
    a.commit(1, &[op(Op::Set(s("one two three")))], &text_view());
    let dots = crate::cut_dots(&a.state, 4, 4).unwrap(); // "two "
    a.commit(2, &[op(Op::Delete { at: 4, len: 4 })], &text_view());
    assert_eq!(read_str(&a.state), "one three");
    // a remote inserts inside "two" before seeing the cut
    let mut b = Replica::new(2);
    b.state = a.state.clone();
    let mut pre = Fragment::default();
    pre.join(a.state.clone());
    a.commit(3, &[op(Op::Paste { dots: dots.clone(), at: 9 })], &text_view());
    assert_eq!(read_str(&a.state), "one threetwo ");
    // the pasted elements are the cut ones
    let Fragment::Seq(sq) = &a.state else { panic!() };
    let vis = visible(sq);
    assert_eq!(vis.iter().skip(9).take(4).cloned().collect::<Vec<_>>(), dots);
    // a paste whose clipboard no longer matches fails (the caller inserts instead)
    let mut c = Replica::new(3);
    c.commit(1, &[op(Op::Set(s("x")))], &text_view());
    let mut bt = Batch::new(&c.state, Writer::new(ts(5 << 16), node(3), c.lo));
    assert!(bt.apply(&op(Op::Paste { dots, at: 0 }), &text_view()).is_err());

}

/// §5.7: a list delete against a concurrent newer nested write resurrects the element holding
/// only the newer write, on every node; an older nested write is dropped.
#[test]
fn list_delete_vs_concurrent_nested_write_spec_5_7() {
    let ty = Ty::List(Box::new(Ty::Struct([(1, Ty::Register), (2, Ty::Register)].into_iter().collect())));
    let view = TyView(ty);
    let item = |a: i64, b: i64| Value::Map([(Value::Int(1), Value::Int(a)), (Value::Int(2), Value::Int(b))].into_iter().collect());
    let mut a = Replica::new(1);
    a.commit(1, &[op(Op::Set(Value::List(vec![item(1, 2)])))], &view);
    let base = a.state.clone();
    let mut b = Replica::new(2);
    b.state = base.clone();
    let (del, _, _) = b.commit(5, &[op(Op::Delete { at: 0, len: 1 })], &view).unwrap();
    let mut c = Replica::new(3);
    c.state = base.clone();
    let field = |v: i64| PathOp { path: vec![PathSeg::Index(0), PathSeg::Field(2)], op: Op::Set(Value::Int(v)) };
    let (newer, _, _) = c.commit(6, &[field(9)], &view).unwrap();
    let mut d = Replica::new(4);
    d.state = base.clone();
    let (older, _, _) = d.commit(4, &[field(7)], &view).unwrap();
    let only = Value::List(vec![Value::Map([(Value::Int(2), Value::Int(9))].into_iter().collect())]);
    let mut s1 = base.clone();
    s1.join(del.clone());
    s1.join(older.clone());
    assert_eq!(s1.read(), Some(Value::List(vec![])), "an older nested write loses to the reset");
    s1.join(newer.clone());
    assert_eq!(s1.read(), Some(only.clone()));
    let mut s2 = base.clone();
    for x in [&newer, &older, &del] {
        s2.join(x.clone());
    }
    assert_eq!(s1, s2);
}

/// §7, §4.7, §6.1: an insert anchored at an embedded character keeps its place after the
/// register write expires, whether a node saw the value or only the value-less register.
#[test]
fn derived_anchor_outlives_its_register_spec_7() {
    let reg_w = |v: Option<Value>| {
        let mut w = Writer::new(ts(1 << 16), node(1), 1);
        let mut f = create(&mut w, &crate::AnyView, &s("ab")).unwrap();
        if let Fragment::Register(r) = &mut f {
            r.write.as_mut().unwrap().value = v;
        }
        f
    };
    let embedded = |f: Fragment| match f {
        Fragment::Register(r) => crate::state::embed(&r, crate::Encoding::Text).unwrap(),
        _ => panic!(),
    };
    // a text slot alone: the register's embedding
    let mut p = Fragment::default();
    p.join(embedded(reg_w(Some(s("ab")))));
    assert_eq!(read_str(&p), "ab");
    let mut b = Replica::new(2);
    b.state = p.clone();
    let (q, _, _) = b.commit(2, &[op(Op::Insert { at: 1, items: vec![s("q")] })], &text_view()).unwrap();
    p.join(q.clone());
    assert_eq!(read_str(&p), "aqb");
    let expired = |d: &crate::Dot| d.src == node(1) && d.ctr == 1;
    p.strip(&expired);
    assert_eq!(read_str(&p), "q");
    // a node that only saw the value-less register
    let mut n2 = Fragment::default();
    n2.join(embedded(reg_w(None)));
    n2.join(q);
    n2.strip(&expired);
    assert_eq!(n2, p);
}

/// §4.6, §5.7 Undo: an element moved twice undoes twice: the second move's undo restores the
/// first move's anchor, so the first move's undo (the winner is that restoring write) writes
/// the anchor before it.
#[test]
fn move_undo_chain_spec_4_6() {
    let mut a = Replica::new(1);
    a.commit(1, &[op(Op::Set(s("FOOBAR")))], &text_view());
    let s0 = a.state.clone();
    let (m1, src, r1) = a.commit(2, &[op(Op::Move { at: 0, len: 1, to: 5 })], &text_view()).unwrap();
    assert_eq!(read_str(&a.state), "OOBARF");
    let s1 = a.state.clone();
    let (m2, _, r2) = a.commit(3, &[op(Op::Move { at: 5, len: 1, to: 2 })], &text_view()).unwrap();
    assert_eq!(read_str(&a.state), "OOFBAR");
    let none = |_: &crate::Stamp| false;
    let mut w = Writer::new(ts(4 << 16), node(1), a.lo);
    let u2 = undo(&mut w, &Undone { delta: &m2, source: &src, range: r2, restored: &none }, &a.state, &s1, &text_view()).unwrap().unwrap();
    a.lo = w.range().hi;
    a.state.join(u2);
    assert_eq!(read_str(&a.state), "OOBARF");
    let restored = |x: &crate::Stamp| x.ts == ts(4 << 16);
    let mut w = Writer::new(ts(5 << 16), node(1), a.lo);
    assert!(undo(&mut w, &Undone { delta: &m1, source: &src, range: r1, restored: &none }, &a.state, &s0, &text_view()).unwrap().is_none_or(|x| read_str(&{
        let mut t = a.state.clone();
        t.join(x);
        t
    }) != "FOOBAR"));
    let mut w = Writer::new(ts(5 << 16), node(1), a.lo);
    let u1 = undo(&mut w, &Undone { delta: &m1, source: &src, range: r1, restored: &restored }, &a.state, &s0, &text_view()).unwrap().unwrap();
    a.state.join(u1);
    assert_eq!(read_str(&a.state), "FOOBAR");
}

/// A writer's delta through the wire: encoded and decoded under its header range (deletes come
/// back as range records).
fn wired(d: &Fragment, src: &Source, range: CounterRange, t: u64) -> Fragment {
    let cx = DeltaCtx { ts: ts(t << 16), own: src.clone(), range, kind: DeltaKind::Writer };
    let bytes = encode_delta(&Delta { nonce: [0; 16], fragment: d.clone() }, &cx, None).unwrap();
    decode_delta(&bytes, &cx, &mut Interner::new(), None).unwrap().fragment
}

/// §6 (`seq_lin`), §3.3 rule 3: deltas joined as received from the wire (a delete of several
/// elements is one range record over several state records) keep the cached placement, equal
/// to a whole pass after every join.
#[test]
fn cached_placement_follows_wire_deltas_spec_6() {
    let mut r = Rng(17);
    let mut a = Replica::new(1);
    let mut b = Replica::new(2);
    let (mut kept, mut joins) = (0, 0);
    for k in 0..150u64 {
        let n = read_str(&a.state).chars().count();
        let o = if n > 4 && r.chance(1, 3) {
            let at = r.below(n - 3);
            Op::Delete { at, len: 1 + r.below(3) }
        } else {
            Op::Insert { at: r.below(n + 1), items: vec![s("abc")] }
        };
        let (d, src, range) = a.commit(k + 1, &[op(o)], &text_view()).unwrap();
        let _ = read_str(&b.state);
        b.state.join(wired(&d, &src, range, k + 1));
        crate::testutil::check_lin(&b.state);
        joins += 1;
        if matches!(&b.state, Fragment::Seq(x) if x.lin_check() == Some(true)) {
            kept += 1;
        }
        assert_eq!(read_str(&a.state), read_str(&b.state));
    }
    assert!(kept + 2 >= joins, "kept {kept} of {joins}");
}

/// §6.1 sibling order (`seq_lin`): a run anchored where a newer and an older run already hang
/// lands between them, without a whole pass.
#[test]
fn cached_placement_between_siblings_spec_6() {
    let mut base = Replica::new(1);
    base.commit(1, &[op(Op::Set(s(&"x".repeat(80))))], &text_view());
    let fork = |n: u8| Replica { state: base.state.clone(), src: node(n), lo: 1 };
    let (mut old, mut mid, mut new, mut d) = (fork(2), fork(3), fork(4), fork(5));
    let at = |o: Op| [op(o)];
    let (dold, _, _) = old.commit(2, &at(Op::Insert { at: 40, items: vec![s("ooo")] }), &text_view()).unwrap();
    let (dmid, _, _) = mid.commit(4, &at(Op::Insert { at: 40, items: vec![s("mm")] }), &text_view()).unwrap();
    let (dnew, _, _) = new.commit(6, &at(Op::Insert { at: 40, items: vec![s("nnnn")] }), &text_view()).unwrap();
    for x in [dold, dnew, dmid] {
        let _ = read_str(&d.state);
        d.state.join(x);
        crate::testutil::check_lin(&d.state);
        assert!(matches!(&d.state, Fragment::Seq(q) if q.lin_check() == Some(true)), "followed");
    }
    assert_eq!(read_str(&d.state), format!("{}nnnnmmooo{}", "x".repeat(40), "x".repeat(40)));
}

/// §4.5 (`Batch`): sequence ops at one position resolve against a kept view of it once the
/// batch has written there; an op elsewhere drops it; the result equals one-by-one commits.
#[test]
fn batch_keeps_sequence_view_spec_4_5() {
    let ty = Ty::Struct([(1, Ty::Text), (2, Ty::Register)].into_iter().collect());
    let view = TyView(ty);
    let mut a = Replica::new(1);
    let f = |text: &str| Value::Map([(Value::Int(1), s(text)), (Value::Int(2), Value::Int(0))].into_iter().collect());
    a.commit(1, &[op(Op::Set(f("hello world")))], &view);
    let text = |o: Op| PathOp { path: vec![PathSeg::Field(1)], op: o };
    let mut bt = Batch::new(&a.state, Writer::new(ts(2 << 16), node(1), a.lo));
    bt.apply(&text(Op::Insert { at: 5, items: vec![s(",")] }), &view).unwrap();
    assert!(!bt.keeps_view(), "nothing of the batch there before the first op");
    bt.apply(&text(Op::Insert { at: 0, items: vec![s(">")] }), &view).unwrap();
    assert!(bt.keeps_view());
    bt.apply(&text(Op::Delete { at: 8, len: 2 }), &view).unwrap();
    assert!(bt.keeps_view());
    bt.apply(&PathOp { path: vec![PathSeg::Field(2)], op: Op::Set(Value::Int(7)) }, &view).unwrap();
    assert!(!bt.keeps_view(), "dropped by an op elsewhere");
    assert_eq!(bt.view().read(), Some(Value::Map([(Value::Int(1), s(">hello, rld")), (Value::Int(2), Value::Int(7))].into_iter().collect())));
}
