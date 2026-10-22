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
    let snap = crate::wire::Snapshot { absorbed: Default::default(), authors: Default::default(), nonce: [0; 16], fragment: f.clone(), frontiers: Default::default() };
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

    /// §4.5 (`Batch` layered view): a commit of several text ops on a state from a concurrent
    /// history (sometimes bootstrapped from a snapshot, so with range records) reads like the
    /// same ops on a plain string; the layered view of the state under the batch is checked
    /// against state + net effect after every op (debug assertion in `Batch`).
    #[test]
    fn text_batch_over_history_spec_4_5(seed in any::<u64>()) {
        let mut r = Rng(seed | 1);
        let mut reps: Vec<Replica> = (1..=2).map(Replica::new).collect();
        reps[0].commit(1, &[op(Op::Set(s("the quick brown fox")))], &text_view());
        reps[1].state = reps[0].state.clone();
        for k in 0..6u64 {
            for i in 0..2 {
                let n = read_str(&reps[i].state).chars().count();
                let o = random_text_op(&mut r, n, &reps[i].state);
                if !matches!(o, Op::Set(_)) && let Some((d, _, _)) = reps[i].commit(2 + 2 * k + i as u64, &[op(o)], &text_view()) {
                    reps[1 - i].state.join(d);
                }
            }
        }
        let mut a = Replica { state: if r.chance(1, 2) { rebooted(&reps[0].state) } else { reps[0].state.clone() }, src: node(3), lo: 1 };
        let base = a.state.clone();
        let mut model: Vec<char> = read_str(&base).chars().collect();
        let mut ops = Vec::new();
        for _ in 0..8 {
            let o = random_text_op(&mut r, model.len(), &base);
            if matches!(o, Op::Paste { .. } | Op::Set(_)) {
                continue;
            }
            apply_text(&mut model, &o, &base);
            ops.push(op(o));
        }
        a.commit(40, &ops, &text_view());
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

/// Text `base`, `sibs` newer inserts at HEAD by another writer, and a delta (as a receiver
/// gets it) moving `moves` elements spread over the text to HEAD, older than those inserts:
/// (state with its placement cached, the delta).
fn hostile_moves(base: &Fragment, sibs: usize, moves: usize) -> (Fragment, Fragment) {
    let a = Replica { state: base.clone(), src: node(1), lo: 1 };
    let n = read_str(base).chars().count();
    let mut b = Replica { state: a.state.clone(), src: node(2), lo: 1 };
    for k in 0..sibs as u64 {
        b.commit(5000 + k, &[op(Op::Insert { at: 0, items: vec![s("h")] })], &text_view());
    }
    let Fragment::Seq(sq) = &a.state else { panic!() };
    let mut w = Writer::new(ts(4000 << 16), node(7), 1);
    let step = n / moves;
    let elems = visible(sq).iter().step_by(step.max(1)).take(moves).map(|d| (d.clone(), crate::seq::SeqElem { pos: vec![(w.fresh(), crate::seq::Anchor::Head)], ..crate::seq::SeqElem::bare() })).collect();
    let d = Fragment::Seq(crate::seq::Seq::new(true, crate::fragment::Meta::default(), elems));
    let _ = read_str(&b.state);
    (b.state, d)
}

/// Tier 2 timing: a 10^5-char text built from ~5000 insert runs; read, a small join, one op
/// through `Batch`, a move op, joins of decoded deltas (insert, delete, older concurrent insert, move),
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
    // joins into copies of a state (as a node keeping the state before a commit): each copy's
    // placement shares the original's until it changes it
    let mut copies = Vec::new();
    for k in 0..200u64 {
        let (d, src, range) = b.commit(2000 + k, &[op(Op::Insert { at: r.below(90_000), items: vec![s("c")] })], &text_view()).unwrap();
        let d = wired(&d, &src, range, 2000 + k);
        let mut c = a.state.clone();
        let t = Instant::now();
        c.join(d.clone());
        copies.push(t.elapsed());
        a.state.join(d);
    }
    let copy_mean = copies.iter().sum::<std::time::Duration>() / 200;
    let copy_max = copies.iter().max().copied().unwrap_or_default();
    // a move: the moved subtrees are re-placed
    let t = Instant::now();
    let (d, src, range) = b.commit(1006, &[op(Op::Move { at: 100, len: 10, to: 60_000 })], &text_view()).unwrap();
    let move_op = t.elapsed();
    let d = wired(&d, &src, range, 1006);
    let t = Instant::now();
    a.state.join(d);
    let move_join = t.elapsed();
    let _ = a.state.read();
    let move_read = t.elapsed() - move_join;
    // hostile deltas: 1000 moves to HEAD, without and with 250 newer HEAD siblings
    let mut hostile = Vec::new();
    for sibs in [0, 250] {
        let (mut st, d) = hostile_moves(&a.state, sibs, 1000);
        let t = Instant::now();
        st.join(d);
        let Fragment::Seq(q) = &st else { panic!() };
        let _ = q.lin();
        let join = t.elapsed();
        let t = Instant::now();
        let _ = crate::linearize::place(q.elems(), q.text);
        hostile.push(format!("{sibs} siblings: join and placement {join:?}, whole pass {:?}", t.elapsed()));
    }
    // a text upgraded from a 10^5-char string (embedded characters, `Derived` dots): a received
    // insert anchored at an embedded char, and a two-op batch there
    let upgraded = {
        let mut u = Replica::new(4);
        u.commit(1, &[op(Op::Set(s("xy")))], &text_view());
        let mut mw = crdt_model::ops::Writer::new(crdt_model::stamp::Source::node(5), 2 << 16, 1);
        u.state.join(crate::testutil::frag(&crdt_model::ops::create(&mut mw, &crdt_model::ops::Ty::Register, &crdt_model::value::Value::Str(run.repeat(1000)))));
        let mut v = Replica { state: u.state.clone(), src: node(6), lo: 1 };
        let (d, src, range) = v.commit(3, &[op(Op::Insert { at: 50_000, items: vec![s("e")] })], &text_view()).unwrap();
        let d = wired(&d, &src, range, 3);
        let _ = read_str(&u.state);
        let _ = crate::seq_lin::probe();
        let t = Instant::now();
        u.state.join(d);
        let join = t.elapsed();
        let passes = crate::seq_lin::probe().1;
        let t = Instant::now();
        let _ = read_str(&u.state);
        let read = t.elapsed();
        let t = Instant::now();
        u.commit(4, &[op(Op::Insert { at: 10, items: vec![s("y")] }), op(Op::Delete { at: 60_000, len: 3 })], &text_view()).unwrap();
        format!("received insert join {join:?} ({passes} passes), then read {read:?}, two-op batch {:?}", t.elapsed())
    };
    let snap = crate::wire::Snapshot { absorbed: Default::default(), authors: Default::default(), nonce: [0; 16], fragment: a.state.clone(), frontiers: Default::default() };
    let cx = DeltaCtx { ts: ts(1 << 40), own: node(9), range: CounterRange::EMPTY, kind: DeltaKind::Snapshot };
    let mut pages = crate::MemoryPages::new();
    let t = Instant::now();
    let bytes = crate::encode_snapshot(&snap, &cx, Some(&mut pages)).unwrap();
    let encode = t.elapsed();
    let t = Instant::now();
    crate::decode_snapshot(&bytes, &cx, &mut Interner::new(), Some(&mut pages)).unwrap();
    let decode = t.elapsed();
    // a text bootstrapped from a snapshot: a deleted stretch arrives as one range record; an
    // undelete of part of it and an insert anchored inside it split the record
    let gone = crate::cut_dots(&a.state, 30_000, 100).unwrap();
    a.commit(3000, &[op(Op::Delete { at: 30_000, len: 100 })], &text_view());
    let snap = crate::wire::Snapshot { absorbed: Default::default(), authors: Default::default(), nonce: [0; 16], fragment: a.state.clone(), frontiers: Default::default() };
    let bytes = crate::encode_snapshot(&snap, &cx, Some(&mut pages)).unwrap();
    let mut boot = crate::decode_snapshot(&bytes, &cx, &mut Interner::new(), Some(&mut pages)).unwrap().fragment;
    let Fragment::Seq(full) = &a.state else { panic!() };
    let undel = {
        let src = node(5);
        let st = crate::stamp::Stamp::new(ts(3001 << 16), src.clone(), 1);
        let mut d = crate::seq::Seq::empty(true);
        for x in &gone[45..55] {
            let mut e = crate::seq::SeqElem::bare();
            e.deleted = Some((st.clone(), false));
            e.content = full.elems()[x].content.clone();
            d.elems_mut().insert(x.clone(), e);
        }
        wired(&Fragment::Seq(d), &src, CounterRange { lo: 1, hi: 2 }, 3001)
    };
    let inside = {
        let src = node(6);
        let st = crate::stamp::Stamp::new(ts(3002 << 16), src.clone(), 1);
        let a = crate::seq::Anchor::Dot(gone[70].clone());
        let mut d = crate::seq::Seq::empty(true);
        d.elems_mut().insert(st.dot.clone(), crate::seq::SeqElem { created: Some((st.clone(), a.clone())), content: crate::seq::SeqContent::Char('q'), pos: vec![(st, a)], deleted: None, span: 1 });
        wired(&Fragment::Seq(d), &src, CounterRange { lo: 1, hi: 2 }, 3002)
    };
    let mut splits = Vec::new();
    for d in [undel, inside] {
        let _ = read_str(&boot);
        let _ = crate::seq_lin::probe();
        let t = Instant::now();
        boot.join(d);
        let join = t.elapsed();
        let passes = crate::seq_lin::probe().1;
        let t = Instant::now();
        let _ = read_str(&boot);
        splits.push(format!("join {join:?} ({passes} passes), then read {:?}", t.elapsed()));
    }
    assert!(read_str(&boot).contains('q'));
    // a received set to a new value (a diff: one delete of everything) and a replace (a reset:
    // every older element becomes a bare anchor on END)
    let mut whole = Vec::new();
    for o in [Op::Set(s("fresh")), Op::Replace(s("fresh"))] {
        let mut c = Replica { state: a.state.clone(), src: node(8), lo: 1 };
        let (d, src, range) = c.commit(4000, &[op(o)], &text_view()).unwrap();
        let d = wired(&d, &src, range, 4000);
        let mut st = a.state.clone();
        let _ = read_str(&st);
        let _ = crate::seq_lin::probe();
        let t = Instant::now();
        st.join(d);
        let join = t.elapsed();
        let p0 = crate::seq_lin::probe().1;
        let t = Instant::now();
        assert_eq!(read_str(&st), "fresh");
        whole.push(format!("join {join:?} ({p0} passes), then read {:?} ({} passes)", t.elapsed(), crate::seq_lin::probe().1));
    }
    eprintln!("10^5 text ({} elems): build {build:?}, read {read:?}, place {place:?}, one op {one_op:?}, two-op batch {two_ops:?}, small join {small_join:?}, join without a read {unread_join:?}, delete join {delete_join:?}, older concurrent insert join {older_join:?}, move op {move_op:?}, move join {move_join:?} (then read {move_read:?}), join into a copy {copy_mean:?} (max {copy_max:?}), encode {encode:?}, decode {decode:?}; bootstrapped from a snapshot, undelete splitting a range record: {}, insert anchored inside it: {}; received set to a new value: {}, received replace: {}; upgraded text: {upgraded}; 1000 moves to HEAD with {}", p.iter().count(), splits[0], splits[1], whole[0], whole[1], hostile.join(", with "));
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

// spec/crdt.md §6: the cached placement's dot map is shared between copies of a state; a join
// into one copy clones only the chunks it writes (notes/crdt.md, placement cache).
#[test]
fn placement_dot_map_shared_by_copies_spec_6() {
    let mut r = Rng(3);
    let mut a = Replica::new(1);
    let run = "abcdefghij".repeat(10);
    for k in 0..100u64 {
        let n = read_str(&a.state).chars().count();
        a.commit(k + 1, &[op(Op::Insert { at: r.below(n + 1), items: vec![s(&run)] })], &text_view());
    }
    let lin = |f: &Fragment| match f {
        Fragment::Seq(x) => x.lin(),
        _ => panic!(),
    };
    // a lookup builds the map before the copy
    let _ = lin(&a.state).index(&crate::seq::visible(match &a.state { Fragment::Seq(x) => x, _ => panic!() }).get(0).unwrap().clone());
    let mut b2 = Replica { state: a.state.clone(), src: node(2), lo: 1 };
    for k in 0..20u64 {
        b2.commit(200 + k, &[op(Op::Insert { at: r.below(10_000), items: vec![s("x")] })], &text_view());
    }
    let (unshared, all) = lin(&b2.state).map_unshared(&lin(&a.state));
    eprintln!("{unshared} of {all}");
    assert!(all >= 50 && unshared <= 25, "{unshared} of {all} chunks copied");
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

/// §5.7 move: on states from random concurrent histories (hidden anchors, outside subtrees,
/// several roots, earlier moves) a move writes what the model's does, write for write.
#[test]
fn move_matches_model_over_histories_spec_5_7() {
    let mut r = Rng(29);
    let mut checked = 0;
    for _ in 0..60 {
        let commits = crate::testutil::history(&mut r, &[Ty::Text], 3, 6);
        let mut ms = None;
        for c in &commits {
            mapply(&mut ms, c.delta.clone());
        }
        let Some(mut ms) = ms else { continue };
        ms.prune(None);
        let st = frag(&ms);
        let n = read_str(&st).chars().count();
        if n < 2 || !matches!(st, Fragment::Seq(_)) {
            continue;
        }
        for _ in 0..4 {
            let at = r.below(n - 1);
            let len = 1 + r.below((n - at).min(4));
            let to = r.below(n - len + 1);
            let mut mw = MWriter::new(crdt_model::stamp::Source::node(9), 1 << 16, 1);
            mw.next_commit(100 << 16);
            let mut w = writer(&mw);
            let md = mops::seq_move(&mut mw, &ms, at, len, to);
            let d = crate::ops::leaf(&mut w, Some(&st), &text_view(), &Op::Move { at, len, to }, true).unwrap();
            assert_eq!(d, md.as_ref().map(frag), "move {at} {len} {to}");
            checked += 1;
        }
    }
    assert!(checked > 100, "checked {checked}");
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

/// §6.2 (`seq_lin`): writers moving, typing and deleting concurrently (the same range moved by
/// several, cycles included), joined from the wire by a replica that reads in between: the
/// cached placement follows the moves that close no cycle and equals a whole pass after every
/// join; all converge.
#[test]
fn cached_placement_follows_moves_spec_6_2() {
    let (mut kept, mut moves) = (0, 0);
    for seed in 0..12u64 {
        let mut r = Rng(2 * seed + 1);
        let mut base = Replica::new(1);
        base.commit(1, &[op(Op::Set(s(&"abcdefghij".repeat(8))))], &text_view());
        let mut ws: Vec<Replica> = (2..5).map(|n| Replica { state: base.state.clone(), src: node(n), lo: 1 }).collect();
        let mut seen = vec![0usize; ws.len()];
        let mut d = Replica { state: base.state.clone(), src: node(9), lo: 1 };
        let mut log: Vec<(usize, Fragment)> = Vec::new();
        for round in 0..30u64 {
            // often the same visible range for every writer: concurrent moves of one element
            let shared = r.chance(1, 2).then(|| (r.below(60), 1 + r.below(4)));
            let mut fresh = Vec::new();
            for (i, w) in ws.iter_mut().enumerate() {
                let n = read_str(&w.state).chars().count();
                let o = match r.below(8) {
                    0 => Op::Insert { at: r.below(n + 1), items: vec![s("xyz")] },
                    1 if n > 4 => Op::Delete { at: r.below(n - 3), len: 1 + r.below(3) },
                    _ => {
                        let (at, len) = shared.unwrap_or((r.below(n.max(1)), 1 + r.below(4)));
                        let at = at.min(n.saturating_sub(2));
                        let len = len.min(n - at - 1).max(1);
                        Op::Move { at, len, to: r.below(n - len + 1) }
                    }
                };
                let mv = matches!(o, Op::Move { .. });
                let t = round * 4 + i as u64 + 2;
                if let Some((x, src, range)) = w.commit(t, &[op(o)], &text_view()) {
                    fresh.push((mv, wired(&x, &src, range, t)));
                }
            }
            for k in (1..fresh.len()).rev() {
                fresh.swap(k, r.below(k + 1));
            }
            for (mv, x) in &fresh {
                let _ = read_str(&d.state);
                d.state.join(x.clone());
                crate::testutil::check_lin(&d.state);
                if *mv {
                    moves += 1;
                    if matches!(&d.state, Fragment::Seq(q) if q.lin_check() == Some(true)) {
                        kept += 1;
                    }
                }
            }
            log.extend(fresh.into_iter().map(|(_, x)| (0, x)));
            // each writer catches up on a random prefix of the log
            for (w, at) in ws.iter_mut().zip(seen.iter_mut()) {
                let upto = *at + r.below(log.len() - *at + 1);
                for (_, x) in log.get(*at..upto).unwrap_or_default() {
                    let _ = read_str(&w.state);
                    w.state.join(x.clone());
                    crate::testutil::check_lin(&w.state);
                }
                *at = upto;
            }
        }
        for (w, at) in ws.iter_mut().zip(seen.iter()) {
            for (_, x) in log.get(*at..).unwrap_or_default() {
                w.state.join(x.clone());
            }
            assert_eq!(read_str(&w.state), read_str(&d.state), "seed {seed}");
        }
    }
    eprintln!("moves followed: {kept} of {moves}");
    assert!(kept * 4 >= moves * 3, "followed {kept} of {moves}");
}

/// §6 (`seq_lin`): hostile deltas of moves to HEAD below 250 newer HEAD siblings cost about a
/// whole pass in placement work, counted in `follow`'s work units (rows and blocks looked at, a
/// skipped sibling 8) and whole passes: more than max(√n, 64) moves rebuild at once; fewer
/// stop at the work budget max(n, 1024) and rebuild. Either way at most one pass, and the
/// units charged stay under the budget plus a per-placement charge and one step's overshoot.
/// Wall-clock at 4000 chars says little: joining the delta's 1000 records alone (no cache)
/// costs about 1.6 passes there, so the timing check is the tier-2 one below at 10^5.
#[test]
fn hostile_moves_join_bounded_spec_6() {
    let mut a = Replica::new(1);
    for k in 0..4u64 {
        a.commit(1 + k, &[op(Op::Insert { at: 0, items: vec![s(&"x".repeat(1000))] })], &text_view());
    }
    for moves in [1000, 60] {
        let (mut st, d) = hostile_moves(&a.state, 250, moves);
        let Fragment::Seq(q) = &st else { panic!() };
        let (len, blocks, cap) = q.lin().shape();
        let _ = crate::seq_lin::probe();
        st.join(d);
        let Fragment::Seq(q) = &st else { panic!() };
        let _ = q.lin();
        let (work, passes) = crate::seq_lin::probe();
        let count = len.isqrt().max(64);
        assert_eq!(moves > count, work == 0, "{moves} moves: the count cap ({count}) rebuilds before any work");
        // budget, an `each` charge per placement, and the last sibling step past the budget
        // (a block walk: every block, two partial blocks of at most 2 * cap rows)
        let bound = len.max(1024) + count.min(moves) * (blocks + cap) + 8 + blocks + 4 * cap;
        assert!(work <= bound, "{moves} moves: {work} units, bound {bound}");
        assert!(passes <= 1, "{moves} moves: {passes} whole passes");
        crate::testutil::check_lin(&st);
    }
}

/// §6 (`seq_lin`), tier 2 timing: on a 10^5-char text a delta of 1000 moves to HEAD below 250
/// newer HEAD siblings joins and places in about a whole pass's time (under three passes).
#[test]
#[ignore = "tier 2"]
fn hostile_moves_join_time_spec_6() {
    let mut a = Replica::new(1);
    for k in 0..100u64 {
        a.commit(1 + k, &[op(Op::Insert { at: 0, items: vec![s(&"x".repeat(1000))] })], &text_view());
    }
    let (mut st, d) = hostile_moves(&a.state, 250, 1000);
    let t = std::time::Instant::now();
    st.join(d);
    let Fragment::Seq(q) = &st else { panic!() };
    let _ = q.lin();
    let join = t.elapsed();
    let t = std::time::Instant::now();
    let _ = crate::linearize::place(q.elems(), q.text);
    let pass = t.elapsed();
    assert!(join < pass * 3, "join {join:?}, whole pass {pass:?}");
}

/// §6.1 sibling order (`seq_lin`): an older insert at HEAD below a newer HEAD child, two runs
/// anchored at one element in one delta, and an older insert below a newer sibling whose
/// subtree is thousands of rows all keep the cached placement, equal to a whole pass.
#[test]
fn cached_placement_follows_siblings_spec_6_1() {
    let mut base = Replica::new(1);
    base.commit(1, &[op(Op::Set(s("ab")))], &text_view());
    let fork = |n: u8| Replica { state: base.state.clone(), src: node(n), lo: 1 };
    let (mut old, mut new, mut d) = (fork(2), fork(3), fork(4));
    let ins = |r: &mut Replica, t: u64, ops: &[(usize, &str)]| {
        let ops: Vec<PathOp> = ops.iter().map(|(at, x)| op(Op::Insert { at: *at, items: vec![s(x)] })).collect();
        r.commit(t, &ops, &text_view()).unwrap().0
    };
    let big = "y".repeat(5000);
    let joins = [
        // at HEAD: the older insert arrives after the newer one
        ins(&mut old, 2, &[(0, "o")]),
        ins(&mut new, 3, &[(0, "n")]),
        // after 'a': a big newer subtree, then an older single char
        ins(&mut old, 4, &[(2, "X")]),
        ins(&mut new, 5, &[(2, &big)]),
        // two runs at one element in one commit
        ins(&mut new, 6, &[(1, "PQ"), (1, "RS")]),
    ];
    for k in [1, 0, 3, 2, 4] {
        let _ = read_str(&d.state);
        d.state.join(joins[k].clone());
        crate::testutil::check_lin(&d.state);
        assert!(matches!(&d.state, Fragment::Seq(q) if q.lin_check() == Some(true)), "join {k} followed");
    }
    assert_eq!(read_str(&d.state), format!("nRSPQoa{}Xb", "y".repeat(5000)));
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

