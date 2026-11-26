//! Sequence ops, net effect, undo, cut/paste, diff and `edit` (spec/crdt.md §4.5, §4.6, §5.7, §9).

use crate::delta::DeltaBuilder;
use crate::fragment::Fragment;
use crate::ops::{Op, PathOp, PathSeg, Writer, create, diff, diff_values};
use crate::seq::visible;
use crate::stamp::{CounterRange, Source};
use crate::testutil::{Pager, TyView, build, frag, joined, mapply, node, ostate, s, text_view, ts, value, via_snapshot, writer};
use crate::undo::{Undone, undo};
use crate::wire::{DeltaCtx, DeltaKind};
use crdt_model::r#gen::{Rng, random_value};
use crdt_model::ops::{self as mops, Ty, Writer as MWriter};
use crdt_model::state::Content;
use osis_base::Value;
use proptest::prelude::*;

fn read_str(f: &Fragment) -> String {
    match f.read() {
        Some(Value::Str(x)) => x,
        _ => String::new(),
    }
}
fn list_ty() -> Ty {
    Ty::List(Box::new(Ty::Struct([(1, Ty::Register), (2, Ty::Register)].into_iter().collect())))
}
/// An element of `list_ty`.
fn item(a: i64, b: i64) -> Value {
    Value::Map([(Value::Int(1), Value::Int(a)), (Value::Int(2), Value::Int(b))].into_iter().collect())
}
/// Whether `f`'s placement is cached and equals a whole pass.
fn cached(f: &Fragment) -> bool {
    matches!(f, Fragment::Seq(x) if x.lin_check() == Some(true))
}

/// §8 (pages are joined independently), `seq_place`: `ops` by `w` on sequence `st` held in part
/// (pages of `per` records, loading what it misses) write what they write on the whole state.
/// (That commit, the pager.)
#[track_caller]
fn paged(st: &Fragment, per: usize, w: impl Fn() -> Writer, ops: &[PathOp], view: &TyView) -> (Option<(Fragment, CounterRange)>, Pager) {
    let Fragment::Seq(sq) = st else { panic!("a sequence") };
    let want = build(st, w(), ops, view);
    let mut pg = Pager::new(sq, per);
    let got = pg.run(|f| build(f, w(), ops, view));
    assert!(got == want, "{ops:?}\n got {got:?}\n want {want:?}");
    (want, pg)
}

/// The state of a random history of `ty` (`n` writers, `rounds` rounds) without the commits
/// held back (each one in `hold`), pruned, a third of the time through a snapshot: (state,
/// held back).
fn history_state(r: &mut Rng, ty: &Ty, n: usize, rounds: usize, hold: u64) -> (Option<Fragment>, Vec<crdt_model::state::Frag>) {
    let (mut ms, mut held) = (None, Vec::new());
    for c in crate::testutil::history(r, std::slice::from_ref(ty), n, rounds) {
        if r.chance(1, hold) {
            held.push(c.delta);
        } else {
            mapply(&mut ms, c.delta);
        }
    }
    let Some(mut ms) = ms else { return (None, held) };
    ms.prune(None);
    let st = frag(&ms);
    (Some(if r.chance(1, 3) { via_snapshot(&st) } else { st }), held)
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
    /// Writer `n` holding this replica's state.
    fn fork(&self, n: u8) -> Replica {
        Replica { state: self.state.clone(), src: node(n), lo: 1 }
    }
    /// Applies `ops` as one commit at time `t`; the delta goes through the wire as a writer's.
    fn commit(&mut self, t: u64, ops: &[PathOp], view: &TyView) -> Option<(Fragment, Source, CounterRange)> {
        let mut b = DeltaBuilder::new(&self.state, Writer::new(ts(t << 16), self.src.clone(), self.lo));
        for op in ops {
            b.apply(op, view).unwrap();
        }
        let (d, range) = b.finish()?;
        self.lo = range.hi;
        let back = wired(&d, &self.src, range, t);
        assert_eq!(back, d, "a writer's delta round-trips");
        self.state.join(back);
        crate::testutil::check_lin(&self.state);
        Some((d, self.src.clone(), range))
    }
    /// `commit` for a large test's setup: no wire round trip and no whole pass after it (both
    /// checked per commit by the tests of commits; a pass per setup commit is quadratic).
    fn grow(&mut self, t: u64, ops: &[PathOp], view: &TyView) {
        let mut b = DeltaBuilder::new(&self.state, Writer::new(ts(t << 16), self.src.clone(), self.lo));
        for op in ops {
            b.apply(op, view).unwrap();
        }
        if let Some((d, range)) = b.finish() {
            self.lo = range.hi;
            self.state.join(d);
        }
    }
}

/// A writer's delta through the wire: encoded and decoded under its header range (deletes come
/// back as range records).
fn wired(d: &Fragment, src: &Source, range: CounterRange, t: u64) -> Fragment {
    crate::testutil::wired(d, &DeltaCtx { ts: ts(t << 16), own: src.clone(), range, kind: DeltaKind::Writer })
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
                let e = crate::seq_span::Recs::elem(sq.elems(), &d).unwrap();
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
    /// §4.5, §7 (write into the slot of their schema's encoding), `DeltaBuilder` layered view: a commit of several text ops on a state from a
    /// concurrent history (sometimes upgraded from a string, a `Slots` position, and sometimes
    /// bootstrapped from a snapshot, so with range records) reads like the same ops on a plain
    /// string; the layered view of the state under the delta is checked against state + net
    /// effect after every op (debug assertion in `DeltaBuilder`).
    #[test]
    fn text_batch_over_history_spec_4_5(seed in any::<u64>()) {
        let mut r = crate::testutil::rng(seed | 1);
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
        if r.chance(1, 3) {
            let mut mw = crdt_model::ops::Writer::new(crdt_model::stamp::Source::session(5, 0), 30 << 16, 1);
            let v = crdt_model::value::Value::Str(crdt_model::r#gen::random_text(&mut r, 20) + "s");
            reps[0].state.join(crate::testutil::frag(&crdt_model::ops::create(&mut mw, &Ty::Register, &v)));
        }
        let mut a = Replica { state: if r.chance(1, 2) { via_snapshot(&reps[0].state) } else { reps[0].state.clone() }, src: node(3), lo: 1 };
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

    /// §4.6, §5.7 Undo: list insert, delete (re-insert), move and nested edits undo.
    #[test]
    fn list_undo_restores_spec_4_6(seed in any::<u64>()) {
        let ty = list_ty();
        let view = TyView(ty.clone());
        let mut r = crate::testutil::rng(seed | 1);
        let mut a = Replica::new(1);
        let v = value(&random_value(&mut r, &ty, 0));
        a.commit(1, &[op(Op::Set(v))], &view);
        for k in 0..3 {
            let o = random_list_op(&mut r, &a.state, &ty);
            a.commit(2 + k, &[o], &view);
        }
        let before = a.state.clone();
        let o = random_list_op(&mut r, &a.state, &ty);
        let Some((d, src, range)) = a.commit(10, &[o], &view) else { return Ok(()) };
        let u = Undone { delta: &d, source: &src, range };
        let mut w = Writer::new(ts(11 << 16), node(1), a.lo);
        let full = undo(&mut w, &u, &a.state, &before, &view).unwrap();
        prop_assert!(crate::undo::restores(&u) || w.copied().is_empty());
        if let Some(ud) = full {
            a.state.join(ud);
        }
        prop_assert_eq!(a.state.read(), before.read());
    }

    /// §9: the structural diff reaches the value, text and list, from random states.
    #[test]
    fn seq_diff_reaches_value_spec_9(seed in any::<u64>()) {
        let mut r = crate::testutil::rng(seed | 1);
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
        let mut r = crate::testutil::rng(seed | 1);
        let mut a = Replica::new(1);
        let base = "alpha beta gamma delta";
        a.commit(1, &[op(Op::Set(s(base)))], &text_view());
        // the user edits inside "beta", a remote appends after "delta"
        let new = base.replacen("beta", if r.chance(1, 2) { "BETA!" } else { "bet" }, 1);
        let ops = diff_values(Some(&s(base)), &s(&new), &text_view()).unwrap();
        let mut plain = a.state.clone();
        plain.join(build(&plain, Writer::new(ts(3 << 16), node(1), a.lo), &ops, &text_view()).unwrap().0);
        prop_assert_eq!(read_str(&plain), new.clone());
        let mut remote = a.fork(2);
        let (rd, _, _) = remote.commit(2, &[op(Op::Insert { at: base.len(), items: vec![s(" epsilon")] })], &text_view()).unwrap();
        a.state.join(rd);
        a.commit(3, &ops, &text_view());
        prop_assert_eq!(read_str(&a.state), format!("{new} epsilon"));
    }

    /// notes/api.md `edit` on a list: changed elements are edited in place (nested), so a
    /// concurrent edit to another field of the same element survives.
    #[test]
    fn list_edit_rebases_spec_9(seed in any::<u64>()) {
        let ty = list_ty();
        let view = TyView(ty.clone());
        let mut r = crate::testutil::rng(seed | 1);
            let base = Value::List((0..4).map(|k| item(k, 10 + k)).collect());
        let mut a = Replica::new(1);
        a.commit(1, &[op(Op::Set(base.clone()))], &view);
        let k = r.below(4);
        let Value::List(mut items) = base.clone() else { panic!() };
        items[k] = item(100, 10 + k as i64);
        let new = Value::List(items.clone());
        let ops = diff_values(Some(&base), &new, &view).unwrap();
        // remote: field 2 of element k
        let mut b = a.fork(2);
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
    use crate::seq::{Anchor, Seq, SeqContent, SeqElem};
    use crate::stamp::Stamp;
    let n = read_str(base).chars().count();
    // `sibs` chars inserted at HEAD one commit each (each newer than the last), joined as one
    // delta of their records: what those commits leave, without a whole pass per commit
    let hs = (0..sibs as u64).map(|k| {
        let st = Stamp::new(ts((5000 + k) << 16), node(2), k + 1);
        (st.dot.clone(), SeqElem { created: Some((st.clone(), Anchor::Head)), content: SeqContent::Char('h'), pos: vec![(st, Anchor::Head, None)], deleted: None, undel: None, span: 1, each: None })
    });
    let mut b = Replica { state: base.clone(), src: node(2), lo: 1 };
    b.state.join(Fragment::Seq(Seq::new(true, crate::fragment::Meta::default(), hs.collect())));
    assert_eq!(read_str(&b.state), "h".repeat(sibs) + &read_str(base));
    let Fragment::Seq(sq) = base else { panic!() };
    let mut w = Writer::new(ts(4000 << 16), node(7), 1);
    let step = n / moves;
    let elems = visible(sq).iter().step_by(step.max(1)).take(moves).map(|d| (d.clone(), crate::seq::SeqElem { pos: vec![(w.fresh(), crate::seq::Anchor::Head, None)], ..crate::seq::SeqElem::bare() })).collect();
    let d = Fragment::Seq(crate::seq::Seq::new(true, crate::fragment::Meta::default(), elems));
    let _ = read_str(&b.state);
    (b.state, d)
}

/// §6 (a deterministic function of state), `seq_lin`, spec/requirements.md Scale (a change costs O(change)): joins of small
/// received deltas (an insert, a delete, a move) into a text of `runs` insert runs at random
/// places follow the cached placement: no whole pass, and `follow`'s work units grow far below
/// linearly from n to 10n runs (counted: about √n, the block walk).
#[test]
fn small_joins_follow_cached_placement_spec_6() {
    let work = |runs: u64| {
        let mut r = crate::testutil::rng(0);
        let mut a = Replica::new(1);
        let mut len = 0usize;
        let run: String = "abcdefghij".repeat(10);
        for k in 0..runs {
            // the last run at the front: the moved chars are one record, so each size places
            // one piece (a move's work is per record it takes, and that count is random)
            let at = if k + 1 == runs { 0 } else { r.below(len + 1) };
            len += 100;
            a.grow(k + 1, &[op(Op::Insert { at, items: vec![s(&run)] })], &text_view());
        }
        crate::testutil::check_lin(&a.state);
        let mut b = a.fork(2);
        let ops = [Op::Insert { at: len / 3, items: vec![s("x")] }, Op::Delete { at: len / 2, len: 3 }, Op::Move { at: 10, len: 10, to: len / 2 }];
        let mut total = 0;
        for (i, o) in ops.into_iter().enumerate() {
            let t = runs + 1 + i as u64;
            let (d, _, _) = b.commit(t, &[op(o)], &text_view()).unwrap();
            let _ = read_str(&a.state);
            let _ = crate::seq_lin::probe();
            a.state.join(d);
            let Fragment::Seq(q) = &a.state else { panic!() };
            let _ = q.lin();
            let (w, passes) = crate::seq_lin::probe();
            assert_eq!(passes, 0, "{runs} runs, join {i}: a whole pass");
            total += w;
        }
        assert_eq!(read_str(&a.state), read_str(&b.state));
        total
    };
    let (small, big) = (work(30), work(300));
    assert!(big <= 4 * small, "follow work {small} at 30 runs, {big} at 300");
}

/// §6.1, `seq_lin`: a commit inserting a char and moving it (alone, or in a range with held
/// chars; forward or back), as a text session's edit then move writes, joins by following the
/// cached placement: no whole pass, and the placement is a whole pass's.
#[test]
fn new_element_moved_in_its_delta_follows_spec_6_1() {
    let mut a = Replica::new(1);
    for k in 0..3u64 {
        a.commit(k + 1, &[op(Op::Insert { at: 0, items: vec![s("abcdefghij")] })], &text_view());
    }
    for (i, mv) in [Op::Move { at: 7, len: 1, to: 20 }, Op::Move { at: 5, len: 4, to: 20 }, Op::Move { at: 7, len: 1, to: 2 }].into_iter().enumerate() {
        let mut b = a.fork(2 + i as u8);
        let (d, _, _) = b.commit(10, &[op(Op::Insert { at: 7, items: vec![s("e")] }), op(mv)], &text_view()).unwrap();
        let mut st = a.state.clone();
        let _ = read_str(&st);
        let _ = crate::seq_lin::probe();
        st.join(d);
        let Fragment::Seq(q) = &st else { panic!() };
        let _ = q.lin();
        assert_eq!(crate::seq_lin::probe().1, 0, "move {i}: a whole pass");
        crate::testutil::check_lin(&st);
        assert_eq!(read_str(&st), read_str(&b.state));
    }
}

/// §7 Read: a text op at a position holding only a string register writes into the text slot the
/// register embeds (a slot not held adds nothing to the embedding), indexing what the position
/// reads.
#[test]
fn text_op_over_register_spec_7() {
    let mut mw = MWriter::new(crdt_model::stamp::Source::session(5, 0), 3 << 16, 1);
    let reg = crdt_model::ops::create(&mut mw, &Ty::Register, &crdt_model::value::Value::Str("ab".into()));
    let mut st = Fragment::default();
    st.join(frag(&reg));
    let mut a = Replica { state: st, src: node(3), lo: 1 };
    a.commit(10, &[op(Op::Insert { at: 1, items: vec![s("x")] })], &text_view()).unwrap();
    assert_eq!(read_str(&a.state), "axb");
}

/// §4.2, §6.1: a received replace prunes the old records whole, so they go; a newer concurrent
/// insert anchored inside the old text sits at its virtual anchor, after the new content, as at a
/// node that never held the old text (worked example "Reset against a newer insert").
#[test]
fn reset_drops_old_records_spec_4_2() {
    let mut a = Replica::new(1);
    for k in 0..20u64 {
        a.commit(k + 1, &[op(Op::Insert { at: 5 * k as usize, items: vec![s("abcde")] })], &text_view());
    }
    let base = a.state.clone();
    let mut b = Replica { state: base.clone(), src: node(2), lo: 1 };
    let (newer, _, _) = b.commit(50, &[op(Op::Insert { at: 37, items: vec![s("q")] })], &text_view()).unwrap();
    let (d, _, _) = a.commit(40, &[op(Op::Replace(s("xyz")))], &text_view()).unwrap();
    let mut never = Fragment::default();
    never.join(d.clone());
    never.join(newer.clone());
    for (x, y) in [(d.clone(), newer.clone()), (newer, d)] {
        let mut st = base.clone();
        let _ = read_str(&st);
        st.join(x);
        st.join(y);
        crate::testutil::check_lin(&st);
        assert_eq!(read_str(&st), "xyzq");
        assert_eq!(st, never, "pruned records equal never-held ones");
    }
}

/// §4.2: replacing a text whole keeps only the latest value's records: the state after 10n
/// replaces holds as many as after n (records whose writes a reset pruned go).
#[test]
fn replaces_keep_state_flat_spec_4_2() {
    let records = |n: u64| {
        let mut a = Replica::new(1);
        for k in 0..n {
            a.commit(k + 1, &[op(Op::Replace(s("abcde")))], &text_view());
        }
        let Fragment::Seq(q) = &a.state else { panic!() };
        crate::seq_span::expand(q.elems().clone()).len()
    };
    assert_eq!(records(10), 5);
    assert_eq!(records(100), records(10));
}

/// §6 (a deterministic function of state), `seq_lin`, §3.3 rule 3: typing and deleting at random
/// places, joined by another replica as received from the wire (a delete of several elements is
/// one range record over several state records), keeps the cached placement (no whole pass),
/// equal to a whole pass after every join, with or without a read in between.
#[test]
fn cached_placement_follows_typing_spec_6() {
    let mut r = crate::testutil::rng(0);
    let mut a = Replica::new(1);
    let mut b = Replica::new(2);
    let mut kept = 0;
    for k in 0..200u64 {
        let n = read_str(&a.state).chars().count();
        let o = if n > 4 && r.chance(1, 3) { Op::Delete { at: r.below(n - 3), len: 1 + r.below(3) } } else { Op::Insert { at: r.below(n + 1), items: vec![s("xy")] } };
        let (d, _, _) = a.commit(k + 1, &[op(o)], &text_view()).unwrap();
        if k < 197 {
            let _ = read_str(&b.state);
        }
        b.state.join(d);
        crate::testutil::check_lin(&b.state);
        kept += usize::from(cached(&b.state));
        assert!(k < 197 || cached(&b.state), "joins without a read in between follow it");
        assert_eq!(read_str(&a.state), read_str(&b.state));
    }
    assert!(kept >= 198, "kept {kept}");
}

/// One commit on `a` of `fixed` ops, then random inserts, deletes, typos deleted again and moves
/// until each was drawn `each` times and `least` ops were drawn (then `after`), checked against the ops on a plain string; after every op, how
/// `DeltaBuilder` holds its view: per op kind (insert 0, typo deleted again 1, delete 2, move 3,
/// fixed 4) drawn, kept a view, kept a layer (no copy); and whether each fixed op kept a view.
fn text_batch(a: &mut Replica, r: &mut Rng, fixed: Vec<Op>, each: usize, least: usize, after: Vec<Op>) -> ([(usize, usize, usize); 5], Vec<bool>) {
    let base = a.state.clone();
    let mut model: Vec<char> = read_str(&base).chars().collect();
    let (mut ops, mut kinds) = (Vec::new(), Vec::new());
    let mut push = |model: &mut Vec<char>, kind: usize, o: Op| {
        apply_text(model, &o, &base);
        ops.push(op(o));
        kinds.push(kind);
    };
    for o in fixed {
        push(&mut model, 4, o);
    }
    let mut last_insert = None;
    let mut drawn = [0; 4];
    while drawn.iter().any(|d| *d < each) || drawn.iter().sum::<usize>() < least {
        // a typo's odds are about 1/16 per op
        assert!(drawn.iter().sum::<usize>() < 64 * (each + least), "drawn {drawn:?}");
        let n = model.len();
        let (kind, o) = match r.below(4) {
            0 => {
                let at = r.below(n + 1);
                last_insert = Some(at);
                (0, Op::Insert { at, items: vec![s("xy")] })
            }
            1 => match last_insert.take() {
                // a typo deleted in the same commit
                Some(at) if r.chance(1, 2) => (1, Op::Delete { at, len: 1 }),
                _ => {
                    let at = r.below(n);
                    (2, Op::Delete { at, len: (1 + r.below(3)).min(n - at) })
                }
            },
            _ => {
                let at = r.below(n);
                let len = (1 + r.below(3)).min(n - at);
                (3, Op::Move { at, len, to: r.below(n - len + 1) })
            }
        };
        drawn[kind] += 1;
        push(&mut model, kind, o);
    }
    for o in after {
        push(&mut model, 4, o);
    }
    let mut b = DeltaBuilder::new(&a.state, Writer::new(ts(50 << 16), a.src.clone(), a.lo));
    let mut tally = [(0, 0, 0); 5];
    let mut fixed_kept = Vec::new();
    for (o, k) in ops.iter().zip(&kinds) {
        b.apply(o, &text_view()).unwrap();
        let t = &mut tally[*k];
        *t = (t.0 + 1, t.1 + b.keeps_view() as usize, t.2 + b.keeps_layer() as usize);
        if *k == 4 {
            fixed_kept.push(b.keeps_view());
        }
    }
    // the commit as `Replica::commit` makes it, from this builder
    let (d, range) = b.finish().unwrap();
    let back = wired(&d, &a.src, range, 50);
    assert_eq!(back, d, "a writer's delta round-trips");
    a.state.join(back);
    crate::testutil::check_lin(&a.state);
    assert_eq!(read_str(&a.state), model.iter().collect::<String>());
    (tally, fixed_kept)
}

// spec/crdt.md §4.5, §5.7: a commit of a hundred moves, inserts and deletes on a text of a
// thousand chars (many placement blocks) reads like the same ops on a plain string, and
// `DeltaBuilder` keeps a view of the text through most ops, checked against state + net effect
// after every op (debug assertion in `DeltaBuilder`): on typed text often a layer over the
// state; with range records (a delete splitting one first) a copy. Constructed: a char moved after a fresh
// char that is then deleted, and moved twice more, so its kept writes no longer name the fresh
// char and the net effect omits it (`seq::Foot` refuses to follow there); a reset of the text
// and edits after it. Tallied: every random op kind is drawn, and all but a typo deleted again
// (its element omitted: the view goes) keep the view.
#[test]
fn large_text_batch_is_net_effect_spec_4_5() {
    let mut r = crate::testutil::rng(0);
    let mut a = Replica::new(1);
    for k in 0..10u64 {
        let n = read_str(&a.state).chars().count();
        a.commit(k + 1, &[op(Op::Insert { at: r.below(n + 1), items: vec![s(&"abcdefghij".repeat(10))] })], &text_view());
    }
    // each random kind drawn 4 times, 80 random ops at least; all but a typo keep the view at
    // least half the times
    let (each, least) = (4, 80);
    let check = |tally: &[(usize, usize, usize); 5], layers: bool| {
        let (n, kept, layered) = tally.iter().fold((0, 0, 0), |x, t| (x.0 + t.0, x.1 + t.1, x.2 + t.2));
        assert!(kept * 10 >= n * 8, "kept the view through {kept} of {n} ops");
        // (a layer goes on until an op it cannot follow; a copy then holds the view)
        assert!(!layers || layered > 0, "layered {layered} of {kept} views");
        for (k, (drawn, kept, _)) in tally.iter().enumerate().take(4) {
            assert!(k == 1 || *kept * 2 >= *drawn, "kind {k}: kept the view {kept} of {drawn} times");
        }
    };
    // the batches end resetting the text and editing the new one
    let after = || vec![Op::Set(s("fresh text")), Op::Insert { at: 5, items: vec![s("ly")] }, Op::Move { at: 0, len: 5, to: 7 }];
    // typed text: the view is a layer
    let mut typed = a.fork(1);
    typed.lo = a.lo;
    check(&text_batch(&mut typed, &mut r, vec![], each, least, after()).0, true);
    // a concurrent insert anchored inside a stretch deleted here: after the snapshot the
    // stretch is one range record with "Q" placed inside it
    let mut c = a.fork(2);
    let (q, _, _) = c.commit(39, &[op(Op::Insert { at: 150, items: vec![s("Q")] })], &text_view()).unwrap();
    a.commit(40, &[op(Op::Delete { at: 100, len: 200 })], &text_view());
    a.state.join(q);
    a.state = via_snapshot(&a.state);
    assert_eq!(read_str(&a.state).chars().nth(100), Some('Q'));
    let fixed = vec![
        // deleting from "Q" on flags the rest of that record: the write splits it
        Op::Delete { at: 100, len: 2 },
        // a char moved after a fresh "W", "W" deleted, the char moved twice more: its two kept
        // position writes no longer name "W", which the net effect omits
        Op::Insert { at: 300, items: vec![s("W")] },
        Op::Move { at: 500, len: 1, to: 301 },
        Op::Delete { at: 300, len: 1 },
        Op::Move { at: 300, len: 1, to: 600 },
        Op::Move { at: 600, len: 1, to: 50 },
    ];
    let (tally, fixed_kept) = text_batch(&mut a, &mut r, fixed, each, least, after());
    assert!(fixed_kept[1] && fixed_kept[4], "a view after the splitting delete, and before the move omitting \"W\"");
    check(&tally, false);
    assert!(!read_str(&a.state).contains('W'));
}

// spec/crdt.md §6: the cached placement's dot map is shared between copies of a state; a join
// into one copy clones only the chunks it writes (notes/crdt.md, placement cache).
#[test]
fn placement_dot_map_shared_by_copies_spec_6() {
    let mut r = crate::testutil::rng(0);
    let mut a = Replica::new(1);
    let run = "abcdefghij".repeat(10);
    for k in 0..100u64 {
        let n = read_str(&a.state).chars().count();
        a.grow(k + 1, &[op(Op::Insert { at: r.below(n + 1), items: vec![s(&run)] })], &text_view());
    }
    crate::testutil::check_lin(&a.state);
    let lin = |f: &Fragment| match f {
        Fragment::Seq(x) => x.lin(),
        _ => panic!(),
    };
    let mut b2 = a.fork(2);
    for k in 0..20u64 {
        b2.grow(200 + k, &[op(Op::Insert { at: r.below(10_000), items: vec![s("x")] })], &text_view());
    }
    let (unshared, all) = lin(&b2.state).map_unshared(&lin(&a.state));
    assert!(all >= 50 && unshared <= 25, "{unshared} of {all} chunks copied");
}

/// §6.1 sibling order (`seq_lin`): two writers typing at one place concurrently (each insert
/// lands next to the other's, older ones below newer siblings and their subtrees) keep the
/// cached placement of a third replica receiving both, equal to a whole pass.
#[test]
fn cached_placement_follows_concurrent_typing_spec_6() {
    let mut r = crate::testutil::rng(0);
    let mut a = Replica::new(1);
    a.commit(1, &[op(Op::Set(s(&"base text ".repeat(20))))], &text_view());
    let mut b = a.fork(2);
    let mut c = a.fork(3);
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
            if cached(&c.state) {
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
    let base = Value::List(vec![item(1, 1)]);
    for new in [Value::List(vec![]), Value::List(vec![item(2, 1)])] {
        let mut a = Replica::new(1);
        a.commit(1, &[op(Op::Set(base.clone()))], &view);
        let mut b = a.fork(2);
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
    let mut b = a.fork(2);
    let mut d = crate::seq::Seq::empty(true);
    let st = crate::stamp::Stamp::new(ts(3 << 16), node(2), 1);
    d.elems_mut().insert(st.dot.clone(), crate::seq::SeqElem { created: Some((st.clone(), crate::seq::Anchor::Dot(dots[1].clone()))), content: crate::seq::SeqContent::Char('X'), pos: vec![(st, crate::seq::Anchor::Dot(dots[1].clone()), None)], deleted: None, undel: None, span: 1, each: None });
    b.state.join(Fragment::Seq(d));
    assert_eq!(read_str(&b.state), "aXef");
    let mut bt = DeltaBuilder::new(&b.state, Writer::new(ts(5 << 16), node(2), 2));
    assert!(bt.apply(&op(Op::Paste { dots, at: 3 }), &text_view()).is_err());
}

/// §9 identity rule: a list diff keeps the dot of an element it edits (paired in order), so a
/// concurrent nested write into that element survives.
#[test]
fn list_diff_keeps_dots_spec_9() {
    let view = TyView(list_ty());
    let mut a = Replica::new(1);
    a.commit(1, &[op(Op::Set(Value::List(vec![item(1, 1), item(2, 2)])))], &view);
    let mut b = a.fork(2);
    let (bd, _, _) = b.commit(2, &[PathOp { path: vec![PathSeg::Index(1), PathSeg::Field(2)], op: Op::Set(Value::Int(7)) }], &view).unwrap();
    a.commit(3, &[op(Op::Set(Value::List(vec![item(1, 1), item(9, 2), item(3, 3)])))], &view);
    a.state.join(bd);
    assert_eq!(a.state.read(), Some(Value::List(vec![item(1, 1), item(9, 7), item(3, 3)])));
}

/// §4.6, §5.7 Undo, Live: undoing a list delete brings back only what read before it. A deleted
/// element holding a newer nested write (hidden, §5.7) inside the deleted range stays deleted.
#[test]
fn list_undo_delete_skips_hidden_element_spec_4_6() {
    let view = TyView(list_ty());
    let mut a = Replica::new(1);
    a.commit(1, &[op(Op::Set(Value::List(vec![item(1, 1), item(2, 2), item(3, 3)])))], &view);
    let mut b = a.fork(2);
    a.commit(2, &[op(Op::Delete { at: 1, len: 1 })], &view);
    // b, not having seen the delete, edits the element after it: newer than its reset
    let (bd, _, _) = b.commit(3, &[PathOp { path: vec![PathSeg::Index(1), PathSeg::Field(2)], op: Op::Set(Value::Int(7)) }], &view).unwrap();
    a.state.join(bd);
    assert_eq!(a.state.read(), Some(Value::List(vec![item(1, 1), item(3, 3)])));
    let before = a.state.clone();
    let (d, src, range) = a.commit(4, &[op(Op::Delete { at: 0, len: 2 })], &view).unwrap();
    assert_eq!(a.state.read(), Some(Value::List(vec![])));
    let u = Undone { delta: &d, source: &src, range };
    let ud = undo(&mut Writer::new(ts(5 << 16), node(1), a.lo), &u, &a.state, &before, &view).unwrap().unwrap();
    a.state.join(ud);
    assert_eq!(a.state.read(), before.read());
}

/// §5.7 Undo: a move undoes by writing the old anchors back (notes/crdt.md, Sibling keys).
#[test]
fn move_undo_spec_5_7() {
    let mut a = Replica::new(1);
    a.commit(1, &[op(Op::Set(s("FOOBAR")))], &text_view());
    let before = a.state.clone();
    let (d, src, range) = a.commit(2, &[op(Op::Move { at: 0, len: 3, to: 3 })], &text_view()).unwrap();
    assert_eq!(read_str(&a.state), "BARFOO");
    let u = Undone { delta: &d, source: &src, range };
    let mut w = Writer::new(ts(3 << 16), node(1), a.lo);
    let full = undo(&mut w, &u, &a.state, &before, &text_view()).unwrap().unwrap();
    assert!(crate::undo::restores(&u), "a move writes back the old anchors");
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

/// §4.6, §5.7 Undo, §6.1: a move's undo restores the old sibling keys, so the element lands after
/// a newer sibling it followed (issue crdt-undo-move-order: `eab`, move `a`, undo gave `aeb`), and a
/// concurrent insert at the old anchor newer than the old write stays before it, as if the move had
/// not happened. A receiver joins the undo through the wire (keys naming earlier commits) and its
/// cached placement follows it.
#[test]
fn move_undo_keeps_sibling_order_spec_5_7() {
    let mut a = Replica::new(1);
    a.commit(1, &[op(Op::Set(s("ab")))], &text_view());
    a.commit(2, &[op(Op::Insert { at: 0, items: vec![s("e")] })], &text_view());
    assert_eq!(read_str(&a.state), "eab");
    let before = a.state.clone();
    let (d, src, range) = a.commit(3, &[op(Op::Move { at: 1, len: 1, to: 2 })], &text_view()).unwrap();
    assert_eq!(read_str(&a.state), "eba");
    let mut b = a.fork(2);
    let (x, _, _) = b.commit(4, &[op(Op::Insert { at: 0, items: vec![s("x")] })], &text_view()).unwrap();
    let u = Undone { delta: &d, source: &src, range };
    let mut w = Writer::new(ts(5 << 16), node(1), a.lo);
    let ud = undo(&mut w, &u, &a.state, &before, &text_view()).unwrap().unwrap();
    let back = wired(&ud, &src, w.range(), 5);
    assert_eq!(back, ud, "the undo round-trips as a writer's delta");
    let mut alone = joined(&a.state, &ud);
    assert_eq!(read_str(&alone), "eab");
    // the receiver holds the concurrent insert and a cached placement
    assert_eq!(read_str(&b.state), "x".to_string() + &read_str(&a.state));
    b.state.join(back);
    let Fragment::Seq(sq) = &b.state else { panic!("text") };
    assert_eq!(sq.lin_check(), Some(true), "the cached placement followed the undo");
    assert_eq!(read_str(&b.state), "xeab");
    // the undoing node, once it receives the insert
    alone.join(x);
    assert_eq!(read_str(&alone), "xeab");
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
    let mut r = crate::testutil::rng(0);
    for _ in 0..20 {
        let mut mw = MWriter::new(crdt_model::stamp::Source::session(1, 0), 1 << 16, 1);
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

/// §5.7 move: on states from random concurrent histories (content-less anchors, outside subtrees,
/// several roots, earlier moves) a move writes what the model's does, write for write.
#[test]
fn move_matches_model_over_histories_spec_5_7() {
    let mut r = crate::testutil::rng(0);
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
            let mut mw = MWriter::new(crdt_model::stamp::Source::session(9, 0), 1 << 16, 1);
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

/// §5.7 move, §6.2: on a state holding a broken cycle (the worked example: "acb", a moved after
/// b and b after a concurrently, b's older move demoted) every move writes what the model's does,
/// write for write, and leaves the model's state, including moves that re-place the cycle's
/// elements and so read unlike the same move on plain text.
#[test]
fn move_beside_broken_cycle_matches_model_spec_6_2() {
    let mw = |n: u8, t: u64| MWriter::new(crdt_model::stamp::Source::session(n, 0), t << 16, 1);
    let mut base = mops::seq_insert(&mut mw(1, 1), None, true, 0, "acb".chars().map(Content::Char).collect());
    base.prune(None);
    let mut ms = Some(base.clone());
    mapply(&mut ms, mops::seq_move(&mut mw(2, 5), &base, 0, 1, 2).unwrap());
    mapply(&mut ms, mops::seq_move(&mut mw(3, 4), &base, 2, 1, 1).unwrap());
    let ms = ms.unwrap();
    let st = frag(&ms);
    assert_eq!(read_str(&st), "cba");
    assert!(st.seq_place().is_some_and(|p| !p.top().cyc.is_empty()), "a broken cycle");
    let mut replaced = 0;
    for (at, len, to) in (0..3).flat_map(|at| (1..=3 - at).flat_map(move |len| (0..=3 - len).map(move |to| (at, len, to)))) {
        let mut m = mw(4, 6);
        let mut w = writer(&m);
        let md = mops::seq_move(&mut m, &ms, at, len, to);
        let d = crate::ops::leaf(&mut w, Some(&st), &text_view(), &Op::Move { at, len, to }, true).unwrap();
        assert_eq!(d, md.as_ref().map(frag), "move {at} {len} {to}");
        if let (Some(d), Some(md)) = (d, md) {
            let (mut got, mut want) = (st.clone(), ms.clone());
            got.join(d);
            want.join(md);
            assert_eq!(got, frag(&want), "move {at} {len} {to}");
            let mut plain: Vec<char> = "cba".chars().collect();
            let cut: Vec<char> = plain.drain(at..at + len).collect();
            plain.splice(to..to, cut);
            replaced += usize::from(read_str(&got) != plain.into_iter().collect::<String>());
        }
    }
    // the corner: a move re-placing the cycle's elements reads unlike the same move on plain text
    assert!(replaced > 0, "no move re-placed the cycle");
}

/// §5.7 cut, paste: a paste of cut text moves the original elements back and undeletes them; one
/// whose clipboard the state does not hold fails.
#[test]
fn cut_and_paste_keeps_identity_spec_5_7() {
    let mut a = Replica::new(1);
    a.commit(1, &[op(Op::Set(s("one two three")))], &text_view());
    let dots = crate::cut_dots(&a.state, 4, 4).unwrap(); // "two "
    a.commit(2, &[op(Op::Delete { at: 4, len: 4 })], &text_view());
    assert_eq!(read_str(&a.state), "one three");
    a.commit(3, &[op(Op::Paste { dots: dots.clone(), at: 9 })], &text_view());
    assert_eq!(read_str(&a.state), "one threetwo ");
    // the pasted elements are the cut ones
    let Fragment::Seq(sq) = &a.state else { panic!() };
    let vis = visible(sq);
    assert_eq!(vis.iter().skip(9).take(4).cloned().collect::<Vec<_>>(), dots);
    // a paste whose clipboard no longer matches fails (the caller inserts instead)
    let mut c = Replica::new(3);
    c.commit(1, &[op(Op::Set(s("x")))], &text_view());
    let mut bt = DeltaBuilder::new(&c.state, Writer::new(ts(5 << 16), node(3), c.lo));
    assert!(bt.apply(&op(Op::Paste { dots, at: 0 }), &text_view()).is_err());
}

/// §5.7 Live: a list delete against a concurrent newer nested write: the element stays deleted on
/// every node and the write stays hidden (the stale writer reads it until the delete arrives); an
/// older nested write is dropped.
#[test]
fn list_delete_vs_concurrent_nested_write_spec_5_7() {
    let view = TyView(list_ty());
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
    let mut s1 = joined(&base, &del);
    s1.join(older.clone());
    assert_eq!(s1.read(), Some(Value::List(vec![])), "an older nested write loses to the reset");
    s1.join(newer.clone());
    assert_eq!(s1.read(), Some(Value::List(vec![])), "a newer nested write does not revive the element");
    let stale = joined(&base, &newer);
    assert_eq!(stale.read(), Some(Value::List(vec![item(1, 9)])), "read until the delete arrives");
    let mut s2 = base.clone();
    for x in [&newer, &older, &del] {
        s2.join(x.clone());
    }
    assert_eq!(s1, s2);
}

/// §7, §4.7, §6.1: an insert anchored at an embedded character sits at its virtual anchor after
/// the register write expires, as at a node that never held the register.
#[test]
fn derived_anchor_outlives_its_register_spec_7() {
    let reg_w = || {
        let mut w = Writer::new(ts(1 << 16), node(1), 1);
        create(&mut w, &crate::AnyView, &s("ab")).unwrap()
    };
    let embedded = |f: Fragment| match f {
        Fragment::Register(r) => crate::state::embed(&r, crate::Encoding::Text).unwrap(),
        _ => panic!(),
    };
    // a text slot alone: the register's embedding
    let mut p = Fragment::default();
    p.join(embedded(reg_w()));
    assert_eq!(read_str(&p), "ab");
    let mut b = Replica::new(2);
    b.state = p.clone();
    let (q, _, _) = b.commit(2, &[op(Op::Insert { at: 1, items: vec![s("q")] })], &text_view()).unwrap();
    p.join(q.clone());
    assert_eq!(read_str(&p), "aqb");
    let expired = |d: &crate::Dot| d.src == node(1) && d.ctr == 1;
    let mut reg = reg_w();
    reg.remove_gone(&expired);
    let gone = joined(&reg, &q);
    assert_eq!(read_str(&gone), "q");
    assert_eq!(gone, joined(&Fragment::default(), &q));
}

/// §4.6, §5.7 Undo (restores the prior read): an element moved twice undoes twice: the second
/// move's undo puts it back where the first move left it, so the first move's undo writes the
/// anchor before it.
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
    let mut w = Writer::new(ts(4 << 16), node(1), a.lo);
    let u2 = undo(&mut w, &Undone { delta: &m2, source: &src, range: r2 }, &a.state, &s1, &text_view()).unwrap().unwrap();
    a.lo = w.range().hi;
    a.state.join(u2);
    assert_eq!(read_str(&a.state), "OOBARF");
    let mut w = Writer::new(ts(5 << 16), node(1), a.lo);
    let u1 = undo(&mut w, &Undone { delta: &m1, source: &src, range: r1 }, &a.state, &s0, &text_view()).unwrap().unwrap();
    a.state.join(u1);
    assert_eq!(read_str(&a.state), "FOOBAR");
}

/// §6.2 (incremental implementations must produce the same result), `seq_lin`: writers moving, typing and deleting concurrently (the same range moved by
/// several, cycles included), joined from the wire by a replica that reads in between: the
/// cached placement follows the moves that close no cycle and equals a whole pass after every
/// join; all converge.
#[test]
#[ignore = "property"]
fn cached_placement_follows_moves_plain_spec_6_2() {
    let out = crate::testutil::crdt_seeds("tests_seq_ops::cached_placement_follows_moves_plain_spec_6_2", 0..12, follows_moves_case);
    osis_base::testenv::reach_floor("move joins", out.iter().map(|x| x.1), 1, 1);
    // most moves close no cycle: followed, in every seed (the fewest seen about 56%)
    for (seed, (kept, moves)) in out.iter().enumerate() {
        assert!(kept * 5 > moves * 2, "seed {seed} of the range: followed {kept} of {moves}");
    }
}

/// One seed of `cached_placement_follows_moves_plain`: (move joins followed, move joins).
fn follows_moves_case(seed: u64) -> (usize, usize) {
    let mut r = crate::testutil::fixed(seed);
    let (mut kept, mut moves) = (0, 0);
    let mut base = Replica::new(1);
    base.commit(1, &[op(Op::Set(s(&"abcdefghij".repeat(8))))], &text_view());
    let mut ws: Vec<Replica> = (2..5).map(|n| base.fork(n)).collect();
    let mut seen = vec![0usize; ws.len()];
    let mut d = base.fork(9);
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
            if let Some((x, _, _)) = w.commit(t, &[op(o)], &text_view()) {
                fresh.push((mv, x));
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
                if cached(&d.state) {
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
    (kept, moves)
}

/// §6 (a deterministic function of state), `seq_lin`: hostile deltas of moves to HEAD below 250 newer HEAD siblings cost about a
/// whole pass in placement work, counted in `follow`'s work units (rows and blocks looked at, a
/// skipped sibling 8) and whole passes: more than max(√n, 64) moves rebuild at once (checked
/// at that count and one past it); fewer stop at the work budget max(n, 1024) and rebuild.
/// Either way at most one pass, and the units charged stay under the budget plus a
/// per-placement charge and one step's overshoot.
#[test]
fn hostile_moves_join_bounded_spec_6() {
    let mut a = Replica::new(1);
    for k in 0..4u64 {
        a.commit(1 + k, &[op(Op::Insert { at: 0, items: vec![s(&"x".repeat(1000))] })], &text_view());
    }
    // n = 4250 rows: the count cap √n (65) above its floor, the budget n above its floor
    let count = (4000usize + 250).isqrt().max(64);
    for moves in [count + 1, count] {
        let (mut st, d) = hostile_moves(&a.state, 250, moves);
        let Fragment::Seq(q) = &st else { panic!() };
        let (len, blocks, cap) = q.lin().shape();
        assert_eq!(len.isqrt().max(64), count);
        let _ = crate::seq_lin::probe();
        st.join(d);
        let Fragment::Seq(q) = &st else { panic!() };
        let _ = q.lin();
        let (work, passes) = crate::seq_lin::probe();
        assert_eq!(moves > count, work == 0, "{moves} moves: the count cap ({count}) rebuilds before any work");
        // budget, an `each` charge per placement, and the last sibling step past the budget
        // (a block walk: every block, two partial blocks of at most 2 * cap rows)
        let bound = len.max(1024) + count.min(moves) * (blocks + cap) + 8 + blocks + 4 * cap;
        assert!(work <= bound, "{moves} moves: {work} units, bound {bound}");
        assert!(passes <= 1, "{moves} moves: {passes} whole passes");
        crate::testutil::check_lin(&st);
    }
    // one move below 300 newer HEAD siblings, within the work budget: the 256th sibling skipped
    // rebuilds
    let (mut st, d) = hostile_moves(&a.state, 300, 1);
    let Fragment::Seq(q) = &st else { panic!() };
    let len = q.lin().shape().0;
    let _ = crate::seq_lin::probe();
    st.join(d);
    let Fragment::Seq(q) = &st else { panic!() };
    let _ = q.lin();
    let (work, passes) = crate::seq_lin::probe();
    assert!(work > 0 && work < len.max(1024) && passes == 1, "{work} units, {passes} whole passes");
    crate::testutil::check_lin(&st);
}

/// §6 (a deterministic function of state), `seq_lin`: a delta of flag writes each splitting one long deleted chain (a range record
/// at the root) with a deep subtree below it: each cut shifts the subtree's depths; the work
/// stays within the budget plus one cut, or the count cap rebuilds before any work.
#[test]
fn hostile_cuts_join_bounded_spec_6() {
    use crate::seq::{Anchor, Seq, SeqContent, SeqElem};
    use crate::stamp::{Dot, Stamp};
    let (a, b, c) = (node(1), node(2), node(3));
    let chain = 2000u64;
    let mut elems = std::collections::BTreeMap::new();
    let del = Some((Stamp::new(ts(2 << 16), b.clone(), 1), true));
    elems.insert(Dot::new(a.clone(), 1), SeqElem { created: Some((Stamp::new(ts(1 << 16), a.clone(), 1), Anchor::Head)), content: SeqContent::None, pos: vec![(Stamp::new(ts(1 << 16), a.clone(), 1), Anchor::Head, None)], deleted: del, undel: None, span: chain, each: None });
    // a typed chain of 2000 chars below the range's last element: depth 2000
    let mut prev = Anchor::Dot(Dot::new(a.clone(), chain));
    for k in 1..=2000u64 {
        let st = Stamp::new(ts(3 << 16), c.clone(), k);
        elems.insert(st.dot.clone(), SeqElem { created: Some((st.clone(), prev.clone())), content: SeqContent::Char('x'), pos: vec![(st.clone(), prev, None)], deleted: None, undel: None, span: 1, each: None });
        prev = Anchor::Dot(st.dot);
    }
    let base = Fragment::Seq(Seq::new(true, crate::fragment::Meta::default(), elems));
    let Fragment::Seq(q) = &base else { panic!() };
    let (len, blocks, cap) = q.lin().shape();
    let count = len.isqrt().max(64);
    for writes in [count / 2 - 1, count] {
        let mut st = base.clone();
        let _ = read_str(&st);
        // newer delete flags on single elements spread over the chain: two cuts each
        let w = Stamp::new(ts(4 << 16), node(4), 1);
        let step = chain / (writes as u64 + 1);
        let d = (1..=writes as u64).map(|j| (Dot::new(a.clone(), 1 + j * step), SeqElem { deleted: Some((w.clone(), true)), ..SeqElem::bare() })).collect();
        let _ = crate::seq_lin::probe();
        st.join(Fragment::Seq(Seq::new(true, crate::fragment::Meta::default(), d)));
        let Fragment::Seq(q) = &st else { panic!() };
        let _ = q.lin();
        let (work, passes) = crate::seq_lin::probe();
        assert_eq!(2 * writes > count, work == 0, "{writes} writes: the count cap ({count}) rebuilds before any work");
        // budget, then one cut: its charge, the subtree walk and the reshift (each every block
        // and two partial blocks of at most 2 * cap rows)
        let bound = len.max(1024) + 3 * (blocks + 4 * cap);
        assert!(work <= bound, "{writes} writes: {work} units, bound {bound}");
        assert!(passes <= 1, "{writes} writes: {passes} whole passes");
        crate::testutil::check_lin(&st);
    }
}

/// §6.1 sibling order (`seq_lin`): an older insert at HEAD below a newer HEAD child, two runs
/// anchored at one element in one delta, an older insert below a newer sibling whose subtree is
/// thousands of rows, and a run landing between a newer and an older one already there all keep
/// the cached placement, equal to a whole pass.
#[test]
fn cached_placement_follows_siblings_spec_6_1() {
    let mut base = Replica::new(1);
    base.commit(1, &[op(Op::Set(s("ab")))], &text_view());
    let fork = |n: u8| base.fork(n);
    let (mut old, mut new, mut d, mut mid) = (fork(2), fork(3), fork(4), fork(5));
    let ins = |r: &mut Replica, t: u64, ops: &[(usize, &str)]| {
        let ops: Vec<PathOp> = ops.iter().map(|(at, x)| op(Op::Insert { at: *at, items: vec![s(x)] })).collect();
        r.commit(t, &ops, &text_view()).unwrap().0
    };
    let big = "y".repeat(5000);
    let joins = [
        // at HEAD: the older insert arrives after the newer one
        ins(&mut old, 2, &[(0, "o")]),
        ins(&mut new, 3, &[(0, "n")]),
        // after 'a': a big newer subtree, then an older single char, then a run between them
        ins(&mut old, 4, &[(2, "X")]),
        ins(&mut new, 6, &[(2, &big)]),
        ins(&mut mid, 5, &[(1, "MM")]),
        // two runs at one element in one commit
        ins(&mut new, 7, &[(1, "PQ"), (1, "RS")]),
    ];
    for k in [1, 0, 3, 2, 4, 5] {
        let _ = read_str(&d.state);
        d.state.join(joins[k].clone());
        crate::testutil::check_lin(&d.state);
        assert!(cached(&d.state), "join {k} followed");
    }
    assert_eq!(read_str(&d.state), format!("nRSPQoa{}MMXb", "y".repeat(5000)));
}

/// §6.1 sibling order (`seq_lin`): one delta inserting a run and then into it (`PQ` after `a`,
/// then `R` after `P`): `R` is `P`'s newer child, ahead of `Q`, so `P` ends its run there. A cached
/// placement, whole or held in part, follows it to a whole pass's order.
#[test]
fn cached_placement_follows_an_insert_into_its_own_run_spec_6_1() {
    let mut w = Replica::new(1);
    w.commit(1, &[op(Op::Set(s("ab")))], &text_view());
    let mut d = w.fork(2);
    let ops = [op(Op::Insert { at: 1, items: vec![s("P"), s("Q")] }), op(Op::Insert { at: 2, items: vec![s("R")] })];
    let (delta, _, _) = w.commit(2, &ops, &text_view()).unwrap();
    assert_eq!(read_str(&w.state), "aPRQb");
    let (Fragment::Seq(st), Fragment::Seq(ds)) = (&d.state, &delta) else { panic!("text") };
    assert!(crate::testutil::partial_follow(st, ds, 1).is_some(), "followed in part");
    let _ = read_str(&d.state);
    d.state.join(delta);
    crate::testutil::check_lin(&d.state);
    assert!(cached(&d.state), "followed");
    assert_eq!(read_str(&d.state), "aPRQb");
}

/// §6.1 sibling order (`seq_lin`): one delta inserting into what it inserted, nested (new under new
/// under new, a run's middle and its end, a newer child ahead of an older), on its own, beside a
/// concurrent delta into the same spot, and with moves: a cached placement equals a whole pass;
/// an insert-only one is followed, whole and held in part.
#[test]
fn cached_placement_follows_nested_inserts_in_one_delta_spec_6_1() {
    for seed in 0..120u64 {
        let mut r = Rng(seed);
        let moves = seed % 3 == 2;
        let mut w = Replica::new(1);
        w.commit(1, &[op(Op::Set(s("abcd")))], &text_view());
        let (mut d, mut o) = (w.fork(2), w.fork(3));
        // each op inserts at or beside the last one's spot, so later ones land inside earlier runs
        let mut at = 1 + r.below(3);
        let mut n = 4;
        let mut ops = Vec::new();
        for _ in 0..3 + r.below(6) {
            if moves && n > 2 && r.chance(1, 3) {
                let from = r.below(n - 1);
                ops.push(op(Op::Move { at: from, len: 1, to: r.below(n) }));
                continue;
            }
            let k = 1 + r.below(3);
            ops.push(op(Op::Insert { at, items: vec![s(&"PQRSTUVW"[..k])] }));
            n += k;
            at += r.below(k + 1);
        }
        let (delta, _, _) = w.commit(2, &ops, &text_view()).unwrap();
        let ctx = format!("seed {seed}: {ops:?}");
        let (Fragment::Seq(st), Fragment::Seq(ds)) = (&d.state, &delta) else { panic!("text") };
        if !moves {
            assert!(crate::testutil::partial_follow(st, ds, 1).is_some(), "{ctx}: followed in part");
        }
        let _ = read_str(&d.state);
        d.state.join(delta.clone());
        crate::testutil::check_lin(&d.state);
        assert!(moves || cached(&d.state), "{ctx}: followed");
        assert_eq!(read_str(&d.state), read_str(&w.state), "{ctx}");
        // a concurrent delta into the same spot, joined after
        let (od, _, _) = o.commit(3, &[op(Op::Insert { at: 2, items: vec![s("xy")] }), op(Op::Insert { at: 3, items: vec![s("z")] })], &text_view()).unwrap();
        let _ = read_str(&d.state);
        d.state.join(od.clone());
        crate::testutil::check_lin(&d.state);
        o.state.join(delta);
        assert_eq!(read_str(&d.state), read_str(&o.state), "{ctx}: concurrent");
    }
}

/// §6.1 sibling order (`seq_lin`): one joined delta creating `P` and two children of it by two
/// writers, the newer child earlier in dot order (it continues `P`'s run) and the older one the
/// newest run start of the delta: the older still goes after the newer.
#[test]
fn cached_placement_follows_children_of_a_new_element_by_two_writers_spec_6_1() {
    for (q, r) in [(2, 3), (3, 2)] {
        let mut w = Replica::new(1);
        w.commit(1, &[op(Op::Set(s("ab")))], &text_view());
        let mut d = w.fork(4);
        let (dp, _, _) = w.commit(2, &[op(Op::Insert { at: 1, items: vec![s("P")] })], &text_view()).unwrap();
        let (mut wq, mut wr) = (w.fork(q), w.fork(r));
        let (dq, _, _) = wq.commit(9, &[op(Op::Insert { at: 2, items: vec![s("Q")] })], &text_view()).unwrap();
        let (dr, _, _) = wr.commit(5, &[op(Op::Insert { at: 2, items: vec![s("R")] })], &text_view()).unwrap();
        let mut all = dp;
        all.join(dq);
        all.join(dr);
        let _ = read_str(&d.state);
        d.state.join(all);
        crate::testutil::check_lin(&d.state);
        assert!(cached(&d.state), "Q by {q}: followed");
        assert_eq!(read_str(&d.state), "aPQRb", "Q by {q}");
    }
}

/// §4.5 (net effect): `DeltaBuilder`'s sequence ops at one position resolve against a kept view of it once the
/// delta has written there; an op elsewhere drops it; the result equals one-by-one commits.
#[test]
fn delta_keeps_sequence_view_spec_4_5() {
    let ty = Ty::Struct([(1, Ty::Text), (2, Ty::Register)].into_iter().collect());
    let view = TyView(ty);
    let mut a = Replica::new(1);
    let f = |text: &str| Value::Map([(Value::Int(1), s(text)), (Value::Int(2), Value::Int(0))].into_iter().collect());
    a.commit(1, &[op(Op::Set(f("hello world")))], &view);
    let text = |o: Op| PathOp { path: vec![PathSeg::Field(1)], op: o };
    let mut bt = DeltaBuilder::new(&a.state, Writer::new(ts(2 << 16), node(1), a.lo));
    bt.apply(&text(Op::Insert { at: 5, items: vec![s(",")] }), &view).unwrap();
    assert!(!bt.keeps_view(), "nothing of the delta there before the first op");
    bt.apply(&text(Op::Insert { at: 0, items: vec![s(">")] }), &view).unwrap();
    assert!(bt.keeps_view());
    bt.apply(&text(Op::Delete { at: 8, len: 2 }), &view).unwrap();
    assert!(bt.keeps_view());
    bt.apply(&PathOp { path: vec![PathSeg::Field(2)], op: Op::Set(Value::Int(7)) }, &view).unwrap();
    assert!(!bt.keeps_view(), "dropped by an op elsewhere");
    assert_eq!(bt.view().read(), Some(Value::Map([(Value::Int(1), s(">hello, rld")), (Value::Int(2), Value::Int(7))].into_iter().collect())));
}


// spec/crdt.md §6 (a deterministic function of state), §5.7 (Read): after joins that insert, delete and move, the
// placement holds the visible elements of a whole pass in order, and reads by index
// (`visible_range`, `read_elems`) read what the whole read does.
#[test]
fn placement_read_by_index_spec_6() {
    let mut a = Replica::new(1);
    let text: String = (0..3000).map(|i| char::from(b'a' + (i % 26) as u8)).collect();
    a.commit(1, &[op(Op::Set(s(&text)))], &text_view());
    let vis = |f: &Fragment| f.visible_range(0..usize::MAX).unwrap();
    for (k, o) in [Op::Insert { at: 1500, items: vec![s("XYZ")] }, Op::Delete { at: 10, len: 3 }, Op::Move { at: 2000, len: 4, to: 7 }].into_iter().enumerate() {
        a.commit(k as u64 + 2, &[op(o)], &text_view());
        // the placement is a whole pass's
        assert_eq!(vis(&a.state), vis(&via_snapshot(&a.state)), "step {k}");
        let all = read_str(&a.state);
        let dots = a.state.visible_range(1490..1520).unwrap();
        assert_eq!(a.state.read_elems(&dots), Some(s(&all.chars().skip(1490).take(30).collect::<String>())), "step {k}");
        assert_eq!(a.state.read_elems(&a.state.visible_range(0..usize::MAX).unwrap()), Some(s(&all)));
    }
}

/// The placement order of a sequence `f` (§6.1), hidden elements included: (element, shown).
fn full_order(f: &Fragment) -> Vec<(crate::Dot, bool)> {
    let Fragment::Seq(sq) = f else { return Vec::new() };
    let l = sq.lin();
    l.p.iter().flat_map(|r| (0..r.span).map(move |i| (crate::seq_span::nth(&r.dot, i), r.shown))).collect()
}

/// The visible length of sequence `f`.
fn shown(f: &Fragment) -> usize {
    full_order(f).iter().filter(|x| x.1).count()
}

/// A new element of `ty`: `text` in a text, else a random list item.
fn new_item(r: &mut Rng, ty: &Ty, text: &str) -> Value {
    if let Ty::List(e) = ty { value(&random_value(r, e, 1)) } else { s(text) }
}

/// An insert of `items` or a delete of up to `most` visible elements of placement `order`, by
/// index and resolved (by anchor, by the dots of the placement slice): (by index, resolved).
fn resolved_pair(r: &mut Rng, order: &[(crate::Dot, bool)], insert: bool, items: Vec<Value>, most: usize) -> (Op, Op) {
    let vis: Vec<&crate::Dot> = order.iter().filter(|x| x.1).map(|x| &x.0).collect();
    let n = vis.len();
    if insert {
        let at = r.below(n + 1);
        return (Op::Insert { at, items: items.clone() }, Op::InsertAfter { anchor: at.checked_sub(1).map(|i| vis[i].clone()), items });
    }
    let at = r.below(n);
    let len = 1 + r.below((n - at).min(most));
    let i0 = order.iter().position(|x| x.0 == *vis[at]).unwrap();
    let i1 = order.iter().position(|x| x.0 == *vis[at + len - 1]).unwrap();
    (Op::Delete { at, len }, Op::DeleteDots { dots: order[i0..=i1].iter().map(|x| x.0.clone()).collect() })
}

/// §5.7 insert, delete; §6.1: on states from random concurrent histories (some commits missing:
/// hidden subtrees; moves; range records from a snapshot), an insert by anchor (the visible
/// element before the index, or HEAD) and a delete by the dots of the placement slice write what
/// the same ops by index write; the new elements land directly after their anchor in the
/// placement order (a new insert has the greatest stamp there), and a delete changes no element's
/// place, only its visibility. What a node keeping the placement apart relies on.
#[test]
fn resolved_insert_delete_match_index_ops_spec_6_1() {
    let mut r = crate::testutil::rng(0);
    let (mut inserts, mut deletes) = (0, 0);
    for round in 0..80 {
        let text = round % 2 == 0;
        let ty = if text { Ty::Text } else { list_ty() };
        let view = TyView(ty.clone());
        let (Some(mut st @ Fragment::Seq(_)), _) = history_state(&mut r, &ty, 3, 6, 8) else { continue };
        for k in 0..6u64 {
            let order = full_order(&st);
            let w = || Writer::new(ts((100 + k) << 16), node(9), 1 + 10 * k);
            let insert = shown(&st) == 0 || r.chance(1, 2);
            let items = vec![new_item(&mut r, &ty, "pq")];
            let (by_index, resolved) = resolved_pair(&mut r, &order, insert, items, 5);
            (inserts, deletes) = (inserts + usize::from(insert), deletes + usize::from(!insert));
            let d1 = crate::ops::leaf(&mut w(), Some(&st), &view, &by_index, true).unwrap();
            let d2 = crate::ops::leaf(&mut w(), Some(&st), &view, &resolved, true).unwrap();
            assert_eq!(d1, d2, "round {round} step {k}: {by_index:?}");
            let Some(d) = d2 else { continue };
            let next = joined(&st, &d);
            let after = full_order(&next);
            match &resolved {
                Op::InsertAfter { anchor, .. } => {
                    let at = anchor.as_ref().map_or(0, |a| order.iter().position(|x| x.0 == *a).unwrap() + 1);
                    let new = after.len() - order.len();
                    let mut want = order.clone();
                    let made: Vec<(crate::Dot, bool)> = after[at..at + new].to_vec();
                    assert!(made.iter().all(|(d, shown)| *shown && d.src == node(9)), "round {round} step {k}: new elements directly after the anchor");
                    want.splice(at..at, made);
                    assert_eq!(after, want, "round {round} step {k}");
                }
                Op::DeleteDots { dots } => {
                    let gone: std::collections::HashSet<&crate::Dot> = dots.iter().collect();
                    let want: Vec<(crate::Dot, bool)> = order.iter().map(|(d, sh)| (d.clone(), *sh && !gone.contains(d))).collect();
                    assert_eq!(after, want, "round {round} step {k}");
                }
                _ => unreachable!(),
            }
            st = next;
        }
    }
    assert!(inserts > 100 && deletes > 100, "{inserts} inserts, {deletes} deletes");
}

/// §7, §5.7, §6.1: on an upgraded text (embedded `Derived` chars at a `Slots` position) an insert
/// by anchor and a delete by dots write what the index ops write. And the precondition of
/// landing right after the anchor: a sibling there stamped above the writer's `ts` (which §2.2
/// and §8 rule out for a node's own commits) still gets the same delta, but places first.
#[test]
fn resolved_ops_on_embedded_text_and_skew_spec_6_1() {
    let tv = TyView(Ty::Text);
    let mut st = crate::ops::leaf(&mut Writer::new(ts(100 << 16), node(8), 1), None, &TyView(Ty::Register), &Op::Set(s("hello wide world of embedded chars")), true).unwrap().unwrap();
    let mut r = crate::testutil::rng(0);
    let text_of = |f: &Fragment| -> Fragment {
        match f {
            Fragment::Slots(x) => x.slots.get(&crate::fragment::Encoding::Text).cloned().unwrap(),
            f => f.clone(),
        }
    };
    let (mut ctr, mut derived_del) = (1, 0);
    for k in 0..60u64 {
        let w = || Writer::new(ts((200 + k) << 16), node(9), ctr);
        let order = full_order(&text_of(&st));
        let insert = shown(&text_of(&st)) < 3 || r.chance(1, 3);
        let (by_index, resolved) = resolved_pair(&mut r, &order, insert, vec![s("pq")], 4);
        derived_del += usize::from(matches!(&resolved, Op::DeleteDots { dots } if dots.iter().any(|d| d.src.is_derived())));
        let d1 = crate::ops::leaf(&mut w(), Some(&st), &tv, &by_index, true).unwrap();
        let d2 = crate::ops::leaf(&mut w(), Some(&st), &tv, &resolved, true).unwrap();
        assert_eq!(d1, d2, "step {k}: {by_index:?}");
        let Some(d) = d2 else { continue };
        ctr += 10;
        st.join(d);
    }
    assert!(derived_del > 5, "{derived_del} deletes over embedded chars");
    // skew: a sibling at the anchor stamped above the writer's ts
    let vis = |st: &Fragment| -> Vec<crate::Dot> { full_order(&text_of(st)).iter().filter(|x| x.1).map(|x| x.0.clone()).collect() };
    // at the fourth visible element (the deletes may have left fewer)
    if vis(&st).len() < 4 {
        st.join(crate::ops::leaf(&mut Writer::new(ts(300 << 16), node(9), ctr), Some(&st), &tv, &Op::Insert { at: 0, items: vec![s("wxyz")] }, true).unwrap().unwrap());
    }
    let anchor = vis(&st)[3].clone();
    let d = crate::ops::leaf(&mut Writer::new(ts(1_000_000 << 16), node(5), 1), Some(&st), &tv, &Op::InsertAfter { anchor: Some(anchor.clone()), items: vec![s("ZZ")] }, true).unwrap().unwrap();
    st.join(d);
    let w = || Writer::new(ts(500 << 16), node(9), 5000);
    let d1 = crate::ops::leaf(&mut w(), Some(&st), &tv, &Op::Insert { at: 4, items: vec![s("Y")] }, true).unwrap();
    let d2 = crate::ops::leaf(&mut w(), Some(&st), &tv, &Op::InsertAfter { anchor: Some(anchor.clone()), items: vec![s("Y")] }, true).unwrap();
    assert_eq!(d1, d2);
    st.join(d2.unwrap());
    let after = full_order(&text_of(&st));
    let ai = after.iter().position(|x| x.0 == anchor).unwrap();
    assert_eq!(after[ai + 1].0.src, node(5), "the newer sibling places first");
}

/// §5.7 Ops, §6, §8 (pages are joined independently), `seq_place`: ops by index (insert, delete, move, paste; two in one commit)
/// on a sequence held in part as a node holds a paged one (records in pages, the placement's
/// blocks and dot-map chunks loaded on a miss and the ops run again) write what they write on
/// the whole state, loading part of it; so do an edit and a `Set`, and a read held in part
/// reads the whole one once what it missed is loaded.
#[test]
fn index_ops_on_partial_placement_match_whole_spec_5_7() {
    let mut r = crate::testutil::rng(0);
    let (mut runs, mut moves, mut multi, mut loaded, mut total, mut edits, mut sets, mut wholes) = (0, 0, 0, 0, 0, 0, 0, 0);
    for round in 0..80 {
        let mut stale = None;
        let text = round % 2 == 0;
        let ty = if text { Ty::Text } else { list_ty() };
        let view = TyView(ty.clone());
        let (Some(mut st), _) = history_state(&mut r, &ty, 3, 6, 8) else { continue };
        for k in 0..4u64 {
            let Fragment::Seq(sq) = &st else { break };
            let sq = sq.clone();
            let n = shown(&st);
            let mut mk = |r: &mut Rng| -> Op {
                let at = r.below(n.max(1));
                let len = 1 + r.below((n.saturating_sub(at)).clamp(1, 6));
                match r.below(if text { 4 } else { 3 }) {
                    0 => Op::Insert { at: r.below(n + 1), items: vec![new_item(r, &ty, "pq")] },
                    1 => Op::Delete { at, len },
                    2 => {
                        moves += 1;
                        Op::Move { at, len, to: r.below(n.saturating_sub(len) + 1) }
                    }
                    _ => match crate::seq_ops::cut_dots(&st, at, len.min(n - at.min(n))) {
                        Ok(dots) if !dots.is_empty() => Op::Paste { dots, at: r.below(n + 1) },
                        _ => Op::Delete { at, len },
                    },
                }
            };
            let mut ops: Vec<Op> = (0..1 + r.below(2)).map(|_| mk(&mut r)).collect();
            // an edit (what a text session writes): against the read, or a stale one
            if r.chance(1, 3) {
                let base = if r.chance(1, 4) { stale.clone() } else { st.read() };
                if let Some(base) = base {
                    let new = edited(&mut r, &base, &ty);
                    ops.insert(0, Op::Edit { base, new });
                    edits += 1;
                }
            }
            // a `Set` (a whole-value diff, §9), after the other ops
            if r.chance(1, 4)
                && let Some(base) = st.read()
            {
                ops.push(Op::Set(edited(&mut r, &base, &ty)));
                sets += 1;
            }
            if k == 0 {
                stale = st.read();
            }
            multi += usize::from(ops.len() > 1);
            let w = || Writer::new(ts((100 + k) << 16), node(9), 1 + 10 * k);
            let per = 1 + r.below(8);
            let (want, pg) = paged(&st, per, w, &ops.iter().cloned().map(op).collect::<Vec<_>>(), &view);
            runs += 1;
            // (a `Set` diffs the whole read, which may take a whole pass)
            if !ops.iter().any(|o| matches!(o, Op::Set(_))) {
                wholes += pg.whole_passes;
            }
            // (an edit against a stale read, or after another op, and a `Set` load whole)
            if !ops.iter().any(|o| matches!(o, Op::Edit { .. } | Op::Set(_))) {
                loaded += pg.whole.top().blocks.len() - pg.p.stubs().0.len();
                total += pg.whole.top().blocks.len();
            }
            assert_eq!(Pager::new(&sq, per).run(|f| f.read()), st.read(), "round {round} step {k}: read held in part");
            if let Some((d, _)) = want {
                st.join(d);
            }
        }
    }
    assert!(runs > 200 && moves > 50 && multi > 50 && edits > 50 && sets > 50, "{runs} runs, {moves} moves, {multi} two-op commits, {edits} edits, {sets} sets");
    // ops whose layered follow or placement fails other than by a miss: rare
    assert!(wholes * 40 <= runs, "{wholes} of {runs} runs by a whole pass");
    assert!(loaded * 4 < total * 3, "{loaded} of {total} blocks loaded");
}

/// §5.7, §8: an op held in part reads the rows of its range only, so a delete whose range spans
/// blocks of hidden rows (skipped by their visible counts when its indices are found) loads the
/// blocks its range covers, never the blocks after it.
#[test]
fn delete_across_hidden_blocks_loads_its_range_spec_5_7() {
    let view = text_view();
    let mut st = Fragment::default();
    let text: String = (0..4_000).map(|i| (b'a' + (i % 26) as u8) as char).collect();
    st.join(create(&mut Writer::new(ts(1 << 16), node(1), 1), &view, &s(&text)).unwrap());
    // single deletes, so the hidden rows stay a row each and fill whole blocks
    for k in 0..400 {
        let (d, _) = build(&st, Writer::new(ts((2 + k) << 16), node(3), 1 + k), &[op(Op::Delete { at: 1_000, len: 1 })], &view).unwrap();
        st.join(d);
    }
    let (_, pg) = paged(&st, 64, || Writer::new(ts(1 << 30), node(2), 1), &[op(Op::Delete { at: 999, len: 2 })], &view);
    let (all, hidden) = (pg.whole.top().blocks.len(), pg.whole.top().blocks.iter().filter(|b| b.shown == 0).count());
    let loaded = all - pg.p.stubs().0.len();
    assert!(hidden >= 2 && loaded <= hidden + 4, "{loaded} of {all} blocks loaded, {hidden} hidden");
}

/// §5.7, §8: an op held in part whose range's first node is in a dot-map chunk not loaded (its
/// last node's loaded by an earlier op) misses that chunk, not the rows from the start to its last
/// node: it loads a few blocks, and writes what it writes on the whole state.
#[test]
fn delete_from_unloaded_chunk_loads_its_range_spec_5_7() {
    let view = text_view();
    let mut st = Fragment::default();
    let text: String = (0..4_000).map(|i| (b'a' + (i % 26) as u8) as char).collect();
    st.join(create(&mut Writer::new(ts(1 << 16), node(1), 1), &view, &s(&text)).unwrap());
    // a node of another writer near the end, its dot in the dot map's last chunk
    let (d, _) = build(&st, Writer::new(ts(2 << 16), node(2), 1), &[op(Op::Insert { at: 3_500, items: vec![s("x")] })], &view).unwrap();
    st.join(d);
    let Fragment::Seq(sq) = &st else { panic!() };
    let mut pg = Pager::new(sq, 64);
    let w = || Writer::new(ts(3 << 16), node(3), 1);
    let first = [op(Op::Delete { at: 3_500, len: 1 })];
    pg.run(|f| build(f, w(), &first, &view));
    let before = pg.whole.top().blocks.len() - pg.p.stubs().0.len();
    let ops = [op(Op::Delete { at: 3_499, len: 2 })];
    let got = pg.run(|f| build(f, w(), &ops, &view));
    assert!(got == build(&st, w(), &ops, &view), "same delta as on the whole state");
    let (all, loaded) = (pg.whole.top().blocks.len(), pg.whole.top().blocks.len() - pg.p.stubs().0.len());
    assert!(loaded <= before + 2, "{loaded} of {all} blocks loaded ({before} before)");
}

/// §5.7 Read, §9: a text whose placement is held in part reads a char from its record when the
/// row keeps none (stored rows keep none), or misses, so a `Set` there writes what it writes on
/// the whole, alone and after an insert in the same commit (fuzz: seq_ops).
#[test]
fn set_on_partial_text_matches_whole_spec_5_7() {
    let view = text_view();
    for ops in [vec![Op::Set(s(""))], vec![Op::Insert { at: 0, items: vec![s("x")] }, Op::Set(s(""))], vec![Op::Insert { at: 1, items: vec![s("bc")] }, Op::Set(s("bd"))]] {
        let mut st = Fragment::default();
        st.join(create(&mut Writer::new(ts(1 << 16), node(1), 1), &view, &s("a")).unwrap());
        let Some(Op::Set(v)) = ops.last().cloned() else { panic!() };
        let (got, _) = paged(&st, 1, || Writer::new(ts(2 << 16), node(2), 1), &ops.into_iter().map(op).collect::<Vec<_>>(), &view);
        st.join(got.unwrap().0);
        assert_eq!(st.read(), Some(v));
    }
}

/// §5.7 Read, §9: after a move or delete in the same commit, a `Set` on a sequence held in part
/// (a list or a text, records in pages of one) writes what it writes on the whole, for every
/// value one item away from the read after the first op (fuzz-style, exhaustive on short ones).
#[test]
fn set_after_op_on_partial_matches_whole_spec_5_7() {
    let mut r = crate::testutil::rng(0);
    let mut runs = 0;
    for text in [false, true] {
        let ty = if text { Ty::Text } else { list_ty() };
        let view = TyView(ty.clone());
        for n in 2..6usize {
            let items: Vec<Value> = match &ty {
                Ty::List(e) => (0..n).map(|_| value(&random_value(&mut r, e, 1))).collect(),
                _ => (0..n).map(|i| s(&((b'a' + i as u8) as char).to_string())).collect(),
            };
            let v0 = if text { Value::Str(items.iter().map(|v| if let Value::Str(x) = v { x.clone() } else { unreachable!() }).collect()) } else { Value::List(items.clone()) };
            let mut st = Fragment::default();
            st.join(create(&mut Writer::new(ts(1 << 16), node(1), 1), &view, &v0).unwrap());
            let mut firsts = vec![op(Op::Delete { at: 0, len: 1 }), op(Op::Delete { at: n - 1, len: 1 })];
            for at in 0..n {
                for to in 0..n {
                    firsts.push(op(Op::Move { at, len: 1, to }));
                }
                if !text {
                    // a write inside an element
                    firsts.push(PathOp { path: vec![PathSeg::Index(at), PathSeg::Field(1)], op: Op::Set(Value::Int(77)) });
                }
            }
            for first in firsts {
                let mut mid = st.clone();
                let mut b = DeltaBuilder::new(&mid, Writer::new(ts(2 << 16), node(2), 1));
                b.apply(&first, &view).unwrap();
                if let Some((d, _)) = b.finish() {
                    mid.join(d);
                }
                let read = mid.read().unwrap();
                let mut targets = vec![read.clone()];
                let k = match &read {
                    Value::List(l) => l.len(),
                    Value::Str(x) => x.chars().count(),
                    _ => unreachable!(),
                };
                for i in 0..k {
                    targets.push(match &read {
                        Value::List(l) => Value::List(l.iter().enumerate().filter(|x| x.0 != i).map(|x| x.1.clone()).collect()),
                        Value::Str(x) => Value::Str(x.chars().enumerate().filter(|c| c.0 != i).map(|c| c.1).collect()),
                        _ => unreachable!(),
                    });
                }
                for v in targets {
                    paged(&st, 1, || Writer::new(ts(2 << 16), node(2), 1), &[first.clone(), op(Op::Set(v))], &view);
                    runs += 1;
                }
            }
        }
    }
    assert!(runs > 300, "{runs}");
}

/// `count` inserts by another writer at random places of `st`, so its records and blocks are many.
fn scatter(r: &mut Rng, st: &mut Fragment, count: u64, ty: &Ty, text: &str) {
    for k in 0..count {
        let at = r.below(shown(st) + 1);
        let ins = op(Op::Insert { at, items: vec![new_item(r, ty, text)] });
        st.join(build(st, Writer::new(ts((10 + k) << 16), node(2), 1 + 10 * k), &[ins], &TyView(ty.clone())).unwrap().0);
    }
}

/// `base` with one random change: a splice of a text, an item removed, replaced or inserted in
/// a list.
fn edited(r: &mut Rng, base: &Value, ty: &Ty) -> Value {
    match base {
        Value::Str(x) => {
            let mut c: Vec<char> = x.chars().collect();
            let at = r.below(c.len() + 1);
            let del = r.below((c.len() - at).min(4) + 1);
            c.splice(at..at + del, "ed".chars().take(r.below(3)));
            Value::Str(c.into_iter().collect())
        }
        Value::List(x) => {
            let Ty::List(e) = ty else { return base.clone() };
            let mut x = x.clone();
            let at = r.below(x.len() + 1);
            match r.below(3) {
                0 if at < x.len() => {
                    x.remove(at);
                }
                1 if at < x.len() => x[at] = value(&random_value(r, e, 1)),
                _ => x.insert(at, value(&random_value(r, e, 1))),
            }
            Value::List(x)
        }
        _ => base.clone(),
    }
}

/// §5.7 Ops, §6.1, §8 (pages are joined independently), `seq_place`: larger random histories than
/// `index_ops_on_partial_placement_match_whole_spec_5_7` (many blocks), ops by index whose
/// commit ts is often below stamps already at their anchor (clock skew, a carried write), piles
/// of concurrent inserts from many writers at one index (more siblings than a block), and the
/// joins of held-back commits and of those piles: on a sequence held in part, ops write what
/// they write on the whole state, and a followed join is a whole pass (`partial_follow`).
#[test]
#[ignore = "property"]
fn partial_placement_skew_piles_and_joins_plain_spec_6_1() {
    let out = crate::testutil::crdt_seeds("tests_seq_ops::partial_placement_skew_piles_and_joins_plain_spec_6_1", 0..48, skew_piles_case);
    use osis_base::testenv::reach_floor as f;
    f("skewed", out.iter().map(|x| x[1]), 1, 2);
    f("piles", out.iter().map(|x| x[2]), 1, 2);
    f("joins followed in part", out.iter().map(|x| x[4]), 2, 1);
    // per seed (its six runs): under half by a whole pass, over a quarter of its joins followed
    // in part (the most seen two of six, the fewest about 37%)
    for (i, [runs, _, _, joins, followed, wholes]) in out.iter().enumerate() {
        assert!(wholes * 2 < *runs, "seed {i} of the range: {wholes} of {runs} runs by a whole pass");
        assert!(followed * 4 > *joins, "seed {i} of the range: {followed} of {joins} joins followed in part");
    }
}

/// One seed of `partial_placement_skew_piles_and_joins_plain`: [runs, skewed, piles, joins,
/// joins followed in part, runs by a whole pass].
fn skew_piles_case(round: u64) -> [usize; 6] {
    let mut r = crate::testutil::fixed(round);
    let (mut runs, mut low, mut piles, mut joins, mut followed, mut wholes) = (0, 0, 0, 0, 0, 0);
    let text = round.is_multiple_of(2);
    let ty = if text { Ty::Text } else { list_ty() };
    let view = TyView(ty.clone());
    let (Some(mut st), held) = history_state(&mut r, &ty, 4, 12, 6) else { return [0; 6] };
    let join_check = |st: &mut Fragment, d: Fragment, r: &mut Rng, joins: &mut usize, followed: &mut usize| {
        if let (Fragment::Seq(sq), Fragment::Seq(ds)) = (&*st, &d) {
            *joins += 1;
            *followed += usize::from(crate::tests_seq::partial_follow(sq, ds, 1 + r.below(6)).is_some());
        }
        st.join(d);
    };
    for k in 0..6u64 {
        if !matches!(st, Fragment::Seq(_)) {
            break;
        }
        let n = shown(&st);
        // half the time a skewed clock below the history's stamps (inserts only: a move or
        // delete below the stamps it overwrites breaks §2.2's clock rule, which `DeltaBuilder` checks)
        let skew = r.chance(1, 2);
        low += usize::from(skew);
        // above the sequence's reset, which would prune what the commit writes
        let floor = st.reset().map_or(0, |x| (x.ts.to_u64() >> 16) + 1);
        let t = if skew { floor + 1 + r.below(100) as u64 } else { 200 + k };
        let pin = r.below(n + 1);
        let ops: Vec<PathOp> = (0..1 + r.below(3))
            .map(|_| {
                let at = r.below(n.max(1));
                let len = 1 + r.below((n.saturating_sub(at)).clamp(1, 12));
                op(match if skew { 0 } else { r.below(5) } {
                    0 | 1 => Op::Insert { at: pin, items: vec![new_item(&mut r, &ty, "xy")] },
                    2 => Op::Delete { at, len },
                    _ => Op::Move { at, len, to: r.below(n.saturating_sub(len) + 1) },
                })
            })
            .collect();
        let w = || Writer::new(ts(t << 16), node(20 + k as u8), 1);
        let per = 1 + r.below(6);
        let (want, pg) = paged(&st, per, w, &ops, &view);
        runs += 1;
        wholes += pg.whole_passes;
        if let Some((d, _)) = want {
            join_check(&mut st, d, &mut r, &mut joins, &mut followed);
        }
        // a pile: writers at one index of this state, each unaware of the others
        if r.chance(1, 3) {
            piles += 1;
            let base = st.clone();
            let n = shown(&base);
            let at = r.below(n + 1);
            let mut ds = Vec::new();
            for j in 0..12u64 {
                let floor = base.reset().map_or(0, |x| (x.ts.to_u64() >> 16) + 1);
                let t = if r.chance(1, 2) { floor + 1 + r.below(300) as u64 } else { 400 + j };
                let mut b = DeltaBuilder::new(&base, Writer::new(ts((t << 16) + j), node(40 + j as u8 + 12 * (k as u8 % 4)), 1 + 100 * k));
                b.apply(&op(Op::Insert { at, items: vec![new_item(&mut r, &ty, "xy")] }), &view).unwrap();
                ds.extend(b.finish().map(|x| x.0));
            }
            for d in ds {
                join_check(&mut st, d, &mut r, &mut joins, &mut followed);
            }
        }
    }
    for d in held {
        join_check(&mut st, frag(&d), &mut r, &mut joins, &mut followed);
    }
    [runs, low, piles, joins, followed, wholes]
}

/// §5.7 Ops, §8 (pages are joined independently), `seq_place`, notes/api.md `edit`: on a text of many blocks held in part, an
/// edit against the current read (what a text session writes) loads only the blocks and records
/// around its change and writes what it writes on the whole state; one against a stale read (a
/// concurrent change elsewhere) or of the whole text matches whole, also equal.
#[test]
fn edit_on_partial_placement_loads_its_window_spec_5_7() {
    let mut r = crate::testutil::rng(0);
    let view = TyView(Ty::Text);
    let mut w = Writer::new(ts(1 << 16), node(1), 1);
    // not periodic: a window repeated elsewhere in base matches whole
    let text: String = (0..3000).map(|_| (b'a' + r.below(26) as u8) as char).collect();
    let mut st = create(&mut w, &view, &s(&text)).unwrap();
    scatter(&mut r, &mut st, 60, &Ty::Text, "xyz");
    let (mut few, mut stale_whole) = (0, 0);
    let mut stale = st.read().unwrap();
    for k in 0..40u64 {
        let cur = st.read().unwrap();
        let base = match k % 4 {
            3 => stale.clone(),
            _ => cur.clone(),
        };
        let new = match k % 8 {
            // every char changed: the window is the whole text
            7 => s("whole"),
            _ => edited(&mut r, &base, &Ty::Text),
        };
        let w = || Writer::new(ts((200 + k) << 16), node(9), 1000 + 10 * k);
        let (want, pg) = paged(&st, 40, w, &[op(Op::Edit { base: base.clone(), new })], &view);
        let (all, stubs) = (pg.whole.top().blocks.len(), pg.p.stubs().0.len());
        // (after a whole replace the text is short and may be emptied: an empty base is a look
        // at every record)
        if base == cur && k % 8 != 7 && base != s("") {
            assert!(all > 20 && all - stubs <= 3 && pg.loaded.len() <= 10, "step {k}: {} of {all} blocks, {} pages", all - stubs, pg.loaded.len());
            few += 1;
        } else if base != cur {
            stale_whole += usize::from(stubs == 0);
        }
        if let Some((d, _)) = want {
            st.join(d);
        }
        if k % 4 == 1 {
            stale = st.read().unwrap();
        }
    }
    assert!(few >= 20 && stale_whole >= 3, "{few} edits at their window, {stale_whole} stale edits matched whole");
}

/// §6.1 (greatest first): siblings by edge stamp, newest first, §8 (pages are joined independently), `seq_place`: a placement keeps a stamp at
/// or above every position write's, so a join of an insert stamped above it (a node's own
/// commit) places the run right after its anchor without looking at the anchor's children's
/// records: on a text held in part whose chars have children from another writer, such joins
/// follow as a whole pass would and load fewer pages than without the bound, never more.
#[test]
fn newest_stamp_skips_children_records_spec_6_1() {
    let mut r = crate::testutil::rng(0);
    let view = text_view();
    let mut w = Writer::new(ts(1 << 16), node(1), 1);
    let text: String = (0..800).map(|_| (b'a' + r.below(26) as u8) as char).collect();
    let mut st = create(&mut w, &view, &s(&text)).unwrap();
    // another writer's chars under many of them
    scatter(&mut r, &mut st, 150, &Ty::Text, "y");
    let (mut with, mut without, mut fewer) = (0, 0, 0);
    for k in 0..40u64 {
        let Fragment::Seq(sq) = &st else { panic!() };
        let n = shown(&st);
        let mut b = DeltaBuilder::new(&st, Writer::new(ts((1000 + k) << 16), node(9), 1 + 10 * k));
        b.apply(&PathOp { path: Vec::new(), op: Op::Insert { at: r.below(n + 1), items: vec![s("z")] } }, &view).unwrap();
        let (d, _) = b.finish().unwrap();
        let Fragment::Seq(ds) = &d else { panic!() };
        let (Some((_, a)), Some((_, b))) = (crate::tests_seq::partial_follow_in(sq, ds, 8, true), crate::tests_seq::partial_follow_in(sq, ds, 8, false)) else { panic!("step {k}: not followed") };
        assert!(a <= b, "step {k}: {a} pages with the bound, {b} without");
        (with, without, fewer) = (with + a, without + b, fewer + usize::from(a < b));
        st.join(d);
    }
    assert!(fewer >= 10 && with < without, "{with} pages with the bound, {without} without, fewer in {fewer} joins");
}

/// §6.1 (greatest first): siblings by edge stamp, newest first: a commit inserting x, moving an element right
/// after x, then inserting y right after x (y newest, x's run continues with it) places y
/// before the moved element; joined into a placed copy (whole and held in part) it follows
/// as a whole pass does, though the move is newer than everything before the commit.
#[test]
fn newest_move_onto_new_element_spec_6_1() {
    let view = text_view();
    let mut w = Writer::new(ts(1 << 16), node(1), 1);
    let text: String = (0..300).map(|i| (b'a' + (i % 26) as u8) as char).collect();
    let st = create(&mut w, &view, &s(&text)).unwrap();
    let mut b = DeltaBuilder::new(&st, Writer::new(ts(1000 << 16), node(9), 1));
    for op in [Op::Insert { at: 10, items: vec![s("x")] }, Op::Move { at: 50, len: 1, to: 11 }, Op::Insert { at: 11, items: vec![s("y")] }] {
        b.apply(&PathOp { path: Vec::new(), op }, &view).unwrap();
    }
    let (d, _) = b.finish().unwrap();
    let (Fragment::Seq(sq), Fragment::Seq(ds)) = (&st, &d) else { panic!() };
    assert!(crate::tests_seq::partial_follow(sq, ds, 8).is_some());
    let mut j = st.clone();
    let _ = j.read();
    j.join(d);
    assert!(cached(&j));
    let Some(Value::Str(got)) = j.read() else { panic!() };
    // index 50 after the insert: text's 49th char
    assert_eq!(got[9..13], format!("jxy{}", &text[49..50]));
}

/// §5.7 Ops, §8 (pages are joined independently), `seq_place`, notes/api.md `edit`: the list form of
/// `edit_on_partial_placement_loads_its_window_spec_5_7`: on a list of many blocks held in part,
/// an edit against the current read loads only the blocks and records around its change
/// (`edit_window`'s stretch, where a node reads the links it lends) and writes what it writes on
/// the whole list, never by a whole pass; one against a stale read of another length, or whose
/// stretch repeats in base, matches whole, also equal.
#[test]
fn list_edit_on_partial_placement_loads_its_window_spec_5_7() {
    let mut r = crate::testutil::rng(0);
    let ty = list_ty();
    let view = TyView(ty.clone());
    let Ty::List(e) = &ty else { unreachable!() };
    let mut w = Writer::new(ts(1 << 16), node(1), 1);
    let items: Vec<Value> = (0..1500).map(|_| value(&random_value(&mut r, e, 1))).collect();
    let mut st = create(&mut w, &view, &Value::List(items)).unwrap();
    scatter(&mut r, &mut st, 40, &ty, "");
    let (mut few, mut repeats, mut stale_whole) = (0, 0, 0);
    let mut stale = st.read().unwrap();
    for k in 0..24u64 {
        let cur = st.read().unwrap();
        let base = if k % 4 == 3 { stale.clone() } else { cur.clone() };
        let new = edited(&mut r, &base, &ty);
        let (Value::List(b), Value::List(nl)) = (&base, &new) else { panic!() };
        let win = crate::seq_diff::edit_window(b, nl);
        let w = || Writer::new(ts((200 + k) << 16), node(9), 1000 + 10 * k);
        let (want, pg) = paged(&st, 40, w, &[op(Op::Edit { base: base.clone(), new: new.clone() })], &view);
        assert_eq!(pg.whole_passes, 0, "step {k}: a whole pass");
        let (all, stubs) = (pg.whole.top().blocks.len(), pg.p.stubs().0.len());
        match win {
            Some(w) if base == cur => {
                assert!(w.lo <= w.pre.saturating_sub(32) && w.hi >= b.len() - w.suf && w.hi - w.lo <= 66, "step {k}: {w:?}");
                assert!(all > 10 && all - stubs <= 3 && pg.loaded.len() <= 10, "step {k}: {} of {all} blocks, {} pages", all - stubs, pg.loaded.len());
                few += 1;
            }
            None if base == cur => {
                repeats += 1;
                assert_eq!(stubs, 0, "step {k}: a repeated stretch matches whole");
            }
            // a stale base of another length than the read cannot take the window; one of the
            // same length may (base's own indices, the window equal in the read)
            _ if matches!(&cur, Value::List(c) if c.len() != b.len()) => {
                assert_eq!(stubs, 0, "step {k}: a stale edit of another length matches whole");
                stale_whole += 1;
            }
            _ => {}
        }
        if let Some((d, _)) = want {
            st.join(d);
        }
        if k % 4 == 1 {
            stale = st.read().unwrap();
        }
    }
    assert!(few >= 12 && stale_whole >= 2, "{few} edits at their window, {repeats} repeated, {stale_whole} stale edits matched whole");
}

/// §5.7, §9 (identity), notes/api.md `edit`: an edit resolved at its window writes what one matched against
/// the whole read writes, on random texts (runs of one char, periodic, words, random) after
/// concurrent changes (same-length replaces, shifts across the window, inserts) and random local
/// edits; at its window it lands at base's own indices. They differ only where whole's LCS, in a
/// periodic stretch changed on both sides, leaves the edit's base elements unmatched (its edit
/// lost or moved; the window's is the app's).
#[test]
#[ignore = "property"]
fn edit_window_matches_whole_plain_spec_5_7() {
    let out = crate::testutil::crdt_seeds("tests_seq_ops::edit_window_matches_whole_plain_spec_5_7", 0..3000, edit_window_case);
    use osis_base::testenv::reach_floor as f;
    // some edits resolved at their window (about 1 in 18), mostly alike
    f("at their window", out.iter().map(|x| usize::from(x.0)), 1, 60);
    f("same length", out.iter().map(|x| usize::from(x.1)), 1, 8);
    f("same", out.iter().map(|x| usize::from(x.2)), 29, 30);
}

/// One seed of `edit_window_matches_whole_plain`: (resolved at its window, the text kept its
/// length, the window's delta equals whole's).
fn edit_window_case(round: u64) -> (bool, bool, bool) {
    let mut r = crate::testutil::fixed(round);
    let view = text_view();
    let n = 1 + r.below(200);
    let base: Vec<char> = match r.below(5) {
        4 => {
            let words = ["the ", "cat ", "sat ", "on ", "mat ", "\n", "    "];
            let mut v = Vec::new();
            while v.len() < n {
                v.extend(words[r.below(words.len())].chars());
            }
            v
        }
        0 => vec!['a'; n],
        1 => {
            let m: Vec<char> = (0..1 + r.below(4)).map(|_| (b'a' + r.below(3) as u8) as char).collect();
            (0..n).map(|i| m[i % m.len()]).collect()
        }
        2 => (0..n).map(|i| if r.chance(1, 30) { 'z' } else { ['a', 'b'][i % 2] }).collect(),
        _ => (0..n).map(|_| (b'a' + r.below(26) as u8) as char).collect(),
    };
    let bs: String = base.iter().collect();
    let mut w = Writer::new(ts(1 << 16), node(1), 1);
    let mut st = create(&mut w, &view, &s(&bs)).unwrap();
    // concurrent changes, often keeping the length
    let mut ctr = 1000;
    for k in 0..1 + r.below(3) {
        let len = read_str(&st).chars().count();
        let ops = match r.below(3) {
            // a shift: delete before, insert as many after (or the reverse)
            0 => {
                let d = 1 + r.below(4.min(len.max(1)));
                let (i, j) = (r.below(len + 1), r.below(len + 1));
                let ins: String = (0..d).map(|_| ['a', 'b', 'z'][r.below(3)]).collect();
                let del = Op::Delete { at: i.min(len.saturating_sub(d)), len: d.min(len) };
                vec![del, Op::Insert { at: j.min(len - d.min(len)), items: vec![s(&ins)] }]
            }
            // a replace in place
            1 if len > 0 => {
                let i = r.below(len);
                let d = 1 + r.below((len - i).min(4));
                let ins: String = (0..d).map(|_| ['a', 'b', 'q'][r.below(3)]).collect();
                vec![Op::Delete { at: i, len: d }, Op::Insert { at: i, items: vec![s(&ins)] }]
            }
            _ => vec![Op::Insert { at: r.below(len + 1), items: vec![s("ab")] }],
        };
        let mut b = DeltaBuilder::new(&st, Writer::new(ts((10 + k as u64) << 16), node(2), ctr));
        let mut ok = true;
        for o in &ops {
            ok &= b.apply(&op(o.clone()), &view).is_ok();
        }
        if ok && let Some((d, range)) = b.finish() {
            ctr = range.hi;
            st.join(d);
        }
    }
    // the local edit against base
    let mut c = base.clone();
    let at = r.below(c.len() + 1);
    let del = r.below((c.len() - at).min(5) + 1);
    let ins: String = (0..r.below(4)).map(|_| ['a', 'b', 'X'][r.below(3)]).collect();
    c.splice(at..at + del, ins.chars());
    let o = Op::Edit { base: s(&bs), new: s(&c.iter().collect::<String>()) };
    let run = |whole: bool| {
        crate::seq_diff::WHOLE_ONLY.set(whole);
        let mut b = DeltaBuilder::new(&st, Writer::new(ts(1 << 40), node(9), 1 << 20));
        b.apply(&op(o.clone()), &view).unwrap();
        let got = b.finish().map(|x| x.0);
        crate::seq_diff::WHOLE_ONLY.set(false);
        got
    };
    let before = crate::seq_diff::WINDOWED.get();
    let (win, whole) = (run(false), run(true));
    let at_window = crate::seq_diff::WINDOWED.get() > before;
    let windowed = read_str(&st).chars().count() == base.len();
    let rd = |d: &Option<Fragment>| {
        let mut x = st.clone();
        if let Some(d) = d {
            x.join(d.clone());
        }
        read_str(&x)
    };
    // at its window, the edit (base to new less their common prefix and suffix) lands at
    // base's own indices in the current read
    let mut want: Vec<char> = read_str(&st).chars().collect();
    if at_window {
        let pre = base.iter().zip(&c).take_while(|(x, y)| x == y).count();
        let suf = base[pre..].iter().rev().zip(c[pre..].iter().rev()).take_while(|(x, y)| x == y).count();
        want.splice(pre..base.len() - suf, c[pre..c.len() - suf].iter().copied());
        assert_eq!(rd(&win), want.iter().collect::<String>(), "round {round}: at its window");
    }
    if win != whole {
        // they differ only where whole's LCS left a base element of the change unmatched in a
        // periodic stretch (Myers' alignment there, the text changed on both sides): its edit
        // lost or moved, so the reads differ and the edit was at its window
        assert!(rd(&win) != rd(&whole), "round {round}: the deltas differ, the reads alike");
        assert!(at_window, "round {round}: the reads differ\nbase {bs:?}\ncur  {:?}\nnew  {:?}\nwin  {:?}\nwhole {:?}", read_str(&st), c.iter().collect::<String>(), rd(&win), rd(&whole));
    }
    (at_window, windowed, win == whole)
}


/// A text over range records with concurrent chars anchored inside them: deleted stretches,
/// snapshot, then those chars (uppercase) on top.
fn ranged_text(r: &mut Rng) -> (Fragment, u64) {
    let mut a = Replica::new(1);
    for k in 0..8u64 {
        let n = read_str(&a.state).chars().count();
        a.commit(k + 1, &[op(Op::Insert { at: r.below(n + 1), items: vec![s(&"abcdefghij".repeat(4))] })], &text_view());
    }
    let mut c = a.fork(2);
    let mut qs = Vec::new();
    for (i, ch) in ["Q", "R", "S", "T"].into_iter().enumerate() {
        let n = read_str(&c.state).chars().count();
        qs.push(c.commit(20 + i as u64, &[op(Op::Insert { at: 20 + r.below(n - 40), items: vec![s(ch)] })], &text_view()).unwrap().0);
    }
    for k in 0..3u64 {
        let n = read_str(&a.state).chars().count();
        a.commit(30 + k, &[op(Op::Delete { at: r.below(n - 60), len: 20 + r.below(40) })], &text_view());
    }
    for q in qs {
        a.state.join(q);
    }
    (via_snapshot(&a.state), a.lo)
}

/// §4.5, §5.7: a commit of 30 ops (inserts, typos deleted again, moves of fresh and older
/// text, ops at both ends, a reset now and then) on a text with range records and chars
/// anchored inside them, or on a `Slots` position, encodes and reads like the same ops on a
/// plain string and like the ops committed one by one; `DeltaBuilder`'s kept view and the net
/// effect's omissions are checked after every op (debug assertions).
#[test]
#[ignore = "property"]
fn long_text_batch_is_net_effect_plain_spec_4_5() {
    crate::testutil::crdt_seeds("tests_seq_ops::long_text_batch_is_net_effect_plain_spec_4_5", 0..32, long_text_batch_case);
}

/// One seed of `long_text_batch_is_net_effect_plain`.
fn long_text_batch_case(seed: u64) {
    let mut r = crate::testutil::fixed(seed);
    let (state, lo) = if r.chance(1, 2) {
        ranged_text(&mut r)
    } else {
        let mut a = Replica::new(1);
        a.commit(1, &[op(Op::Set(s("the quick brown fox jumps over")))], &text_view());
        let mut mw = crdt_model::ops::Writer::new(crdt_model::stamp::Source::session(5, 0), 30 << 16, 1);
        let v = crdt_model::value::Value::Str(crdt_model::r#gen::random_text(&mut r, 20) + "s");
        a.state.join(crate::testutil::frag(&crdt_model::ops::create(&mut mw, &Ty::Register, &v)));
        (a.state, a.lo)
    };
    let mut model: Vec<char> = read_str(&state).chars().collect();
    let mut ops = Vec::new();
    let mut recent: Vec<usize> = Vec::new();
    for _ in 0..30 {
        let n = model.len();
        let near = |r: &mut Rng| {
            let ps: Vec<usize> = model.iter().enumerate().filter(|(_, c)| c.is_ascii_uppercase()).map(|(i, _)| i).collect();
            match recent.last() {
                Some(&p) if p < n && r.chance(1, 2) => p,
                _ if !ps.is_empty() && r.chance(1, 2) => ps[r.below(ps.len())],
                _ => r.below(n.max(1)),
            }
        };
        let o = match r.below(12) {
            0..=2 => {
                let at = (near(&mut r) + r.below(2)).min(n);
                recent.push(at);
                Op::Insert { at, items: vec![s(&(crdt_model::r#gen::random_text(&mut r, 2) + "z"))] }
            }
            3..=4 if n > 0 => {
                let at = near(&mut r);
                recent.pop();
                Op::Delete { at, len: (1 + r.below(4)).min(n - at) }
            }
            5..=8 if n > 1 => {
                let at = near(&mut r);
                let len = (1 + r.below(5)).min(n - at);
                Op::Move { at, len, to: r.below(n - len + 1) }
            }
            9 if r.chance(1, 4) => {
                recent.clear();
                Op::Set(s(&crdt_model::r#gen::random_text(&mut r, 6)))
            }
            10 if n > 0 => Op::Delete { at: 0, len: 1 },
            _ => Op::Insert { at: if r.chance(1, 2) { 0 } else { n }, items: vec![s("e")] },
        };
        apply_text(&mut model, &o, &state);
        ops.push(op(o));
    }
    let mut one = Replica { state: state.clone(), src: node(1), lo };
    for (k, o) in ops.iter().enumerate() {
        one.commit(51 + k as u64, std::slice::from_ref(o), &text_view());
    }
    let mut a = Replica { state, src: node(1), lo };
    a.commit(50, &ops, &text_view());
    assert_eq!(read_str(&a.state), model.iter().collect::<String>());
    assert_eq!(read_str(&a.state), read_str(&one.state));
}

/// §5.7 Live, §4.7: a list element whose creating delta expires goes, others' values in it
/// with it, whichever of the expiry and the nested write comes first: as at a node that only
/// holds the nested write (and as un-merging its creator, §4.6).
#[test]
fn expired_list_element_takes_others_values_spec_5_7() {
    let view = TyView(list_ty());
    let mut a = Replica::new(1);
    a.commit(1, &[op(Op::Set(Value::List(vec![item(1, 2)])))], &view);
    let base = a.state.clone();
    let mut c = Replica::new(3);
    c.state = base.clone();
    let (newer, _, _) = c.commit(6, &[PathOp { path: vec![PathSeg::Index(0), PathSeg::Field(2)], op: Op::Set(Value::Int(9)) }], &view).unwrap();
    let expired = |d: &crate::stamp::Dot| d.src == a.src;
    assert_eq!(joined(&base, &newer).read(), Some(Value::List(vec![item(1, 9)])));
    let mut gone = base.clone();
    gone.remove_gone(&expired);
    let only = joined(&Fragment::default(), &newer);
    assert_eq!(joined(&gone, &newer), only, "the nested write after");
    assert_eq!(joined(&newer, &gone), only, "and before");
    assert!(!matches!(only.read(), Some(Value::List(ref l)) if !l.is_empty()), "the element goes: {:?}", only.read());
}

/// §4.5, §5.7: a text element its commit made and removed, kept because the commit anchors at
/// it, goes as its creation without its char and with no flag (one at the delta stamp would lie
/// below the creation and lose to it); it reads hidden at the writer, at a receiver and through
/// a snapshot of either.
#[test]
fn removed_anchor_goes_charless_spec_4_5() {
    let view = text_view();
    let mut a = Replica::new(1);
    a.commit(1, &[op(Op::Set(s("hello")))], &view);
    let mut bt = DeltaBuilder::new(&a.state, Writer::new(ts(2 << 16), node(1), a.lo));
    bt.apply(&op(Op::Insert { at: 2, items: vec![s("abc")] }), &view).unwrap();
    bt.apply(&op(Op::Delete { at: 2, len: 1 }), &view).unwrap();
    bt.apply(&op(Op::Delete { at: 3, len: 1 }), &view).unwrap();
    assert_eq!(bt.view().read(), Some(s("hebllo")));
    let (d, range) = bt.finish().unwrap();
    let Fragment::Seq(sq) = &d else { panic!("{d:?}") };
    assert!(sq.elems().values().all(|e| e.deleted.is_none()), "no flag: {d:?}");
    assert_eq!(sq.elems().values().filter(|e| e.created.is_some() && matches!(e.content, crate::seq::SeqContent::None)).count(), 1, "'a' as its bare creation: {d:?}");
    let back = wired(&d, &node(1), range, 2);
    assert_eq!(back, d);
    let mut b = back.clone();
    assert_eq!(b.read(), Some(s("b")), "a receiver without the base");
    assert_eq!(via_snapshot(&b).read(), Some(s("b")));
    b.join(a.state.clone());
    a.state.join(back);
    for f in [&a.state, &b] {
        assert_eq!(f.read(), Some(s("hebllo")));
        assert_eq!(via_snapshot(f).read(), Some(s("hebllo")));
    }
}

/// §4.1 copy order, §6 (a deterministic function of state), `seq_lin`: a forged copy of an element's chosen position write (one
/// stamp, another anchor: two writers sharing a source and clock move one char apart), joined
/// into a replica whose placement is cached, with or without another writer's concurrent move:
/// the cached placement equals a whole pass and both orders join alike.
#[test]
fn forged_edge_copy_cached_placement_spec_6() {
    let mut base = Replica::new(1);
    base.commit(1, &[op(Op::Insert { at: 0, items: vec![s("abcde")] })], &text_view());
    for at in 0..5 {
        for (to1, to2) in (0..5).flat_map(|x| (0..5).map(move |y| (x, y))).filter(|(x, y)| x != y) {
            for other in [None, Some((4 - at, at))] {
                let fork = || Replica { state: base.state.clone(), src: base.src.clone(), lo: base.lo };
                let (mut a1, mut a2) = (fork(), fork());
                let (Some((d1, ..)), Some((d2, ..))) = (a1.commit(5, &[op(Op::Move { at, len: 1, to: to1 })], &text_view()), a2.commit(5, &[op(Op::Move { at, len: 1, to: to2 })], &text_view())) else { continue };
                let mut c = base.fork(2);
                let d3 = other.and_then(|(at, to)| c.commit(5, &[op(Op::Move { at, len: 1, to })], &text_view())).map(|d| d.0);
                let joined: Vec<Fragment> = [(&d1, &d2), (&d2, &d1)]
                    .into_iter()
                    .map(|(first, second)| {
                        let mut x = d3.iter().fold(base.state.clone(), |x, d| joined(&x, d));
                        x.join(first.clone());
                        let _ = x.read();
                        x.join(second.clone());
                        crate::testutil::check_lin(&x);
                        #[cfg(debug_assertions)]
                        {
                            let mut y = x.clone();
                            y.drop_caches();
                            assert_eq!(x.read(), y.read(), "cached read: move {at} to {to1}/{to2}, other {other:?}");
                        }
                        x
                    })
                    .collect();
                assert_eq!(joined[0], joined[1], "both orders: move {at} to {to1}/{to2}, other {other:?}");
            }
        }
    }
}

/// §5.7 move, §6.1, §4.6: one replica lacking a deleted element's creation and one holding it
/// make the same move. Where the creation is lacking, the move leaves the record holding no
/// position write on END, as a virtual anchor (a flag-only record), and moves what hangs below
/// it as roots, so undoing the move there restores the read, as END cannot be written back.
/// Once each holds everything they read alike, and undoing both moves restores the read from
/// before them, whichever move is newer.
#[test]
fn move_unplaced_record_converges_spec_5_7() {
    let view = text_view();
    let ins = |at: usize, x: &str| op(Op::Insert { at, items: vec![s(x)] });
    for later in [false, true] {
        let mut b = Replica::new(2);
        let (xc, _, _) = b.commit(1, &[ins(0, "x")], &view).unwrap();
        let (y, _, _) = b.commit(2, &[ins(1, "y")], &view).unwrap();
        let (del, _, _) = b.commit(3, &[op(Op::Delete { at: 0, len: 1 })], &view).unwrap();
        let mut a = Replica::new(1);
        a.commit(4, &[ins(0, "u")], &view);
        a.commit(5, &[ins(0, "zw")], &view);
        a.state.join(y);
        a.state.join(del);
        // c holds a's text and x's creation
        let mut c = a.fork(3);
        c.state.join(xc.clone());
        assert_eq!(c.state.read(), Some(s("zwuy")));
        let mv = [op(Op::Move { at: 2, len: 1, to: 0 }), op(Op::Move { at: 2, len: 2, to: 0 })];
        let (ta, tc) = if later { (7, 6) } else { (6, 7) };
        let (ab, cb) = (a.state.clone(), c.state.clone());
        let (da, sa, ra) = a.commit(ta, &mv, &view).unwrap();
        let (dc, sc, rc) = c.commit(tc, &mv, &view).unwrap();
        // a's own read before x's creation arrives (the second move's range "w", x, "y": x
        // stays, y moves as a root), its own undo, then everything joined
        assert_eq!(a.state.read(), Some(s("wyuz")));
        let x = crate::stamp::Dot { src: node(2), ctr: 1 };
        assert!(matches!(&da, Fragment::Seq(sq) if !sq.elems().contains_key(&x)), "no position write for x");
        let alone = joined(&a.state, &undo(&mut Writer::new(ts(8 << 16), sa.clone(), a.lo), &Undone { delta: &da, source: &sa, range: ra }, &a.state, &ab, &view).unwrap().unwrap());
        assert_eq!(alone.read(), ab.read());
        a.state.join(xc.clone());
        a.state.join(dc.clone());
        c.state.join(da.clone());
        assert_eq!(a.state, c.state);
        assert_eq!(a.state.read(), Some(s("wyuz")), "later {later}");
        let ua = undo(&mut Writer::new(ts(8 << 16), sa.clone(), a.lo), &Undone { delta: &da, source: &sa, range: ra }, &a.state, &ab, &view).unwrap();
        let uc = undo(&mut Writer::new(ts(9 << 16), sc.clone(), c.lo), &Undone { delta: &dc, source: &sc, range: rc }, &c.state, &cb, &view).unwrap();
        for u in [ua, uc].into_iter().flatten() {
            a.state.join(u.clone());
            c.state.join(u);
        }
        assert_eq!(a.state, c.state);
        assert_eq!(a.state.read(), Some(s("zwuy")), "both undone, later {later}");
    }
}

/// §5.7 paste: a paste whose dots no longer lie in the placement in the clipboard's order fails
/// (the caller inserts), so a paste reads as the clipboard's text. Here a paste re-anchors `d`
/// (below `x`, outside the pasted slice) at `f`, before `q`.
#[test]
fn paste_out_of_clipboard_order_fails_spec_5_7() {
    let view = text_view();
    let mut a = Replica::new(1);
    a.commit(1, &[op(Op::Insert { at: 0, items: vec![s("xd")] })], &view);
    a.commit(2, &[op(Op::Insert { at: 1, items: vec![s("cfq")] })], &view);
    assert_eq!(read_str(&a.state), "xcfqd");
    let xc = crate::cut_dots(&a.state, 0, 2).unwrap();
    let qd = crate::cut_dots(&a.state, 3, 2).unwrap();
    a.commit(3, &[op(Op::Delete { at: 3, len: 2 }), op(Op::Delete { at: 0, len: 2 })], &view);
    assert_eq!(read_str(&a.state), "f");
    // q goes from below f to HEAD, f to HEAD before it
    a.commit(4, &[op(Op::Move { at: 0, len: 1, to: 0 })], &view);
    // d hangs below x outside the slice: re-anchored at f, the visible element before x
    a.commit(5, &[op(Op::Paste { dots: xc, at: 0 })], &view);
    assert_eq!(read_str(&a.state), "xcf");
    let mut b = DeltaBuilder::new(&a.state, Writer::new(ts(6 << 16), a.src.clone(), a.lo));
    assert!(b.apply(&op(Op::Paste { dots: qd, at: 3 }), &view).is_err(), "d lies before q");
}

/// §5.7; spec/requirements.md, Scale: a deleted list element stays as a dead record (a later
/// insert may anchor at it), held in a range record as its creation `ts` and, when not anchored
/// at its source's element before, its anchor: the bytes a state holds (`approx_bytes`) per
/// element added from n to 10n elements, each appended by a commit of its own and all deleted by
/// one, at the writer (compacted) and decoded from its snapshot, about what the snapshot encodes
/// at most, for a list of registers and one of structs, one writer appending or two taking turns.
#[test]
fn deleted_elements_cost_a_ts_and_anchor_each_spec_5_7() {
    for (ty, item) in [(Ty::List(Box::new(Ty::Register)), (|c: usize| s(&c.to_string())) as fn(usize) -> Value), (list_ty(), |c: usize| item(c as i64, 1))] {
        let view = TyView(ty);
        for writers in [1u8, 2] {
            let cost = |n: usize| {
                let mut ws: Vec<Replica> = (1..=writers).map(Replica::new).collect();
                for c in 0..n {
                    let k = c % ws.len();
                    ws[k].grow(10 + c as u64, &[op(Op::Insert { at: c, items: vec![item(c)] })], &view);
                    let st = ws[k].state.clone();
                    ws.iter_mut().for_each(|w| w.state = st.clone());
                }
                ws[0].grow(10 + n as u64, &[op(Op::Delete { at: 0, len: n })], &view);
                let mut st = ws[0].state.clone();
                st.compact();
                let snap = via_snapshot(&st);
                assert_eq!(snap, st);
                assert_eq!(st.read(), Some(Value::List(vec![])), "every element deleted");
                [st.approx_bytes(), snap.approx_bytes(), crate::testutil::snapshot_bytes(&snap).len()]
            };
            let (x, y) = (cost(20), cost(200));
            let per: Vec<usize> = (0..3).map(|i| (y[i] - x[i]) / 180).collect();
            assert!(per[0] <= 8 + 24 * usize::from(writers - 1) && per[1] == per[0] && per[0] <= per[2] + 2, "bytes per deleted element with {writers} writers (state, snapshot decoded, encoded): {per:?}");
        }
    }
}

/// §4.2, `seq_span::coalesce`: a range's creations never fall in `ts`, so deleted text elements
/// of one source created at `ts` 1, 3, 2 (one delete over them) do not compact to one range, and a
/// reset at 2.5 keeps the same creations (the second's alone) whether or not the state was
/// compacted first.
#[test]
fn compact_never_ranges_falling_creations_spec_4_7() {
    use crate::fragment::Meta;
    use crate::seq::{Anchor, Seq, SeqContent, SeqElem};
    use crate::stamp::{Dot, Stamp};
    let del = Stamp::new(ts(4 << 16), node(2), 9);
    let el = |k: u64, t: u64| {
        let st = Stamp::new(ts(t << 16), node(1), k);
        let at = if k == 1 { Anchor::Head } else { Anchor::Dot(Dot::new(node(1), k - 1)) };
        (st.dot.clone(), SeqElem { created: Some((st.clone(), at.clone())), content: SeqContent::None, pos: vec![(st, at, None)], deleted: Some((del.clone(), true)), undel: None, span: 1, each: None })
    };
    let plain = Fragment::Seq(Seq::new(true, Meta::default(), [el(1, 1), el(2, 3), el(3, 2)].into_iter().collect()));
    let reset = Fragment::Seq(Seq::new(true, Meta { reset: Some(Stamp::new(ts(5 << 15), node(2), 1)), ..Meta::default() }, Default::default()));
    let mut compacted = plain.clone();
    compacted.compact();
    let (mut a, mut b) = (plain, compacted);
    a.join(reset.clone());
    b.join(reset);
    assert_eq!(b, a, "compacting changes no join");
    let Fragment::Seq(s) = &a else { unreachable!() };
    let created: Vec<Dot> = crate::seq_span::expand(s.elems().clone()).into_iter().filter(|(_, e)| e.created.is_some()).map(|(d, _)| d).collect();
    assert_eq!(created, vec![Dot::new(node(1), 2)], "the element created above the reset alone keeps its creation");
}
