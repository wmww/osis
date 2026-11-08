//! The writes that win (spec/crdt.md §4.8, `Fragment::winners`): against a from-scratch,
//! pairwise definition over every write a fragment holds, and small examples of one write op
//! stamping many writes of which only some die.

use crate::batch::Batch;
use crate::fragment::{Elem, Fragment, Meta};
use crate::ops::{Op, PathOp, Writer};
use crate::seq::{Seq, SeqContent, SeqElem};
use crate::stamp::{Dot, Source, Stamp};
use crate::testutil::{TyView, frag, history, history_honest, sess, sink_no_seq, ts};
use crate::winners::{ByWrite, Kind, Place, Won};
use crdt_model::ops::Ty;
use osis_base::{Tid, Ts, Value};
use proptest::prelude::*;
use std::collections::{BTreeMap, BTreeSet};

/// A write as held, whether it wins or not, with what the pairwise rule needs to know.
#[derive(Clone, Debug)]
struct Raw {
    w: Won,
    /// A text element's creation, not an embedded char's (§7).
    text_creation: bool,
    /// A creation's own position write: it beats position writes below it, but is the
    /// creation, not a write of its own.
    shadow: bool,
}

/// Every write `f` holds, by position as `winners` keys them: every record of a map dot, both
/// position writes of a sequence element, a deleted text element's creation.
fn raw(f: &Fragment) -> Vec<Raw> {
    let mut out = Vec::new();
    walk(f, &mut Vec::new(), &mut out);
    out
}

fn put(out: &mut Vec<Raw>, path: &[Place], kind: Kind, s: &Stamp) {
    out.push(Raw { w: Won { path: path.to_vec(), kind, stamp: s.clone() }, text_creation: false, shadow: false });
}

fn walk(f: &Fragment, path: &mut Vec<Place>, out: &mut Vec<Raw>) {
    let meta = |out: &mut Vec<Raw>, path: &[Place], m: &Meta| {
        m.reset.iter().for_each(|s| put(out, path, Kind::Reset, s));
        m.w.iter().for_each(|s| put(out, path, Kind::W, s));
    };
    let inside = |f: &Fragment, path: &mut Vec<Place>, out: &mut Vec<Raw>| {
        path.push(Place::In);
        walk(f, path, out);
        path.pop();
    };
    let elems = |es: &BTreeMap<Dot, Elem>, path: &mut Vec<Place>, out: &mut Vec<Raw>| {
        for (d, e) in es {
            path.push(Place::Elem(d.clone()));
            e.reset.iter().for_each(|s| put(out, path, Kind::Reset, s));
            if let Some(x) = e.frag.as_deref() {
                inside(x, path, out);
            }
            path.pop();
        }
    };
    match f {
        Fragment::Register(r) => {
            r.reset.iter().for_each(|s| put(out, path, Kind::Reset, s));
            r.write.iter().for_each(|w| put(out, path, Kind::Value, &w.stamp));
        }
        Fragment::Slots(s) => {
            if let Some(r) = &s.reg {
                walk(&Fragment::Register(r.clone()), path, out);
            }
            s.slots.values().for_each(|x| walk(x, path, out));
        }
        Fragment::Bag(b) => {
            meta(out, path, &b.meta);
            elems(&b.elems, path, out);
        }
        Fragment::Set(b) => {
            meta(out, path, &b.meta);
            elems(&b.elems, path, out);
        }
        Fragment::Struct(s) => {
            meta(out, path, &s.meta);
            for (k, x) in &s.fields {
                path.push(Place::Field(*k));
                walk(x, path, out);
                path.pop();
            }
        }
        Fragment::Enum(e) => {
            meta(out, path, &e.meta);
            e.case.iter().for_each(|c| put(out, path, Kind::Case, &c.stamp));
            for (k, x) in &e.payloads {
                path.push(Place::Case(*k));
                walk(x, path, out);
                path.pop();
            }
        }
        Fragment::Map(m) => {
            meta(out, path, &m.meta);
            for (id, e) in &m.entries {
                path.push(Place::Entry(id.dot.clone()));
                e.reset.iter().for_each(|s| put(out, path, Kind::Reset, s));
                e.created.iter().for_each(|s| put(out, path, Kind::Created, s));
                if let Some(x) = e.frag.as_deref() {
                    inside(x, path, out);
                }
                path.pop();
            }
        }
        Fragment::Seq(s) => {
            meta(out, path, &s.meta);
            for (d, e) in s.elems() {
                for k in 0..e.span {
                    let (d, e) = crate::seq_span::piece(d, e, k, 1);
                    path.push(Place::Item(d.clone()));
                    if let Some((c, _)) = &e.created {
                        out.push(Raw { w: Won { path: path.clone(), kind: Kind::Created, stamp: c.clone() }, text_creation: s.text && !d.src.is_derived(), shadow: false });
                    }
                    for p in &e.pos {
                        out.push(Raw { w: Won { path: path.clone(), kind: Kind::Pos, stamp: p.0.clone() }, text_creation: false, shadow: p.0.dot == d });
                    }
                    if let Some((st, v)) = &e.deleted {
                        let kind = match (s.text, v) {
                            (false, _) => Kind::ElemReset,
                            (true, true) => Kind::Delete,
                            (true, false) => Kind::Undelete,
                        };
                        out.push(Raw { w: Won { path: path.clone(), kind, stamp: st.clone() }, text_creation: false, shadow: false });
                    }
                    if let SeqContent::Frag(x) = &e.content {
                        inside(x, path, out);
                    }
                    path.pop();
                }
            }
        }
    }
}

/// Whether a write of `all` with a greater stamp resets `w` from at or above (a reset, or a
/// register write, which implies one) or resets the list element it is inside.
fn pruned(w: &Raw, all: &[Raw]) -> bool {
    let prefix = |p: &[Place]| w.w.path.starts_with(p);
    all.iter().any(|s| {
        s.w.stamp > w.w.stamp
            && match s.w.kind {
                Kind::Reset | Kind::Value => prefix(&s.w.path),
                Kind::ElemReset => s.w.path.len() < w.w.path.len() && prefix(&s.w.path),
                _ => false,
            }
    })
}

/// A text flag write: a delete or an undelete, one register.
fn is_flag(k: Kind) -> bool {
    matches!(k, Kind::Delete | Kind::Undelete)
}

/// Whether `s` beats `w` at its position: a greater stamp of the same kind (a flag of a flag),
/// or a text creation above a flag of its element (the char is one register over both, §5.7);
/// of copies of one flag write, a delete beats an undelete (§4.1 copy order).
fn beats(s: &Raw, w: &Raw) -> bool {
    let tie = s.w.stamp == w.w.stamp && s.w.kind == Kind::Delete && w.w.kind == Kind::Undelete;
    s.w.path == w.w.path && (tie || s.w.stamp > w.w.stamp && (s.w.kind == w.w.kind || is_flag(s.w.kind) && is_flag(w.w.kind) || s.w.kind == Kind::Created && is_flag(w.w.kind)))
}

/// §4.8 from scratch: `w` is superseded among `all` when it is pruned there, a write there beats
/// it at its position, or it is a text element's creation whose winning flag (of the flags there
/// at or above it and not pruned) is a delete.
fn superseded(w: &Raw, all: &[Raw]) -> bool {
    let pairwise = pruned(w, all) || all.iter().any(|s| beats(s, w));
    let deleted = w.text_creation && all.iter().filter(|s| is_flag(s.w.kind) && s.w.path == w.w.path && s.w.stamp >= w.w.stamp && !pruned(s, all)).max_by(|a, b| (&a.w.stamp, a.w.kind == Kind::Delete).cmp(&(&b.w.stamp, b.w.kind == Kind::Delete))).is_some_and(|f| f.w.kind == Kind::Delete);
    pairwise || deleted
}

/// §4.8 When, from scratch: whether `s` supersedes `w` alone (pruning it, beating it at its
/// position, or deleting its text element).
fn kills(s: &Raw, w: &Raw) -> bool {
    pruned(w, std::slice::from_ref(s)) || beats(s, w) || w.text_creation && s.w.kind == Kind::Delete && s.w.path == w.w.path && s.w.stamp >= w.w.stamp
}

/// The writes of `all` none of `all` supersedes.
fn unsuperseded(all: &[Raw]) -> BTreeSet<Won> {
    all.iter().filter(|w| !w.shadow && !superseded(w, all)).map(|w| w.w.clone()).collect()
}

fn join(a: &Fragment, b: &Fragment) -> Fragment {
    let mut x = a.clone();
    x.join(b.clone());
    x
}

/// Random histories of `types`, joins of random subsets of their commits (as snapshots carry
/// them): `winners` is the from-scratch set of each, and the writes of one dead in a join of two
/// are those the other's writes supersede, so one the other holds supersedes each (`ByWrite`
/// of its `held_writes`; any clocks). Every write the bodies (deltas, and joins of them as snapshots) hold, noted by write
/// (`ByWrite`), each dated at its body's latest stamp: the earliest superseding a write is the
/// earliest body holding any write that supersedes it alone.
fn winners_check(seed: u64, types: &[Ty], honest: bool) {
    let mut r = crate::testutil::rng(seed | 1);
    let commits = if honest { history_honest(&mut r, types, 3, 4) } else { history(&mut r, types, 3, 4) };
    let bodies: Vec<Fragment> = commits.iter().map(|c| frag(&c.delta)).collect();
    first_superseding_check(&bodies);
    for _ in 0..6 {
        let mut pick = || bodies.iter().filter(|_| r.chance(1, 2)).fold(Fragment::default(), |f, b| join(&f, b));
        let (a, b) = (pick(), pick());
        let ab = join(&a, &b);
        // joined bodies, as snapshots: a deleted text creation still supersedes
        first_superseding_check(&[a.clone(), b.clone()]);
        for x in [&a, &b, &ab] {
            let got: BTreeSet<Won> = x.winners().iter().collect();
            assert_eq!(got, unsuperseded(&raw(x)), "winners are the writes held that none held supersedes: {x:?}");
        }
        let both: Vec<Raw> = raw(&a).into_iter().chain(raw(&b)).collect();
        let want: BTreeSet<Won> = raw(&a).into_iter().filter(|w| a.winners().contains(&w.w) && superseded(w, &both)).map(|w| w.w).collect();
        let dead = a.winners().minus(&ab.winners());
        assert_eq!(dead, want, "dead in a join: the winners the other side's writes supersede");
        let mut other: ByWrite<()> = ByWrite::default();
        other.note(&b.held_writes(), |_| ());
        for w in &dead {
            assert!(a.holds_stamp(&w.stamp), "a dead write is the side's by exact stamp: {w:?}");
            assert!(other.first_superseding(w, |_| Some(w.stamp.ts)).is_some(), "a dead write dies by a write the other side holds: {w:?} in {ab:?}");
        }
    }
}

fn first_superseding_check(bodies: &[Fragment]) {
    let date = |b: &Fragment| raw(b).iter().map(|x| x.w.stamp.ts).max().unwrap_or_default();
    let mut ix: ByWrite<Option<Ts>> = ByWrite::default();
    for b in bodies {
        let d = date(b);
        ix.note(&b.held_writes(), |x| *x = Some(x.map_or(d, |y| y.min(d))));
    }
    for w in bodies.iter().flat_map(raw).filter(|w| !w.shadow) {
        let want = bodies.iter().filter(|b| raw(b).iter().any(|s| kills(s, &w))).map(date).min();
        assert_eq!(ix.first_superseding(&w.w, |x| *x), want, "the earliest body superseding {w:?}");
    }
}

proptest! {
    /// §4.8: `winners` against the pairwise definition, maps, structs, registers and bags.
    #[test]
    fn winners_from_scratch_spec_4_8(seed in any::<u64>()) {
        winners_check(seed, &[sink_no_seq()], false);
        winners_check(seed, &[sink_no_seq()], true);
    }

    /// §4.8, §5.6, §5.7, §7: sequences at any depth, and positions written in several encodings.
    #[test]
    fn seq_winners_from_scratch_spec_4_8(seed in any::<u64>()) {
        for honest in [false, true] {
            winners_check(seed, &[Ty::Text], honest);
            winners_check(seed, &[Ty::List(Box::new(Ty::Struct([(1, Ty::Register), (2, Ty::Text)].into_iter().collect())))], honest);
            winners_check(seed, &[Ty::Map(Box::new(Ty::Register), Box::new(Ty::Text))], honest);
            winners_check(seed, &[Ty::Text, Ty::Register, sink_no_seq()], honest);
        }
    }
}

fn x() -> Source {
    sess(Tid::from_bytes([1; 15]))
}

fn text_view() -> TyView {
    TyView(Ty::Text)
}

/// The delta of `ops` against `st`, written at `t` from counter `lo`.
fn edit(st: &Fragment, t: u64, lo: u64, ops: Vec<Op>) -> Fragment {
    let mut b = Batch::new(st, Writer::new(ts(t), x(), lo));
    for o in ops {
        b.apply(&PathOp { path: vec![], op: o }, &text_view()).unwrap();
    }
    b.finish().unwrap().0
}

fn s(v: &str) -> Value {
    Value::Str(v.into())
}

/// The writes of `a` dead in `a ⊔ b`, by kind and stamp.
fn dead(a: &Fragment, b: &Fragment) -> Vec<(Kind, Stamp)> {
    a.winners().minus(&join(a, b).winners()).into_iter().map(|w| (w.kind, w.stamp)).collect()
}

/// §4.1, §4.8: a register beaten by a greater stamp dies, a late older write dies on arrival,
/// a reset kills the writes below it.
#[test]
fn beaten_and_pruned_die_spec_4_8() {
    use crate::fragment::{RegWrite, Register, Struct};
    let st = |t: u64, c: u64| Stamp::new(ts(t), x(), c);
    let reg = |s: Stamp, v: i64| Fragment::Register(Register { reset: None, write: Some(RegWrite { stamp: s, value: Some(Value::Int(v)) }) });
    let field = |s: Stamp, v: i64| Fragment::Struct(Struct { fields: [(1, reg(s, v))].into_iter().collect(), ..Default::default() });
    let (a, b) = (field(st(1, 1), 1), field(st(2, 2), 2));
    assert_eq!(dead(&a, &b), vec![(Kind::Value, st(1, 1))]);
    assert_eq!(dead(&field(st(1, 3), 3), &b), vec![(Kind::Value, st(1, 3))], "a late older write");
    assert!(dead(&b, &a).is_empty());
    let mut reset = Struct::default();
    reset.meta.reset = Some(st(3, 4));
    assert_eq!(dead(&b, &Fragment::Struct(reset)), vec![(Kind::Value, st(2, 2))]);
}

/// §5.7 (`pos` keeps the beaten `cur` as `prev`): one move writes the position of two elements
/// with one stamp; a later move of one of them kills that element's position write alone,
/// though its record keeps it.
#[test]
fn move_beaten_as_cur_dies_kept_as_prev_spec_4_8() {
    let ins = edit(&Fragment::default(), 1, 1, vec![Op::Insert { at: 0, items: vec![s("abc")] }]);
    let mv = edit(&ins, 2, 10, vec![Op::Move { at: 0, len: 2, to: 1 }]);
    let a = join(&ins, &mv);
    assert_eq!(a.read(), Some(s("cab")));
    let moved: Vec<Won> = mv.winners().iter().filter(|w| w.kind == Kind::Pos).collect();
    assert_eq!(moved.len(), 2, "one move, two position writes");
    let again = edit(&a, 3, 20, vec![Op::Move { at: 1, len: 1, to: 2 }]);
    let ab = join(&a, &again);
    assert_eq!(ab.read(), Some(s("cba")));
    let gone: Vec<Won> = a.winners().minus(&ab.winners()).into_iter().collect();
    assert_eq!(gone.len(), 1, "only the moved element's write: {gone:?}");
    assert!(moved.contains(&gone[0]));
    assert!(ab.holds_stamp(&gone[0].stamp), "kept as `prev`");
}

/// §4.8 (an element deleted): deleting one char of an insert kills that element's creation
/// alone, though its record keeps it.
#[test]
fn text_creation_dies_at_delete_kept_in_record_spec_4_8() {
    let a = edit(&Fragment::default(), 1, 1, vec![Op::Insert { at: 0, items: vec![s("abc")] }]);
    let del = edit(&a, 2, 10, vec![Op::Delete { at: 1, len: 1 }]);
    let ab = join(&a, &del);
    assert_eq!(ab.read(), Some(s("ac")));
    let gone: Vec<Won> = a.winners().minus(&ab.winners()).into_iter().collect();
    assert_eq!(gone.iter().map(|w| w.kind).collect::<Vec<_>>(), vec![Kind::Created], "{gone:?}");
    let created: Vec<Won> = a.winners().iter().filter(|w| w.kind == Kind::Created).collect();
    assert_eq!(created.len(), 3);
    assert_eq!(gone[0], created[1], "the middle char's");
    assert!(ab.holds_stamp(&gone[0].stamp), "its record keeps it");
    // an undelete over the delete: the creation wins again
    let mut un = Seq::empty(true);
    let Place::Item(d) = gone[0].path[0].clone() else { panic!() };
    un.elems_mut().insert(d, SeqElem { deleted: Some((Stamp::new(ts(3), x(), 30), false)), ..SeqElem::bare() });
    assert!(join(&ab, &Fragment::Seq(un)).winners().contains(&gone[0]));
}

/// §5.6 (a dot's records are one entry): one put writes k1 and k2 under one stamp; k1's value
/// held value-less in its key-erased record (a snapshot's copy of an expiring put) is beaten by
/// a later write in the keyed record: k1's write is dead, k2's not, though each record keeps
/// its own.
#[test]
fn record_pair_cross_death_spec_5_6() {
    use crate::ops::{create, diff};
    use crate::view::AnyView;
    let map = |k1: &str| Value::Map(osis_base::ValueMap::from([(s("k1"), s(k1)), (s("k2"), s("p"))]));
    let put = create(&mut Writer::new(ts(5), x(), 1), &AnyView, &map("p")).unwrap();
    let later = diff(&mut Writer::new(ts(8), x(), 20), Some(&put), &AnyView, &map("w")).unwrap().unwrap();
    let mut erased = put.clone();
    erased.strip(&|d| d.ctr < 20);
    let pw: BTreeSet<Won> = put.winners().iter().filter(|w| w.kind == Kind::Value).collect();
    assert_eq!(pw.len(), 2, "two values");
    assert_eq!(pw.iter().map(|w| &w.stamp).collect::<BTreeSet<_>>().len(), 1, "under one stamp");
    for (a, b) in [(&erased, &later), (&later, &erased)] {
        let ab = join(a, b);
        let gone = erased.winners().minus(&ab.winners());
        assert_eq!(gone.len(), 1, "k1's value alone: {gone:?}");
        assert!(pw.contains(gone.iter().next().unwrap()));
        assert!(ab.holds_stamp(&gone.iter().next().unwrap().stamp), "each record keeps its write");
    }
}
