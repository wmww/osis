//! Undo against the reference model (spec/crdt.md §4.6, §5.1, §5.2, §5.7): the model's undo is written from
//! the spec alone (core/test/crdt-model/src/undo.rs); both undo one random op, with and without a concurrent op
//! of another writer, from states with absent spots, and must read alike. Fresh-dot allocation may differ, so
//! reads are compared, not deltas.

use crate::fragment::Fragment;
use crate::ops::Writer;
use crate::stamp::CounterRange;
use crate::testutil::{TyView, frag, mapply, source, ts, value};
use crate::undo::{Undone, undo};
use crdt_model::r#gen::{Rng, random_op, random_value};
use crdt_model::ops::{Ty, Writer as MWriter};
use crdt_model::stamp::{Dot, Source as MSource};
use crdt_model::state::Frag;
use crdt_model::undo::{Stats, undo_stats};
use crdt_model::value::Value as MValue;
use proptest::prelude::*;

/// Every encoding with sequences, nested: a list of structs holding a text and a set, a map of the same, an
/// enum whose payload is the same.
fn sink() -> Ty {
    let inner = Ty::Struct([(1, Ty::Register), (2, Ty::Set(Box::new(Ty::Register))), (3, Ty::Text)].into_iter().collect());
    let cases = [(0, None), (1, Some(Ty::Register)), (2, Some(inner.clone()))].into_iter().collect();
    Ty::Struct(
        [
            (1, Ty::Register),
            (2, Ty::Counter),
            (3, Ty::Max),
            (4, Ty::Text),
            (5, Ty::Enum(cases)),
            (6, Ty::Set(Box::new(Ty::Register))),
            (7, Ty::Map(Box::new(Ty::Register), Box::new(inner.clone()))),
            (8, Ty::List(Box::new(inner))),
            (9, Ty::Min),
            (10, Ty::List(Box::new(Ty::Register))),
        ]
        .into_iter()
        .collect(),
    )
}

fn types() -> Vec<Ty> {
    vec![sink(), sink(), sink(), Ty::Text, Ty::List(Box::new(Ty::Register)), Ty::Counter, Ty::Map(Box::new(Ty::Register), Box::new(Ty::Set(Box::new(Ty::Register))))]
}

/// `v` with some composite struct fields and composite enum payloads left out, at any depth. Register fields
/// stay: a register absent below a present composite cannot be made absent again (§4.6), so undo would not be
/// exact there.
fn partial(r: &mut Rng, ty: &Ty, v: &MValue) -> MValue {
    match (ty, v) {
        (Ty::Struct(fts), MValue::Map(kv)) => MValue::Map(
            kv.iter()
                .filter_map(|(k, fv)| {
                    let MValue::Int(id) = k else { return Some((k.clone(), fv.clone())) };
                    let ft = &fts[&(*id as u64)];
                    if ft.enc() != 0 && r.chance(1, 3) {
                        return None;
                    }
                    Some((k.clone(), partial(r, ft, fv)))
                })
                .collect(),
        ),
        (Ty::Enum(cases), MValue::Enum(id, Some(p))) => match &cases[id] {
            Some(pt) if pt.enc() != 0 && r.chance(1, 3) => MValue::Enum(*id, None),
            Some(pt) => MValue::Enum(*id, Some(Box::new(partial(r, pt, p)))),
            None => v.clone(),
        },
        (Ty::Map(_, vt), MValue::Map(kv)) => MValue::Map(kv.iter().map(|(k, x)| (k.clone(), partial(r, vt, x))).collect()),
        (Ty::List(et), MValue::List(items)) => MValue::List(items.iter().map(|x| partial(r, et, x)).collect()),
        _ => v.clone(),
    }
}

fn mread(s: &Option<Frag>) -> Option<osis_base::Value> {
    s.as_ref().and_then(|s| s.read()).map(|v| value(&v))
}

/// What one case exercised.
#[derive(Default, Debug)]
struct Hits {
    stats: Stats,
    cases: usize,
    undone: usize,
    redone: usize,
    again: usize,
    concurrent_below: usize,
    concurrent_above: usize,
    seq: usize,
    exact: usize,
}

fn add(a: &mut Stats, b: &Stats) {
    a.absent_root += b.absent_root;
    a.absent_nested += b.absent_nested;
    a.absent_blocked += b.absent_blocked;
    a.replace += b.replace;
    a.bag_reset += b.bag_reset;
    a.register += b.register;
    a.register_kept += b.register_kept;
    a.creation += b.creation;
    a.flag += b.flag;
    a.list_reinsert += b.list_reinsert;
    a.set_readd += b.set_readd;
    a.key_readd += b.key_readd;
    a.position += b.position;
    a.position_kept += b.position_kept;
    a.stepped += b.stepped;
}

fn has_seq(f: &Frag) -> bool {
    match f {
        Frag::Seq { .. } => true,
        Frag::Struct { fields, .. } => fields.values().any(has_seq),
        Frag::Enum { payloads, .. } => payloads.values().any(has_seq),
        Frag::Map { entries, .. } => entries.values().any(|e| e.frag.as_deref().is_some_and(has_seq)),
        _ => false,
    }
}

/// Whether the delta holds a position write that is not a creation (a move).
fn has_move(f: &Frag) -> bool {
    match f {
        Frag::Seq { elems, .. } => elems.values().any(|e| (e.created.is_none() && !e.pos.is_empty()) || matches!(&e.content, crdt_model::state::Content::Frag(x) if has_move(x))),
        Frag::Struct { fields, .. } => fields.values().any(has_move),
        Frag::Enum { payloads, .. } => payloads.values().any(has_move),
        Frag::Map { entries, .. } => entries.values().any(|e| e.frag.as_deref().is_some_and(has_move)),
        _ => false,
    }
}

/// One random case: a base (absent, partial, or after a few ops), writer 1's op d1 against it, now and then
/// writer 2's op d2 against the same base (stamped below d1, between d1 and the undo, or above the undo); the
/// undo of d1 by model and implementation against the joined state with the base as the undo buffer.
fn case(r: &mut Rng, hits: &mut Hits) {
    let tys = types();
    let ty = tys[r.below(tys.len())].clone();
    let view = TyView(ty.clone());
    let (n1, n2) = (MSource::node(1), MSource::node(2));
    let mut w1 = MWriter::new(n1.clone(), 1 << 16, 1);
    let mut w2 = MWriter::new(n2.clone(), 1 << 16, 1);
    let mut base: Option<Frag> = None;
    if !r.chance(1, 5) {
        let v = random_value(r, &ty, 0);
        let v = if r.chance(2, 3) { partial(r, &ty, &v) } else { v };
        base = Some(crdt_model::ops::create(&mut w1, &ty, &v));
        base.as_mut().unwrap().prune(None);
    }
    for k in 0..r.below(8) as u64 {
        let w = if r.chance(1, 2) { &mut w1 } else { &mut w2 };
        let before = w.clone();
        w.next_commit(((2 + k) << 16) + 1);
        match random_op(r, w, &ty, base.as_ref()) {
            Some(d) => mapply(&mut base, d),
            None => *w = before,
        }
    }
    hits.cases += 1;
    let (t1, tu) = (20u64 << 16, 30u64 << 16);
    w1.next_commit(t1);
    let Some(d1) = random_op(r, &mut w1, &ty, base.as_ref()) else { return };
    let mut state = base.clone();
    mapply(&mut state, d1.clone());
    let conc = r.chance(1, 2);
    let mut later = false;
    if conc {
        let t2 = [10u64, 25, 40][r.below(3)] << 16;
        w2.next_commit(t2 + 2);
        if let Some(d2) = random_op(r, &mut w2, &ty, base.as_ref()) {
            if t2 > (30 << 16) {
                hits.concurrent_above += 1;
            } else {
                hits.concurrent_below += 1;
            }
            later = t2 > t1;
            mapply(&mut state, d2);
        }
    }
    let state = state.unwrap();
    let (lo, hi) = (w1.lo, w1.hi());
    let made = |d: &Dot| d.source == n1 && (lo..hi).contains(&d.ctr);
    // model
    let mut mu = MWriter::new(n1.clone(), tu, hi);
    let (mud, stats) = undo_stats(&mut mu, &ty, &d1, &made, &state, base.as_ref(), &|_| false);
    add(&mut hits.stats, &stats);
    let mut mafter = Some(state.clone());
    if let Some(u) = mud.clone() {
        mapply(&mut mafter, u);
    }
    // implementation
    let d1i = frag(&d1);
    let src = source(&n1);
    let u = Undone { delta: &d1i, source: &src, range: CounterRange { lo, hi }, restored: &|_| false };
    let si = frag(&state);
    let bi = base.as_ref().map(frag).unwrap_or_default();
    let mut iw = Writer::new(ts(tu), src.clone(), hi);
    let iud = undo(&mut iw, &u, &si, &bi, &view).unwrap();
    let irange = iw.range();
    let mut iafter: Fragment = si.clone();
    if let Some(u) = iud.clone() {
        iafter.join(u);
    }
    hits.undone += 1;
    hits.seq += usize::from(has_seq(&d1));
    assert_eq!(iafter.read(), mread(&mafter), "undo reads differ\nty {ty:?}\nbase {base:?}\nd1 {d1:?}\nstate {state:?}\nmodel undo {mud:?}\nimpl undo {iud:?}");
    if !conc && !has_move(&d1) {
        // a single writer's undo restores the pre-commit read (moves aside: a restored position write is newer
        // than the anchor's other children, so it can land before ones it followed, §5.7)
        hits.exact += 1;
        assert_eq!(mread(&mafter), mread(&base), "undo not exact\nty {ty:?}\nbase {base:?}\nd1 {d1:?}\nmodel undo {mud:?}");
    }
    // redo: each side undoes its own undo commit (§4.6), the state before it as the buffer
    let (Some(mud), Some(iud)) = (mud, iud) else {
        return;
    };
    let tr = 35u64 << 16;
    let (ulo, uhi) = (mu.lo, mu.hi());
    let umade = |d: &Dot| d.source == n1 && (ulo..uhi).contains(&d.ctr);
    let mafter = mafter.unwrap();
    let mut mrw = MWriter::new(n1.clone(), tr, uhi);
    let (mrd, _) = undo_stats(&mut mrw, &ty, &mud, &umade, &mafter, Some(&state), &|_| false);
    let mrw_hi = mrw.hi();
    let mut mredo = Some(mafter.clone());
    if let Some(x) = mrd.clone() {
        mapply(&mut mredo, x);
    }
    let iu = Undone { delta: &iud, source: &src, range: irange, restored: &|_| false };
    let mut irw = Writer::new(ts(tr), src.clone(), irange.hi);
    let ird = undo(&mut irw, &iu, &iafter, &si, &view).unwrap();
    let mut iredo = iafter.clone();
    if let Some(x) = ird.clone() {
        iredo.join(x);
    }
    hits.redone += 1;
    assert_eq!(iredo.read(), mread(&mredo), "redo reads differ\nty {ty:?}\nstate {state:?}\nmodel undo {mud:?}\nimpl undo {iud:?}\nmodel redo {mrd:?}\nimpl redo {ird:?}");
    if !conc && !has_move(&d1) {
        assert_eq!(mread(&mredo), state.read().map(|v| value(&v)), "redo not exact\nty {ty:?}\nstate {state:?}\nmodel undo {mud:?}\nmodel redo {mrd:?}");
    }
    // d1 undone again after the redo: a write the redo restored is stepped back through (§4.6 `restored`),
    // unless d2 is a later live change of the aspect
    let (Some(mrd), Some(ird)) = (mrd, ird) else { return };
    let ta = 40u64 << 16;
    let (rlo, rhi) = (uhi, mrw_hi);
    let mrestored = |s: &crdt_model::stamp::Stamp| !later && s.dot.source == n1 && (rlo..rhi).contains(&s.dot.ctr);
    let mredo = mredo.unwrap();
    let (mad, st) = undo_stats(&mut MWriter::new(n1.clone(), ta, rhi), &ty, &d1, &made, &mredo, base.as_ref(), &mrestored);
    hits.stats.stepped += st.stepped;
    let mut magain = Some(mredo.clone());
    if let Some(x) = mad.clone() {
        mapply(&mut magain, x);
    }
    let irr = irw.range();
    let irestored = |s: &crate::stamp::Stamp| !later && s.dot.src == src && (irr.lo..irr.hi).contains(&s.dot.ctr);
    let iu = Undone { delta: &d1i, source: &src, range: CounterRange { lo, hi }, restored: &irestored };
    let iad = undo(&mut Writer::new(ts(ta), src.clone(), irr.hi), &iu, &iredo, &bi, &view).unwrap();
    let mut iagain = iredo.clone();
    if let Some(x) = iad.clone() {
        iagain.join(x);
    }
    hits.again += 1;
    assert_eq!(iagain.read(), mread(&magain), "undo after redo reads differ\nty {ty:?}\nd1 {d1:?}\nredo state {mredo:?}\nmodel redo {mrd:?}\nimpl redo {ird:?}\nmodel undo {mad:?}\nimpl undo {iad:?}");
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 64, ..ProptestConfig::default() })]
    /// §4.6: model and implementation undo reads alike, concurrent ops included; alone, undo restores the
    /// pre-commit read.
    #[test]
    fn undo_matches_model_spec_4_6(seed in any::<u64>()) {
        let mut r = crate::testutil::rng(seed | 1);
        let mut hits = Hits::default();
        for _ in 0..8 {
            case(&mut r, &mut hits);
        }
    }
}

/// The differential reaches every rule: "Absent before" at the root and nested, replace, bag, register step
/// back, creation, text flag, list re-insert, set and key re-add, position restore, concurrency on both sides.
#[test]
fn undo_matches_model_coverage_spec_4_6() {
    let mut r = crate::testutil::rng(0x05ee_d0d0);
    let mut hits = Hits::default();
    for _ in 0..1500 {
        case(&mut r, &mut hits);
    }
    eprintln!("{hits:#?}");
    let s = &hits.stats;
    for (name, n) in [
        ("absent_root", s.absent_root),
        ("absent_nested", s.absent_nested),
        ("absent_blocked", s.absent_blocked),
        ("replace", s.replace),
        ("bag_reset", s.bag_reset),
        ("register", s.register),
        ("creation", s.creation),
        ("flag", s.flag),
        ("list_reinsert", s.list_reinsert),
        ("set_readd", s.set_readd),
        ("key_readd", s.key_readd),
        ("position", s.position),
        ("stepped", s.stepped),
        ("concurrent_below", hits.concurrent_below),
        ("concurrent_above", hits.concurrent_above),
        ("seq", hits.seq),
        ("exact", hits.exact),
        ("redone", hits.redone),
        ("again", hits.again),
    ] {
        assert!(n >= 3, "{name} hit {n} times: {hits:#?}");
    }
}




/// Node 1 sets `v1` at ts 20 on `base`; node 2 sets `v2` at ts `t2` without seeing it; node 1 undoes its commit at
/// ts 30 holding both. Model and implementation must read alike.
fn seen_concurrent(ty: &Ty, base: &MValue, v1: &MValue, v2: &MValue, t2: u64) {
    let view = TyView(ty.clone());
    let (n1, n2) = (MSource::node(1), MSource::node(2));
    let mut base = Some(crdt_model::ops::create(&mut MWriter::new(n1.clone(), 1 << 16, 1), ty, base));
    base.as_mut().unwrap().prune(None);
    let mut w1 = MWriter::new(n1.clone(), 20 << 16, 10);
    let d1 = crdt_model::diff::diff(&mut w1, base.as_ref(), ty, v1).unwrap();
    let d2 = crdt_model::diff::diff(&mut MWriter::new(n2, (t2 << 16) + 2, 1), base.as_ref(), ty, v2).unwrap();
    let mut state = base.clone();
    mapply(&mut state, d1.clone());
    mapply(&mut state, d2);
    let state = state.unwrap();
    let (lo, hi) = (w1.lo, w1.hi());
    let made = |d: &Dot| d.source == n1 && (lo..hi).contains(&d.ctr);
    let mud = crdt_model::undo::undo(&mut MWriter::new(n1.clone(), 30 << 16, hi), ty, &d1, &made, &state, base.as_ref(), &|_| false);
    let mut m = Some(state.clone());
    if let Some(u) = mud {
        mapply(&mut m, u);
    }
    let d1i = frag(&d1);
    let src = source(&n1);
    let u = Undone { delta: &d1i, source: &src, range: CounterRange { lo, hi }, restored: &|_| false };
    let si = frag(&state);
    let iud = undo(&mut Writer::new(ts(30 << 16), src.clone(), hi), &u, &si, &frag(base.as_ref().unwrap()), &view).unwrap();
    let mut i = si.clone();
    if let Some(u) = iud {
        i.join(u);
    }
    assert_eq!(i.read(), mread(&m), "t2 {t2}, v1 {v1:?}, v2 {v2:?}");
}

/// §4.6 "Absent before" against writes of another commit already in the undoing node's state: a concurrent case
/// write it holds (newer, or older but with a payload) or explicit `W` (an empty text) blocks the reset and stays;
/// a losing case write is not held, so it does not block. (Found the implementation resetting over both.)
#[test]
fn undo_absent_keeps_seen_case_or_w_spec_4_6() {
    let one = |v: MValue| MValue::fields(vec![(1, MValue::Int(0)), (5, v)]);
    let cases = [(0, None), (1, Some(Ty::Register))].into_iter().collect();
    let ty = Ty::Struct([(1, Ty::Register), (5, Ty::Enum(cases))].into_iter().collect());
    let base = MValue::fields(vec![(1, MValue::Int(0))]);
    for t2 in [10, 25] {
        seen_concurrent(&ty, &base, &one(MValue::Enum(0, None)), &one(MValue::Enum(1, Some(Box::new(MValue::Int(7))))), t2);
        seen_concurrent(&ty, &base, &one(MValue::Enum(0, None)), &one(MValue::Enum(0, None)), t2);
    }
    let ty = Ty::Struct([(1, Ty::Register), (5, Ty::Text)].into_iter().collect());
    for t2 in [10, 25] {
        seen_concurrent(&ty, &base, &one(MValue::Str("ab".into())), &one(MValue::Str(String::new())), t2);
    }
}

