//! Sequences (spec/crdt.md §5.7, §6): differential join/read and wire against models/crdt, run
//! rejections, the worked examples of notes/crdt.md.

use crate::codec::{decode_delta, decode_snapshot, encode_delta, encode_snapshot};
use crate::fragment::Fragment;
use crate::fragment::Meta;
use crate::linearize::place;
use crate::seq::{Anchor, Seq, SeqContent, SeqElem};
use crate::seq_span::{expand, nth};
use crate::stamp::{Dot, Stamp};
use std::collections::BTreeMap;
use crate::stamp::{CounterRange, Interner};
use crate::testutil::{frag, history_with, mapply, source, ts};
use crate::tests_join::lockstep;
use crate::tests_wire::{delta, i, l, rejects, snap_cx, wcx, writer_cx};
use crate::wire::{Delta, DeltaCtx, DeltaKind, Frontiers, Snapshot};
use crdt_model::r#gen::{Rng, kitchen_sink};
use crdt_model::ops::{self as mops, Ty, Writer as MWriter};
use crdt_model::stamp::Source as MSource;
use crdt_model::state::{Content, Frag as MFrag};
use crdt_model::wire::{Ctx, encode_delta as m_encode_delta, encode_snapshot as m_encode_snapshot};
use osis_core::{ErrorClass, Value};
use proptest::prelude::*;

fn inner() -> Ty {
    Ty::Struct([(1, Ty::Register), (2, Ty::Set(Box::new(Ty::Register)))].into_iter().collect())
}

proptest! {
    /// §5.7, §6: text join and read equal the model's under random delivery and duplication.
    #[test]
    fn text_join_matches_model_spec_5_7(seed in any::<u64>()) {
        lockstep(seed, &[Ty::Text], 3, 5);
    }

    /// §5.7: list join (element resets, nested fragments) equals the model's.
    #[test]
    fn list_join_matches_model_spec_5_7(seed in any::<u64>()) {
        lockstep(seed, &[Ty::List(Box::new(inner()))], 3, 6);
    }

    /// §5.7 nested in every other encoding.
    #[test]
    fn kitchen_sink_matches_model_spec_5_7(seed in any::<u64>()) {
        lockstep(seed, &[kitchen_sink()], 2, 4);
    }

    /// §7: register and text at one position (embedded characters, Derived anchors).
    #[test]
    fn text_slots_match_model_spec_7(seed in any::<u64>()) {
        lockstep(seed, &[Ty::Register, Ty::Text, Ty::List(Box::new(Ty::Register))], 3, 6);
    }

    /// §3.2 Run, §3.3: sequence deltas and snapshots encode byte-identically with the model.
    #[test]
    fn seq_wire_matches_model_spec_3_2(seed in any::<u64>()) {
        let types = [Ty::Text, Ty::List(Box::new(inner()))];
        wire_matches(seed, &types, (1..=3).map(MSource::node).collect());
    }

    /// §3.3 rule 2: commit form.
    #[test]
    fn seq_wire_commit_form_spec_3_3(seed in any::<u64>()) {
        let sources = [0x80u8, 0x10, 0xf0].iter().map(|b| MSource::Commit([*b; 32])).collect();
        wire_matches(seed, &[Ty::Text, Ty::List(Box::new(Ty::Register))], sources);
    }

    /// §7: snapshots carry embedded characters (Derived sources).
    #[test]
    fn seq_wire_slots_spec_7(seed in any::<u64>()) {
        wire_matches(seed, &[Ty::Register, Ty::Text], (1..=3).map(MSource::node).collect());
    }

    /// §4.7: strip of text and list states equals the model's and commutes with join.
    #[test]
    fn seq_expiry_laws_spec_4_7(seed in any::<u64>()) {
        crate::tests_life::expiry_laws(seed, &Ty::Text);
        crate::tests_life::expiry_laws(seed, &Ty::List(Box::new(inner())));
    }

    /// §4.6: un-merge of text and list (created elements stay as hidden anchors).
    #[test]
    fn seq_unmerge_spec_4_6(seed in any::<u64>()) {
        crate::tests_life::unmerge_check(seed, &Ty::Text);
        crate::tests_life::unmerge_check(seed, &Ty::List(Box::new(inner())));
    }

    /// §8: bootstrap from a text or list snapshot, then concurrent edits, converges.
    #[test]
    fn seq_bootstrap_then_edit_spec_8(seed in any::<u64>()) {
        crate::tests_life::bootstrap_check(seed, &Ty::Text);
        crate::tests_life::bootstrap_check(seed, &Ty::List(Box::new(inner())));
    }

    /// §5.7 undelete: random deleted chars undeleted with their content reach a node that only
    /// holds the snapshot (deleted chars not carried) and read the same there.
    #[test]
    fn random_undelete_spec_5_7(seed in any::<u64>()) {
        let mut r = Rng(seed | 1);
        let commits = history_with(&mut r, &[Ty::Text], vec![MSource::node(1), MSource::node(2)], 6);
        let mut full = Fragment::default();
        for c in &commits {
            full.join(frag(&c.delta));
        }
        let snap = Snapshot { absorbed: Default::default(), nonce: [0; 16], fragment: full.clone(), frontiers: Frontiers::default() };
        let bytes = encode_snapshot(&snap, &snap_cx(), None).unwrap();
        let mut boot = decode_snapshot(&bytes, &snap_cx(), &mut Interner::new(), None).unwrap().fragment;
        let Fragment::Seq(sq) = &full else { return Ok(()) };
        let dead: Vec<crate::stamp::Dot> = sq.elems().iter().filter(|(_, e)| e.flag() && matches!(e.content, SeqContent::Char(_))).map(|(d, _)| d.clone()).filter(|_| r.chance(1, 2)).collect();
        if dead.is_empty() {
            return Ok(());
        }
        let src = crate::stamp::Source::node(osis_core::Tid::from_bytes([7; 15]));
        let st = crate::stamp::Stamp::new(ts(1 << 30), src.clone(), 1);
        let mut d = crate::seq::Seq::empty(true);
        for x in &dead {
            let mut e = crate::seq::SeqElem::bare();
            e.deleted = Some((st.clone(), false));
            e.content = sq.elems()[x].content.clone();
            d.elems_mut().insert(x.clone(), e);
        }
        let cx = DeltaCtx { ts: ts(1 << 30), own: src, range: CounterRange { lo: 1, hi: 2 }, kind: DeltaKind::Writer };
        let bytes = encode_delta(&Delta { nonce: [0; 16], fragment: Fragment::Seq(d) }, &cx, None).unwrap();
        let u = decode_delta(&bytes, &cx, &mut Interner::new(), None).unwrap().fragment;
        full.join(u.clone());
        boot.join(u);
        prop_assert_eq!(full.read(), boot.read());
        prop_assert_eq!(as_carried(&full), boot);
    }

    /// §3.3 rule 7: mutated sequence deltas are rejected or decode, never panic.
    #[test]
    fn mutated_seq_delta_never_panics_spec_3_3(seed in any::<u64>(), pos in any::<usize>(), byte in any::<u8>()) {
        let mut r = Rng(seed | 1);
        let commits = history_with(&mut r, &[Ty::Text, Ty::List(Box::new(inner()))], vec![MSource::node(1), MSource::node(2)], 3);
        let mut state = Fragment::default();
        for c in &commits {
            let cx = writer_cx(&c.w);
            let mut bytes = encode_delta(&Delta { nonce: [1; 16], fragment: frag(&c.delta) }, &cx, None).unwrap();
            let p = pos % bytes.len();
            bytes[p] = byte;
            if let Ok(d) = decode_delta(&bytes, &cx, &mut Interner::new(), None) {
                state.join(d.fragment);
                let _ = state.read();
            }
        }
    }
}

/// §6.2: cycle breaking is linear. Adversarial graph: a chain of 20,000 plus 20,000 mutual-`cur`
/// pairs whose `prev` is the chain's tail (each victim's new edge walks into the chain).
#[test]
fn cycle_breaking_is_linear_spec_6_2() {
    use crate::seq::{Anchor, SeqElem};
    use crate::stamp::{Dot, Source, Stamp};
    let (len, k) = (20_000u64, 20_000u64);
    let a = Source::node(osis_core::Tid::from_bytes([1; 15]));
    let st = |t: u64, c: u64| Stamp::new(ts(t << 16), a.clone(), c);
    let mut elems = std::collections::BTreeMap::new();
    let mut prev = Anchor::Head;
    for c in 1..=len {
        let s = st(1, c);
        elems.insert(Dot::new(a.clone(), c), SeqElem { created: Some((s.clone(), prev.clone())), content: SeqContent::Char('x'), pos: vec![(s, prev.clone())], deleted: None, span: 1 });
        prev = Anchor::Dot(Dot::new(a.clone(), c));
    }
    let tail = prev;
    let (mut c, mut m) = (len + 1, 10_000_000u64);
    for _ in 0..k {
        let (x, y) = (Dot::new(a.clone(), c), Dot::new(a.clone(), c + 1));
        let (cx, cy, mx, my) = (st(2, c), st(2, c + 1), st(3, m), st(3, m + 1));
        c += 2;
        m += 2;
        elems.insert(x.clone(), SeqElem { created: Some((cx.clone(), tail.clone())), content: SeqContent::Char('a'), pos: vec![(mx, Anchor::Dot(y.clone())), (cx, tail.clone())], deleted: None, span: 1 });
        elems.insert(y.clone(), SeqElem { created: Some((cy.clone(), tail.clone())), content: SeqContent::Char('b'), pos: vec![(my, Anchor::Dot(x.clone())), (cy, tail.clone())], deleted: None, span: 1 });
    }
    let t = std::time::Instant::now();
    let p = crate::linearize::place_idx(&elems);
    let took = t.elapsed();
    assert_eq!(p.order.len(), (len + 2 * k) as usize);
    // linear: well under a second in release; a generous bound for a loaded debug build
    assert!(took.as_secs() < 10, "cycle breaking took {took:?}");
}

/// Tier 2: the differential suite at size (more writers, rounds and seeds).
#[test]
#[ignore]
fn seq_differential_large_spec_5_7() {
    for seed in 0..200 {
        lockstep(seed, &[Ty::Text], 4, 16);
        lockstep(seed, &[Ty::List(Box::new(inner()))], 4, 12);
        lockstep(seed, &[Ty::Register, Ty::Text], 4, 10);
        wire_matches(seed, &[Ty::Text, Ty::List(Box::new(inner())), kitchen_sink()], (1..=4).map(MSource::node).collect());
    }
}

/// A text state with the chars of deleted elements dropped: what a snapshot carries (§3.3 rule 5).
fn as_carried(f: &Fragment) -> Fragment {
    let mut f = f.clone();
    drop_deleted_chars(&mut f);
    f
}

fn drop_deleted_chars(f: &mut Fragment) {
    match f {
        Fragment::Seq(s) => {
            for e in s.elems_mut().values_mut() {
                match &mut e.content {
                    SeqContent::Char(_) if e.deleted.as_ref().is_some_and(|d| d.1) => e.content = SeqContent::None,
                    SeqContent::Frag(x) => drop_deleted_chars(x),
                    _ => {}
                }
            }
        }
        Fragment::Struct(s) => s.fields.values_mut().for_each(drop_deleted_chars),
        Fragment::Enum(s) => s.payloads.values_mut().for_each(drop_deleted_chars),
        Fragment::Map(m) => m.entries.values_mut().filter_map(|e| e.frag.as_deref_mut()).for_each(drop_deleted_chars),
        Fragment::Set(crate::fragment::Set { elems, .. }) | Fragment::Bag(crate::fragment::Bag { elems, .. }) => {
            elems.values_mut().filter_map(|e| e.frag.as_deref_mut()).for_each(drop_deleted_chars)
        }
        Fragment::Slots(s) => s.members.values_mut().for_each(drop_deleted_chars),
        Fragment::Register(_) => {}
    }
}

/// Every delta of a random history encodes like the model's and decodes back to itself; snapshots
/// of the joined state likewise (deleted text carried without its chars).
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
        let msnap = m_encode_snapshot(st, &[], [3; 16], &mut Ctx::new(1 << 40, MSource::node(250), 1));
        let s = Snapshot { absorbed: Default::default(), nonce: [3; 16], fragment: frag(st), frontiers: Frontiers::default() };
        let sbytes = encode_snapshot(&s, &snap_cx(), None).unwrap();
        assert_eq!(sbytes, msnap, "snapshot bytes equal the model's");
        let back = decode_snapshot(&sbytes, &snap_cx(), &mut Interner::new(), None).unwrap();
        assert_eq!(back.fragment, as_carried(&s.fragment), "snapshot round trip");
        assert_eq!(back.fragment.read(), s.fragment.read());
    }
}

// ---- §3.3 rule 7 for runs (writer of node 1, range [3, 6), ts 5·2^16)

fn text_with(runs: Vec<Value>) -> Value {
    l(vec![i(9), l(vec![]), l(vec![]), l(runs)])
}
fn list_with(runs: Vec<Value>) -> Value {
    l(vec![i(8), l(vec![]), l(vec![]), l(runs)])
}
fn run(dot: Value, n: i64, creation: Value, content: Value, posw: Vec<Value>, flagw: Vec<Value>) -> Value {
    l(vec![dot, i(n), creation, content, l(posw), l(flagw)])
}
fn s(x: &str) -> Value {
    Value::Str(x.into())
}
fn reg(v: i64) -> Value {
    l(vec![i(0), l(vec![]), i(0), i(v)])
}
/// A creation run from HEAD by this commit.
fn created(n: i64) -> Value {
    l(vec![i(0), l(vec![l(vec![i(0), i(n)])])])
}

fn accepts(f: Value, cx: &DeltaCtx) -> Fragment {
    decode_delta(&delta(vec![], vec![], f), cx, &mut Interner::new(), None).unwrap().fragment
}

#[test]
fn accepts_valid_runs_spec_3_2() {
    let f = accepts(text_with(vec![run(i(3), 3, created(3), s("abc"), vec![], vec![])]), &wcx());
    assert_eq!(f.read(), Some(s("abc")));
    // a flag write on earlier elements, a position write, an undelete carrying content
    accepts(text_with(vec![run(i(1), 2, l(vec![]), l(vec![]), vec![], vec![l(vec![i(0), i(1), i(0), Value::Bool(true)])])]), &wcx());
    accepts(text_with(vec![run(i(1), 1, l(vec![]), l(vec![]), vec![l(vec![i(0), l(vec![i(0), i(4)]), i(2)])], vec![])]), &wcx());
    accepts(text_with(vec![run(i(1), 2, l(vec![]), s("xy"), vec![], vec![l(vec![i(0), i(1), i(0), Value::Bool(false)])])]), &wcx());
    let f = accepts(list_with(vec![run(i(3), 2, created(2), l(vec![reg(1), reg(2)]), vec![], vec![])]), &wcx());
    assert_eq!(f.read(), Some(l(vec![i(1), i(2)])));
}

#[test]
fn rejects_bad_runs_spec_3_3() {
    let bad = |f: Value| rejects(&delta(vec![], vec![], f), &wcx(), ErrorClass::BadInput);
    // n = 0 and n > 2^16
    bad(text_with(vec![run(i(1), 0, l(vec![]), l(vec![]), vec![], vec![l(vec![i(0), i(0), i(0), Value::Bool(true)])])]));
    bad(text_with(vec![run(i(1), (1 << 16) + 1, l(vec![]), l(vec![]), vec![], vec![])]));
    // flag and position indices out of range, reversed flag range
    bad(text_with(vec![run(i(1), 2, l(vec![]), l(vec![]), vec![], vec![l(vec![i(0), i(2), i(0), Value::Bool(true)])])]));
    bad(text_with(vec![run(i(1), 2, l(vec![]), l(vec![]), vec![], vec![l(vec![i(1), i(0), i(0), Value::Bool(true)])])]));
    bad(text_with(vec![run(i(1), 1, l(vec![]), l(vec![]), vec![l(vec![i(1), l(vec![i(0), i(4)]), i(2)])], vec![])]));
    // an undelete in a list run
    bad(list_with(vec![run(i(1), 1, l(vec![]), l(vec![]), vec![], vec![l(vec![i(0), i(0), i(0), Value::Bool(false)])])]));
    // content length differs from the content-carrying elements
    bad(text_with(vec![run(i(3), 3, created(3), s("ab"), vec![], vec![])]));
    bad(text_with(vec![run(i(3), 3, created(3), s("abcd"), vec![], vec![])]));
    bad(list_with(vec![run(i(3), 2, created(2), l(vec![reg(1)]), vec![], vec![])]));
    // segments: short, too long, of another commit's source
    bad(text_with(vec![run(i(3), 3, created(2), s("abc"), vec![], vec![])]));
    bad(text_with(vec![run(i(3), 2, created(3), s("ab"), vec![], vec![])]));
    // own creation above the range, a creation outside the range, own counter used twice
    bad(text_with(vec![run(i(5), 2, created(2), s("ab"), vec![], vec![])]));
    bad(text_with(vec![run(i(1), 2, created(2), s("ab"), vec![], vec![])]));
    bad(text_with(vec![run(i(3), 1, created(1), s("a"), vec![l(vec![i(0), i(0), i(0)])], vec![])]));
    // non-maximal runs (rule 3) and unsorted runs (rule 2): caught by the canonical re-encode
    bad(text_with(vec![run(i(3), 1, created(1), s("a"), vec![], vec![]), run(i(4), 1, l(vec![i(3), l(vec![l(vec![i(0), i(1)])])]), s("b"), vec![], vec![])]));
    bad(text_with(vec![run(i(2), 1, l(vec![]), l(vec![]), vec![], vec![l(vec![i(0), i(0), i(0), Value::Bool(true)])]), run(i(1), 1, l(vec![]), l(vec![]), vec![], vec![l(vec![i(0), i(0), i(0), Value::Bool(true)])])]));
    // content for a deleted element, an empty list element fragment
    bad(text_with(vec![run(i(1), 1, l(vec![]), s("a"), vec![], vec![l(vec![i(0), i(0), i(0), Value::Bool(true)])])]));
    bad(list_with(vec![run(i(3), 1, created(1), l(vec![l(vec![i(0), l(vec![])])]), vec![], vec![])]));
}

/// §3.3 rule 7: bare-anchor runs only in snapshots; at most `MAX_DELTA_BARE` content-less
/// elements per writer or import delta; a writer's flag writes carry the delta stamp.
#[test]
fn rejects_bare_and_oversized_runs_spec_3_3() {
    let other = osis_core::Tid::from_bytes([9; 15]);
    let srcs = || vec![Value::Bytes(other.as_bytes().to_vec())];
    let flag = || vec![l(vec![i(0), i(65535), i(0), Value::Bool(true)])];
    let runs = |k: i64, f: &dyn Fn() -> Vec<Value>| text_with((0..k).map(|j| run(l(vec![i(1), i(1 + j * 65536)]), 65536, l(vec![]), l(vec![]), vec![], f())).collect());
    let import = DeltaCtx { kind: DeltaKind::Import, ..wcx() };
    // bare anchors: rejected in writer and import deltas
    rejects(&delta(srcs(), vec![], runs(1, &Vec::new)), &wcx(), ErrorClass::BadInput);
    rejects(&delta(srcs(), vec![], runs(1, &Vec::new)), &import, ErrorClass::BadInput);
    // 4 · 2^16 = MAX_DELTA_BARE flagged elements pass, 5 · 2^16 do not
    decode_delta(&delta(srcs(), vec![], runs(4, &flag)), &wcx(), &mut Interner::new(), None).unwrap();
    rejects(&delta(srcs(), vec![], runs(5, &flag)), &wcx(), ErrorClass::BadInput);
    // a flag write off the delta stamp
    let off = text_with(vec![run(i(1), 1, l(vec![]), l(vec![]), vec![], vec![l(vec![i(0), i(0), l(vec![i(0), i(4)]), Value::Bool(true)])])]);
    rejects(&delta(vec![], vec![], off), &wcx(), ErrorClass::BadInput);
}

/// §3.3 rule 7, §8: a snapshot carries bare anchors (a reset text).
#[test]
fn snapshot_carries_bare_anchors_spec_3_3() {
    let (m, base) = typed("abc");
    let rm = mops::remove(&mut mw(1, 5), 9);
    let st = joined(&base, &[&rm]);
    let s = Snapshot { absorbed: Default::default(), nonce: [0; 16], fragment: st.clone(), frontiers: Frontiers::default() };
    let bytes = encode_snapshot(&s, &snap_cx(), None).unwrap();
    assert_eq!(decode_snapshot(&bytes, &snap_cx(), &mut Interner::new(), None).unwrap().fragment, st);
    let _ = m;
}

/// §3.3 rule 7: a segment's commit has the run's source.
#[test]
fn rejects_segment_of_another_source_spec_3_3() {
    let (a, b) = (osis_core::Tid::from_bytes([1; 15]), osis_core::Tid::from_bytes([2; 15]));
    let srcs = vec![Value::Bytes(a.as_bytes().to_vec()), Value::Bytes(b.as_bytes().to_vec())];
    let commits = vec![l(vec![i(1), l(vec![l(vec![i(10), i(0), i(1)])])]), l(vec![i(2), l(vec![l(vec![i(10), i(0), i(1)])])])];
    let with = |ci: i64| {
        let r = run(l(vec![i(1), i(1)]), 1, l(vec![i(0), l(vec![l(vec![i(ci), i(1)])])]), s("a"), vec![], vec![]);
        let f = text_with(vec![r, run(l(vec![i(2), i(1)]), 1, l(vec![i(0), l(vec![l(vec![i(2), i(1)])])]), s("b"), vec![], vec![])]);
        delta(srcs.clone(), commits.clone(), f)
    };
    decode_delta(&with(1), &snap_cx(), &mut Interner::new(), None).unwrap();
    rejects(&with(2), &snap_cx(), ErrorClass::BadInput);
}

/// §3.3 rule 7: a creation run of a `Derived` source only in snapshots (embedded characters).
#[test]
fn rejects_derived_creation_in_writer_delta_spec_3_3() {
    let f = text_with(vec![run(l(vec![i(1), i(1)]), 1, created(1), s("a"), vec![], vec![])]);
    // Sources: Derived of own dot 3
    rejects(&delta(vec![l(vec![i(0), i(3)])], vec![], f), &wcx(), ErrorClass::BadInput);
    // an anchor at an embedded character is fine
    let f = text_with(vec![run(i(3), 1, l(vec![l(vec![i(2), i(1)]), l(vec![l(vec![i(0), i(1)])])]), s("q"), vec![], vec![])]);
    let other = osis_core::Tid::from_bytes([9; 15]);
    let srcs = vec![Value::Bytes(other.as_bytes().to_vec()), l(vec![i(1), i(4)])];
    decode_delta(&delta(srcs, vec![], f), &wcx(), &mut Interner::new(), None).unwrap();
}

// ---- notes/crdt.md, Worked examples (model ops, joined by this implementation)

fn chars(x: &str) -> Vec<Content> {
    x.chars().map(Content::Char).collect()
}
fn mw(n: u8, t: u64) -> MWriter {
    MWriter::new(MSource::node(n), t << 16, 1)
}
fn joined(base: &Fragment, ds: &[&MFrag]) -> Fragment {
    let mut f = base.clone();
    for d in ds {
        f.join(frag(d));
    }
    f
}
fn reads(f: &Fragment) -> Option<String> {
    match f.read() {
        Some(Value::Str(x)) => Some(x),
        _ => None,
    }
}
/// `x` typed by node 1 at t=1, as a model state and ours.
fn typed(x: &str) -> (MFrag, Fragment) {
    let mut a = mw(1, 1);
    let mut st = mops::seq_insert(&mut a, None, true, 0, chars(x));
    st.prune(None);
    let f = frag(&st);
    (st, f)
}
/// The model writer's header as a delta context.
fn cx_of(w: &MWriter) -> DeltaCtx {
    DeltaCtx { ts: ts(w.ts), own: source(&w.source), range: CounterRange { lo: w.lo, hi: w.hi() }, kind: DeltaKind::Writer }
}
fn fragment_value(bytes: &[u8]) -> Value {
    let Value::List(top) = osis_core::decode(bytes, &osis_core::Limits { max_depth: 64, max_bytes: 1 << 20 }).unwrap() else { panic!() };
    top[3].clone()
}

#[test]
fn typing_spec_example() {
    let mut a = mw(1, 1);
    let d = mops::seq_insert(&mut a, None, true, 0, chars("FOOBAR"));
    let bytes = encode_delta(&Delta { nonce: [0; 16], fragment: frag(&d) }, &cx_of(&a), None).unwrap();
    let runs = l(vec![run(i(1), 6, l(vec![i(0), l(vec![l(vec![i(0), i(6)])])]), s("FOOBAR"), vec![], vec![])]);
    assert_eq!(fragment_value(&bytes), l(vec![i(9), l(vec![]), l(vec![]), runs]));
    assert_eq!(reads(&frag(&d)).as_deref(), Some("FOOBAR"));
}

#[test]
fn concurrent_inserts_at_one_anchor_spec_example() {
    let (m, base) = typed("FOOBAR");
    let mut b = mw(2, 2);
    let x = mops::seq_insert(&mut b, Some(&m), true, 3, chars("x"));
    let bytes = encode_delta(&Delta { nonce: [0; 16], fragment: frag(&x) }, &cx_of(&b), None).unwrap();
    let runs = l(vec![run(i(1), 1, l(vec![l(vec![i(1), i(3)]), l(vec![l(vec![i(0), i(1)])])]), s("x"), vec![], vec![])]);
    assert_eq!(fragment_value(&bytes), l(vec![i(9), l(vec![]), l(vec![]), runs]));
    let mut c = mw(3, 3);
    let y = mops::seq_insert(&mut c, Some(&m), true, 3, chars("y"));
    assert_eq!(reads(&joined(&base, &[&x, &y])).as_deref(), Some("FOOyxBAR"));
    assert_eq!(reads(&joined(&base, &[&y, &x])).as_deref(), Some("FOOyxBAR"));
}

#[test]
fn move_with_concurrent_insert_spec_example() {
    let (m, base) = typed("FOOBAR");
    let mut b = mw(2, 2);
    let x = mops::seq_insert(&mut b, Some(&m), true, 3, chars("x"));
    let mut a = mw(1, 3);
    a.lo = 7;
    a.next = 7;
    let mv = mops::seq_move(&mut a, &m, 0, 3, 3).unwrap();
    assert_eq!(reads(&joined(&base, &[&x, &mv])).as_deref(), Some("BARFOOx"));
    assert_eq!(reads(&joined(&base, &[&mv, &x])).as_deref(), Some("BARFOOx"));
}

#[test]
fn range_with_several_roots_spec_example() {
    let mut w = mw(1, 1);
    let mut st: Option<MFrag> = None;
    for (k, c) in ["c", "b", "a"].iter().enumerate() {
        w.next_commit((k as u64 + 1) << 16);
        let d = mops::seq_insert(&mut w, st.as_ref(), true, 0, chars(c));
        mapply(&mut st, d);
    }
    let m = st.unwrap();
    let base = frag(&m);
    assert_eq!(reads(&base).as_deref(), Some("abc"));
    w.next_commit(4 << 16);
    let mv = mops::seq_move(&mut w, &m, 0, 2, 1).unwrap();
    assert_eq!(reads(&joined(&base, &[&mv])).as_deref(), Some("cab"));
}

#[test]
fn concurrent_moves_of_one_element_spec_example() {
    let (m, base) = typed("abc");
    let m1 = mops::seq_move(&mut mw(2, 5), &m, 0, 1, 2).unwrap();
    let m2 = mops::seq_move(&mut mw(3, 4), &m, 0, 1, 1).unwrap();
    assert_eq!(reads(&joined(&base, &[&m1, &m2])).as_deref(), Some("bca"));
    assert_eq!(reads(&joined(&base, &[&m2, &m1])).as_deref(), Some("bca"));
}

#[test]
fn cycle_spec_example() {
    let (m, base) = typed("acb");
    let m1 = mops::seq_move(&mut mw(2, 5), &m, 0, 1, 2).unwrap();
    let m2 = mops::seq_move(&mut mw(3, 4), &m, 2, 1, 1).unwrap();
    assert_eq!(reads(&joined(&base, &[&m1, &m2])).as_deref(), Some("cba"));
    assert_eq!(reads(&joined(&base, &[&m2, &m1])).as_deref(), Some("cba"));
}

#[test]
fn reset_against_a_newer_insert_spec_example() {
    let (m, base) = typed("abc");
    let mut a = mw(1, 5);
    a.lo = 4;
    a.next = 4;
    let rep = mops::replace(&mut a, &Ty::Text, &crdt_model::value::Value::Str("xyz".into()));
    let q = mops::seq_insert(&mut mw(2, 6), Some(&m), true, 2, chars("q"));
    assert_eq!(reads(&joined(&base, &[&rep, &q])).as_deref(), Some("xyzq"));
    assert_eq!(joined(&base, &[&rep, &q]), joined(&base, &[&q, &rep]));
    let old = mops::seq_insert(&mut mw(3, 3), Some(&m), true, 2, chars("o"));
    assert_eq!(reads(&joined(&base, &[&old, &rep])).as_deref(), Some("xyz"));
    // remove_aspect instead: absent until q arrives, then q
    let rm = mops::remove(&mut mw(1, 5), 9);
    assert_eq!(joined(&base, &[&rm]).read(), None);
    assert_eq!(reads(&joined(&base, &[&rm, &q])).as_deref(), Some("q"));
}

#[test]
fn move_displaces_a_concurrent_insert_spec_example() {
    let (m, base) = typed("abcd");
    let mv = mops::seq_move(&mut mw(2, 5), &m, 1, 1, 3).unwrap();
    let x = mops::seq_insert(&mut mw(3, 4), Some(&m), true, 1, chars("x"));
    assert_eq!(reads(&joined(&base, &[&mv, &x])).as_deref(), Some("acdbx"));
}

#[test]
fn delete_vs_move_spec_example() {
    let (m, base) = typed("abc");
    let del = mops::seq_delete(&mut mw(2, 4), &m, 1, 1).unwrap();
    let mv = mops::seq_move(&mut mw(3, 5), &m, 1, 1, 2).unwrap();
    let st = joined(&base, &[&del, &mv]);
    assert_eq!(reads(&st).as_deref(), Some("ac"));
    assert_eq!(st, joined(&base, &[&mv, &del]));
    // an insert anchored at b (made before the delete) appears after c
    let q = mops::seq_insert(&mut mw(4, 6), Some(&m), true, 2, chars("q"));
    assert_eq!(reads(&joined(&st, &[&q])).as_deref(), Some("acq"));
}

#[test]
fn unknown_anchor_spec_example() {
    let (m, base) = typed("FOOBAR");
    let x = mops::seq_insert(&mut mw(2, 2), Some(&m), true, 3, chars("x"));
    let mut early = Fragment::default();
    early.join(frag(&x));
    assert_eq!(reads(&early).as_deref(), Some(""), "hidden until its anchor arrives");
    let mut a = mw(1, 5);
    a.lo = 7;
    a.next = 7;
    let rep = mops::replace(&mut a, &Ty::Text, &crdt_model::value::Value::Str("Z".into()));
    early.join(frag(&rep));
    assert_eq!(reads(&early).as_deref(), Some("Z"));
    early.join(base);
    assert_eq!(reads(&early).as_deref(), Some("Z"), "x (t=2) is older than the reset");
    // a newer insert into the reset text is placed once its anchor arrives
    let y = mops::seq_insert(&mut mw(3, 6), Some(&m), true, 3, chars("y"));
    let mut late = Fragment::default();
    late.join(frag(&y));
    late.join(frag(&rep));
    assert_eq!(reads(&late).as_deref(), Some("Z"));
    late.join(frag(&m));
    assert_eq!(reads(&late).as_deref(), Some("Zy"));
}

/// §8: a text with many runs pages and re-joins to itself.
#[test]
fn text_pages_spec_8() {
    use crate::page::{MemoryPages, PageParams};
    let params = PageParams { target: 2000, cut: osis_core::ChunkParams { min: 128, max: 1024, mask_bits: 6 }, fanout: 8 };
    let text: String = (0..1500).map(|k| (b'a' + (k % 26) as u8) as char).collect();
    let (_, mut st) = typed(&text);
    // every third char deleted by its own commit: one run per char
    let Fragment::Seq(s) = &mut st else { panic!() };
    let b = crate::stamp::Source::node(osis_core::Tid::from_bytes([2; 15]));
    for (k, e) in s.elems_mut().values_mut().enumerate().filter(|(k, _)| k % 3 == 0) {
        e.deleted = Some((crate::stamp::Stamp::new(ts((k as u64 + 2) << 16), b.clone(), k as u64 + 1), true));
    }
    let mut pages = MemoryPages::with_params(params);
    let snap = Snapshot { absorbed: Default::default(), nonce: [0; 16], fragment: st.clone(), frontiers: Frontiers::default() };
    let bytes = encode_snapshot(&snap, &snap_cx(), Some(&mut pages)).unwrap();
    assert!(!pages.is_empty());
    let got = decode_snapshot(&bytes, &snap_cx(), &mut Interner::new(), Some(&mut pages)).unwrap();
    assert_eq!(got.fragment, as_carried(&st));
    assert_eq!(got.fragment.read(), st.read());
}

// ---- range records (spec/requirements.md Scale: input never causes unbounded allocation)

fn n(b: u8) -> crate::stamp::Source {
    crate::stamp::Source::node(osis_core::Tid::from_bytes([b; 15]))
}
fn st(t: u64, b: u8, c: u64) -> Stamp {
    Stamp::new(ts(t << 16), n(b), c)
}
fn seq_of(elems: BTreeMap<Dot, SeqElem>, reset: Option<Stamp>) -> Fragment {
    Fragment::Seq(Seq::new(true, Meta { reset, w: None }, elems))
}
fn one(d: Dot, e: SeqElem) -> Fragment {
    seq_of(BTreeMap::from([(d, e)]), None)
}
/// `len` chars typed by node 1 at t = 1, chained from HEAD.
fn long_text(len: u64) -> Fragment {
    let mut elems = BTreeMap::new();
    let mut prev = Anchor::Head;
    for c in 1..=len {
        let s = st(1, 1, c);
        elems.insert(s.dot.clone(), SeqElem { created: Some((s.clone(), prev.clone())), content: SeqContent::Char('a'), pos: vec![(s.clone(), prev)], deleted: None, span: 1 });
        prev = Anchor::Dot(s.dot);
    }
    seq_of(elems, None)
}
fn records(f: &Fragment) -> usize {
    match f {
        Fragment::Seq(s) => s.elems().len(),
        _ => panic!("not a sequence"),
    }
}
/// Every placed element in order.
fn order(f: &Fragment) -> Vec<Dot> {
    let Fragment::Seq(s) = f else { panic!("not a sequence") };
    let p = place(s.elems(), s.text);
    p.iter().flat_map(|r| (0..r.span).map(move |i| nth(&r.dot, i))).collect()
}
fn expanded(f: &Fragment) -> Fragment {
    let Fragment::Seq(s) = f else { panic!("not a sequence") };
    Fragment::Seq(Seq::new(s.text, s.meta.clone(), expand(s.elems().clone())))
}
fn snapshot_of(f: &Fragment) -> Vec<u8> {
    encode_snapshot(&Snapshot { absorbed: Default::default(), nonce: [0; 16], fragment: f.clone(), frontiers: Frontiers::default() }, &snap_cx(), None).unwrap()
}

/// §3.2 Run, issue run amplification: a snapshot run of 2^16 - 1 bare anchors (a reset text)
/// or deleted elements is a few bytes and decodes to one record, not one per element.
#[test]
fn snapshot_runs_decode_to_ranges_spec_3_2() {
    let len = 65535;
    let mut bare = long_text(len);
    bare.join(seq_of(BTreeMap::new(), Some(st(2, 2, 1))));
    let mut deleted = long_text(len);
    deleted.join(one(Dot::new(n(1), 1), SeqElem { deleted: Some((st(2, 2, 1), true)), span: len, ..SeqElem::bare() }));
    assert_eq!(records(&deleted), len as usize, "a range write splits nothing into a per-element state");
    for (what, f) in [("bare", &bare), ("deleted", &deleted)] {
        let bytes = snapshot_of(f);
        assert!(bytes.len() < 100, "{what}: {} bytes", bytes.len());
        let back = decode_snapshot(&bytes, &snap_cx(), &mut Interner::new(), None).unwrap().fragment;
        assert_eq!(records(&back), 1, "{what}");
        assert_eq!(back, as_carried(f), "{what}");
        assert_eq!(back.read(), f.read(), "{what}");
        assert_eq!(order(&back), order(f), "{what}");
        assert_eq!(snapshot_of(&back), bytes, "{what}");
    }
    // the reset text's run is the attack shape: [Dot, n, [], [], [], []]
    let v = osis_core::decode(&snapshot_of(&bare), &osis_core::Limits { max_depth: 16, max_bytes: 1 << 20 }).unwrap();
    let Value::List(top) = v else { panic!("snapshot") };
    let Value::List(f) = &top[3] else { panic!("fragment") };
    assert_eq!(f[3], l(vec![run(l(vec![i(2), i(1)]), 65535, l(vec![]), l(vec![]), vec![], vec![])]));
}

/// §4.2, §5.7, §6: writes landing inside a range record (an insert anchored in it, a move and an
/// undelete of one of its elements, a reset between its creations) split it only there, and
/// give the same state, read and order as the per-element state.
#[test]
fn ranges_split_where_writes_land_spec_6() {
    let len = 40_000;
    let mut deleted = long_text(len);
    deleted.join(one(Dot::new(n(1), 1), SeqElem { deleted: Some((st(2, 2, 1), true)), span: len, ..SeqElem::bare() }));
    let ranged = decode_snapshot(&snapshot_of(&deleted), &snap_cx(), &mut Interner::new(), None).unwrap().fragment;
    assert_eq!(records(&ranged), 1);
    let flat = expanded(&ranged);
    let x = st(3, 3, 1);
    let at = Anchor::Dot(Dot::new(n(1), 1000));
    let insert = one(x.dot.clone(), SeqElem { created: Some((x.clone(), at.clone())), content: SeqContent::Char('x'), pos: vec![(x.clone(), at)], deleted: None, span: 1 });
    let mv = one(Dot::new(n(1), 500), SeqElem { pos: vec![(st(4, 3, 2), Anchor::Head)], ..SeqElem::bare() });
    let undelete = one(Dot::new(n(1), 2000), SeqElem { deleted: Some((st(5, 3, 3), false)), content: SeqContent::Char('u'), ..SeqElem::bare() });
    // creations of t = 1 below (1, node 1, 30000) go: a reset inside the chain
    let reset = seq_of(BTreeMap::new(), Some(st(1, 1, 30_000)));
    let (mut a, mut b) = (ranged.clone(), flat.clone());
    for (k, d) in [insert, mv, undelete, reset].into_iter().enumerate() {
        if k == 3 {
            assert_eq!(reads(&a).as_deref(), Some("xu"));
        }
        a.join(d.clone());
        b.join(d);
        assert_eq!(a, b);
        assert_eq!(a.read(), b.read());
        assert_eq!(order(&a), order(&b));
        assert!(records(&a) <= 12, "{} records", records(&a));
    }
    // the reset pruned the undeleted char's creation, so only its flag revived (§5.7)
    assert_eq!(reads(&a).as_deref(), Some("x"));
    let bytes = snapshot_of(&a);
    assert_eq!(bytes, snapshot_of(&b));
    assert_eq!(decode_snapshot(&bytes, &snap_cx(), &mut Interner::new(), None).unwrap().fragment, as_carried(&a));
}

proptest! {
    /// §6: range records place, read and encode like their elements (random histories, every
    /// uniform stretch coalesced).
    #[test]
    fn ranges_place_like_elements_spec_6(seed in any::<u64>()) {
        let mut r = Rng(seed | 1);
        // text slots: embedded chars (`Derived` dots) beside range records
        let types: &[Ty] = if seed % 2 == 0 { &[Ty::Text, Ty::List(Box::new(inner()))] } else { &[Ty::Register, Ty::Text] };
        let commits = crate::testutil::history(&mut r, types, 3, 6);
        let mut state = None;
        for c in &commits {
            mapply(&mut state, c.delta.clone());
            let f = match frag(state.as_ref().unwrap()) {
                Fragment::Slots(x) => x.members.get(&crate::fragment::Encoding::Text).cloned().unwrap_or_default(),
                f => f,
            };
            let Fragment::Seq(_) = &f else { continue };
            let flat = expanded(&f);
            prop_assert_eq!(order(&f), order(&flat));
            prop_assert_eq!(f.read(), flat.read());
            prop_assert_eq!(snapshot_of(&f), snapshot_of(&flat));
        }
    }
}

/// A created char `c` of `dot` at `t`, anchored at `at`.
fn char_at(dot: Dot, t: u64, at: Anchor, c: char) -> SeqElem {
    let s = Stamp { ts: ts(t << 16), dot };
    SeqElem { created: Some((s.clone(), at.clone())), content: SeqContent::Char(c), pos: vec![(s, at)], deleted: None, span: 1 }
}
/// Through a snapshot: uniform stretches become range records.
fn via_snapshot(f: &Fragment) -> Fragment {
    decode_snapshot(&snapshot_of(f), &snap_cx(), &mut Interner::new(), None).unwrap().fragment
}
/// `op` applied by node 4 at t = 9: the delta and the joined state.
fn apply_op(f: &Fragment, op: crate::ops::Op) -> (Fragment, Fragment) {
    let mut b = crate::batch::Batch::new(f, crate::ops::Writer::new(ts(9 << 16), n(4), 1));
    b.apply(&crate::ops::PathOp { path: vec![], op }, &crate::testutil::TyView(Ty::Text)).unwrap();
    let (d, _) = b.finish().unwrap();
    let mut s = f.clone();
    s.join(d.clone());
    (d, s)
}

/// §5.7 move, §6: bare anchors left by a reset sit on END one by one, so moving a selection
/// that spans some moves each of them; a state from a snapshot (range records) and one built
/// element by element give the same writes and read.
#[test]
fn move_over_bare_ranges_spec_5_7() {
    let mut elems = BTreeMap::new();
    let mut prev = Anchor::Head;
    for (k, c) in "hello".chars().enumerate() {
        let d = Dot::new(n(1), k as u64 + 1);
        elems.insert(d.clone(), char_at(d.clone(), 1, prev, c));
        prev = Anchor::Dot(d);
    }
    for c in 1..=10 {
        elems.insert(Dot::new(n(2), c), SeqElem::bare());
    }
    elems.insert(Dot::new(n(3), 1), char_at(Dot::new(n(3), 1), 3, Anchor::Dot(Dot::new(n(2), 5)), 'a'));
    elems.insert(Dot::new(n(3), 2), char_at(Dot::new(n(3), 2), 3, Anchor::Dot(Dot::new(n(2), 10)), 'x'));
    let flat = seq_of(elems, None);
    assert_eq!(reads(&flat).as_deref(), Some("helloax"));
    let ranged = via_snapshot(&flat);
    assert!(records(&ranged) < 10, "{} records", records(&ranged));
    let (d1, s1) = apply_op(&flat, crate::ops::Op::Move { at: 5, len: 2, to: 0 });
    let (d2, s2) = apply_op(&ranged, crate::ops::Op::Move { at: 5, len: 2, to: 0 });
    assert_eq!(d1, d2);
    assert_eq!(reads(&s1).as_deref(), Some("axhello"));
    assert_eq!(s1, s2);
    assert_eq!(order(&s1), order(&s2));
}

/// The bare range `(node 2, 1..=10)` as one record, and the same element by element.
fn bare_ten() -> (Fragment, Fragment) {
    let flat = seq_of((1..=10).map(|c| (Dot::new(n(2), c), SeqElem::bare())).collect(), None);
    let mut e = SeqElem::bare();
    e.span = 10;
    (seq_of(BTreeMap::from([(Dot::new(n(2), 1), e)]), None), flat)
}

/// §2.2, §7: a `Derived(S, 5)` record sorts between `(S, 5)` and `(S, 6)`: joining one splits a
/// range of `S` there (`split_at`), and a range delta over it is cut there (`join_elems`).
#[test]
fn derived_keys_split_ranges_spec_7() {
    let (mut a, mut b) = bare_ten();
    let dd = Dot::new(crate::stamp::Source::derived(Dot::new(n(2), 5)).unwrap(), 1);
    let emb = one(dd.clone(), char_at(dd, 4, Anchor::Head, 'q'));
    let flag = one(Dot::new(n(2), 1), SeqElem { deleted: Some((st(5, 5, 1), true)), span: 10, ..SeqElem::bare() });
    for d in [emb, flag] {
        a.join(d.clone());
        b.join(d);
        assert_eq!(a, b);
        assert_eq!(order(&a), order(&b));
        assert_eq!(a.read(), b.read());
    }
    assert_eq!(records(&a), 3);
    assert_eq!(snapshot_of(&a), snapshot_of(&b));
}

/// §6.1: an element anchored at a `Derived(S, 5)` dot absent from the state sits under a
/// virtual anchor between `(S, 5)` and `(S, 6)` on END; a range of `S` places around it like
/// its elements do (hidden order included).
#[test]
fn virtual_derived_anchor_inside_range_spec_6_1() {
    let (mut a, mut b) = bare_ten();
    let dd = Dot::new(crate::stamp::Source::derived(Dot::new(n(2), 5)).unwrap(), 1);
    let y = one(Dot::new(n(3), 1), char_at(Dot::new(n(3), 1), 4, Anchor::Dot(dd), 'y'));
    let z = one(Dot::new(n(3), 2), char_at(Dot::new(n(3), 2), 4, Anchor::Dot(Dot::new(n(2), 10)), 'z'));
    for d in [y, z] {
        a.join(d.clone());
        b.join(d);
    }
    assert_eq!(order(&a), order(&b));
    assert_eq!(reads(&a).as_deref(), Some("yz"));
    // a delete over the selection flags the same hidden elements
    let (d1, _) = apply_op(&a, crate::ops::Op::Delete { at: 0, len: 2 });
    let (d2, _) = apply_op(&b, crate::ops::Op::Delete { at: 0, len: 2 });
    assert_eq!(d1, d2);
}

/// §6.2: a creation chain whose first element anchors inside its own run is a cycle; as one
/// range record it breaks like its elements.
#[test]
fn chain_anchored_into_itself_spec_6_2() {
    let s0 = st(1, 1, 1);
    let at = Anchor::Dot(Dot::new(n(1), 3));
    let e = SeqElem { created: Some((s0.clone(), at.clone())), pos: vec![(s0, at)], deleted: Some((st(2, 2, 1), true)), span: 5, ..SeqElem::bare() };
    let mut a = seq_of(BTreeMap::from([(Dot::new(n(1), 1), e)]), None);
    a.join(one(Dot::new(n(3), 1), char_at(Dot::new(n(3), 1), 4, Anchor::Dot(Dot::new(n(1), 5)), 'v')));
    let b = expanded(&a);
    assert_eq!(order(&a), order(&b));
    assert_eq!(reads(&a).as_deref(), Some("v"));
    assert_eq!(snapshot_of(&a), snapshot_of(&b));
}

/// §3.3 rule 7: runs that overlap (here the second starts inside the first) are bad input.
#[test]
fn rejects_overlapping_runs_spec_3_3() {
    let runs = vec![run(i(1), 5, l(vec![]), l(vec![]), vec![], vec![]), run(i(3), 5, l(vec![]), l(vec![]), vec![], vec![])];
    let bytes = osis_core::encode(&l(vec![Value::Bytes(vec![0; 16]), l(vec![]), l(vec![]), text_with(runs), l(vec![])]));
    let e = decode_snapshot(&bytes, &snap_cx(), &mut Interner::new(), None).unwrap_err();
    assert_eq!(osis_core::Classified::class(&e), ErrorClass::BadInput, "{e}");
}
