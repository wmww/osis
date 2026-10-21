//! Expiry, un-merge, snapshots and paging (spec/crdt.md §4.6, §4.7, §8).

use crate::codec::{decode_delta, decode_snapshot, encode_delta, encode_snapshot};
use crate::fragment::Fragment;
use crate::lifecycle::{unmerge, unmerge_in_place};
use crate::page::{MemoryPages, PageParams, PageSink};
use crate::stamp::{CounterRange, Dot, Interner, Source};
use crate::testutil::{TyView, frag, history, mapply, ostate, sink_no_seq, source, ts};
use crate::wire::{Delta, DeltaCtx, DeltaKind, Frontiers, Received, Snapshot};
use crate::Batch;
use crate::ops::{Op, PathOp};
use crdt_model::r#gen::{Rng, random_op};
use crdt_model::ops::Ty;
use crdt_model::stamp::Source as MSource;
use osis_core::{ChunkParams, Tid, Value};
use proptest::prelude::*;
use std::collections::BTreeSet;

type Range = (Source, u64, u64);

fn in_ranges(r: &[Range]) -> impl Fn(&Dot) -> bool + '_ {
    move |d: &Dot| r.iter().any(|(s, lo, hi)| d.src == *s && (*lo..*hi).contains(&d.ctr))
}

fn join(a: &Fragment, b: &Fragment) -> Fragment {
    let mut x = a.clone();
    x.join(b.clone());
    x
}

/// Three states by different writers and the ranges of their commits.
type Three = (Vec<Fragment>, Vec<crdt_model::state::Frag>, Vec<Range>, Vec<(MSource, u64, u64)>);

fn three(seed: u64, ty: &Ty) -> Three {
    let mut r = Rng(seed | 1);
    let mut ours = Vec::new();
    let mut models = Vec::new();
    let mut ranges = Vec::new();
    let mut mranges = Vec::new();
    for i in 0..3u8 {
        let mut w = crdt_model::ops::Writer::new(MSource::node(i + 1), ((r.below(5) as u64 + 1) << 16) + i as u64, 1);
        let mut st = None;
        for k in 0..4 {
            w.next_commit(w.ts + ((r.below(3) as u64) << 16) + 1 + k);
            if let Some(d) = random_op(&mut r, &mut w, ty, st.as_ref()) {
                mapply(&mut st, d);
                ranges.push((source(&w.source), w.lo, w.hi()));
                mranges.push((w.source.clone(), w.lo, w.hi()));
            }
        }
        ours.push(ostate(&st));
        models.push(st.unwrap_or_else(|| crdt_model::state::Frag::empty(0)));
    }
    (ours, models, ranges, mranges)
}

proptest! {
    /// §4.7: strip equals the model's, commutes with join, is idempotent; a valued copy wins.
    #[test]
    fn expiry_laws_spec_4_7(seed in any::<u64>()) {
        expiry_laws(seed, &sink_no_seq());
    }

    /// §4.6: removing an author in place equals the model; un-merge of held bodies is
    /// order-independent and agrees with the in-place fast path where that applies.
    #[test]
    fn unmerge_spec_4_6(seed in any::<u64>()) {
        unmerge_check(seed, &sink_no_seq());
    }

    /// §8: a node bootstrapped from a snapshot and then editing converges with the source node;
    /// frontiers cover every commit.
    #[test]
    fn bootstrap_then_edit_spec_8(seed in any::<u64>()) {
        bootstrap_check(seed, &sink_no_seq());
    }
}

/// §4.7 laws of `strip` over random states of type `ty`.
pub(crate) fn expiry_laws(seed: u64, ty: &Ty) {
    let (s, m, ranges, mranges) = three(seed, ty);
    let mut r = Rng(seed ^ 0x55);
    let pick: Vec<bool> = ranges.iter().map(|_| r.chance(1, 2)).collect();
    let expired: Vec<Range> = ranges.iter().zip(&pick).filter(|x| *x.1).map(|x| x.0.clone()).collect();
    let mexpired: Vec<(MSource, u64, u64)> = mranges.iter().zip(&pick).filter(|x| *x.1).map(|x| x.0.clone()).collect();
    let strip = |f: &Fragment| {
        let mut g = f.clone();
        g.strip(&in_ranges(&expired));
        g
    };
    for (o, mo) in s.iter().zip(&m) {
        let mut ms = mo.clone();
        ms.strip(&|d| mexpired.iter().any(|(src, lo, hi)| d.source == *src && (*lo..*hi).contains(&d.ctr)));
        assert_eq!(strip(o), frag(&ms), "strip equals the model");
    }
    let (a, b) = (&s[0], &s[1]);
    assert_eq!(strip(&join(a, b)), join(&strip(a), &strip(b)), "strip commutes with join");
    assert_eq!(strip(&strip(a)), strip(a), "idempotent");
    assert_eq!(join(a, &strip(a)), a.clone(), "valued copy wins");
}

/// §4.6 un-merge over a random history of type `ty`.
pub(crate) fn unmerge_check(seed: u64, ty: &Ty) {
    let mut r = Rng(seed | 1);
    let commits = history(&mut r, std::slice::from_ref(ty), 3, 4);
    let mut mstate = None;
    for c in &commits {
        mapply(&mut mstate, c.delta.clone());
    }
    let state = ostate(&mstate);
    let bad = source(&MSource::node(2));
    let author = |s: &Source| *s == bad;
    if let Some(ms) = &mstate {
        let mut mm = ms.clone();
        mm.unmerge(&|s| *s == MSource::node(2));
        let mut ours = state.clone();
        ours.remove_author(&author);
        assert_eq!(ours, frag(&mm), "remove_author equals the model");
    }
    let mut held: Vec<Fragment> = commits.iter().map(|c| frag(&c.delta)).collect();
    held.push(state.clone());
    let u1 = unmerge(held.clone(), &author);
    held.reverse();
    let u2 = unmerge(held, &author);
    assert_eq!(&u1, &u2, "order-independent");
    let mut fast = state.clone();
    if unmerge_in_place(&mut fast, &author) {
        assert_eq!(fast.read(), u1.read(), "fast path agrees");
    }
}

/// §8 bootstrap from a snapshot, then concurrent edits of type `ty`.
pub(crate) fn bootstrap_check(seed: u64, ty: &Ty) {
    let mut r = Rng(seed | 1);
    let commits = history(&mut r, std::slice::from_ref(ty), 3, 4);
    let mut a = Fragment::default();
    let mut received = Received::new();
    for c in &commits {
        a.join(frag(&c.delta));
        received.add(source(&c.w.source).as_node().unwrap(), CounterRange { lo: c.w.lo, hi: c.w.hi() });
    }
    for c in &commits {
        let tid = source(&c.w.source).as_node().unwrap();
        assert!(received.frontier(&tid) >= c.w.hi() - 1);
    }
    let snap = |f: &Fragment, fr: Frontiers| encode_snapshot(&Snapshot { nonce: [0; 16], fragment: f.clone(), frontiers: fr, authors: Default::default() }, &scx(), None).unwrap();
    let bytes = snap(&a, received.frontiers());
    let got = decode_snapshot(&bytes, &scx(), &mut Interner::new(), None).unwrap();
    let mut b = Fragment::default();
    b.join(got.fragment);
    let mut rb = Received::new();
    rb.add_frontiers(&got.frontiers);
    assert_eq!(rb.frontiers(), received.frontiers());
    assert_eq!(b.read(), a.read());
    // b edits; a edits concurrently; both exchange
    let view = TyView(ty.clone());
    let v = crate::testutil::value(&crdt_model::r#gen::random_value(&mut r, ty, 0));
    let mut bb = Batch::new(&b, crate::Writer::new(ts(1 << 30), Source::node(Tid::from_bytes([9; 15])), 1));
    bb.apply(&PathOp { path: vec![], op: Op::Set(v) }, &view).unwrap();
    let mut mw = crdt_model::ops::Writer::new(MSource::node(1), (1 << 30) + 1, 100);
    mw.next_commit((1 << 30) + 2);
    let da = random_op(&mut r, &mut mw, ty, None).map(|d| frag(&d));
    if let Some((db, _)) = bb.finish() {
        a.join(db.clone());
        b.join(db);
    }
    if let Some(da) = da {
        a.join(da.clone());
        b.join(da);
    }
    // equal up to the chars of deleted text, which a snapshot does not carry (§3.3 rule 5)
    assert_eq!(a.read(), b.read());
    assert_eq!(snap(&a, Frontiers::default()), snap(&b, Frontiers::default()));
}


// ---- paging (§8, spec/wire.md §6)

const SMALL: PageParams = PageParams { target: 2000, cut: ChunkParams { min: 128, max: 1024, mask_bits: 6 }, fanout: 8 };

fn big_set(n: usize, order_seed: u64) -> Fragment {
    let node = |i: u8| Source::node(Tid::from_bytes([i; 15]));
    let mut idx: Vec<usize> = (0..n).collect();
    let mut r = Rng(order_seed | 1);
    for k in (1..idx.len()).rev() {
        idx.swap(k, r.below(k + 1));
    }
    let mut st = Fragment::default();
    for i in idx {
        let mut w = crate::Writer::new(ts(((i as u64 % 7) + 1) << 16), node((i % 3) as u8 + 1), 1 + i as u64);
        let d = crate::create(&mut w, &crate::AnyView, &Value::Set([Value::Str(format!("element number {i}"))].into_iter().collect())).unwrap();
        st.join(d);
    }
    st
}

fn snap(f: &Fragment) -> Snapshot {
    Snapshot { nonce: [0; 16], fragment: f.clone(), frontiers: Frontiers::default(), authors: Default::default() }
}

fn scx() -> DeltaCtx {
    DeltaCtx { ts: ts(1 << 40), own: Source::node(Tid::from_bytes([250; 15])), range: CounterRange::EMPTY, kind: DeltaKind::Snapshot }
}

/// Plaintexts of every page written.
struct Recording {
    inner: MemoryPages,
    pages: Vec<Vec<u8>>,
}
impl PageSink for Recording {
    fn put(&mut self, p: &[u8]) -> Result<osis_core::Link, crate::PageError> {
        self.pages.push(p.to_vec());
        self.inner.put(p)
    }
    fn params(&self) -> PageParams {
        PageSink::params(&self.inner)
    }
}

fn paged(f: &Fragment, params: PageParams) -> (Vec<u8>, Recording) {
    let mut rec = Recording { inner: MemoryPages::with_params(params), pages: Vec::new() };
    let bytes = encode_snapshot(&snap(f), &scx(), Some(&mut rec)).unwrap();
    (bytes, rec)
}

#[test]
fn paging_round_trip_and_bounds_spec_8() {
    for n in [3usize, 100, 400] {
        let st = big_set(n, 1);
        let (bytes, mut rec) = paged(&st, SMALL);
        // paged iff the plain array is above the target (the 3-element set is not)
        assert_eq!(rec.pages.is_empty(), n == 3, "n = {n}");
        for p in &rec.pages {
            let v = osis_core::decode(p, &osis_core::Limits::DEFAULT).unwrap();
            let osis_core::Value::List(items) = &v else { panic!() };
            let is_links = items.iter().all(|i| matches!(i, osis_core::Value::Link(_)));
            if is_links {
                assert!(items.len() <= SMALL.fanout);
            } else {
                // whole elements; a page ends once it reaches the maximum
                let last = osis_core::encode(items.last().unwrap()).len();
                assert!(p.len() < SMALL.cut.max + last + 8, "page of {} bytes", p.len());
            }
        }
        let got = decode_snapshot(&bytes, &scx(), &mut Interner::new(), Some(&mut rec.inner)).unwrap();
        assert_eq!(got.fragment, st);
    }
}

#[test]
fn paging_two_levels_and_limit_spec_8() {
    let st = big_set(600, 2);
    let (bytes, mut rec) = paged(&st, SMALL);
    let has_link_pages = rec.pages.iter().any(|p| matches!(osis_core::decode(p, &osis_core::Limits::DEFAULT), Ok(osis_core::Value::List(i)) if i.iter().all(|x| matches!(x, osis_core::Value::Link(_)))));
    assert!(has_link_pages, "link pages appear above the link target");
    assert_eq!(decode_snapshot(&bytes, &scx(), &mut Interner::new(), Some(&mut rec.inner)).unwrap().fragment, st);
    // a fragment that would need a third level cannot be written
    let tiny = PageParams { target: 200, cut: ChunkParams { min: 64, max: 256, mask_bits: 4 }, fanout: 2 };
    let mut pages = MemoryPages::with_params(tiny);
    assert!(encode_snapshot(&snap(&st), &scx(), Some(&mut pages)).is_err());
}

#[test]
fn equal_states_equal_pages_spec_8() {
    let a = big_set(300, 3);
    let b = big_set(300, 4);
    assert_eq!(a, b);
    let (_, ra) = paged(&a, SMALL);
    let (_, rb) = paged(&b, SMALL);
    let set = |r: &Recording| r.pages.iter().filter(|p| !matches!(osis_core::decode(p, &osis_core::Limits::DEFAULT), Ok(osis_core::Value::List(i)) if i.iter().all(|x| matches!(x, osis_core::Value::Link(_))))).cloned().collect::<BTreeSet<_>>();
    assert_eq!(set(&ra), set(&rb));
}

#[test]
fn paging_canonical_rejections_spec_8() {
    let st = big_set(400, 5);
    let (bytes, mut rec) = paged(&st, SMALL);
    // a source with other parameters would have cut elsewhere: the paging is not canonical
    let mut other = MemoryPages::with_params(PageParams { cut: ChunkParams { min: 200, max: 1024, mask_bits: 6 }, ..SMALL });
    for p in &rec.pages {
        other.put(p).unwrap();
    }
    assert!(decode_snapshot(&bytes, &scx(), &mut Interner::new(), Some(&mut other)).is_err());
    // without the pages the commit cannot apply
    assert!(decode_snapshot(&bytes, &scx(), &mut Interner::new(), None).is_err());
    // unpaged where paging is mandatory
    let plain = encode_snapshot(&snap(&st), &scx(), Some(&mut MemoryPages::with_params(PageParams { target: usize::MAX, ..SMALL }))).unwrap();
    assert!(decode_snapshot(&plain, &scx(), &mut Interner::new(), Some(&mut rec.inner)).is_err());
}

/// §8 at the format's sizes: a set above 64 KiB pages and round-trips.
#[test]
fn paging_format_size_spec_8() {
    let st = big_set(3000, 6);
    let mut pages = MemoryPages::new();
    let bytes = encode_snapshot(&snap(&st), &scx(), Some(&mut pages)).unwrap();
    assert!(!pages.is_empty());
    assert!(bytes.len() < crate::page::PageParams::FORMAT.target);
    assert_eq!(decode_snapshot(&bytes, &scx(), &mut Interner::new(), Some(&mut pages)).unwrap().fragment, st);
    // a writer's delta pages the same way (§8: any delta may page)
    let node = Source::node(Tid::from_bytes([1; 15]));
    let mut w = crate::Writer::new(ts(1 << 20), node.clone(), 1);
    let items: BTreeSet<Value> = (0..3000).map(|i| Value::Str(format!("bulk import {i}"))).collect();
    let d = crate::create(&mut w, &crate::AnyView, &Value::Set(items)).unwrap();
    let cx = DeltaCtx { ts: ts(1 << 20), own: node, range: w.range(), kind: DeltaKind::Writer };
    let mut pages = MemoryPages::new();
    let bytes = encode_delta(&Delta { nonce: [0; 16], fragment: d.clone() }, &cx, Some(&mut pages)).unwrap();
    assert_eq!(decode_delta(&bytes, &cx, &mut Interner::new(), Some(&mut pages)).unwrap().fragment, d);
}

/// A struct of `n` string fields of `len` bytes, the last one an enum whose payload is such a
/// struct again, as one writer's delta.
fn wide_struct(n: u64, len: usize) -> (Fragment, DeltaCtx) {
    let inner: std::collections::BTreeMap<u64, Ty> = (0..n).map(|i| (i, Ty::Register)).collect();
    let mut fields = inner.clone();
    fields.insert(n, Ty::Enum([(1, Some(Ty::Struct(inner.clone())))].into_iter().collect()));
    let ty = Ty::Struct(fields);
    let strs = || (0..n).map(|i| (Value::Int(i as i64), Value::Str(format!("{i:04}{}", "x".repeat(len))))).collect::<std::collections::BTreeMap<_, _>>();
    let mut v = strs();
    v.insert(Value::Int(n as i64), Value::Enum(1, Some(Box::new(Value::Map(strs())))));
    let node = Source::node(Tid::from_bytes([1; 15]));
    let mut w = crate::Writer::new(ts(1 << 20), node.clone(), 1);
    let d = crate::create(&mut w, &TyView(ty), &Value::Map(v)).unwrap();
    (d, DeltaCtx { ts: ts(1 << 20), own: node, range: w.range(), kind: DeltaKind::Writer })
}

/// §8: a struct's field map and an enum's payload map page like element arrays: pages are maps
/// of whole consecutive fields, the delta stays at the target whatever the field count, and it
/// round-trips; below the target nothing pages.
#[test]
fn struct_field_paging_spec_8() {
    for (n, paged) in [(3u64, false), (200, true)] {
        let (d, cx) = wide_struct(n, 100);
        let mut rec = Recording { inner: MemoryPages::with_params(SMALL), pages: Vec::new() };
        let bytes = encode_delta(&Delta { nonce: [0; 16], fragment: d.clone() }, &cx, Some(&mut rec)).unwrap();
        assert_eq!(!rec.pages.is_empty(), paged, "n = {n}");
        assert!(bytes.len() <= SMALL.target || !paged);
        let mut maps = 0;
        for p in &rec.pages {
            match osis_core::decode(p, &osis_core::Limits::DEFAULT).unwrap() {
                Value::Map(m) => {
                    maps += 1;
                    let last = m.iter().next_back().map(|(k, v)| osis_core::encode(k).len() + osis_core::encode(v).len()).unwrap();
                    assert!(p.len() < SMALL.cut.max + last + 8, "page of {} bytes", p.len());
                }
                Value::List(items) => assert!(items.iter().all(|i| matches!(i, Value::Link(_))) && items.len() <= SMALL.fanout),
                v => panic!("page {v:?}"),
            }
        }
        assert!(maps > 1 || !paged);
        assert_eq!(decode_delta(&bytes, &cx, &mut Interner::new(), Some(&mut rec.inner)).unwrap().fragment, d);
        // equal fields give equal pages
        let mut again = Recording { inner: MemoryPages::with_params(SMALL), pages: Vec::new() };
        encode_delta(&Delta { nonce: [0; 16], fragment: d.clone() }, &cx, Some(&mut again)).unwrap();
        assert_eq!(again.pages, rec.pages);
    }
}

/// §8: a field map unpaged above the target, a page that is not a map, an empty page, fields
/// out of order across pages: rejected.
#[test]
fn struct_field_paging_rejections_spec_8() {
    let (d, cx) = wide_struct(200, 100);
    let mut rec = Recording { inner: MemoryPages::with_params(SMALL), pages: Vec::new() };
    let bytes = encode_delta(&Delta { nonce: [0; 16], fragment: d.clone() }, &cx, Some(&mut rec)).unwrap();
    let plain = encode_delta(&Delta { nonce: [0; 16], fragment: d }, &cx, Some(&mut MemoryPages::with_params(PageParams { target: usize::MAX, ..SMALL }))).unwrap();
    assert!(decode_delta(&plain, &cx, &mut Interner::new(), Some(&mut rec.inner)).is_err());
    // swap the struct's top field links for crafted pages
    let top = osis_core::decode(&bytes, &osis_core::Limits::DEFAULT).unwrap();
    let with_children = |c: Value| {
        let Value::List(mut a) = top.clone() else { panic!() };
        let Some(Value::List(f)) = a.get_mut(3) else { panic!() };
        f[3] = c;
        osis_core::encode(&Value::List(a))
    };
    let mut pages = MemoryPages::with_params(SMALL);
    let field = |i: i64| (Value::Int(i), Value::List(vec![Value::Int(0), Value::List(vec![]), Value::Int(0), Value::Str("v".into())]));
    let page = |pages: &mut MemoryPages, v: Value| Value::Link(pages.put(&osis_core::encode(&v)).unwrap());
    let a = page(&mut pages, Value::Map([field(5)].into_iter().collect()));
    let b = page(&mut pages, Value::Map([field(2)].into_iter().collect()));
    let empty = page(&mut pages, Value::Map(Default::default()));
    let list = page(&mut pages, Value::List(vec![Value::Int(1)]));
    for (links, why) in [(vec![a.clone(), b], "order"), (vec![a.clone(), empty], "empty"), (vec![a, list], "map")] {
        let e = decode_delta(&with_children(Value::List(links)), &cx, &mut Interner::new(), Some(&mut pages)).unwrap_err();
        assert!(e.to_string().contains(why), "{why}: {e}");
    }
}

#[test]
#[ignore]
fn paging_large_spec_8() {
    let st = big_set(100_000, 7);
    let mut pages = MemoryPages::new();
    let bytes = encode_snapshot(&snap(&st), &scx(), Some(&mut pages)).unwrap();
    assert_eq!(decode_snapshot(&bytes, &scx(), &mut Interner::new(), Some(&mut pages)).unwrap().fragment, st);
}

/// §4.7, §7: a value-less register embeds like its valued copy after stripping.
#[test]
fn value_less_embedding_spec_7() {
    let node = Source::node(Tid::from_bytes([1; 15]));
    let mut w = crate::Writer::new(ts(3 << 16), node.clone(), 1);
    let reg = crate::create(&mut w, &crate::AnyView, &Value::Int(5)).unwrap();
    let mut w2 = crate::Writer::new(ts(2 << 16), Source::node(Tid::from_bytes([2; 15])), 1);
    let counter = crate::Fragment::empty(crate::Encoding::Counter).unwrap();
    let _ = &mut w2;
    let all = |_: &Dot| true;
    let mut valued = join(&reg, &counter);
    valued.join(crate::ops::create(&mut w2, &TyView(Ty::Counter), &Value::Int(1)).unwrap());
    let mut a = valued.clone();
    a.strip(&all);
    let mut less = reg.clone();
    less.strip(&all);
    let mut b = join(&less, &crate::ops::create(&mut crate::Writer::new(ts(2 << 16), Source::node(Tid::from_bytes([2; 15])), 1), &TyView(Ty::Counter), &Value::Int(1)).unwrap());
    b.strip(&all);
    assert_eq!(a, b);
}

/// §3.3 rule 3: a list run closes once its content reaches `CHUNK_MAX` bytes, so 65 values of
/// 128 KiB inserted at once make several runs: the model's bytes unpaged, and paged every page
/// within `CHUNK_MAX` plus one element; it round-trips.
#[test]
fn list_run_closes_at_chunk_max_spec_3_3() {
    use crdt_model::value::Value as MV;
    let ty = crdt_model::ops::Ty::List(Box::new(crdt_model::ops::Ty::Register));
    let mut w = crdt_model::ops::Writer::new(crdt_model::stamp::Source::node(1), 5 << 16, 1);
    let big = |i: usize| MV::Str(format!("{i:03}{}", "x".repeat(128 * 1024 - 16)));
    let delta = crdt_model::ops::create(&mut w, &ty, &MV::List((0..65).map(big).collect()));
    let mbytes = crdt_model::wire::encode_delta(&delta, [7; 16], &mut crdt_model::wire::Ctx::new(w.ts, w.source.clone(), w.lo));
    let cx = crate::tests_wire::writer_cx(&w);
    let d = Delta { nonce: [7; 16], fragment: crate::testutil::frag(&delta) };
    let mut flat = MemoryPages::with_params(PageParams { target: usize::MAX, ..PageParams::FORMAT });
    let bytes = encode_delta(&d, &cx, Some(&mut flat)).unwrap();
    assert_eq!(bytes, mbytes, "the model's bytes");
    let top = osis_core::decode(&bytes, &osis_core::Limits { max_bytes: usize::MAX, ..osis_core::Limits::DEFAULT }).unwrap();
    let Value::List(a) = top else { panic!() };
    let Some(Value::List(f)) = a.get(3) else { panic!() };
    let Some(Value::List(runs)) = f.get(3) else { panic!() };
    // two elements stay just below 256 KiB, three reach it: 21 runs of 3, one of 2
    assert_eq!(runs.len(), 22);
    let mut rec = Recording { inner: MemoryPages::new(), pages: Vec::new() };
    let paged = encode_delta(&d, &cx, Some(&mut rec)).unwrap();
    assert!(rec.pages.iter().all(|p| p.len() < osis_core::format::CHUNK_MAX + 3 * 128 * 1024), "pages {:?}", rec.pages.iter().map(Vec::len).collect::<Vec<_>>());
    assert_eq!(decode_delta(&paged, &cx, &mut Interner::new(), Some(&mut rec.inner)).unwrap().fragment, d.fragment);
}

/// §3.3 rule 7: a list run whose content goes on past `CHUNK_MAX` bytes is rejected.
#[test]
fn rejects_list_run_past_chunk_max_spec_3_3() {
    use crdt_model::value::Value as MV;
    let ty = crdt_model::ops::Ty::List(Box::new(crdt_model::ops::Ty::Register));
    let mut w = crdt_model::ops::Writer::new(crdt_model::stamp::Source::node(1), 5 << 16, 1);
    let delta = crdt_model::ops::create(&mut w, &ty, &MV::List((0..6).map(|i| MV::Str(format!("{i}{}", "x".repeat(128 * 1024)))).collect()));
    let cx = crate::tests_wire::writer_cx(&w);
    let d = Delta { nonce: [7; 16], fragment: crate::testutil::frag(&delta) };
    let mut flat = MemoryPages::with_params(PageParams { target: usize::MAX, ..PageParams::FORMAT });
    let bytes = encode_delta(&d, &cx, Some(&mut flat)).unwrap();
    assert!(decode_delta(&bytes, &cx, &mut Interner::new(), Some(&mut flat)).is_ok());
    // join the runs of 2 into one run of 6
    let Value::List(mut a) = osis_core::decode(&bytes, &osis_core::Limits::DEFAULT).unwrap() else { panic!() };
    let Some(Value::List(f)) = a.get_mut(3) else { panic!() };
    let Some(Value::List(runs)) = f.get_mut(3) else { panic!() };
    assert_eq!(runs.len(), 3);
    let mut all = Vec::new();
    for r in runs.iter() {
        let Value::List(r) = r else { panic!() };
        let Some(Value::List(c)) = r.get(3) else { panic!() };
        all.extend(c.iter().cloned());
    }
    let Some(Value::List(r0)) = runs.first_mut() else { panic!() };
    r0[1] = Value::Int(6);
    r0[2] = Value::List(vec![Value::Int(0), Value::List(vec![Value::List(vec![Value::Int(0), Value::Int(6)])])]);
    r0[3] = Value::List(all);
    runs.truncate(1);
    let bad = osis_core::encode(&Value::List(a));
    let e = decode_delta(&bad, &cx, &mut Interner::new(), Some(&mut flat)).unwrap_err();
    assert!(e.to_string().contains("not canonical"), "{e}");
}
