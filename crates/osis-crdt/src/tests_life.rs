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
        let ty = sink_no_seq();
        let (s, m, ranges, mranges) = three(seed, &ty);
        let mut r = Rng(seed ^ 0x55);
        let pick: Vec<bool> = ranges.iter().map(|_| r.chance(1, 2)).collect();
        let expired: Vec<Range> = ranges.iter().zip(&pick).filter(|x| *x.1).map(|x| x.0.clone()).collect();
        let mexpired: Vec<(MSource, u64, u64)> = mranges.iter().zip(&pick).filter(|x| *x.1).map(|x| x.0.clone()).collect();
        let strip = |f: &Fragment| { let mut g = f.clone(); g.strip(&in_ranges(&expired)); g };
        for (o, mo) in s.iter().zip(&m) {
            let mut ms = mo.clone();
            ms.strip(&|d| mexpired.iter().any(|(src, lo, hi)| d.source == *src && (*lo..*hi).contains(&d.ctr)));
            prop_assert_eq!(strip(o), frag(&ms), "strip equals the model");
        }
        let (a, b) = (&s[0], &s[1]);
        prop_assert_eq!(strip(&join(a, b)), join(&strip(a), &strip(b)), "strip commutes with join");
        prop_assert_eq!(strip(&strip(a)), strip(a), "idempotent");
        prop_assert_eq!(join(a, &strip(a)), a.clone(), "valued copy wins");
    }

    /// §4.6: removing an author in place equals the model; un-merge of held bodies is
    /// order-independent and agrees with the in-place fast path where that applies.
    #[test]
    fn unmerge_spec_4_6(seed in any::<u64>()) {
        let ty = sink_no_seq();
        let mut r = Rng(seed | 1);
        let commits = history(&mut r, std::slice::from_ref(&ty), 3, 4);
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
            prop_assert_eq!(ours, frag(&mm), "remove_author equals the model");
        }
        let mut held: Vec<Fragment> = commits.iter().map(|c| frag(&c.delta)).collect();
        held.push(state.clone());
        let u1 = unmerge(held.clone(), &author);
        held.reverse();
        let u2 = unmerge(held, &author);
        prop_assert_eq!(&u1, &u2, "order-independent");
        let mut fast = state.clone();
        if unmerge_in_place(&mut fast, &author) {
            prop_assert_eq!(fast.read(), u1.read(), "fast path agrees");
        }
    }

    /// §8: a node bootstrapped from a snapshot and then editing converges with the source node;
    /// frontiers cover every commit.
    #[test]
    fn bootstrap_then_edit_spec_8(seed in any::<u64>()) {
        let ty = sink_no_seq();
        let mut r = Rng(seed | 1);
        let commits = history(&mut r, std::slice::from_ref(&ty), 3, 4);
        let mut a = Fragment::default();
        let mut received = Received::new();
        for c in &commits {
            a.join(frag(&c.delta));
            received.add(source(&c.w.source).as_node().unwrap(), CounterRange { lo: c.w.lo, hi: c.w.hi() });
        }
        for c in &commits {
            let tid = source(&c.w.source).as_node().unwrap();
            prop_assert!(received.frontier(&tid) >= c.w.hi() - 1);
        }
        let scx = DeltaCtx { ts: ts(1 << 40), own: Source::node(Tid::from_bytes([250; 15])), range: CounterRange::EMPTY, kind: DeltaKind::Snapshot };
        let snap = Snapshot { nonce: [0; 16], fragment: a.clone(), frontiers: received.frontiers() };
        let bytes = encode_snapshot(&snap, &scx, None).unwrap();
        let got = decode_snapshot(&bytes, &scx, &mut Interner::new(), None).unwrap();
        let mut b = Fragment::default();
        b.join(got.fragment);
        let mut rb = Received::new();
        rb.add_frontiers(&got.frontiers);
        prop_assert_eq!(rb.frontiers(), received.frontiers());
        prop_assert_eq!(b.read(), a.read());
        // b edits; a edits concurrently; both exchange
        let view = TyView(ty.clone());
        let v = crate::testutil::value(&crdt_model::r#gen::random_value(&mut r, &ty, 0));
        let mut bb = Batch::new(&b, crate::Writer::new(ts(1 << 30), Source::node(Tid::from_bytes([9; 15])), 1));
        bb.apply(&PathOp { path: vec![], op: Op::Set(v) }, &view).unwrap();
        let mut mw = crdt_model::ops::Writer::new(MSource::node(1), (1 << 30) + 1, 100);
        mw.next_commit((1 << 30) + 2);
        let da = random_op(&mut r, &mut mw, &ty, None).map(|d| frag(&d));
        if let Some((db, _)) = bb.finish() {
            a.join(db.clone());
            b.join(db);
        }
        if let Some(da) = da {
            a.join(da.clone());
            b.join(da);
        }
        prop_assert_eq!(&a, &b);
    }
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
    Snapshot { nonce: [0; 16], fragment: f.clone(), frontiers: Frontiers::default() }
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
