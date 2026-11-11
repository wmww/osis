//! Expiry, un-merge, snapshots and paging (spec/crdt.md §4.6, §4.7, §8).

use crate::codec::{decode_delta, decode_snapshot, encode_delta, encode_snapshot};
use crate::fragment::Fragment;
use crate::page::{MemoryPages, PageParams, PageSink};
use crate::stamp::{CounterRange, Dot, Interner, Source};
use crate::testutil::{TyView, frag, history, mapply, ostate, sess, sink_no_seq, source, ts};
use crate::wire::{Delta, DeltaCtx, DeltaKind, Frontiers, Received, Snapshot};
use crate::Batch;
use crate::ops::{Op, PathOp};
use crdt_model::r#gen::random_op;
use crdt_model::ops::Ty;
use crdt_model::stamp::Source as MSource;
use osis_base::{ChunkParams, Tid, Value};
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
    let mut r = crate::testutil::rng(seed | 1);
    let mut ours = Vec::new();
    let mut models = Vec::new();
    let mut ranges = Vec::new();
    let mut mranges = Vec::new();
    for i in 0..3u8 {
        let mut w = crdt_model::ops::Writer::new(MSource::session(i + 1, 0), ((r.below(5) as u64 + 1) << 16) + i as u64, 1);
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

    /// §4.6: un-merge of held bodies equals the model's and is order-independent.
    #[test]
    fn unmerge_spec_4_6(seed in any::<u64>()) {
        unmerge_check(seed, &sink_no_seq());
    }

    /// §4.8, §8: a state without a set of commits' writes (`remove_writes`) holds none of them,
    /// and joined with those commits reads as the state: others' writes nested in their records
    /// stay.
    #[test]
    fn remove_writes_rejoins_spec_4_8(seed in any::<u64>()) {
        remove_writes_check(seed, &sink_no_seq());
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
    let mut r = crate::testutil::rng(seed ^ 0x55);
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
    // a stripped map write moves to its dot's key-erased record (§4.7), which the valued
    // records' read joins: the same read, and the same state once stripped
    assert_eq!(join(a, &strip(a)), *a, "valued copy wins");
    assert_eq!(strip(&join(a, &strip(a))), strip(a), "valued copy wins, stripped");
}

/// §4.6 un-merge over a random history of type `ty`.
pub(crate) fn unmerge_check(seed: u64, ty: &Ty) {
    let mut r = crate::testutil::rng(seed | 1);
    let commits = history(&mut r, std::slice::from_ref(ty), 3, 4);
    let mut mstate = None;
    for c in &commits {
        mapply(&mut mstate, c.delta.clone());
    }
    let state = ostate(&mstate);
    let bad = source(&MSource::session(2, 0));
    let mut model = None;
    let mut ours = Fragment::default();
    for c in &commits {
        let mut m = c.delta.clone();
        m.unmerge(&|d| d.source == MSource::session(2, 0), &|_| false);
        mapply(&mut model, m);
        let mut b = frag(&c.delta);
        b.remove_dots(&|d| d.src == bad);
        ours.join(b);
    }
    assert_eq!(ours, ostate(&model), "un-merged bodies equal the model's");
    // an author's writes (§4.6) and one delta's (spec/permissions.md §5.2): the join of the held
    // bodies each without them is order-independent
    let held: Vec<Fragment> = commits.iter().map(|c| frag(&c.delta)).chain(std::iter::once(state.clone())).collect();
    type Pred = Box<dyn Fn(&Dot) -> bool>;
    let mut preds: Vec<Pred> = vec![Box::new(move |d: &Dot| d.src == bad)];
    for c in &commits {
        let (src, lo, hi) = (source(&c.w.source), c.w.lo, c.w.hi());
        preds.push(Box::new(move |d: &Dot| d.src == src && lo <= d.ctr && d.ctr < hi));
    }
    for pred in &preds {
        let unmerged = |bodies: &mut dyn Iterator<Item = &Fragment>| {
            let mut out = Fragment::default();
            for b in bodies {
                let mut b = b.clone();
                b.remove_dots(pred);
                out.join(b);
            }
            out
        };
        let want = unmerged(&mut held.iter());
        assert_eq!(want, unmerged(&mut held.iter().rev()), "order-independent");
    }
}

/// `remove_writes` over a random history of type `ty`: for random sets of its commits.
pub(crate) fn remove_writes_check(seed: u64, ty: &Ty) {
    let mut r = crate::testutil::rng(seed | 1);
    let commits = history(&mut r, std::slice::from_ref(ty), 3, 4);
    let mut state = Fragment::default();
    for c in &commits {
        state.join(frag(&c.delta));
    }
    for _ in 0..4 {
        let pick: Vec<bool> = commits.iter().map(|_| r.chance(1, 2)).collect();
        let ranges: Vec<Range> = commits.iter().zip(&pick).filter(|x| *x.1).map(|(c, _)| (source(&c.w.source), c.w.lo, c.w.hi())).collect();
        let pred = in_ranges(&ranges);
        let mut rest = state.clone();
        rest.remove_writes(&pred);
        let left: Vec<_> = rest.writes().into_iter().filter(|(d, ts)| ts.is_some() && pred(d)).collect();
        assert!(left.is_empty(), "left {left:?}");
        // as a replay plays them: the commits (before the snapshot), then the rest; and after
        let mut back = Fragment::default();
        for c in commits.iter().zip(&pick).filter(|x| *x.1) {
            back.join(frag(&c.0.delta));
        }
        back.join(rest.clone());
        assert_eq!(back.read(), state.read(), "rejoined");
        let mut after = rest.clone();
        for c in commits.iter().zip(&pick).filter(|x| *x.1) {
            after.join(frag(&c.0.delta));
        }
        assert_eq!(after.read(), state.read(), "rejoined after");
    }
}

/// §8 bootstrap from a snapshot, then concurrent edits of type `ty`.
pub(crate) fn bootstrap_check(seed: u64, ty: &Ty) {
    let mut r = crate::testutil::rng(seed | 1);
    let commits = history(&mut r, std::slice::from_ref(ty), 3, 4);
    let mut a = Fragment::default();
    let mut received = Received::new();
    for c in &commits {
        a.join(frag(&c.delta));
        received.add(&source(&c.w.source), CounterRange { lo: c.w.lo, hi: c.w.hi() });
    }
    for c in &commits {
        assert!(received.frontier(&source(&c.w.source)) >= c.w.hi() - 1);
    }
    let snap = |f: &Fragment, fr: Frontiers| encode_snapshot(&Snapshot { absorbed: Default::default(), nonce: [0; 16], fragment: f.clone(), frontiers: fr }, &scx(), None).unwrap();
    // frontiers of the sources left in the state only (§8)
    let traced = |f: &Fragment, mut fr: Frontiers| {
        fr.retain(&crate::sources_of(f, &scx()).unwrap());
        fr
    };
    let bytes = snap(&a, traced(&a, received.frontiers()));
    let got = decode_snapshot(&bytes, &scx(), &mut Interner::new(), None).unwrap();
    let mut b = Fragment::default();
    b.join(got.fragment);
    let mut rb = Received::new();
    rb.add_frontiers(&got.frontiers);
    assert_eq!(rb.frontiers(), traced(&a, received.frontiers()));
    assert_eq!(b.read(), a.read());
    // b edits; a edits concurrently; both exchange
    let view = TyView(ty.clone());
    let v = crate::testutil::value(&crdt_model::r#gen::random_value(&mut r, ty, 0));
    let mut bb = Batch::new(&b, crate::Writer::new(ts(1 << 30), sess(Tid::from_bytes([9; 15])), 1));
    bb.apply(&PathOp { path: vec![], op: Op::Set(v) }, &view).unwrap();
    let mut mw = crdt_model::ops::Writer::new(MSource::session(1, 0), (1 << 30) + 1, 100);
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

const SMALL: PageParams = PageParams { target: 2000, cut: ChunkParams { min: 128, max: 1024, mask_bits: 6 }, fanout: 8, ..PageParams::FORMAT };

pub(crate) fn big_set(n: usize, order_seed: u64) -> Fragment {
    let node = |i: u8| sess(Tid::from_bytes([i; 15]));
    let mut idx: Vec<usize> = (0..n).collect();
    let mut r = crate::testutil::rng(order_seed | 1);
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
    Snapshot { absorbed: Default::default(), nonce: [0; 16], fragment: f.clone(), frontiers: Frontiers::default() }
}

fn scx() -> DeltaCtx {
    DeltaCtx { ts: ts(1 << 40), own: sess(Tid::from_bytes([250; 15])), range: CounterRange::EMPTY, kind: DeltaKind::Snapshot }
}

/// Plaintexts of every page written.
struct Recording {
    inner: MemoryPages,
    pages: Vec<Vec<u8>>,
}
impl PageSink for Recording {
    fn put(&mut self, p: &[u8]) -> Result<osis_base::Link, crate::PageError> {
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
            let v = osis_base::decode(p, &osis_base::Limits::DEFAULT).unwrap();
            let osis_base::Value::List(items) = &v else { panic!() };
            let is_links = items.iter().all(|i| matches!(i, osis_base::Value::Link(_)));
            if is_links {
                assert!(items.len() <= SMALL.fanout);
            } else {
                // whole elements; a page ends once it reaches the maximum
                let last = osis_base::encode(items.last().unwrap()).len();
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
    let has_link_pages = rec.pages.iter().any(|p| matches!(osis_base::decode(p, &osis_base::Limits::DEFAULT), Ok(osis_base::Value::List(i)) if i.iter().all(|x| matches!(x, osis_base::Value::Link(_)))));
    assert!(has_link_pages, "link pages appear above the link target");
    assert_eq!(decode_snapshot(&bytes, &scx(), &mut Interner::new(), Some(&mut rec.inner)).unwrap().fragment, st);
    // a fragment that would need a third level cannot be written
    let tiny = PageParams { target: 200, cut: ChunkParams { min: 64, max: 256, mask_bits: 4 }, fanout: 2, ..PageParams::FORMAT };
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
    let set = |r: &Recording| r.pages.iter().filter(|p| !matches!(osis_base::decode(p, &osis_base::Limits::DEFAULT), Ok(osis_base::Value::List(i)) if i.iter().all(|x| matches!(x, osis_base::Value::Link(_))))).cloned().collect::<BTreeSet<_>>();
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

/// §8: an ephemeral delta is never paged: above the page target it encodes inline and decodes
/// only as unpaged; a paged one is bad input there.
#[test]
fn unpaged_ephemeral_deltas_spec_8() {
    let st = big_set(3000, 7);
    let plain = encode_snapshot(&snap(&st), &scx(), Some(&mut crate::Unpaged)).unwrap();
    assert!(plain.len() > PageParams::FORMAT.target);
    assert_eq!(decode_snapshot(&plain, &scx(), &mut Interner::new(), Some(&mut crate::Unpaged)).unwrap().fragment, st);
    assert!(decode_snapshot(&plain, &scx(), &mut Interner::new(), None).is_err(), "durable: paging is mandatory");
    let mut pages = MemoryPages::new();
    let paged = encode_snapshot(&snap(&st), &scx(), Some(&mut pages)).unwrap();
    let e = decode_snapshot(&paged, &scx(), &mut Interner::new(), Some(&mut crate::Unpaged)).unwrap_err();
    assert_eq!(osis_base::Classified::class(&e), osis_base::ErrorClass::BadInput);
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
    let node = sess(Tid::from_bytes([1; 15]));
    let mut w = crate::Writer::new(ts(1 << 20), node.clone(), 1);
    let items: osis_base::ValueSet = (0..3000).map(|i| Value::Str(format!("bulk import {i}"))).collect();
    let d = crate::create(&mut w, &crate::AnyView, &Value::Set(items)).unwrap();
    let cx = DeltaCtx { ts: ts(1 << 20), own: node, range: w.range(), kind: DeltaKind::Writer };
    let mut pages = MemoryPages::new();
    let bytes = encode_delta(&Delta { nonce: [0; 16], fragment: d.clone() }, &cx, Some(&mut pages)).unwrap();
    assert_eq!(decode_delta(&bytes, &cx, &mut Interner::new(), Some(&mut pages)).unwrap().fragment, d);
}

const CAP_ERR: &str = "page or root fragment above MAX_PAGE_ITEMS items";

fn is_cap(e: &crate::Error) -> bool {
    matches!(e, crate::Error::Malformed(m) if *m == CAP_ERR)
}

/// §8 `MAX_PAGE_ITEMS`: a root fragment or page of more items (CBOR items, text bytes) is bad
/// input at every durable reader, found from the heads before anything is decoded; at the cap
/// the count passes. Ephemeral (unpaged) deltas are not counted.
#[test]
fn page_items_cap_spec_8() {
    use osis_base::format::MAX_PAGE_ITEMS;
    let none = || Value::List(Vec::new());
    // a register whose value holds `n` items, or a text string of `n` bytes
    let root = |val: Value, snapshot: bool| {
        let mut top = vec![Value::Bytes(vec![0; 16]), none(), none(), Value::List(vec![Value::Int(0), none(), Value::Int(0), val])];
        if snapshot {
            top.extend([none(), none()]);
        }
        osis_base::encode(&Value::List(top))
    };
    let zeros = |n: usize| Value::List(vec![Value::Int(0); n]);
    // the fragment `[0, [], 0, [0 * n]]` counts n + 5 items
    let over = MAX_PAGE_ITEMS - 4;
    for (val, capped) in [(zeros(over), true), (zeros(over - 1), false), (Value::Str("x".repeat(MAX_PAGE_ITEMS)), true)] {
        for snapshot in [false, true] {
            let bytes = root(val.clone(), snapshot);
            let mut pages = MemoryPages::new();
            let errs = if snapshot {
                [decode_snapshot(&bytes, &scx(), &mut Interner::new(), None).unwrap_err(), decode_snapshot(&bytes, &scx(), &mut Interner::new(), Some(&mut pages)).unwrap_err()]
            } else {
                [decode_delta(&bytes, &scx(), &mut Interner::new(), None).unwrap_err(), decode_delta(&bytes, &scx(), &mut Interner::new(), Some(&mut pages)).unwrap_err()]
            };
            for e in errs {
                assert_eq!(is_cap(&e), capped, "{e}");
                assert_eq!(osis_base::Classified::class(&e), osis_base::ErrorClass::BadInput);
            }
            let e = decode_snapshot(&root(val.clone(), true), &scx(), &mut Interner::new(), Some(&mut crate::Unpaged)).unwrap_err();
            assert!(!is_cap(&e), "ephemeral deltas are not counted: {e}");
        }
    }
    // a page: the set's element array links to one page of too many items
    for (n, capped) in [(MAX_PAGE_ITEMS, true), (MAX_PAGE_ITEMS - 1, false)] {
        let mut pages = MemoryPages::new();
        let link = pages.put(&osis_base::encode(&zeros(n))).unwrap();
        let top = Value::List(vec![Value::Bytes(vec![0; 16]), none(), none(), Value::List(vec![Value::Int(6), none(), none(), Value::List(vec![Value::link(link)])]), none(), none()]);
        let e = decode_snapshot(&osis_base::encode(&top), &scx(), &mut Interner::new(), Some(&mut pages)).unwrap_err();
        assert_eq!(is_cap(&e), capped, "{e}");
    }
}

/// §8 `MAX_PAGE_ITEMS`, honest writers: a paged map and a paged text, as a writer's delta
/// and a snapshot, page far below the cap (each page and root counts at most its bytes) and
/// decode; a text's runs hold at most `MAX_RUN` elements.
#[test]
fn page_items_honest_spec_8() {
    let node = sess(Tid::from_bytes([1; 15]));
    // the text past `PAGE_TARGET` (one byte a char); the map as many bytes in fewer entries
    let chars = 80_000;
    let big_map = Value::Map((0..8_000).map(|i| (Value::Str(format!("key {i}")), Value::Str("v".repeat(10)))).collect());
    let text = Value::Str((0..chars).map(|i| char::from(b'a' + (i % 26) as u8)).collect());
    for (view, v) in [(TyView(Ty::Map(Box::new(Ty::Register), Box::new(Ty::Register))), big_map), (TyView(Ty::Text), text)] {
        let mut w = crate::Writer::new(ts(1 << 20), node.clone(), 1);
        let d = crate::create(&mut w, &view, &v).unwrap();
        let cx = DeltaCtx { ts: ts(1 << 20), own: node.clone(), range: w.range(), kind: DeltaKind::Writer };
        let mut rec = Recording { inner: MemoryPages::new(), pages: Vec::new() };
        let bytes = encode_delta(&Delta { nonce: [0; 16], fragment: d.clone() }, &cx, Some(&mut rec)).unwrap();
        let (sbytes, mut srec) = paged(&d, PageParams::FORMAT);
        for b in [&bytes, &sbytes].into_iter().chain(&rec.pages).chain(&srec.pages) {
            let n = crate::page_items(b).unwrap();
            assert!(n <= b.len() && n < 3 << 18, "{n} items in {} bytes", b.len());
        }
        assert!(!rec.pages.is_empty());
        assert_eq!(decode_delta(&bytes, &cx, &mut Interner::new(), Some(&mut rec.inner)).unwrap().fragment, d);
        assert_eq!(decode_snapshot(&sbytes, &scx(), &mut Interner::new(), Some(&mut srec.inner)).unwrap().fragment, d);
        if matches!(d, Fragment::Seq(_)) {
            // runs `[Dot, n, ...]` of at most `MAX_RUN` elements
            let ns: Vec<u64> = rec.pages.iter().flat_map(|p| match osis_base::decode(p, &osis_base::Limits::DEFAULT).unwrap() {
                Value::List(runs) => runs.into_iter().filter_map(|r| match r {
                    Value::List(r) if r.len() == 6 => r[1].as_uint(),
                    _ => None,
                }).collect(),
                _ => Vec::new(),
            }).collect();
            assert_eq!(ns.iter().sum::<u64>(), chars);
            assert!(ns.iter().all(|&n| n <= crate::MAX_RUN) && ns.contains(&crate::MAX_RUN), "{ns:?}");
        }
    }
}

/// A struct of `n` string fields of `len` bytes, the last one an enum whose payload is such a
/// struct again, as one writer's delta.
fn wide_struct(n: u64, len: usize) -> (Fragment, DeltaCtx) {
    let inner: std::collections::BTreeMap<u64, Ty> = (0..n).map(|i| (i, Ty::Register)).collect();
    let mut fields = inner.clone();
    fields.insert(n, Ty::Enum([(1, Some(Ty::Struct(inner.clone())))].into_iter().collect()));
    let ty = Ty::Struct(fields);
    let strs = || (0..n).map(|i| (Value::Int(i as i64), Value::Str(format!("{i:04}{}", "x".repeat(len))))).collect::<osis_base::ValueMap>();
    let mut v = strs();
    v.insert(Value::Int(n as i64), Value::Enum(1, Some(Box::new(Value::Map(strs())))));
    let node = sess(Tid::from_bytes([1; 15]));
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
            match osis_base::decode(p, &osis_base::Limits::DEFAULT).unwrap() {
                Value::Map(m) => {
                    maps += 1;
                    let last = m.iter().next_back().map(|(k, v)| osis_base::encode(k).len() + osis_base::encode(v).len()).unwrap();
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
    let top = osis_base::decode(&bytes, &osis_base::Limits::DEFAULT).unwrap();
    let with_children = |c: Value| {
        let Value::List(mut a) = top.clone() else { panic!() };
        let Some(Value::List(f)) = a.get_mut(3) else { panic!() };
        f[3] = c;
        osis_base::encode(&Value::List(a))
    };
    let mut pages = MemoryPages::with_params(SMALL);
    let field = |i: i64| (Value::Int(i), Value::List(vec![Value::Int(0), Value::List(vec![]), Value::Int(0), Value::Str("v".into())]));
    let page = |pages: &mut MemoryPages, v: Value| Value::link(pages.put(&osis_base::encode(&v)).unwrap());
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
    let node = sess(Tid::from_bytes([1; 15]));
    let mut w = crate::Writer::new(ts(3 << 16), node.clone(), 1);
    let reg = crate::create(&mut w, &crate::AnyView, &Value::Int(5)).unwrap();
    let mut w2 = crate::Writer::new(ts(2 << 16), sess(Tid::from_bytes([2; 15])), 1);
    let counter = crate::Fragment::empty(crate::Encoding::Counter).unwrap();
    let _ = &mut w2;
    let all = |_: &Dot| true;
    let mut valued = join(&reg, &counter);
    valued.join(crate::ops::create(&mut w2, &TyView(Ty::Counter), &Value::Int(1)).unwrap());
    let mut a = valued.clone();
    a.strip(&all);
    let mut less = reg.clone();
    less.strip(&all);
    let mut b = join(&less, &crate::ops::create(&mut crate::Writer::new(ts(2 << 16), sess(Tid::from_bytes([2; 15])), 1), &TyView(Ty::Counter), &Value::Int(1)).unwrap());
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
    let mut w = crdt_model::ops::Writer::new(crdt_model::stamp::Source::session(1, 0), 5 << 16, 1);
    let big = |i: usize| MV::Str(format!("{i:03}{}", "x".repeat(128 * 1024 - 16)));
    let delta = crdt_model::ops::create(&mut w, &ty, &MV::List((0..65).map(big).collect()));
    let mbytes = crdt_model::wire::encode_delta(&delta, [7; 16], &mut crdt_model::wire::Ctx::new(w.ts, w.source.clone(), w.lo));
    let cx = crate::tests_wire::writer_cx(&w);
    let d = Delta { nonce: [7; 16], fragment: crate::testutil::frag(&delta) };
    let mut flat = MemoryPages::with_params(PageParams { target: usize::MAX, ..PageParams::FORMAT });
    let bytes = encode_delta(&d, &cx, Some(&mut flat)).unwrap();
    assert_eq!(bytes, mbytes, "the model's bytes");
    let top = osis_base::decode(&bytes, &osis_base::Limits { max_bytes: usize::MAX, ..osis_base::Limits::DEFAULT }).unwrap();
    let Value::List(a) = top else { panic!() };
    let Some(Value::List(f)) = a.get(3) else { panic!() };
    let Some(Value::List(runs)) = f.get(3) else { panic!() };
    // two elements stay just below 256 KiB, three reach it: 21 runs of 3, one of 2
    assert_eq!(runs.len(), 22);
    let mut rec = Recording { inner: MemoryPages::new(), pages: Vec::new() };
    let paged = encode_delta(&d, &cx, Some(&mut rec)).unwrap();
    assert!(rec.pages.iter().all(|p| p.len() < osis_base::format::CHUNK_MAX + 3 * 128 * 1024), "pages {:?}", rec.pages.iter().map(Vec::len).collect::<Vec<_>>());
    assert_eq!(decode_delta(&paged, &cx, &mut Interner::new(), Some(&mut rec.inner)).unwrap().fragment, d.fragment);
}

/// §3.3 rule 7: a list run whose content goes on past `CHUNK_MAX` bytes is rejected.
#[test]
fn rejects_list_run_past_chunk_max_spec_3_3() {
    use crdt_model::value::Value as MV;
    let ty = crdt_model::ops::Ty::List(Box::new(crdt_model::ops::Ty::Register));
    let mut w = crdt_model::ops::Writer::new(crdt_model::stamp::Source::session(1, 0), 5 << 16, 1);
    let delta = crdt_model::ops::create(&mut w, &ty, &MV::List((0..6).map(|i| MV::Str(format!("{i}{}", "x".repeat(128 * 1024)))).collect()));
    let cx = crate::tests_wire::writer_cx(&w);
    let d = Delta { nonce: [7; 16], fragment: crate::testutil::frag(&delta) };
    let mut flat = MemoryPages::with_params(PageParams { target: usize::MAX, ..PageParams::FORMAT });
    let bytes = encode_delta(&d, &cx, Some(&mut flat)).unwrap();
    assert!(decode_delta(&bytes, &cx, &mut Interner::new(), Some(&mut flat)).is_ok());
    // join the runs of 2 into one run of 6
    let Value::List(mut a) = osis_base::decode(&bytes, &osis_base::Limits::DEFAULT).unwrap() else { panic!() };
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
    let bad = osis_base::encode(&Value::List(a));
    let e = decode_delta(&bad, &cx, &mut Interner::new(), Some(&mut flat)).unwrap_err();
    assert!(e.to_string().contains("not canonical"), "{e}");
}

/// spec/permissions.md §5.2 (a received delta's writes count from it alone), spec/crdt.md §5.6:
/// a snapshot carrying an entry another node created, holding only a held delta's write inside
/// it, stripped of that delta's copies keeps the creation, so its join gives the entry its
/// creation stamp whether the delta joined before or after (it once pruned the entry with the
/// creation: one held set, two states). Alone it joins nothing.
#[test]
fn stripped_entry_keeps_others_creation_spec_perm_5_2() {
    use crate::ops::{Writer, create};
    use crate::view::AnyView;
    use crate::PathSeg;
    use osis_base::{Tid, Value};
    let (a, b) = (sess(Tid::from_bytes([1; 15])), sess(Tid::from_bytes([2; 15])));
    let k = Value::Str("k".into());
    let w1 = create(&mut Writer::new(ts(1), a, 1), &AnyView, &Value::Map(osis_base::ValueMap::from([(k.clone(), Value::Int(1))]))).unwrap();
    let mut batch = Batch::new(&w1, Writer::new(ts(2), b.clone(), 1));
    batch.apply(&PathOp { path: vec![PathSeg::Key(k)], op: Op::Set(Value::Int(2)) }, &AnyView).unwrap();
    let (w2, _) = batch.finish().unwrap();
    let mut snap = w1.clone();
    snap.join(w2.clone());
    let mut stripped = snap.clone();
    stripped.remove_writes(&|d| d.src == b);
    let mut first = w2.clone();
    first.join(stripped.clone());
    let mut then = snap.clone();
    then.join(w2.clone());
    assert_eq!(first, then, "the delta first, the stripped snapshot after; the snapshot first");
    // an un-merge of another author's dots (a rebuild) keeps the creation for the join too
    let mut unmerged = stripped.clone();
    unmerged.remove_dots(&|d| d.src == sess(Tid::from_bytes([3; 15])));
    let mut later = w2.clone();
    later.join(unmerged);
    assert_eq!(later, then, "removing others' dots kept the creation");
    let mut alone = Fragment::default();
    alone.join(stripped);
    assert!(alone.read().is_none_or(|v| v == Value::Map(osis_base::ValueMap::new())), "a creation alone joins nothing: {alone:?}");
}

/// §4.1 copy order, §4.7, §5.6: two copies of one delta (a forged snapshot's beside the
/// writer's) put one map entry under two keys, its text element anchored apart. The key is a part
/// of its own: the element joins as the greater anchor and char under the greater key, so
/// expiring the delta after the join equals expiring each copy before it (the key decided the
/// anchor, and the copies held key-erased joined to the other one).
#[test]
fn copies_under_two_keys_expire_alike_spec_4_7() {
    use crate::fragment::{Eid, Entry, Map, Meta};
    use crate::seq::{Anchor, Seq, SeqContent, SeqElem};
    use crate::stamp::Stamp;
    use std::collections::BTreeMap;
    let s = sess(Tid::from_bytes([1; 15]));
    let st = |c: u64| Stamp::new(ts(1 << 16), s.clone(), c);
    let (d, e, f) = (Dot::new(s.clone(), 1), Dot::new(s.clone(), 2), Dot::new(s.clone(), 3));
    let copy = |key: &str, anchor: Anchor, c: char| {
        let mut el = SeqElem::bare();
        el.created = Some((st(2), anchor.clone()));
        el.content = SeqContent::Char(c);
        el.pos = vec![(st(2), anchor, None)];
        let text = Fragment::Seq(Seq::new(true, Meta::default(), BTreeMap::from([(e.clone(), el)])));
        let entry = Entry { reset: None, frag: Some(Box::new(text)), created: Some(st(1)) };
        let mut m = Fragment::Map(Map::new(Meta::default(), BTreeMap::from([(Eid::new(d.clone(), Some(Value::Str(key.into()))), entry)])));
        m.prune(None, &mut crate::Changes::new());
        m
    };
    let (a, b) = (copy("b", Anchor::Head, 'x'), copy("a", Anchor::Dot(f), 'y'));
    let both = join(&a, &b);
    assert_eq!(both, join(&b, &a));
    assert_eq!(both.read(), Some(Value::Map(osis_base::ValueMap::from([(Value::Str("b".into()), Value::Str("y".into()))]))), "the greater key, anchor and char");
    let exp = |x: &Dot| x.src == s;
    let strip = |x: &Fragment| {
        let mut y = x.clone();
        y.strip(&exp);
        y
    };
    let late = strip(&both);
    assert_eq!(strip(&join(&strip(&a), &strip(&b))), late, "expired before the join");
    assert_eq!(strip(&join(&a, &strip(&b))), late, "one copy expired before the join");
    assert_eq!(strip(&join(&strip(&a), &b)), late, "the other");
}

/// spec/commits.md §5 (a body's live writes): a removed map entry's tombstone, keyed by its dot,
/// holds the remover's reset, not the creator's write.
#[test]
fn entry_tombstone_is_no_live_write_spec_commits_5() {
    use crate::ops::{Writer, create};
    use crate::view::AnyView;
    use osis_base::{Tid, Value};
    let (a, b) = (sess(Tid::from_bytes([1; 15])), sess(Tid::from_bytes([2; 15])));
    let k = Value::Str("k".into());
    let mut st = create(&mut Writer::new(ts(1), a.clone(), 1), &AnyView, &Value::Map(osis_base::ValueMap::from([(k.clone(), Value::Int(1))]))).unwrap();
    let owned = |s: &Source, lo: u64, _: u64| *s == a && lo <= 1;
    assert!(st.holds_owned_write(&owned));
    let mut batch = Batch::new(&st, Writer::new(ts(2), b, 1));
    batch.apply(&PathOp { path: vec![], op: Op::Remove(k) }, &AnyView).unwrap();
    let (rm, _) = batch.finish().unwrap();
    st.join(rm);
    assert!(st.holds_owned(&owned), "the tombstone is keyed by the entry's dot");
    assert!(!st.holds_owned_write(&owned), "but holds no write of its creator");
    let ours = |w: Vec<(crate::Dot, Option<osis_base::Ts>)>| w.iter().any(|(d, _)| owned(&d.src, d.ctr, d.ctr + 1));
    assert!(ours(st.writes()) && !ours(st.live_writes()), "live_writes agrees");
}

/// §4.3, §4.7: a list element keeps its creation write, value-less, when its commit expires: it
/// anchors, counts toward no presence, and a list whose elements all expired reads absent.
#[test]
fn expired_list_reads_absent_spec_crdt_4_3() {
    use crate::ops::{Writer, create};
    use crate::view::AnyView;
    let x = sess(Tid::from_bytes([1; 15]));
    let mut f = create(&mut Writer::new(ts(5), x.clone(), 1), &AnyView, &Value::List(vec![Value::Int(1), Value::Int(2)])).unwrap();
    f.strip(&|d| d.src == x);
    assert!(!f.present());
    assert_eq!(f.read(), None);
}

/// spec/sync.md §7: a sweep resets what a removal hid, once, so the join leaves no repeated key;
/// never a record merely lacking its creation or a value (one expired here), a live one or an
/// empty tombstone.
#[test]
fn sweep_takes_only_what_is_hidden_spec_sync_7() {
    use crate::ops::{Writer, create};
    use crate::view::AnyView;
    let (x, y) = (sess(Tid::from_bytes([1; 15])), sess(Tid::from_bytes([2; 15])));
    let map = |v: &str| Value::Map([(Value::Str("k".into()), Value::Str(v.into()))].into_iter().collect());
    let put = create(&mut Writer::new(ts(5), x.clone(), 1), &AnyView, &map("a")).unwrap();
    let edit = crate::diff(&mut Writer::new(ts(9), y.clone(), 1), Some(&put), &AnyView, &map("b")).unwrap().unwrap();
    let w = Writer::new(ts(20), y.clone(), 5);
    let r = w.delta_stamp();
    assert_eq!(put.sweep(&r), None, "a live entry");
    assert_eq!(edit.sweep(&r), None, "the creation not held: it may still arrive");
    let dot = Dot::new(x.clone(), 1);
    let removal = crate::reset_entries(&Writer::new(ts(7), x.clone(), 3), &[(dot.clone(), Value::Str("k".into()))]);
    let mut gone = put.clone();
    gone.join(removal.clone());
    assert_eq!(gone.sweep(&r), None, "a tombstone holds nothing");
    let mut hid = gone.clone();
    hid.join(edit.clone());
    assert_eq!(hid.read(), Some(Value::Map(Default::default())));
    let sweep = hid.sweep(&r).expect("a removal hid the edit");
    let mut after = hid.clone();
    after.join(sweep.clone());
    assert_eq!(after.sweep(&r), None, "once");
    assert!(!after.holds_write(&Dot::new(y.clone(), 1)), "the edit is dead");
    let Fragment::Map(m) = &after else { panic!("a map") };
    assert!(m.entries.keys().all(|id| id.key.is_none()), "the key is gone");
    let mine = |d: &crate::Dot| d.src == x;
    let mut expired = put.clone();
    expired.join(edit.clone());
    expired.strip(&mine);
    assert_eq!(expired.read(), Some(map("b")), "another's value keeps the entry");
    assert_eq!(expired.sweep(&r), None, "a live entry");
    let mut own = put.clone();
    own.strip(&mine);
    assert_eq!(own.sweep(&r), None, "expired, nothing else in it");
    // another's removal alone in an expired entry hides it
    let nested = |m: Value| Value::Map([(Value::Str("k".into()), m)].into_iter().collect());
    let put = create(&mut Writer::new(ts(5), x.clone(), 1), &AnyView, &nested(map("a"))).unwrap();
    let removal = crate::diff(&mut Writer::new(ts(9), y.clone(), 1), Some(&put), &AnyView, &nested(Value::Map(Default::default()))).unwrap().unwrap();
    let mut hid = put.clone();
    hid.join(removal.clone());
    hid.strip(&mine);
    assert_eq!(hid.read(), Some(Value::Map(Default::default())));
    assert_eq!(hid.sweep(&r), None, "not removed: a valued write may still arrive");
    // a list element, nested in a live one
    let ty = crate::testutil::TyView(Ty::List(Box::new(Ty::Map(Box::new(Ty::Register), Box::new(Ty::Register)))));
    let list = create(&mut Writer::new(ts(5), x.clone(), 1), &ty, &Value::List(vec![map("a")])).unwrap();
    let new = crate::diff(&mut Writer::new(ts(9), y.clone(), 1), Some(&list), &ty, &Value::List(vec![Value::Map(Default::default())])).unwrap().unwrap();
    assert_eq!(list.sweep(&r), None, "a live element");
    let mut over = list.clone();
    over.join(new);
    assert_eq!(over.sweep(&r), None, "a live element, emptied");
    over.strip(&mine);
    assert_eq!(over.read(), Some(Value::List(Vec::new())));
    assert_eq!(over.sweep(&r), None, "not removed");
    // a removed element with a newer write inside
    let rm = crate::diff(&mut Writer::new(ts(7), x.clone(), 3), Some(&list), &ty, &Value::List(vec![])).unwrap().unwrap();
    let edit = crate::diff(&mut Writer::new(ts(9), y.clone(), 1), Some(&list), &ty, &Value::List(vec![map("b")])).unwrap().unwrap();
    let mut gone = list.clone();
    gone.join(rm);
    gone.join(edit);
    assert_eq!(gone.read(), Some(Value::List(Vec::new())));
    let sweep = gone.sweep(&r).expect("its edit hidden");
    gone.join(sweep);
    assert_eq!(gone.sweep(&r), None);
    assert!(!gone.holds_write(&Dot::new(y, 1)));
}

/// `v` with empty collections left out: a sweep's reset is a write, so a collection another writer
/// reset meanwhile may read empty rather than absent, as under any concurrent removal (§4.3).
fn shown(v: Value) -> Option<Value> {
    match v {
        Value::Map(m) => {
            let m: osis_base::ValueMap = m.into_iter().filter_map(|(k, v)| Some((k, shown(v)?))).collect();
            (!m.is_empty()).then_some(Value::Map(m))
        }
        Value::List(l) => {
            let l: Vec<_> = l.into_iter().filter_map(shown).collect();
            (!l.is_empty()).then_some(Value::List(l))
        }
        v => Some(v),
    }
}

/// spec/sync.md §7: a sweep from any stale view (a random part of the commits, a random part of the
/// expiries) changes no read, there or at a node holding everything; it is a valid writer delta;
/// joined back it finds nothing more, so a compaction does not write forever.
pub(crate) fn sweep_laws(seed: u64, ty: &Ty) -> usize {
    use crate::ops::Writer;
    let mut r = crate::testutil::rng(seed | 1);
    let commits = crate::testutil::history_honest(&mut r, std::slice::from_ref(ty), 3, 5);
    let bodies: Vec<Fragment> = commits.iter().map(|c| frag(&c.delta)).collect();
    let ranges: Vec<Range> = commits.iter().map(|c| (source(&c.w.source), c.w.lo, c.w.hi())).collect();
    let me = sess(Tid::from_bytes([250; 15]));
    let w = Writer::new(ts(1 << 40), me.clone(), 1);
    let stamp = w.delta_stamp();
    let mut swept = 0;
    for _ in 0..6 {
        let expired: Vec<Range> = ranges.iter().filter(|_| r.chance(1, 4)).cloned().collect();
        let gone: Vec<Range> = expired.iter().filter(|_| r.chance(3, 4)).cloned().collect();
        let mut view = Fragment::default();
        for b in bodies.iter().filter(|_| r.chance(2, 3)) {
            view.join(b.clone());
        }
        view.strip(&in_ranges(&gone));
        let Some(sw) = view.sweep(&stamp) else { continue };
        swept += 1;
        let cx = DeltaCtx { ts: ts(1 << 40), own: me.clone(), range: w.range(), kind: DeltaKind::Writer };
        let bytes = encode_delta(&Delta { nonce: [0; 16], fragment: sw.clone() }, &cx, None).unwrap();
        assert_eq!(decode_delta(&bytes, &cx, &mut Interner::new(), None).unwrap().fragment, sw, "the wire");
        let mut after = view.clone();
        after.join(sw.clone());
        after.strip(&in_ranges(&gone));
        assert_eq!(after.read(), view.read(), "the view's read");
        assert_eq!(after.sweep(&stamp), None, "swept once");
        let mut all = Fragment::default();
        for b in &bodies {
            all.join(b.clone());
        }
        all.strip(&in_ranges(&expired));
        let want = all.read();
        all.join(sw);
        all.strip(&in_ranges(&expired));
        assert_eq!(all.read().and_then(shown), want.and_then(shown), "the read of a node holding everything");
    }
    swept
}

#[test]
fn sweep_laws_spec_sync_7() {
    let reg = || Box::new(Ty::Register);
    let pair = || Ty::Struct([(1, Ty::Register), (2, Ty::Text)].into_iter().collect());
    let types = [
        sink_no_seq(),
        Ty::List(Box::new(pair())),
        Ty::List(reg()),
        Ty::Map(reg(), Box::new(pair())),
        Ty::Map(reg(), Box::new(Ty::List(reg()))),
        Ty::List(Box::new(Ty::Map(reg(), reg()))),
        Ty::Struct([(1, Ty::Map(reg(), reg())), (2, Ty::List(Box::new(pair())))].into_iter().collect()),
        Ty::Enum([(0, None), (1, Some(Ty::Map(reg(), reg()))), (2, Some(Ty::List(reg())))].into_iter().collect()),
    ];
    // seeds until each type has swept a few times: some find a hidden write rarely (a removal
    // racing a write inside a sink of many fields), so a fixed range may find none
    for (i, ty) in types.iter().enumerate() {
        let (mut swept, mut s) = (0, 0);
        while swept < 3 && s < 2000 {
            swept += sweep_laws(s * 2 + 1, ty);
            s += 1;
        }
        assert!(swept >= 3, "type {i} swept {swept} times in {s} seeds");
    }
}
