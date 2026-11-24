//! Expiry, un-merge, snapshots, sweeps and paging (spec/crdt.md §4.6, §4.7, §8,
//! spec/sync-compaction.md §1).

use crate::codec::{decode_delta, decode_snapshot, encode_delta, encode_snapshot};
use crate::fragment::Fragment;
use crate::ops::{Op, PathOp, Writer, create, diff, replace};
use crate::page::{MemoryPages, PageParams, PageSink};
use crate::seq::{Seq, SeqElem};
use crate::stamp::{Dot, Interner, Source};
use crate::testutil::{TyView, ctx_of, frag, history, joined, mapply, node, ostate, s, sink_no_seq, snap_cx, snapshot, source, struct_list, ts, wired, writer_cx};
use crate::view::AnyView;
use crate::wire::{Delta, DeltaCtx, Frontiers, Snapshot};
use crate::DeltaBuilder;
use crdt_model::r#gen::random_op;
use crdt_model::ops::Ty;
use crdt_model::stamp::Source as MSource;
use osis_base::{ChunkParams, Value};
use proptest::prelude::*;
use std::collections::BTreeSet;

type Range = (Source, u64, u64);

fn in_ranges(r: &[Range]) -> impl Fn(&Dot) -> bool + '_ {
    move |d: &Dot| r.iter().any(|(s, lo, hi)| d.src == *s && (*lo..*hi).contains(&d.ctr))
}

/// `f` without the writes `gone` names (§4.7).
fn stripped(f: &Fragment, gone: &dyn Fn(&Dot) -> bool) -> Fragment {
    let mut g = f.clone();
    g.remove_gone(gone);
    g
}

/// `held` of every body.
fn held_all(bodies: &[Fragment], gone: &dyn Fn(&Dot) -> bool) -> Fragment {
    held(&bodies.iter().collect::<Vec<_>>(), gone)
}

/// The join of `bodies`, each without the writes `gone` names: a node's state (§4.6, §4.7).
fn held(bodies: &[&Fragment], gone: &dyn Fn(&Dot) -> bool) -> Fragment {
    bodies.iter().fold(Fragment::default(), |f, b| joined(&f, &stripped(b, gone)))
}

/// The types the lifecycle laws run over: every encoding but sequences, nested; a text; a list.
fn law_types() -> [Ty; 3] {
    [sink_no_seq(), Ty::Text, struct_list()]
}

proptest! {
    /// §4.7: removing gone writes equals the model's and is idempotent.
    #[test]
    fn expiry_laws_spec_4_7(seed in any::<u64>()) {
        law_types().iter().for_each(|ty| expiry_laws(seed, ty));
    }

    /// One random history per law type, three laws over it. §4.6: un-merge of held bodies equals
    /// the model's and is order-independent (texts and lists: created elements lose their
    /// creations). §4.8, §8: a state without a set of commits' writes (`remove_writes`) holds none
    /// of them, and joined with those commits reads as the state: others' writes nested in their
    /// records stay. §8: a node bootstrapped from a snapshot and then editing converges with the
    /// source node; frontiers cover every commit.
    #[test]
    fn unmerge_rejoin_and_bootstrap_spec_4_6(seed in any::<u64>()) {
        for ty in &law_types() {
            let mut r = crate::testutil::rng(seed | 1);
            let commits = history(&mut r, std::slice::from_ref(ty), 3, 4);
            unmerge_check(&commits);
            remove_writes_check(&mut r, &commits);
            bootstrap_check(&mut r, ty, &commits);
        }
    }
}

/// §4.7 laws of `remove_gone` over three random states of type `ty`, each by its own writer.
fn expiry_laws(seed: u64, ty: &Ty) {
    let mut r = crate::testutil::rng(seed | 1);
    let (mut s, mut m, mut ranges) = (Vec::new(), Vec::new(), Vec::new());
    for i in 0..3u8 {
        let mut w = crdt_model::ops::Writer::new(MSource::session(i + 1, 0), ((r.below(5) as u64 + 1) << 16) + i as u64, 1);
        let mut st = None;
        for k in 0..4 {
            w.next_commit(w.ts + ((r.below(3) as u64) << 16) + 1 + k);
            if let Some(d) = random_op(&mut r, &mut w, ty, st.as_ref()) {
                mapply(&mut st, d);
                ranges.push((w.source.clone(), w.lo, w.hi()));
            }
        }
        s.push(ostate(&st));
        m.push(st.unwrap_or_else(|| crdt_model::state::Frag::empty(0)));
    }
    let mut r = crate::testutil::rng(seed ^ 0x55);
    let mexpired: Vec<(MSource, u64, u64)> = ranges.into_iter().filter(|_| r.chance(1, 2)).collect();
    let expired: Vec<Range> = mexpired.iter().map(|(s, lo, hi)| (source(s), *lo, *hi)).collect();
    let strip = |f: &Fragment| stripped(f, &in_ranges(&expired));
    for (o, mo) in s.iter().zip(&m) {
        let mut ms = mo.clone();
        ms.remove_gone(&|d| mexpired.iter().any(|(src, lo, hi)| d.source == *src && (*lo..*hi).contains(&d.ctr)));
        assert_eq!(strip(o), frag(&ms), "removal equals the model");
        assert_eq!(strip(&strip(o)), strip(o), "idempotent");
    }
}

/// §4.6 un-merge over a random history.
fn unmerge_check(commits: &[crate::testutil::MCommit]) {
    let bad = source(&MSource::session(2, 0));
    let (mut model, mut whole, mut ours) = (None, None, Fragment::default());
    for c in commits {
        mapply(&mut whole, c.delta.clone());
        let mut m = c.delta.clone();
        m.unmerge(&|d| d.source == MSource::session(2, 0));
        mapply(&mut model, m);
        let mut b = frag(&c.delta);
        b.remove_writes(&|d| d.src == bad);
        ours.join(b);
    }
    assert_eq!(ours, ostate(&model), "un-merged bodies equal the model's");
    // an author's writes (§4.6) and one delta's (spec/permissions.md §5.2): the join of the held
    // bodies (and the whole state) each without them is order-independent
    let held: Vec<Fragment> = commits.iter().map(|c| frag(&c.delta)).chain(std::iter::once(ostate(&whole))).collect();
    type Pred = Box<dyn Fn(&Dot) -> bool>;
    let mut preds: Vec<Pred> = vec![Box::new(move |d: &Dot| d.src == bad)];
    for c in commits {
        let (src, lo, hi) = (source(&c.w.source), c.w.lo, c.w.hi());
        preds.push(Box::new(move |d: &Dot| d.src == src && lo <= d.ctr && d.ctr < hi));
    }
    for pred in &preds {
        let unmerged = |bodies: &mut dyn Iterator<Item = &Fragment>| {
            let mut out = Fragment::default();
            for b in bodies {
                let mut b = b.clone();
                b.remove_writes(pred);
                out.join(b);
            }
            out
        };
        assert_eq!(unmerged(&mut held.iter()), unmerged(&mut held.iter().rev()), "order-independent");
    }
}

/// `remove_writes` over a random history: for random sets of its commits.
fn remove_writes_check(r: &mut crate::testutil::SeedRng, commits: &[crate::testutil::MCommit]) {
    let mut state = Fragment::default();
    for c in commits {
        state.join(frag(&c.delta));
    }
    for _ in 0..4 {
        let picked: Vec<_> = commits.iter().filter(|_| r.chance(1, 2)).collect();
        let ranges: Vec<Range> = picked.iter().map(|c| (source(&c.w.source), c.w.lo, c.w.hi())).collect();
        let picked: Vec<Fragment> = picked.iter().map(|c| frag(&c.delta)).collect();
        let pred = in_ranges(&ranges);
        let mut rest = state.clone();
        rest.remove_writes(&pred);
        let left: Vec<_> = rest.writes().into_iter().filter(|(d, ts)| ts.is_some() && pred(d)).collect();
        assert!(left.is_empty(), "left {left:?}");
        // as a replay plays them: the commits (before the snapshot), then the rest; and after
        let mut back = Fragment::default();
        for d in &picked {
            back.join(d.clone());
        }
        back.join(rest.clone());
        assert_eq!(back.read(), state.read(), "rejoined");
        for d in picked {
            rest.join(d);
        }
        assert_eq!(rest.read(), state.read(), "rejoined after");
    }
}

/// §8 bootstrap from a snapshot of a random history of `ty`, then concurrent edits.
fn bootstrap_check(r: &mut crate::testutil::SeedRng, ty: &Ty, commits: &[crate::testutil::MCommit]) {
    let mut a = Fragment::default();
    let mut received = crdt_model::received::Received::default();
    for c in commits {
        a.join(frag(&c.delta));
        received.add(&c.w.source, c.w.lo, c.w.hi());
    }
    // frontiers of the sources left in the state only (§8)
    let mut fr = Frontiers::default();
    for (s, c) in received.frontiers() {
        fr.insert(&source(&s), c);
    }
    fr.retain(&crate::codec::whole_sources(&a, &snap_cx()).unwrap());
    let bytes = encode_snapshot(&Snapshot { frontiers: fr.clone(), ..snapshot(&a) }, &snap_cx(), None).unwrap();
    let got = decode_snapshot(&bytes, &snap_cx(), &mut Interner::new(), None).unwrap();
    let mut b = joined(&Fragment::default(), &got.fragment);
    assert_eq!(got.frontiers.without_zeros(), fr);
    assert_eq!(b.read(), a.read());
    // b edits; a edits concurrently; both exchange
    let v = crate::testutil::value(&crdt_model::r#gen::random_value(r, ty, 0));
    let mut bb = DeltaBuilder::new(&b, Writer::new(ts(1 << 30), node(9), 1));
    bb.apply(&PathOp { path: vec![], op: Op::Set(v) }, &TyView(ty.clone())).unwrap();
    let mut mw = crdt_model::ops::Writer::new(MSource::session(1, 0), (1 << 30) + 1, 100);
    mw.next_commit((1 << 30) + 2);
    let da = random_op(r, &mut mw, ty, None).map(|d| frag(&d));
    for d in bb.finish().map(|x| x.0).into_iter().chain(da) {
        a.join(d.clone());
        b.join(d);
    }
    // equal up to the chars of deleted text, which a snapshot does not carry (§3.3 rule 5)
    assert_eq!(a.read(), b.read());
    assert_eq!(crate::testutil::snapshot_bytes(&a), crate::testutil::snapshot_bytes(&b));
}

// ---- paging (§8, spec/wire.md §6)

const SMALL: PageParams = PageParams { target: 2000, cut: ChunkParams { min: 128, max: 1024, mask_bits: 6 }, fanout: 8, ..PageParams::FORMAT };

/// A set of `n` strings, each added by its own commit, joined in an order drawn from `order_seed`.
pub(crate) fn big_set(n: usize, order_seed: u64) -> Fragment {
    let mut idx: Vec<usize> = (0..n).collect();
    let mut r = crate::testutil::rng(order_seed | 1);
    for k in (1..idx.len()).rev() {
        idx.swap(k, r.below(k + 1));
    }
    let mut st = Fragment::default();
    for i in idx {
        let mut w = Writer::new(ts(((i as u64 % 7) + 1) << 16), node((i % 3) as u8 + 1), 1 + i as u64);
        st.join(create(&mut w, &AnyView, &Value::Set([Value::Str(format!("element number {i}"))].into_iter().collect())).unwrap());
    }
    st
}

/// A content-addressed page store (equal plaintexts, equal links), counting fetches.
#[derive(Default)]
struct Cas {
    params: Option<PageParams>,
    pages: std::collections::HashMap<[u8; 32], Vec<u8>>,
    fetched: usize,
}

impl PageSink for Cas {
    fn put(&mut self, p: &[u8]) -> Result<osis_base::Link, crate::PageError> {
        let hash = osis_base::hash::hash(p);
        self.pages.insert(hash, p.to_vec());
        Ok(osis_base::Link { hash, blob: osis_base::BlobId(hash), suite: 1, key: [0; 32], salt: [0; 16], del: osis_base::Del::NONE })
    }
    fn params(&self) -> PageParams {
        self.params.unwrap_or(PageParams::FORMAT)
    }
}

impl crate::page::PageSource for Cas {
    fn get(&mut self, l: &osis_base::Link) -> Result<Vec<u8>, crate::PageError> {
        self.fetched += 1;
        self.pages.get(&l.hash).cloned().ok_or(crate::PageError::Missing)
    }
    fn params(&self) -> PageParams {
        self.params.unwrap_or(PageParams::FORMAT)
    }
}

fn paged(f: &Fragment, params: PageParams) -> (Vec<u8>, MemoryPages) {
    let mut rec = MemoryPages::with_params(params);
    let bytes = encode_snapshot(&snapshot(f), &snap_cx(), Some(&mut rec)).unwrap();
    (bytes, rec)
}

/// The page levels of `bytes`'s one paged position (a set's elements), leaves included: the
/// links followed down from the first.
fn depth(bytes: &[u8], pages: &mut dyn crate::page::PageSource) -> usize {
    let mut at = first_link(&osis_base::decode(bytes, &osis_base::Limits::DEFAULT).unwrap());
    let mut n = 0;
    while let Some(l) = at {
        n += 1;
        at = match osis_base::decode(&pages.get(&l).unwrap(), &osis_base::Limits::DEFAULT).unwrap() {
            Value::List(items) => items.first().and_then(|x| if let Value::Link(l) = x { Some(**l) } else { None }),
            _ => None,
        };
    }
    n
}

/// `bytes` decoded as a snapshot whose pages are read from `pages`.
fn unpage(bytes: &[u8], pages: &mut dyn crate::page::PageSource) -> Result<Fragment, crate::Error> {
    decode_snapshot(bytes, &snap_cx(), &mut Interner::new(), Some(pages)).map(|s| s.fragment)
}

/// §8: a fragment pages iff its plain array is above the target, into pages of whole elements
/// ending once they reach the cut maximum, under link pages of at most `fanout` links: one level
/// (100 elements) or two (600), and as many as the array needs (tiny pages). It round-trips, and
/// equal states give equal pages. The paging is canonical: pages cut by other
/// parameters, missing pages and an unpaged fragment where paging is mandatory are rejected.
#[test]
fn paging_spec_8() {
    let links = |p: &[u8]| matches!(osis_base::decode(p, &osis_base::Limits::DEFAULT), Ok(Value::List(i)) if i.iter().all(|x| matches!(x, Value::Link(_))));
    for n in [3usize, 100, 600] {
        let st = big_set(n, 1);
        let (bytes, mut rec) = paged(&st, SMALL);
        assert_eq!(rec.pages.is_empty(), n == 3, "n = {n}");
        assert_eq!(rec.pages.values().any(|p| links(p)), n == 600, "link pages above the link target: n = {n}");
        for p in rec.pages.values() {
            let Ok(Value::List(items)) = osis_base::decode(p, &osis_base::Limits::DEFAULT) else { panic!("a page") };
            if links(p) {
                assert!(items.len() <= SMALL.fanout);
            } else {
                // whole elements; a page ends once it reaches the maximum
                let last = osis_base::encode(items.last().unwrap()).len();
                assert!(p.len() < SMALL.cut.max + last + 8, "page of {} bytes", p.len());
            }
        }
        assert_eq!(unpage(&bytes, &mut rec).unwrap(), st);
        if n < 600 {
            continue;
        }
        let other = big_set(n, 2);
        assert_eq!(other, st);
        assert_eq!(paged(&other, SMALL).1.written, rec.written, "equal states, equal pages");
        let tiny = PageParams { target: 200, cut: ChunkParams { min: 64, max: 256, mask_bits: 4 }, fanout: 2, ..PageParams::FORMAT };
        let (deep, mut deep_rec) = paged(&st, tiny);
        assert!(depth(&deep, &mut deep_rec) > 3, "levels as needed");
        assert_eq!(unpage(&deep, &mut deep_rec).unwrap(), st);
        // a source with other parameters would have cut elsewhere: the paging is not canonical
        let mut cut = MemoryPages::with_params(PageParams { cut: ChunkParams { min: 200, max: 1024, mask_bits: 6 }, ..SMALL });
        for p in rec.pages.values() {
            cut.put(p).unwrap();
        }
        assert!(unpage(&bytes, &mut cut).is_err());
        assert!(decode_snapshot(&bytes, &snap_cx(), &mut Interner::new(), None).is_err(), "the pages are needed");
        let plain = paged(&st, PageParams { target: usize::MAX, ..SMALL }).0;
        assert!(unpage(&plain, &mut rec).is_err(), "unpaged where paging is mandatory");
    }
}

/// §8 scaling, counted (notes/principles.md, Check scaling): a set at n and 10n elements under
/// small pages has 2 and 3 page levels. Encoding puts and decoding fetches every page
/// once (linear in the pages); a read of one element fetches one page per level; an edit of one
/// element changes a few leaf pages whatever n (content-defined cuts resync). Link pages change
/// above them, and after them too where the leaf count moves and groups close by count: at
/// these fan-outs every group does, at the format's (512 against a 1/256 hash cut) about one in
/// seven. (The encoder's memory per level: codec `tests_levels`.)
#[test]
fn page_levels_scale_spec_8() {
    use crate::stream::{Checked, stream_checked, stream_checked_some};
    let params = PageParams { target: 1500, cut: ChunkParams { min: 16, max: 512, mask_bits: 6 }, fanout: 8, ..PageParams::FORMAT };
    let mut seen = Vec::new();
    for (n, levels) in [(100usize, 2usize), (1000, 3)] {
        let st = big_set(n, 1);
        let mut cas = Cas { params: Some(params), ..Cas::default() };
        let bytes = encode_snapshot(&snapshot(&st), &snap_cx(), Some(&mut cas)).unwrap();
        let pages = cas.pages.len();
        let d = depth(&bytes, &mut cas);
        assert_eq!(d, levels, "n = {n}: levels");
        // decode: every page once
        cas.fetched = 0;
        assert_eq!(unpage(&bytes, &mut cas).unwrap(), st);
        assert_eq!(cas.fetched, pages, "n = {n}: decode fetches each page once");
        // a read of one element: one page per level
        let mut index = crate::PageIndex::default();
        stream_checked(Checked::verified(&bytes), &snap_cx(), &mut Interner::new(), Some(&mut cas), &mut |p| {
            index.add(&p);
            Ok(())
        })
        .unwrap();
        let Fragment::Set(set) = &st else { panic!("a set") };
        let (dot, el) = set.elems.iter().nth(n / 2).unwrap();
        let mut one = set.clone();
        one.elems = [(dot.clone(), el.clone())].into();
        let wanted = index.wanted(&Fragment::Set(one));
        cas.fetched = 0;
        let mut got = None;
        stream_checked_some(Checked::verified(&bytes), &snap_cx(), &mut Interner::new(), Some(&mut cas), &|p, at| wanted.wants(p, at), &mut |p| {
            if let crate::Piece::Page { fragment: Fragment::Set(s), .. } = p
                && got.is_none()
            {
                got = s.elems.get(dot).cloned();
            }
            Ok(())
        })
        .unwrap();
        assert_eq!(cas.fetched, levels, "n = {n}: one page per level");
        assert_eq!(got.as_ref(), Some(el), "n = {n}: the element read");
        // one element's value changed: the pages on its path change, and a neighbour where a
        // cut moves
        let mut edited = Fragment::default();
        for i in 0..n {
            let mut w = Writer::new(ts(((i as u64 % 7) + 1) << 16), node((i % 3) as u8 + 1), 1 + i as u64);
            let v = if i == n / 2 { format!("element changed {i}") } else { format!("element number {i}") };
            edited.join(create(&mut w, &AnyView, &Value::Set([Value::Str(v)].into_iter().collect())).unwrap());
        }
        let mut again = Cas { params: Some(params), ..Cas::default() };
        encode_snapshot(&snapshot(&edited), &snap_cx(), Some(&mut again)).unwrap();
        let is_links = |p: &[u8]| matches!(osis_base::decode(p, &osis_base::Limits::DEFAULT), Ok(Value::List(i)) if i.iter().all(|x| matches!(x, Value::Link(_))));
        let new: Vec<&Vec<u8>> = again.pages.iter().filter(|(h, _)| !cas.pages.contains_key(*h)).map(|x| x.1).collect();
        let leaves = new.iter().filter(|p| !is_links(p)).count();
        let changed = (leaves, new.len() - leaves);
        assert!((1..=8).contains(&leaves), "n = {n}: {leaves} leaf pages changed");
        seen.push((n, levels, pages, changed));
    }
    println!("(n, levels, pages, (leaf, link) pages changed by one edit): {seen:?}");
    let pages: Vec<usize> = seen.iter().map(|x| x.2).collect();
    assert!(pages.windows(2).all(|w| (8 * w[0]..=12 * w[0]).contains(&w[1])), "pages linear in n: {pages:?}");
}

/// §8 partial reads at any depth (`PageAt` paths, `Wanted::wants` by prefix): for sets paged at
/// three and four levels, a read of any set of elements fetches exactly the pages on the paths
/// down to the leaves holding them, each once (paths sharing a prefix share its pages), no leaf
/// holding none of them, and every element asked for is read.
#[test]
fn partial_reads_fetch_the_paths_to_their_leaves_spec_8() {
    use crate::stream::{Checked, stream_checked, stream_checked_some};
    let three = PageParams { target: 1500, cut: ChunkParams { min: 16, max: 512, mask_bits: 6 }, fanout: 8, ..PageParams::FORMAT };
    let four = PageParams { target: 400, cut: ChunkParams { min: 16, max: 256, mask_bits: 5 }, fanout: 3, ..PageParams::FORMAT };
    for (params, n, levels) in [(three, 1000, 3), (four, 600, 4)] {
        let st = big_set(n, 1);
        let mut cas = Cas { params: Some(params), ..Cas::default() };
        let bytes = encode_snapshot(&snapshot(&st), &snap_cx(), Some(&mut cas)).unwrap();
        assert!(depth(&bytes, &mut cas) >= levels, "n = {n}: {levels} levels");
        let mut index = crate::PageIndex::default();
        stream_checked(Checked::verified(&bytes), &snap_cx(), &mut Interner::new(), Some(&mut cas), &mut |p| {
            index.add(&p);
            Ok(())
        })
        .unwrap();
        let Fragment::Set(set) = &st else { panic!("a set") };
        let dots: Vec<_> = set.elems.keys().cloned().collect();
        let mut r = crate::testutil::rng(7);
        for k in [1, 1, 2, 2, 3, 5, 8, 20] {
            let mut want = set.clone();
            want.elems = (0..k).map(|_| dots[r.below(dots.len())].clone()).map(|d| (d.clone(), set.elems[&d].clone())).collect();
            let wanted = index.wanted(&Fragment::Set(want.clone()));
            cas.fetched = 0;
            let (mut got, mut ats) = (BTreeSet::new(), Vec::new());
            stream_checked_some(Checked::verified(&bytes), &snap_cx(), &mut Interner::new(), Some(&mut cas), &|p, at| wanted.wants(p, at), &mut |p| {
                if let crate::Piece::Page { fragment: Fragment::Set(s), at, .. } = p {
                    assert!(s.elems.keys().any(|d| want.elems.contains_key(d)), "n = {n}, k = {k}: a leaf holding none asked for");
                    got.extend(s.elems.keys().cloned());
                    ats.push(at);
                }
                Ok(())
            })
            .unwrap();
            assert!(want.elems.keys().all(|d| got.contains(d)), "n = {n}, k = {k}: every element asked for read");
            let paths: BTreeSet<&[usize]> = ats.iter().flat_map(|at| (1..=at.len()).map(move |j| &at[..j])).collect();
            assert_eq!(cas.fetched, paths.len(), "n = {n}, k = {k}: the pages on the paths to {} leaves", ats.len());
        }
    }
}

/// A link page of `ls` put into `cas`.
fn link_page(cas: &mut Cas, ls: &[osis_base::Link]) -> osis_base::Link {
    cas.put(&osis_base::encode(&Value::List(ls.iter().copied().map(Value::link).collect()))).unwrap()
}

/// The links a page of `cas` holds when it is a link page.
fn page_links(cas: &Cas, l: &osis_base::Link) -> Option<Vec<osis_base::Link>> {
    let Ok(Value::List(items)) = osis_base::decode(cas.pages.get(&l.hash)?, &osis_base::Limits::DEFAULT) else { return None };
    items.iter().map(|x| if let Value::Link(l) = x { Some(**l) } else { None }).collect()
}

/// The leaf links under `top`, in order.
fn leaves_under(cas: &Cas, top: &[osis_base::Link]) -> Vec<osis_base::Link> {
    top.iter().flat_map(|l| page_links(cas, l).map_or_else(|| vec![*l], |ls| leaves_under(cas, &ls))).collect()
}

/// The pages a tree under `top` holds, leaves included.
fn pages_under(cas: &Cas, top: &[osis_base::Link]) -> usize {
    top.iter().map(|l| 1 + page_links(cas, l).map_or(0, |ls| pages_under(cas, &ls))).sum()
}

/// Links grouped level by level into link pages while the level's list is above the target,
/// a group closing after a link where `close(level, links in the group so far, link)` says or
/// at the level's end: the root list.
fn grouped(cas: &mut Cas, mut links: Vec<osis_base::Link>, params: PageParams, close: &dyn Fn(usize, usize, &osis_base::Link) -> bool) -> Vec<osis_base::Link> {
    let len = |ls: &[osis_base::Link]| osis_base::encode(&Value::List(ls.iter().copied().map(Value::link).collect())).len();
    let mut level = 0;
    while len(&links) > params.target && links.len() >= 2 {
        let (mut up, mut group) = (Vec::new(), Vec::new());
        for l in &links {
            group.push(*l);
            if close(level, group.len(), l) {
                up.push(link_page(cas, &std::mem::take(&mut group)));
            }
        }
        if !group.is_empty() {
            up.push(link_page(cas, &group));
        }
        links = up;
        level += 1;
    }
    links
}

/// `bytes` with its one paged position's root link list replaced by `top`.
fn with_root(bytes: &[u8], top: &[osis_base::Link]) -> Vec<u8> {
    fn swap(v: &mut Value, top: &[osis_base::Link]) -> bool {
        let Value::List(items) = v else { return false };
        if !items.is_empty() && items.iter().all(|x| matches!(x, Value::Link(_))) {
            *items = top.iter().copied().map(Value::link).collect();
            return true;
        }
        items.iter_mut().any(|x| swap(x, top))
    }
    let mut v = osis_base::decode(bytes, &osis_base::Limits::DEFAULT).unwrap();
    assert!(swap(&mut v, top), "a paged position");
    osis_base::encode(&v)
}

/// §8, spec/wire.md §6, one encoding: for a set paged at three levels, the tree the rule gives
/// its leaves is the one both decoders accept, and every other tree over the same leaf pages a
/// writer can build is refused by both, fetching at most its pages, each once: groups of two (a
/// deeper balanced tree), one group boundary moved, groups closing a link before the fan-out, an
/// extra level of single-link pages below or above, a level missing (a root list above the
/// target), the root list the leaves themselves, and leaves at two depths.
#[test]
fn every_other_link_tree_is_refused_spec_8() {
    use crate::stream::stream_snapshot;
    let params = PageParams { target: 1500, cut: ChunkParams { min: 16, max: 512, mask_bits: 6 }, fanout: 8, ..PageParams::FORMAT };
    let st = big_set(1000, 1);
    let mut cas = Cas { params: Some(params), ..Cas::default() };
    let bytes = encode_snapshot(&snapshot(&st), &snap_cx(), Some(&mut cas)).unwrap();
    assert_eq!(depth(&bytes, &mut cas), 3, "three page levels");
    fn find(v: &Value) -> Option<Value> {
        let Value::List(items) = v else { return None };
        if !items.is_empty() && items.iter().all(|x| matches!(x, Value::Link(_))) {
            return Some(v.clone());
        }
        items.iter().find_map(find)
    }
    let Some(Value::List(top)) = find(&osis_base::decode(&bytes, &osis_base::Limits::DEFAULT).unwrap()) else { panic!("a root link list") };
    let top: Vec<osis_base::Link> = top.iter().map(|x| if let Value::Link(l) = x { **l } else { unreachable!() }).collect();
    let leaves = leaves_under(&cas, &top);
    let rule = |_: usize, n: usize, l: &osis_base::Link| (n >= 2 && l.hash[0] == 0) || n >= params.fanout;
    assert_eq!(grouped(&mut cas, leaves.clone(), params, &rule), top, "the rule's tree is the encoder's");
    assert_eq!(with_root(&bytes, &top), bytes);
    // both decoders: refused, fetching each page of the tree at most once
    let refused = |cas: &mut Cas, root: &[osis_base::Link], what: &str| {
        let b = with_root(&bytes, root);
        let most = pages_under(cas, root);
        cas.fetched = 0;
        let whole = decode_snapshot(&b, &snap_cx(), &mut Interner::new(), Some(&mut *cas));
        assert!(whole.is_err() && cas.fetched <= most, "{what}: whole decode {:?}, {} fetched of {most}", whole.map(|_| ()), cas.fetched);
        cas.fetched = 0;
        let streamed = stream_snapshot(&b, &snap_cx(), &mut Interner::new(), Some(&mut *cas), &mut |_| Ok(()));
        assert!(streamed.is_err() && cas.fetched <= most, "{what}: streamed decode {:?}, {} fetched of {most}", streamed.map(|_| ()), cas.fetched);
    };
    let twos = grouped(&mut cas, leaves.clone(), params, &|_, n, _| n >= 2);
    refused(&mut cas, &twos, "groups of two");
    let early = grouped(&mut cas, leaves.clone(), params, &|_, n, l| (n >= 2 && l.hash[0] == 0) || n + 1 >= params.fanout);
    refused(&mut cas, &early, "a link before the fan-out");
    // one boundary of the first level moved a link later
    let first = grouped(&mut cas, leaves.clone(), PageParams { target: usize::MAX, ..params }, &|_, _, _| false);
    assert_eq!(first, leaves);
    let mut groups: Vec<Vec<osis_base::Link>> = Vec::new();
    let mut g = Vec::new();
    for l in &leaves {
        g.push(*l);
        if rule(0, g.len(), l) {
            groups.push(std::mem::take(&mut g));
        }
    }
    groups.push(g);
    let moved = groups[1].remove(0);
    groups[0].push(moved);
    let level1: Vec<osis_base::Link> = groups.iter().filter(|g| !g.is_empty()).map(|g| link_page(&mut cas, g)).collect();
    let shifted = grouped(&mut cas, level1, params, &rule);
    refused(&mut cas, &shifted, "a boundary moved");
    let wrapped: Vec<osis_base::Link> = leaves.iter().map(|l| link_page(&mut cas, &[*l])).collect();
    let below = grouped(&mut cas, wrapped, params, &rule);
    refused(&mut cas, &below, "single-link pages below");
    let above = link_page(&mut cas, &top);
    refused(&mut cas, &[above], "a single-link page above");
    let lower: Vec<osis_base::Link> = top.iter().flat_map(|l| page_links(&cas, l).unwrap()).collect();
    refused(&mut cas, &lower, "a level missing");
    refused(&mut cas, &leaves, "the leaves as the root");
    let mut uneven = page_links(&cas, &top[0]).unwrap();
    uneven.extend(&top[1..]);
    refused(&mut cas, &uneven, "leaves at two depths");
}

/// The first link in a value, depth first.
fn first_link(v: &Value) -> Option<osis_base::Link> {
    let Value::List(items) = v else { return None };
    items.iter().find_map(|x| if let Value::Link(l) = x { Some(**l) } else { first_link(x) })
}

/// §8 at the format's sizes: a set above 64 KiB pages and round-trips, and a writer's delta of a
/// map pages the same way (any delta may page). An ephemeral delta is never paged: above the page
/// target it encodes inline and decodes only as unpaged; a paged one is bad input there.
/// `MAX_PAGE_ITEMS`, honest writers: each page and root counts at most its bytes.
#[test]
fn paging_format_size_spec_8() {
    let st = big_set(3000, 6);
    let mut rec = MemoryPages::with_params(PageParams::FORMAT);
    let bytes = encode_snapshot(&snapshot(&st), &snap_cx(), Some(&mut rec)).unwrap();
    assert!(!rec.pages.is_empty());
    assert!(bytes.len() < PageParams::FORMAT.target);
    assert_eq!(unpage(&bytes, &mut rec).unwrap(), st);
    honest_page_items(&bytes, &rec);
    let e = unpage(&bytes, &mut crate::Unpaged).unwrap_err();
    assert_eq!(osis_base::Classified::class(&e), osis_base::ErrorClass::BadInput);
    let plain = encode_snapshot(&snapshot(&st), &snap_cx(), Some(&mut crate::Unpaged)).unwrap();
    assert!(plain.len() > PageParams::FORMAT.target);
    assert_eq!(unpage(&plain, &mut crate::Unpaged).unwrap(), st);
    assert!(decode_snapshot(&plain, &snap_cx(), &mut Interner::new(), None).is_err(), "durable: paging is mandatory");
    let mut w = Writer::new(ts(1 << 20), node(1), 1);
    let entries = Value::Map((0..3000).map(|i| (Value::Str(format!("bulk import {i}")), Value::Str("v".repeat(10)))).collect());
    let d = create(&mut w, &TyView(Ty::Map(Box::new(Ty::Register), Box::new(Ty::Register))), &entries).unwrap();
    let mut rec = MemoryPages::with_params(PageParams::FORMAT);
    let bytes = encode_delta(&Delta { nonce: [0; 16], fragment: d.clone() }, &ctx_of(&w), Some(&mut rec)).unwrap();
    assert!(!rec.pages.is_empty());
    honest_page_items(&bytes, &rec);
    assert_eq!(decode_delta(&bytes, &ctx_of(&w), &mut Interner::new(), Some(&mut rec)).unwrap().fragment, d);
}

/// §8 `MAX_PAGE_ITEMS`: an honest writer's root and pages each count at most their bytes, far
/// below the cap.
fn honest_page_items(root: &[u8], rec: &MemoryPages) {
    for b in std::iter::once(root).chain(rec.pages.values().map(Vec::as_slice)) {
        let n = crate::page_items(b).unwrap();
        assert!(n <= b.len() && n < 3 << 18, "{n} items in {} bytes", b.len());
    }
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
    let root = |val: &Value, snapshot: bool| {
        let mut top = vec![Value::Bytes(vec![0; 16]), none(), none(), Value::List(vec![Value::Int(0), none(), Value::Int(0), val.clone()])];
        if snapshot {
            top.extend([none(), none(), none()]);
        }
        osis_base::encode(&Value::List(top))
    };
    // a text string counts its head and a byte each, so the cap is met without millions of
    // values: the fragment `[0, [], 0, "x" * n]` counts n + 5 items
    let text = |n: usize| Value::Str("x".repeat(n));
    let over = MAX_PAGE_ITEMS - 4;
    for (val, capped) in [(text(over), true), (text(over - 1), false)] {
        for snapshot in [false, true] {
            let bytes = root(&val, snapshot);
            let mut pages = MemoryPages::new();
            let errs = if snapshot {
                [decode_snapshot(&bytes, &snap_cx(), &mut Interner::new(), None).unwrap_err(), unpage(&bytes, &mut pages).unwrap_err()]
            } else {
                [decode_delta(&bytes, &snap_cx(), &mut Interner::new(), None).unwrap_err(), decode_delta(&bytes, &snap_cx(), &mut Interner::new(), Some(&mut pages)).unwrap_err()]
            };
            for e in errs {
                assert_eq!(is_cap(&e), capped, "{e}");
                assert_eq!(osis_base::Classified::class(&e), osis_base::ErrorClass::BadInput);
            }
        }
        let e = unpage(&root(&val, true), &mut crate::Unpaged).unwrap_err();
        assert!(!is_cap(&e), "ephemeral deltas are not counted: {e}");
    }
    // a page: the set's element array links to one page of too many items (`["x" * n]`: n + 2)
    for (n, capped) in [(MAX_PAGE_ITEMS - 1, true), (MAX_PAGE_ITEMS - 2, false)] {
        let mut pages = MemoryPages::new();
        let link = pages.put(&osis_base::encode(&Value::List(vec![text(n)]))).unwrap();
        let top = Value::List(vec![Value::Bytes(vec![0; 16]), none(), none(), Value::List(vec![Value::Int(6), none(), none(), Value::List(vec![Value::link(link)])]), none(), none(), none()]);
        let e = unpage(&osis_base::encode(&top), &mut pages).unwrap_err();
        assert_eq!(is_cap(&e), capped, "{e}");
    }
}

/// §8 `MAX_PAGE_ITEMS`, honest writers: a paged text (text bytes count as items), as a writer's
/// delta and a snapshot, pages far below the cap (each page and root counts at most its bytes,
/// whatever the page target) and decodes; its runs hold at most `MAX_RUN` elements. (A set and a
/// map paged at the format's target: `paging_format_size_spec_8`.)
#[test]
fn page_items_honest_spec_8() {
    // runs of `MAX_RUN` and a shorter one, paged at a small target
    let chars = 2 * crate::MAX_RUN + 808;
    let text = Value::Str((0..chars).map(|i| char::from(b'a' + (i % 26) as u8)).collect());
    let mut w = Writer::new(ts(1 << 20), node(1), 1);
    let d = create(&mut w, &TyView(Ty::Text), &text).unwrap();
    let cx = ctx_of(&w);
    let mut rec = MemoryPages::with_params(SMALL);
    let bytes = encode_delta(&Delta { nonce: [0; 16], fragment: d.clone() }, &cx, Some(&mut rec)).unwrap();
    let (sbytes, mut srec) = paged(&d, SMALL);
    assert!(!rec.pages.is_empty() && !srec.pages.is_empty());
    honest_page_items(&bytes, &rec);
    honest_page_items(&sbytes, &srec);
    assert_eq!(decode_delta(&bytes, &cx, &mut Interner::new(), Some(&mut rec)).unwrap().fragment, d);
    assert_eq!(unpage(&sbytes, &mut srec).unwrap(), d);
    // runs `[Dot, n, ...]` of at most `MAX_RUN` elements
    let ns: Vec<u64> = rec.pages.values().flat_map(|p| match osis_base::decode(p, &osis_base::Limits::DEFAULT).unwrap() {
        Value::List(runs) => runs.into_iter().filter_map(|r| match r {
            Value::List(r) if r.len() == 6 => r[1].as_uint(),
            _ => None,
        }).collect(),
        _ => Vec::new(),
    }).collect();
    assert_eq!(ns.iter().sum::<u64>(), chars);
    assert!(ns.iter().all(|&n| n <= crate::MAX_RUN) && ns.contains(&crate::MAX_RUN), "{ns:?}");
}

/// A struct of `n` string fields of `len` bytes, the last one an enum whose payload is such a
/// struct again, as one writer's delta.
fn wide_struct(n: u64, len: usize) -> (Fragment, DeltaCtx) {
    let inner: std::collections::BTreeMap<u64, Ty> = (0..n).map(|i| (i, Ty::Register)).collect();
    let mut fields = inner.clone();
    fields.insert(n, Ty::Enum([(1, Some(Ty::Struct(inner.clone())))].into_iter().collect()));
    let strs = || (0..n).map(|i| (Value::Int(i as i64), Value::Str(format!("{i:04}{}", "x".repeat(len))))).collect::<osis_base::ValueMap>();
    let mut v = strs();
    v.insert(Value::Int(n as i64), Value::Enum(1, Some(Box::new(Value::Map(strs())))));
    let mut w = Writer::new(ts(1 << 20), node(1), 1);
    let d = create(&mut w, &TyView(Ty::Struct(fields)), &Value::Map(v)).unwrap();
    (d, ctx_of(&w))
}

/// §8: a struct's field map and an enum's payload map page like element arrays: pages are maps
/// of whole consecutive fields, the delta stays at the target whatever the field count, and it
/// round-trips; below the target nothing pages.
#[test]
fn struct_field_paging_spec_8() {
    for (n, paged) in [(3u64, false), (200, true)] {
        let (d, cx) = wide_struct(n, 100);
        let mut rec = MemoryPages::with_params(SMALL);
        let bytes = encode_delta(&Delta { nonce: [0; 16], fragment: d.clone() }, &cx, Some(&mut rec)).unwrap();
        assert_eq!(!rec.pages.is_empty(), paged, "n = {n}");
        assert!(bytes.len() <= SMALL.target || !paged);
        let mut maps = 0;
        for p in rec.pages.values() {
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
        assert_eq!(decode_delta(&bytes, &cx, &mut Interner::new(), Some(&mut rec)).unwrap().fragment, d);
        // equal fields give equal pages
        let mut again = MemoryPages::with_params(SMALL);
        encode_delta(&Delta { nonce: [0; 16], fragment: d.clone() }, &cx, Some(&mut again)).unwrap();
        assert_eq!(again.written, rec.written);
    }
}

/// §8: a field map unpaged above the target, a page that is not a map, an empty page, fields
/// out of order across pages: rejected.
#[test]
fn struct_field_paging_rejections_spec_8() {
    let (d, cx) = wide_struct(200, 100);
    let mut rec = MemoryPages::with_params(SMALL);
    let bytes = encode_delta(&Delta { nonce: [0; 16], fragment: d.clone() }, &cx, Some(&mut rec)).unwrap();
    let plain = encode_delta(&Delta { nonce: [0; 16], fragment: d }, &cx, Some(&mut MemoryPages::with_params(PageParams { target: usize::MAX, ..SMALL }))).unwrap();
    assert!(decode_delta(&plain, &cx, &mut Interner::new(), Some(&mut rec)).is_err());
    // swap the struct's top field links for crafted pages
    let top = osis_base::decode(&bytes, &osis_base::Limits::DEFAULT).unwrap();
    let with_children = |c: Value| {
        let Value::List(mut a) = top.clone() else { panic!() };
        let Some(Value::List(f)) = a.get_mut(3) else { panic!() };
        f[3] = c;
        osis_base::encode(&Value::List(a))
    };
    let mut pages = MemoryPages::with_params(SMALL);
    let field = |i: i64| (Value::Int(i), Value::List(vec![Value::Int(0), Value::List(vec![]), Value::Int(0), s("v")]));
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
    let bytes = encode_snapshot(&snapshot(&st), &snap_cx(), Some(&mut pages)).unwrap();
    assert_eq!(unpage(&bytes, &mut pages).unwrap(), st);
}

/// Model writer 1's list of `n` strings of 128 KiB less `pad` bytes and a 3-digit index, made at
/// t = 5: the model delta, its context, and our delta.
fn big_list(n: usize, pad: usize) -> (crdt_model::state::Frag, DeltaCtx, Delta) {
    use crdt_model::value::Value as MV;
    let mut w = crdt_model::ops::Writer::new(MSource::session(1, 0), 5 << 16, 1);
    let delta = crdt_model::ops::create(&mut w, &Ty::List(Box::new(Ty::Register)), &MV::List((0..n).map(|i| MV::Str(format!("{i:03}{}", "x".repeat(128 * 1024 - pad)))).collect()));
    let d = Delta { nonce: [7; 16], fragment: frag(&delta) };
    (delta, writer_cx(&w), d)
}

/// §3.3 rule 3: a list run closes once its content reaches `CHUNK_MAX` bytes, so 65 values of
/// 128 KiB inserted at once make several runs: the model's bytes unpaged, and paged every page
/// within `CHUNK_MAX` plus one element; it round-trips.
#[test]
fn list_run_closes_at_chunk_max_spec_3_3() {
    let (delta, cx, d) = big_list(65, 16);
    let mbytes = crdt_model::wire::encode_delta(&delta, [7; 16], &mut crdt_model::wire::Ctx::new(5 << 16, MSource::session(1, 0), 1));
    let mut flat = MemoryPages::with_params(PageParams { target: usize::MAX, ..PageParams::FORMAT });
    let bytes = encode_delta(&d, &cx, Some(&mut flat)).unwrap();
    assert_eq!(bytes, mbytes, "the model's bytes");
    let top = osis_base::decode(&bytes, &osis_base::Limits { max_bytes: usize::MAX, ..osis_base::Limits::DEFAULT }).unwrap();
    let Value::List(a) = top else { panic!() };
    let Some(Value::List(f)) = a.get(3) else { panic!() };
    let Some(Value::List(runs)) = f.get(3) else { panic!() };
    // two elements stay just below 256 KiB, three reach it: 21 runs of 3, one of 2
    assert_eq!(runs.len(), 22);
    let mut rec = MemoryPages::with_params(PageParams::FORMAT);
    let paged = encode_delta(&d, &cx, Some(&mut rec)).unwrap();
    assert!(rec.pages.values().all(|p| p.len() < osis_base::format::CHUNK_MAX + 3 * 128 * 1024), "pages {:?}", rec.pages.values().map(Vec::len).collect::<Vec<_>>());
    assert_eq!(decode_delta(&paged, &cx, &mut Interner::new(), Some(&mut rec)).unwrap().fragment, d.fragment);
}

/// §3.3 rule 7: a list run whose content goes on past `CHUNK_MAX` bytes is rejected.
#[test]
fn rejects_list_run_past_chunk_max_spec_3_3() {
    let (_, cx, d) = big_list(6, 0);
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

/// The map `{"k": v}`.
fn kmap(v: Value) -> Value {
    Value::Map([(s("k"), v)].into_iter().collect())
}

/// spec/permissions.md §5.2 (a delta's writes count while it is valid; copies), spec/crdt.md §5.6:
/// a snapshot carrying an entry another node created, holding only a held delta's write inside
/// it, stripped of that delta's copies keeps the creation, so its join gives the entry its
/// creation stamp whether the delta joined before or after (it once pruned the entry with the
/// creation: one held set, two states). Alone it joins nothing.
#[test]
fn stripped_entry_keeps_others_creation_spec_perm_5_2() {
    let w1 = create(&mut Writer::new(ts(1), node(1), 1), &AnyView, &kmap(Value::Int(1))).unwrap();
    let mut builder = DeltaBuilder::new(&w1, Writer::new(ts(2), node(2), 1));
    builder.apply(&PathOp { path: vec![crate::PathSeg::Key(s("k"))], op: Op::Set(Value::Int(2)) }, &AnyView).unwrap();
    let (w2, _) = builder.finish().unwrap();
    let snap = joined(&w1, &w2);
    let mut stripped = snap.clone();
    stripped.remove_writes(&|d| d.src == node(2));
    let then = joined(&snap, &w2);
    assert_eq!(joined(&w2, &stripped), then, "the delta first, the stripped snapshot after; the snapshot first");
    // an un-merge of another author's dots (a rebuild) keeps the creation for the join too
    let mut unmerged = stripped.clone();
    unmerged.remove_writes(&|d| d.src == node(3));
    assert_eq!(joined(&w2, &unmerged), then, "removing others' dots kept the creation");
    let alone = joined(&Fragment::default(), &stripped);
    assert!(alone.read().is_none_or(|v| v == Value::Map(osis_base::ValueMap::new())), "a creation alone joins nothing: {alone:?}");
}

/// spec/commits.md §5 (an element's or entry's tombstone is not one of its creator's): a removed
/// map entry's tombstone, keyed by its dot, holds the remover's reset, not the creator's write.
#[test]
fn entry_tombstone_is_no_live_write_spec_commits_5() {
    let mut st = create(&mut Writer::new(ts(1), node(1), 1), &AnyView, &kmap(Value::Int(1))).unwrap();
    let owned = |s: &Source, lo: u64, _: u64| *s == node(1) && lo <= 1;
    assert!(st.holds_owned_write(&owned));
    st.join(crate::testutil::build(&st, Writer::new(ts(2), node(2), 1), &[PathOp { path: vec![], op: Op::Remove(s("k")) }], &AnyView).unwrap().0);
    assert!(st.holds_owned(&owned), "the tombstone is keyed by the entry's dot");
    assert!(!st.holds_owned_write(&owned), "but holds no write of its creator");
    let ours = |w: Vec<(crate::Dot, Option<osis_base::Ts>)>| w.iter().any(|(d, _)| owned(&d.src, d.ctr, d.ctr + 1));
    assert!(ours(st.writes()) && !ours(st.live_writes()), "live_writes agrees");
}

/// §4.3, §4.7: a list whose commit expired reads absent.
#[test]
fn expired_list_reads_absent_spec_crdt_4_3() {
    let f = create(&mut Writer::new(ts(5), node(1), 1), &AnyView, &Value::List(vec![Value::Int(1), Value::Int(2)])).unwrap();
    let f = stripped(&f, &|d| d.src == node(1));
    assert!(!f.present());
    assert_eq!(f.read(), None);
}

/// A list of maps of registers.
fn map_list() -> TyView {
    TyView(Ty::List(Box::new(Ty::Map(Box::new(Ty::Register), Box::new(Ty::Register)))))
}

/// spec/sync-compaction.md §1: a sweep resets what a removal hid, once, so the join leaves no
/// repeated key; never a record merely lacking its creation (one expired here), a live
/// one or an empty tombstone.
#[test]
fn sweep_takes_only_what_is_hidden_spec_sync_7() {
    let (x, y) = (node(1), node(2));
    let r = Writer::new(ts(20), y.clone(), 5).delta_stamp();
    let none = |f: &Fragment, why: &str| assert_eq!(f.sweep(&r, &|_| false), None, "{why}");
    let mine = |d: &Dot| d.src == x;
    let put = create(&mut Writer::new(ts(5), x.clone(), 1), &AnyView, &kmap(s("a"))).unwrap();
    let edit = diff(&mut Writer::new(ts(9), y.clone(), 1), Some(&put), &AnyView, &kmap(s("b"))).unwrap().unwrap();
    none(&put, "a live entry");
    none(&edit, "the creation not held: it may still arrive");
    let removal = crate::reset_entries(&Writer::new(ts(7), x.clone(), 3), &[(Dot::new(x.clone(), 1), s("k"))]);
    let gone = joined(&put, &removal);
    none(&gone, "a tombstone holds nothing");
    let hid = joined(&gone, &edit);
    assert_eq!(hid.read(), Some(Value::Map(Default::default())));
    let sweep = hid.sweep(&r, &|_| false).expect("a removal hid the edit");
    let after = joined(&hid, &sweep);
    none(&after, "once");
    assert!(!after.holds_write(&Dot::new(y.clone(), 1)), "the edit is dead");
    let Fragment::Map(m) = &after else { panic!("a map") };
    assert!(m.entries.keys().all(|id| id.key.is_none()), "the key is gone");
    let expired = held(&[&put, &edit], &mine);
    assert_eq!(expired.read(), Some(Value::Map(Default::default())), "another's value goes with the entry");
    none(&expired, "the creation gone: as not held");
    none(&stripped(&put, &mine), "expired, nothing else in it");
    // a text undelete over its held creation: a live char
    let text = create(&mut Writer::new(ts(5), x.clone(), 1), &TyView(Ty::Text), &s("a")).unwrap();
    let mut undel = Seq::empty(true);
    undel.elems_mut().insert(Dot::new(x.clone(), 1), SeqElem { deleted: Some((Writer::new(ts(9), y.clone(), 1).delta_stamp(), false)), undel: Some('a'), ..SeqElem::bare() });
    assert_eq!(joined(&text, &Fragment::Seq(undel)).sweep(&r, &|_| true), None, "a live char");
    // another's removal alone in an expired entry hides it
    let put = create(&mut Writer::new(ts(5), x.clone(), 1), &AnyView, &kmap(kmap(s("a")))).unwrap();
    let removal = diff(&mut Writer::new(ts(9), y.clone(), 1), Some(&put), &AnyView, &kmap(Value::Map(Default::default()))).unwrap().unwrap();
    let hid = held(&[&put, &removal], &mine);
    assert_eq!(hid.read(), Some(Value::Map(Default::default())));
    none(&hid, "not removed: the creation may still arrive");
    // a list element, nested in a live one
    let ty = map_list();
    let list = create(&mut Writer::new(ts(5), x.clone(), 1), &ty, &Value::List(vec![kmap(s("a"))])).unwrap();
    let new = diff(&mut Writer::new(ts(9), y.clone(), 1), Some(&list), &ty, &Value::List(vec![Value::Map(Default::default())])).unwrap().unwrap();
    none(&list, "a live element");
    let over = joined(&list, &new);
    none(&over, "a live element, emptied");
    let over = held(&[&list, &new], &mine);
    assert_eq!(over.read(), Some(Value::List(Vec::new())));
    none(&over, "not removed");
    // a removed element with a newer write inside
    let rm = diff(&mut Writer::new(ts(7), x.clone(), 3), Some(&list), &ty, &Value::List(vec![])).unwrap().unwrap();
    let edit = diff(&mut Writer::new(ts(9), y.clone(), 1), Some(&list), &ty, &Value::List(vec![kmap(s("b"))])).unwrap().unwrap();
    let mut gone = joined(&joined(&list, &rm), &edit);
    assert_eq!(gone.read(), Some(Value::List(Vec::new())));
    let sweep = gone.sweep(&r, &|_| false).expect("its edit hidden");
    gone.join(sweep);
    none(&gone, "once");
    assert!(!gone.holds_write(&Dot::new(y, 1)));
}

/// spec/sync-compaction.md §1: a creation a parent's reset pruned is dead once the state reflects
/// its delta, so what was written into its record since goes (a map entry, a list element, a text
/// undelete's char); the record merely lacking its creation (not received, or its delta invalid)
/// stays, and so does an enum's payload of a case not current, which a concurrent case write may
/// show.
#[test]
fn sweep_takes_what_a_parent_reset_hid_spec_sync_7() {
    let (x, y, z) = (node(1), node(2), node(3));
    let zw = Writer::new(ts(20), z.clone(), 9);
    let r = zw.delta_stamp();
    let xs = [(x.clone(), 1, 9)];
    let reflected = in_ranges(&xs);
    // each: x creates at 5, y writes inside at 9, z replaces the parent at 7
    let check = |what: &str, put: Fragment, edit: Fragment, over: Fragment| {
        let st = joined(&joined(&put, &over), &edit);
        let want = st.read();
        let partial = joined(&over, &edit);
        assert_eq!(partial.sweep(&r, &|_| false), None, "{what}: the creation may arrive");
        assert_eq!(st.sweep(&r, &|_| false), None, "{what}: its delta not reflected (invalid)");
        let sw = st.sweep(&r, &reflected).unwrap_or_else(|| panic!("{what}: swept"));
        assert_eq!(wired(&sw, &ctx_of(&zw)), sw, "{what}: the wire");
        let after = joined(&st, &sw);
        assert_eq!(after.read(), want, "{what}: the read");
        assert!(!after.holds_write(&Dot::new(y.clone(), 1)), "{what}: the edit is dead");
        assert_eq!(after.sweep(&r, &reflected), None, "{what}: once");
        // the late creation, or the partial view swept, read alike
        assert_eq!(joined(&joined(&partial, &sw), &put).read(), want, "{what}: a late creation stays dead");
    };
    let put = create(&mut Writer::new(ts(5), x.clone(), 1), &AnyView, &kmap(s("a"))).unwrap();
    let edit = diff(&mut Writer::new(ts(9), y.clone(), 1), Some(&put), &AnyView, &kmap(s("b"))).unwrap().unwrap();
    let over = replace(&mut Writer::new(ts(7), z.clone(), 1), &AnyView, &Value::Map(Default::default())).unwrap();
    check("map entry", put, edit, over);
    let ty = map_list();
    let put = create(&mut Writer::new(ts(5), x.clone(), 1), &ty, &Value::List(vec![kmap(s("a"))])).unwrap();
    let edit = diff(&mut Writer::new(ts(9), y.clone(), 1), Some(&put), &ty, &Value::List(vec![kmap(s("b"))])).unwrap().unwrap();
    let over = replace(&mut Writer::new(ts(7), z.clone(), 1), &ty, &Value::List(vec![kmap(s("c"))])).unwrap();
    check("list element", put, edit, over);
    let text = TyView(Ty::Text);
    let put = create(&mut Writer::new(ts(5), x.clone(), 1), &text, &s("a")).unwrap();
    let mut undel = Seq::empty(true);
    undel.elems_mut().insert(Dot::new(x.clone(), 1), SeqElem { deleted: Some((Writer::new(ts(9), y.clone(), 1).delta_stamp(), false)), undel: Some('a'), ..SeqElem::bare() });
    let over = replace(&mut Writer::new(ts(7), z.clone(), 1), &text, &s("c")).unwrap();
    check("text undelete", put, Fragment::Seq(undel), over);
    // an enum: case 1 by x at 5, case 2 by z at 7, an edit of case 1's payload by y at 9
    let ety = TyView(Ty::Enum([(1, Some(Ty::Register)), (2, None)].into_iter().collect()));
    let one = |v: &str| Value::Enum(1, Some(Box::new(s(v))));
    let put = create(&mut Writer::new(ts(5), x.clone(), 1), &ety, &one("a")).unwrap();
    let edit = diff(&mut Writer::new(ts(9), y.clone(), 1), Some(&put), &ety, &one("b")).unwrap().unwrap();
    let two = diff(&mut Writer::new(ts(7), z.clone(), 1), Some(&put), &ety, &Value::Enum(2, None)).unwrap().unwrap();
    let mut st = joined(&joined(&put, &two), &edit);
    assert_eq!(st.read(), Some(Value::Enum(2, None)));
    assert_eq!(st.sweep(&r, &|_| true), None, "a payload of a case not current");
    // a concurrent case write stamped between the case change and the edit, arriving late
    st.join(replace(&mut Writer::new(ts(8), x.clone(), 5), &ety, &one("c")).unwrap());
    assert_eq!(st.read(), Some(one("b")), "a case write stamped below the edit shows it");
}

/// Content-less sequence elements in `f`, what a writer's delta bounds by `MAX_DELTA_BARE`.
fn bare(f: &Fragment) -> u64 {
    match f {
        Fragment::Struct(s) => s.fields.values().map(bare).sum(),
        Fragment::Enum(e) => e.payloads.values().map(bare).sum(),
        Fragment::Map(m) => m.entries.values().filter_map(|en| en.frag.as_deref()).map(bare).sum(),
        Fragment::Seq(s) => s
            .elems()
            .values()
            .map(|el| match &el.content {
                crate::seq::SeqContent::None => el.span,
                crate::seq::SeqContent::Char(_) => 0,
                crate::seq::SeqContent::Frag(f) => bare(f),
            })
            .sum(),
        _ => 0,
    }
}

/// spec/sync-compaction.md §1: a sweep takes at most `MAX_DELTA_BARE` content-less elements, so it
/// is a valid writer delta whatever is hidden; sweeps again take the rest until none is left.
#[test]
fn sweep_is_bounded_and_finishes_spec_sync_7() {
    let (x, y, z) = (node(1), node(2), node(3));
    // x wrote a text, y undeletes all of it, z replaces it concurrently: every char is hidden
    let cap = osis_base::format::MAX_DELTA_BARE;
    let n = cap + 3;
    // x's creation is held nowhere (the replace pruned it), its delta reflected: a range record
    // of all but the last four chars (one record however long), then four records of one, so
    // the cap falls one record past the range and records are left after it in that sweep
    let mut undel = Seq::empty(true);
    let at = Writer::new(ts(9), y.clone(), 1).delta_stamp();
    let hidden = |span, c| SeqElem { deleted: Some((at.clone(), false)), undel: Some(c), span, ..SeqElem::bare() };
    undel.elems_mut().insert(Dot::new(x.clone(), 1), hidden(cap - 1, 'a'));
    for c in cap..=n {
        undel.elems_mut().insert(Dot::new(x.clone(), c), hidden(1, 'b'));
    }
    let mut st = replace(&mut Writer::new(ts(7), z.clone(), 1), &TyView(Ty::Text), &s("c")).unwrap();
    st.join(Fragment::Seq(undel));
    let xs = [(x, 1, n + 1)];
    let reflected = in_ranges(&xs);
    let want = st.read();
    let mut steps = 0;
    for k in 0.. {
        let w = Writer::new(ts(20 + k), z.clone(), 9);
        let Some(sw) = st.sweep(&w.delta_stamp(), &reflected) else { break };
        assert_eq!(bare(&sw), if k == 0 { cap } else { 3 }, "step {k}: the cap, then the rest");
        encode_delta(&Delta { nonce: [0; 16], fragment: sw.clone() }, &ctx_of(&w), None).expect("a valid writer delta");
        st.join(sw);
        steps += 1;
    }
    assert_eq!(steps, 2, "the cap, then the rest");
    assert_eq!(st.read(), want);
    assert!(!st.holds_write(&Dot::new(y, 1)), "every undelete is dead");
}

/// `v` with empty collections left out: a sweep's reset is a write, so a collection another writer
/// reset meanwhile may read empty rather than absent, as under any concurrent removal (§4.3), an
/// enum's payload too.
fn shown(v: Value) -> Option<Value> {
    match v {
        Value::Enum(c, p) => Some(Value::Enum(c, p.and_then(|p| shown(*p)).map(Box::new))),
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

/// spec/sync-compaction.md §1: a sweep from any stale view (a random part of the commits, a random
/// part of the expiries) changes no read, there or at a node holding everything; it is a valid
/// writer delta; joined back it finds nothing more, so a compaction does not write forever; swept
/// one content-less element at a time it ends where it would at once.
fn sweep_laws(seed: u64, ty: &Ty) -> usize {
    let mut r = crate::testutil::rng(seed | 1);
    let commits = crate::testutil::history_honest(&mut r, std::slice::from_ref(ty), 3, 5);
    let bodies: Vec<Fragment> = commits.iter().map(|c| frag(&c.delta)).collect();
    let ranges: Vec<Range> = commits.iter().map(|c| (source(&c.w.source), c.w.lo, c.w.hi())).collect();
    let w = Writer::new(ts(1 << 40), node(250), 1);
    let stamp = w.delta_stamp();
    let mut swept = 0;
    for _ in 0..6 {
        let expired: Vec<Range> = ranges.iter().filter(|_| r.chance(1, 4)).cloned().collect();
        let gone: Vec<Range> = expired.iter().filter(|_| r.chance(3, 4)).cloned().collect();
        let mut mine = Vec::new();
        let mut held_ranges: Vec<Range> = Vec::new();
        for (b, rg) in bodies.iter().zip(&ranges).filter(|_| r.chance(2, 3)) {
            mine.push(b);
            held_ranges.push(rg.clone());
        }
        let view = held(&mine, &in_ranges(&gone));
        let held = held_ranges;
        let reflected = in_ranges(&held);
        let Some(sw) = view.sweep(&stamp, &reflected) else { continue };
        swept += 1;
        assert_eq!(wired(&sw, &ctx_of(&w)), sw, "the wire");
        let after = stripped(&joined(&view, &sw), &in_ranges(&gone));
        assert_eq!(after.read(), view.read(), "the view's read");
        assert_eq!(after.sweep(&stamp, &reflected), None, "swept once");
        // swept a content-less element at a time, over as many commits as that takes: the same
        let mut stepped = view.clone();
        loop {
            let mut left = 1;
            let Some(part) = stepped.sweep_at_most(&stamp, &reflected, &mut left) else { break };
            assert!(bare(&part) <= 1, "one element per step");
            stepped.join(part);
        }
        assert!(stripped(&stepped, &in_ranges(&gone)) == after, "swept in steps");
        let all = held_all(&bodies, &in_ranges(&expired));
        let want = all.read();
        let all = stripped(&joined(&all, &sw), &in_ranges(&expired));
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

/// §4.1 copy order, §5.6: one dot may name several keys in a state, so no reader rule forbids it
/// in a blob. The writer's delta holds the creation and Y's write under "a", a valid snapshot a
/// forged copy of Y's write under "b"; each names one key, their join sits Y's write under "b"
/// and the creation under "a", and the joining node's own snapshot carries both and decodes.
#[test]
fn one_dot_under_two_keys_by_join_spec_5_6() {
    use crate::fragment::{Eid, Entry, Map, Meta, RegWrite, Register};
    use crate::stamp::Stamp;
    use std::collections::BTreeMap;
    let d = Dot::new(node(1), 1);
    let c = Stamp::new(ts(1 << 16), node(1), 1);
    let w = Stamp::new(ts(2 << 16), node(2), 1);
    let reg = || Some(Box::new(Fragment::Register(Register { reset: None, write: Some(RegWrite { stamp: w.clone(), value: Value::Int(7) }) })));
    let rec = |key: &str, created: Option<Stamp>| {
        let mut m = Fragment::Map(Map::new(Meta::default(), BTreeMap::from([(Eid::new(d.clone(), Some(Value::Str(key.into()))), Entry { reset: None, frag: reg(), created })])));
        m.prune(None, &mut crate::Changes::new());
        m
    };
    let a = rec("a", Some(c.clone())); // the delta's: creation and w under "a"
    let b = rec("b", None); // a forged snapshot's copy of w under "b"
    for x in [&a, &b] {
        let bytes = crate::testutil::snapshot_bytes(x);
        decode_snapshot(&bytes, &snap_cx(), &mut Interner::new(), None).unwrap();
    }
    let both = joined(&a, &b);
    let bytes = crate::testutil::snapshot_bytes(&both);
    let back = decode_snapshot(&bytes, &snap_cx(), &mut Interner::new(), None).unwrap().fragment;
    assert_eq!(back, both);
    let Fragment::Map(m) = &both else { panic!("a map") };
    assert_eq!(m.entries.keys().filter(|id| id.dot == d && id.key.is_some()).count(), 2, "two keyed records of one dot");
}
