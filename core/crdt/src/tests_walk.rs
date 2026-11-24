//! The snapshot encoder reading a stored state a page at a time (`Paged`, spec/crdt.md §4.7, §8):
//! random states (histories, bulk writes, equivocating twins, hostile sequences), random
//! collections kept as pages at random cuts, nested ones among them, random writes gone; the bytes
//! and the pages it writes are those of the whole state's encoding with those writes removed.

use crate::codec::{encode_paged_snapshot, encode_snapshot};
use crate::page::{KeyedPath, MemoryPages, PageParams, PageWalk, Paged, StoredPage};
use crate::paging::{Paths, Step};
use crate::testutil::{frag, history_bulk, history_twins, history_with, mapply, snap_cx};
use crate::wire::{Frontiers, Snapshot};
use crate::{Dot, Error, Fragment};
use crdt_model::ops::Ty;
use crdt_model::r#gen::{Rng, kitchen_sink};
use crdt_model::stamp::Source as MSource;
use osis_base::{ChunkParams, Value};
use std::collections::BTreeMap;

/// A stored page: its first dot, the next page's, its content.
type Row = (Option<Dot>, Option<Dot>, Fragment);

/// A state kept as a node keeps one (notes/engine-paged.md): its collections at `paths` as pages
/// cut at `cuts` (each page's first dot past the first page), the rest as the skeleton.
pub(crate) struct Kept {
    pub(crate) whole: Fragment,
    pub(crate) paths: Paths,
    cuts: BTreeMap<Vec<Step>, Vec<Dot>>,
    /// Each collection's pages, cut once (`rows`).
    rows: BTreeMap<Vec<Step>, Vec<Row>>,
    /// Pages served.
    pub(crate) served: usize,
}

impl Kept {
    /// `whole` with each collection reached through steps kept as pages at `chance` (out of
    /// 4), cut before each element at `cut` (out of 8).
    pub(crate) fn new(r: &mut Rng, whole: Fragment, chance: u64, cut: u64) -> Kept {
        let mut paths = Paths::default();
        let mut cuts = BTreeMap::new();
        for (p, c) in whole.collections() {
            if !r.chance(chance, 4) {
                continue;
            }
            let dots = c.elem_dots(None, None);
            cuts.insert(p.clone(), dots.into_iter().skip(1).filter(|_| r.chance(cut, 8)).collect());
            paths.insert(&p);
        }
        Kept { whole, paths, cuts, rows: BTreeMap::new(), served: 0 }
    }

    /// Kept at a page every `per` elements.
    pub(crate) fn every(whole: Fragment, per: usize) -> Kept {
        let mut paths = Paths::default();
        let mut cuts = BTreeMap::new();
        for (p, c) in whole.collections() {
            cuts.insert(p.clone(), c.elem_dots(None, None).into_iter().step_by(per.max(1)).skip(1).collect());
            paths.insert(&p);
        }
        Kept { whole, paths, cuts, rows: BTreeMap::new(), served: 0 }
    }

    fn below(&self, p: &[Step]) -> Paths {
        Paths { here: false, next: self.paths.below(p).map(|x| x.next.clone()).unwrap_or_default() }
    }

    /// The pages of the collection at `p`, as stored: runs of its elements reduced below.
    fn rows(&mut self, p: &[Step]) -> &[Row] {
        if !self.rows.contains_key(p) {
            let rows = self.cut(p);
            self.rows.insert(p.to_vec(), rows);
        }
        &self.rows[p]
    }

    fn cut(&self, p: &[Step]) -> Vec<Row> {
        let Some(c) = self.whole.at_steps(p) else { return Vec::new() };
        let cuts = self.cuts.get(p).cloned().unwrap_or_default();
        let firsts: Vec<Option<Dot>> = std::iter::once(None).chain(cuts.iter().cloned().map(Some)).collect();
        let nested = self.below(p);
        firsts
            .iter()
            .enumerate()
            .map(|(i, lo)| {
                let hi = cuts.get(i).cloned();
                let page = c.elem_range(lo.as_ref(), hi.as_ref(), false).unwrap_or_default().reduced(&nested);
                (lo.clone(), hi, page)
            })
            .collect()
    }

    /// The path from the root to `p` with each entry step's key and creation (`Fragment::wrap`).
    fn keyed(&self, p: &[Step]) -> Vec<(Step, Option<Value>, Option<crate::Stamp>)> {
        let mut out = Vec::new();
        let mut at = Some(&self.whole);
        for s in p {
            let created = match (s, at) {
                (Step::Entry(id), Some(f)) => f.entry_created(id).cloned(),
                _ => None,
            };
            let key = match s {
                Step::Entry(id) => id.key().cloned(),
                _ => None,
            };
            out.push((s.clone(), key, created));
            at = at.and_then(|f| f.step(s));
        }
        out
    }

    pub(crate) fn skeleton(&self) -> Fragment {
        self.whole.reduced(&self.paths)
    }
}

impl PageWalk for Kept {
    fn pages(&mut self, path: &[Step]) -> Result<usize, Error> {
        Ok(self.rows(path).len())
    }
    fn page(&mut self, path: &[Step], i: usize) -> Result<StoredPage, Error> {
        let (lo, hi, frag) = self.rows(path).get(i).cloned().ok_or(Error::Mismatch("no such page"))?;
        self.served += 1;
        Ok(StoredPage { lo, hi, frag })
    }
    fn keyed(&mut self, path: &[Step]) -> Result<KeyedPath, Error> {
        Ok(Kept::keyed(self, path))
    }
    fn page_of(&mut self, path: &[Step], d: &Dot) -> Result<StoredPage, Error> {
        let (lo, hi, frag) = self.rows(path).iter().rfind(|(lo, _, _)| lo.as_ref().is_none_or(|lo| lo <= d)).cloned().ok_or(Error::Mismatch("no such page"))?;
        self.served += 1;
        Ok(StoredPage { lo, hi, frag })
    }
    fn dots_of(&mut self, path: &[Step], k: &Value) -> Result<Vec<Dot>, Error> {
        let Some(c) = self.whole.at_steps(path) else { return Ok(Vec::new()) };
        Ok(c.elem_dots(None, None).into_iter().filter(|d| c.index_values(d).contains(k)).collect())
    }
}

/// Small enough that most states page on the wire, some at several link levels.
const TINY: PageParams = PageParams { target: 600, cut: ChunkParams { min: 48, max: 192, mask_bits: 4 }, fanout: 4, ..PageParams::FORMAT };

/// An encoding and its pages.
type Encoded = Result<(Vec<u8>, MemoryPages), Error>;

/// The whole encoding of `whole` without the writes `gone` names, and the paged one of `k`, with
/// their pages, at `params`.
fn both(k: &mut Kept, gone: &dyn Fn(&Dot) -> bool, params: PageParams) -> (Encoded, Encoded) {
    let fr = Frontiers::default();
    let mut whole = k.whole.clone();
    whole.remove_gone(gone);
    let s = Snapshot { absorbed: Default::default(), facts: Default::default(), nonce: [3; 16], fragment: whole, frontiers: fr.clone() };
    let mut a = MemoryPages::with_params(params);
    let whole = encode_snapshot(&s, &snap_cx(), Some(&mut a)).map(|b| (b, a));
    let skeleton = k.skeleton();
    let paths = k.paths.clone();
    let mut b = MemoryPages::with_params(params);
    let paged = encode_paged_snapshot(&[3; 16], Paged { skeleton: &skeleton, paths: &paths, pages: k, gone }, &fr, &Default::default(), &Default::default(), &snap_cx(), Some(&mut b)).map(|x| (x, b));
    (whole, paged)
}

/// `both` agree: the same bytes, pages, sources and writes, or both refuse.
fn agree(k: &mut Kept, gone: &dyn Fn(&Dot) -> bool, params: PageParams) -> Result<bool, String> {
    let mut whole = k.whole.clone();
    whole.remove_gone(gone);
    let s = crate::codec::whole_sources(&whole, &snap_cx());
    let skeleton = k.skeleton();
    let paths = k.paths.clone();
    let t = crate::sources_of(Paged { skeleton: &skeleton, paths: &paths, pages: k, gone }, &snap_cx());
    if s != t {
        return Err(format!("sources: whole {s:?}, paged {t:?}"));
    }
    for keys in [false, true] {
        let (mut w, mut present) = (std::collections::BTreeSet::new(), false);
        let read = crate::each_piece(Paged { skeleton: &skeleton, paths: &paths, pages: k, gone }, keys, &mut |f| {
            w.extend(f.writes());
            present |= f.present();
            false
        });
        match read.map_err(|e| format!("pieces: {e:?}"))? {
            Some(false) => {}
            None if keys => continue,
            r => return Err(format!("pieces, keys {keys}: {r:?}")),
        }
        let ww: std::collections::BTreeSet<_> = whole.writes().into_iter().collect();
        if w != ww {
            return Err(format!("the pieces' writes are not the stripped state's (keys {keys}): extra {:?}, missing {:?}", w.difference(&ww).collect::<Vec<_>>(), ww.difference(&w).collect::<Vec<_>>()));
        }
        if present != whole.present() {
            return Err(format!("a piece reads present {present}, the stripped state {}", whole.present()));
        }
    }
    match both(k, gone, params) {
        (Ok((a, pa)), Ok((b, pb))) if a == b && pa.len() == pb.len() => Ok(true),
        (Err(_), Err(_)) => Ok(false),
        (a, b) => Err(format!("whole {:?}, paged {:?}", a.map(|x| x.0.len()), b.map(|x| x.0.len()))),
    }
}

/// The sweep (spec/sync-compaction.md §1) of `k` read a page at a time is the whole state's, for
/// a state reflecting every delta and one reflecting none.
fn sweeps_agree(k: &mut Kept) -> Result<(), String> {
    let r = crate::Stamp::new(crate::testutil::ts(1 << 40), crate::testutil::node(250), 1);
    for all in [true, false] {
        let reflected = |_: &Dot| all;
        let whole = k.whole.sweep(&r, &reflected);
        let skeleton = k.skeleton();
        let paths = k.paths.clone();
        let paged = crate::sweep_paged(Paged { skeleton: &skeleton, paths: &paths, pages: k, gone: &|_| false }, &r, &reflected).map_err(|e| format!("{e:?}"))?;
        if whole != paged {
            return Err(format!("sweep, reflected {all}: whole {whole:?}, paged {paged:?}"));
        }
    }
    Ok(())
}

/// Which writes are gone in a case: none, about a third of the origin dots, or every write of
/// the state's first source.
fn gones(r: &mut Rng, st: &Fragment) -> [std::collections::BTreeSet<Dot>; 3] {
    let dots: std::collections::BTreeSet<Dot> = st.writes().into_iter().map(|(d, _)| d.origin().clone()).collect();
    let some = dots.iter().filter(|_| r.chance(1, 3)).cloned().collect();
    let first = dots.iter().next().map(|d| d.src.clone());
    let one = dots.iter().filter(|d| Some(&d.src) == first.as_ref()).cloned().collect();
    [Default::default(), some, one]
}

/// Random states of one seed: the joined state of a random history (plain, bulk or twins) over
/// the seed's types, and of a hostile sequence history.
fn states(seed: u64) -> Vec<Fragment> {
    let mut r = crate::testutil::fixed(seed);
    let nested = Ty::Map(Box::new(Ty::Register), Box::new(Ty::Map(Box::new(Ty::Register), Box::new(Ty::Set(Box::new(Ty::Register))))));
    let types: Vec<Ty> = match seed % 4 {
        0 => vec![Ty::Text],
        1 => vec![Ty::List(Box::new(Ty::Struct([(1, Ty::Register), (2, Ty::Set(Box::new(Ty::Register)))].into_iter().collect())))],
        2 => vec![nested],
        _ => vec![Ty::Register, Ty::Text, kitchen_sink()],
    };
    let sources: Vec<MSource> = (1..=3).map(|n| MSource::session(n, 0)).collect();
    let commits = match seed / 4 % 3 {
        0 => history_with(&mut r, &types, sources, 4),
        1 => history_bulk(&mut r, &types, sources, 8),
        _ => history_twins(&mut r, &types, vec![MSource::session(1, 0), MSource::session(1, 0), MSource::session(2, 0)], 4),
    };
    let mut state = None;
    for c in commits {
        mapply(&mut state, c.delta);
    }
    let mut hostile = None;
    for d in crdt_model::r#gen::hostile(&mut r, seed.is_multiple_of(2), false) {
        mapply(&mut hostile, d);
    }
    [state, hostile].iter().flatten().map(frag).collect()
}

/// §8: a state encoded a page at a time without the writes gone writes the bytes and pages of the
/// whole state with those writes removed (or both refuse), whatever collections are kept as pages
/// and where they are cut, nested or not. A seed runner, so a property.
#[test]
#[ignore = "property"]
fn paged_snapshot_encodes_as_whole_plain_spec_8() {
    paged_cases("tests_walk::paged_snapshot_encodes_as_whole_plain_spec_8", 0..24);
}

/// `paged_snapshot_encodes_as_whole_plain_spec_8` over more seeds.
#[test]
#[ignore = "property"]
fn paged_snapshot_encodes_as_whole_large_spec_8() {
    paged_cases("tests_walk::paged_snapshot_encodes_as_whole_large_spec_8", 0..600);
}

fn paged_cases(name: &str, seeds: std::ops::Range<u64>) {
    let out = crate::testutil::crdt_seeds(name, seeds, |seed| {
        let mut r = crate::testutil::fixed(seed ^ 0x5eed);
        let mut n = [0usize; 4];
        for st in states(seed) {
            let gones = gones(&mut r, &st);
            for (j, (chance, cut, params)) in [(2, 2, TINY), (4, 4, TINY), (3, 1, PageParams::FORMAT)].into_iter().enumerate() {
                let mut k = Kept::new(&mut r, st.clone(), chance, cut);
                if let Err(e) = sweeps_agree(&mut k) {
                    panic!("seed {seed}, case {j}: {e}");
                }
                n[3] += usize::from(st.sweep(&crate::Stamp::new(crate::testutil::ts(1 << 40), crate::testutil::node(250), 1), &|_| true).is_some());
                for g in &gones {
                    match agree(&mut k, &|d| g.contains(d), params) {
                        Ok(true) => n[0] += 1,
                        Ok(false) => n[1] += 1,
                        Err(e) => panic!("seed {seed}, case {j}, {} gone: {e}", g.len()),
                    }
                }
                n[2] += usize::from(k.served > 0);
            }
        }
        n
    });
    use osis_base::testenv::reach_floor as f;
    f("encoded", out.iter().map(|x| x[0]), 1, 2);
    f("walked pages", out.iter().map(|x| x[2]), 1, 2);
    f("swept something", out.iter().map(|x| x[3]), 1, 2);
}

/// §8: kept as pages of one element each, every collection nested in every other: the walk
/// writes the whole state's bytes (the hardest seams: a sequence's runs and every record on a
/// page of its own).
#[test]
fn single_element_pages_encode_as_whole_spec_8() {
    for seed in 0..12 {
        let mut r = crate::testutil::fixed(seed);
        for st in states(seed) {
            for g in gones(&mut r, &st) {
                let mut k = Kept::every(st.clone(), 1);
                assert_eq!(sweeps_agree(&mut k), Ok(()), "seed {seed}");
                assert_eq!(agree(&mut k, &|d| g.contains(d), TINY), Ok(true), "seed {seed}, {} gone", g.len());
            }
        }
    }
}

/// A hostile state: a map whose one dot names `n` keys (forged copies of one entry, §5.6), each
/// record holding its own inner map of `m` entries, every collection kept as pages of `per`
/// elements. The inner maps' writes are another writer's.
fn one_dot_many_keys(n: usize, m: usize, per: usize) -> Kept {
    use crate::fragment::{Eid, Map};
    use crate::ops::{Op, PathOp};
    use crate::testutil::{s, wrote};
    let inner = |k: usize| Value::Map((0..m).map(|j| (s(&format!("e{k}.{j:04}")), Value::Int(j as i64))).collect());
    let v = Value::Map((0..n).map(|k| (s(&format!("k{k:04}")), inner(k))).collect());
    let f = wrote(&Fragment::default(), 1, 1, &[PathOp { path: vec![], op: Op::Set(v) }], &crate::view::AnyView);
    let Fragment::Map(mut map) = f else { panic!("a map") };
    let one = map.entries.keys().next().expect("an entry").dot.clone();
    let entries = std::mem::take(&mut map.entries)
        .into_iter()
        .map(|(id, mut e)| {
            if let Some(c) = e.created.as_mut() {
                c.dot = one.clone();
            }
            (Eid { dot: one.clone(), key: id.key }, e)
        })
        .collect();
    let mut f = Fragment::Map(Map::new(map.meta, entries));
    f.prune(None, &mut crate::Changes::new());
    Kept::every(f, per)
}

/// §8, decode bounds (notes/decode-bounds.md): a snapshot's writer holds a page per collection it
/// is inside, whatever a dot names: one dot naming 4 or 64 keys, each record holding a paged
/// collection, with or without the forged entry's own writes gone (each write sits in one record,
/// so each page strips alone), is encoded as the whole state encodes, holding at once
/// (`snapshot: state held`) a page and, per paged collection below it, a record shell (the
/// node's page index holds as much per collection): never an element per record, nor a page per
/// key (4.6 KB a key with an element each, 3.2 KB pages).
#[test]
fn one_dot_many_keys_holds_a_page_at_a_time_spec_8() {
    let held = |n: usize, strip: bool| {
        let mut k = one_dot_many_keys(n, 40, 4);
        let outer: std::collections::BTreeSet<Dot> = match &k.whole {
            Fragment::Map(m) => m.entries.keys().map(|id| id.dot.clone()).collect(),
            _ => Default::default(),
        };
        let gone = |d: &Dot| strip && outer.contains(d);
        assert_eq!(agree(&mut k, &gone, TINY), Ok(true), "{n} keys");
        let skeleton = k.skeleton();
        let paths = k.paths.clone();
        osis_base::costs::take();
        let mut b = MemoryPages::with_params(TINY);
        encode_paged_snapshot(&[3; 16], Paged { skeleton: &skeleton, paths: &paths, pages: &mut k, gone: &gone }, &Frontiers::default(), &Default::default(), &Default::default(), &snap_cx(), Some(&mut b)).expect("encodes");
        let c = osis_base::costs::take();
        c.iter().find(|x| x.0 == "snapshot: state held").map(|x| x.2).expect("counted")
    };
    for strip in [false, true] {
        let (small, big) = (held(4, strip), held(64, strip));
        assert!(big.saturating_sub(small) / 60 < 1024, "held at once, strip {strip}: {small} at 4 keys, {big} at 64");
    }
}

/// spec/sync-compaction.md §1 Sweep: an edit hidden in an inner entry its removal took, inside a
/// map paged in an entry whose content is all paged (the stored page keeps that entry's creation
/// alone): read a page at a time, the entry reads live (`View` grafts its paged map in) and the
/// sweep reaches the hidden edit as the whole state's does.
#[test]
fn sweep_reaches_below_an_entry_holding_only_paged_content_spec_sync_7() {
    use crate::ops::{Op, PathOp, PathSeg};
    use crate::testutil::{joined, s, wrote};
    let any = crate::view::AnyView;
    let inner = Value::Map((0..24).map(|j| (s(&format!("k{j:02}")), Value::Int(j))).collect());
    let base = wrote(&Fragment::default(), 1, 1, &[PathOp { path: vec![], op: Op::Set(Value::Map([(s("a"), inner)].into_iter().collect())) }], &any);
    let at = |k: &str| vec![PathSeg::Key(s("a")), PathSeg::Key(s(k))];
    let removed = wrote(&base, 2, 2, &[PathOp { path: vec![PathSeg::Key(s("a"))], op: Op::Remove(s("k05")) }], &any);
    let edited = wrote(&base, 3, 3, &[PathOp { path: at("k05"), op: Op::Set(Value::Int(50)) }], &any);
    let st = joined(&joined(&base, &removed), &edited);
    let r = crate::Stamp::new(crate::testutil::ts(1 << 40), crate::testutil::node(250), 1);
    assert!(st.sweep(&r, &|_| true).is_some(), "the hidden edit is swept");
    let mut k = Kept::every(st, 4);
    assert_eq!(sweeps_agree(&mut k), Ok(()));
}

/// The bytes of `f` encoded whole as a snapshot, at `params`.
fn whole_bytes(f: &Fragment, params: PageParams) -> Encoded {
    let s = Snapshot { absorbed: Default::default(), facts: Default::default(), nonce: [3; 16], fragment: f.clone(), frontiers: Frontiers::default() };
    let mut a = MemoryPages::with_params(params);
    encode_snapshot(&s, &snap_cx(), Some(&mut a)).map(|b| (b, a))
}

/// Whether `over` joins `k` a page at a time (`Joined`; osis-engine `pages::joins_by_page`): no
/// collection paged inside another's elements, no paged sequence, and each paged collection
/// keeps its encoding.
fn joins_by_page(k: &Kept, over: &Fragment, pre: &dyn Fn(&Dot) -> bool) -> bool {
    let paths: Vec<Vec<Step>> = k.whole.collections().into_iter().map(|(p, _)| p).filter(|p| k.paths.below(p).is_some_and(|x| x.here)).collect();
    let nested = paths.iter().any(|p| paths.iter().any(|q| q.len() < p.len() && p.starts_with(q)));
    let enc = |p: &[Step]| k.whole.at_steps(p).map(Fragment::encoding);
    if nested || paths.iter().any(|p| matches!(enc(p), Some(crate::Encoding::List | crate::Encoding::Text))) || !paths.iter().all(|p| over.steps_through(p)) {
        return false;
    }
    let mut j = k.skeleton();
    j.remove_gone(pre);
    j.join(over.clone());
    paths.iter().all(|p| j.at_steps(p).is_none_or(|x| Some(x.encoding()) == enc(p)))
}

/// §8 Values: a random history's bodies, a random subset of them with an end. The join of the
/// bodies each without the writes that end (the state as it reads once they end) is the joined
/// state without those writes joined with what they reach in each body without them (osis-engine
/// `retention::snapshot::superseded`); and, the joined state kept as pages at random cuts, read a
/// page at a time with that joined in (`Joined`) it encodes as that state whole.
#[test]
fn joined_pages_read_as_the_bodies_without_writes_that_end_spec_8() {
    let mut paged = 0;
    for seed in 0..16u64 {
        let mut r = crate::testutil::fixed(seed ^ 0x101d);
        let types: Vec<Ty> = match seed % 4 {
            0 => vec![Ty::Text],
            1 => vec![Ty::Map(Box::new(Ty::Register), Box::new(Ty::Register))],
            2 => vec![Ty::Map(Box::new(Ty::Register), Box::new(Ty::Map(Box::new(Ty::Register), Box::new(Ty::Set(Box::new(Ty::Register))))))],
            _ => vec![Ty::Register, kitchen_sink()],
        };
        let sources: Vec<MSource> = (1..=3).map(|n| MSource::session(n, 0)).collect();
        let commits = if seed / 4 % 2 == 0 { history_with(&mut r, &types, sources, 4) } else { history_bulk(&mut r, &types, sources, 6) };
        let bodies: Vec<Fragment> = commits.iter().map(|c| frag(&c.delta)).collect();
        let mut st = Fragment::default();
        for b in &bodies {
            st.join(b.clone());
        }
        let ending: std::collections::BTreeSet<Dot> = bodies.iter().filter(|_| r.chance(1, 3)).flat_map(|b| b.writes().into_iter().map(|(d, _)| d.origin().clone())).collect();
        let pre = |d: &Dot| ending.contains(d);
        let (mut want, mut x, mut over) = (Fragment::default(), Fragment::default(), Fragment::default());
        for b in &bodies {
            let mut w = b.clone();
            w.remove_writes(&pre);
            want.join(w);
            let mut e = b.clone();
            e.remove_writes(&|d| !pre(d));
            x.join(e);
        }
        for b in &bodies {
            let mut g = b.reach(&x);
            g.remove_writes(&pre);
            over.join(g);
        }
        want.compact();
        let mut got = st.clone();
        got.remove_gone(&pre);
        got.join(over.clone());
        let expect = whole_bytes(&want, TINY).map(|x| x.0);
        assert_eq!(whole_bytes(&got, TINY).map(|x| x.0), expect, "seed {seed}: the stored state without the ending writes joined with what they reach");
        for (chance, cut) in [(4, 4), (2, 2)] {
            let mut k = Kept::new(&mut r, st.clone(), chance, cut);
            if !joins_by_page(&k, &over, &pre) {
                continue;
            }
            paged += usize::from(!k.paths.is_empty());
            let skeleton = k.skeleton();
            let paths = k.paths.clone();
            let (mut j, sk) = crate::Joined::new(&mut k, &skeleton, &paths, &over, &pre);
            let mut b = MemoryPages::with_params(TINY);
            let p = encode_paged_snapshot(&[3; 16], Paged { skeleton: &sk, paths: &paths, pages: &mut j, gone: &|_| false }, &Frontiers::default(), &Default::default(), &Default::default(), &snap_cx(), Some(&mut b));
            assert_eq!(p, expect, "seed {seed}, chance {chance}: read a page at a time");
        }
    }
    assert!(paged > 4, "few paged cases: {paged}");
}
