//! Streamed decode (spec/crdt.md §3.3, §8; `stream.rs`): the streaming canonical check accepts
//! and rejects exactly what the whole re-encode did (`codec::oracle`), on mutated roots and
//! pages; joining the pieces equals joining the whole; one page at a time in memory.

use crate::codec::{encode_delta, encode_snapshot, oracle};
use crate::page::{PageError, PageParams, PageSink, PageSource};
use crate::stamp::Interner;
use crate::stream::Piece;
use crate::tests_decoder::{mutate, mutate_tree};
use crate::testutil::{MCommit, frag, history_bulk, history_with, mapply, sess};
use crate::tests_wire::{snap_cx, writer_cx};
use crate::wire::{Delta, DeltaCtx, Frontiers, Snapshot};
use crate::{Fragment, decode_delta, decode_snapshot, stream_delta, stream_snapshot};
use crdt_model::ops::Ty;
use crdt_model::r#gen::{Rng, kitchen_sink};
use crdt_model::stamp::Source as MSource;
use osis_base::{BlobId, ChunkParams, Link};
use proptest::prelude::*;

/// Pages by blob ID, never hash-checked, so a mutated page reaches the decoder.
#[derive(Clone, Debug)]
struct Blobs {
    pages: Vec<Vec<u8>>,
    params: PageParams,
}

impl Blobs {
    fn new(params: PageParams) -> Blobs {
        Blobs { pages: Vec::new(), params }
    }
}

impl PageSink for Blobs {
    fn put(&mut self, p: &[u8]) -> Result<Link, PageError> {
        let mut blob = [0u8; 32];
        blob[..8].copy_from_slice(&(self.pages.len() as u64).to_le_bytes());
        self.pages.push(p.to_vec());
        Ok(Link { hash: osis_base::hash::hash(p), blob: BlobId(blob), suite: 1, key: [0; 32] })
    }
    fn params(&self) -> PageParams {
        self.params
    }
}

impl PageSource for Blobs {
    fn get(&mut self, l: &Link) -> Result<Vec<u8>, PageError> {
        let i = u64::from_le_bytes(l.blob.0[..8].try_into().unwrap());
        self.pages.get(i as usize).cloned().ok_or(PageError::Missing)
    }
    fn params(&self) -> PageParams {
        self.params
    }
}

/// Small enough that most fragments page, some at two levels.
const TINY: PageParams = PageParams { target: 1500, cut: ChunkParams { min: 48, max: 192, mask_bits: 4 }, fanout: 8, ..PageParams::FORMAT };
/// Larger pages: one level, pages of several sequence runs.
const SMALL: PageParams = PageParams { target: 2000, cut: ChunkParams { min: 128, max: 1024, mask_bits: 6 }, fanout: 8, ..PageParams::FORMAT };

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// One input: a delta or snapshot root and its pages.
struct Input {
    root: Vec<u8>,
    pages: Option<Blobs>,
    cx: DeltaCtx,
    snapshot: bool,
}

impl Input {
    fn whole(&self) -> Result<Fragment, crate::Error> {
        let mut p = self.pages.clone();
        let src = p.as_mut().map(|p| p as &mut dyn PageSource);
        if self.snapshot { oracle::decode_snapshot(&self.root, &self.cx, &mut Interner::new(), src).map(|s| s.fragment) } else { oracle::decode_delta(&self.root, &self.cx, &mut Interner::new(), src).map(|d| d.fragment) }
    }
    fn streamed(&self) -> Result<Fragment, crate::Error> {
        let mut p = self.pages.clone();
        let src = p.as_mut().map(|p| p as &mut dyn PageSource);
        if self.snapshot { decode_snapshot(&self.root, &self.cx, &mut Interner::new(), src).map(|s| s.fragment) } else { decode_delta(&self.root, &self.cx, &mut Interner::new(), src).map(|d| d.fragment) }
    }
    /// The pieces `stream_*` hands over, or its error.
    fn pieces(&self) -> Result<Vec<Piece>, crate::Error> {
        let mut p = self.pages.clone();
        let src = p.as_mut().map(|p| p as &mut dyn PageSource);
        let mut out = Vec::new();
        let mut each = |x: Piece| {
            out.push(x);
            Ok(())
        };
        if self.snapshot {
            stream_snapshot(&self.root, &self.cx, &mut Interner::new(), src, &mut each)?;
        } else {
            stream_delta(&self.root, &self.cx, &mut Interner::new(), src, &mut each)?;
        }
        Ok(out)
    }
    /// Old and new decoders agree: both reject, or both accept the same fragment.
    fn agree(&self) -> Result<bool, String> {
        match (self.whole(), self.streamed()) {
            (Ok(a), Ok(b)) if a == b => Ok(true),
            (Err(_), Err(_)) => Ok(false),
            (a, b) => {
                let pages: Vec<String> = self.pages.iter().flat_map(|p| p.pages.iter().map(|x| hex(x))).collect();
                Err(format!("root {} pages {pages:?}: old {a:?}, new {b:?}", hex(&self.root)))
            }
        }
    }
}

/// The encodings of a random history: each commit's delta and the joined state's snapshot,
/// paged at `params` (`None`: unpaged); those needing a third page level are left out.
fn inputs(seed: u64, types: &[Ty], params: Option<PageParams>) -> (Vec<Input>, Vec<MCommit>) {
    let mut r = crate::testutil::rng(seed | 1);
    // where paging is tested, writers start with large writes, so those and the states page
    let sources = (1..=3).map(|n| MSource::session(n, 0)).collect();
    let commits = if params.is_some() { history_bulk(&mut r, types, sources, 12) } else { history_with(&mut r, types, sources, 3) };
    let mut out = Vec::new();
    let mut state = None;
    for c in &commits {
        let cx = writer_cx(&c.w);
        let mut pages = params.map(Blobs::new);
        let d = Delta { nonce: [7; 16], fragment: frag(&c.delta) };
        if let Ok(root) = encode_delta(&d, &cx, pages.as_mut().map(|p| p as &mut dyn PageSink)) {
            out.push(Input { root, pages, cx, snapshot: false });
        }
        mapply(&mut state, c.delta.clone());
    }
    if let Some(st) = &state {
        let s = Snapshot { absorbed: Default::default(), nonce: [3; 16], fragment: frag(st), frontiers: Frontiers::default() };
        let mut pages = params.map(Blobs::new);
        if let Ok(root) = encode_snapshot(&s, &snap_cx(), pages.as_mut().map(|p| p as &mut dyn PageSink)) {
            out.push(Input { root, pages, cx: snap_cx(), snapshot: true });
        }
    }
    (out, commits)
}

/// A mutant of `i`: its root or one of its pages changed bytewise or by one value node.
fn mutant(r: &mut Rng, i: &Input) -> Input {
    let mut root = i.root.clone();
    let mut pages = i.pages.clone();
    let page = pages.as_mut().filter(|p| !p.pages.is_empty() && r.chance(2, 3));
    let target = match page {
        Some(p) => {
            let k = r.below(p.pages.len());
            &mut p.pages[k]
        }
        None => &mut root,
    };
    if r.chance(1, 2) {
        mutate(r, target);
    } else if let Some(b) = mutate_tree(r, target) {
        *target = b;
    }
    Input { root, pages, cx: i.cx.clone(), snapshot: i.snapshot }
}

/// Every input and `per` mutants of each: old and new agree (where `paging`, only inputs that
/// paged: the others repeat the unpaged case). Returns (accepted, rejected, inputs that paged).
fn differential(seed: u64, ins: &[Input], paging: bool, per: usize) -> Result<(usize, usize, usize), String> {
    let mut r = crate::testutil::rng(seed ^ 0x5eed);
    let mut n = (0, 0, 0);
    for i in ins {
        let paged = i.pages.as_ref().is_some_and(|p| !p.pages.is_empty());
        if paging && !paged {
            continue;
        }
        if !i.agree()? {
            return Err(format!("unmutated input rejected: {:?}", i.streamed()));
        }
        n.2 += usize::from(paged);
        for _ in 0..per {
            if mutant(&mut r, i).agree()? { n.0 += 1 } else { n.1 += 1 }
        }
    }
    Ok(n)
}

/// Joining `pieces` into `base` in order (or reversed).
fn join_pieces(base: &Fragment, pieces: &[Piece], rev: bool) -> Fragment {
    let mut st = base.clone();
    let mut fs: Vec<&Fragment> = pieces
        .iter()
        .map(|p| match p {
            Piece::Skeleton(f) => f,
            Piece::Page { fragment, .. } => fragment,
        })
        .collect();
    if rev {
        fs.reverse();
    }
    for f in fs {
        st.join(f.clone());
    }
    st
}

/// §8: each input's pieces, joined into the history's states before each commit (and an empty
/// state), equal the whole fragment joined there, in wire order and reversed; a page piece is
/// the skeleton's position holding that page's elements only.
fn joins_equal(seed: u64, ins: &[Input], commits: &[MCommit]) -> Result<usize, String> {
    let mut bases = vec![Fragment::default()];
    let mut state = None;
    for c in commits {
        mapply(&mut state, c.delta.clone());
        bases.extend(state.as_ref().map(frag));
    }
    let mut paged = 0;
    for i in ins.iter().filter(|i| i.pages.as_ref().is_some_and(|p| !p.pages.is_empty())) {
        let whole = i.streamed().map_err(|e| e.to_string())?;
        let pieces = i.pieces().map_err(|e| e.to_string())?;
        paged += usize::from(pieces.len() > 1);
        for p in &pieces {
            if let Piece::Page { path, fragment } = p
                && fragment.at_steps(path).is_none()
            {
                return Err(format!("piece without its path {path:?}"));
            }
        }
        for b in bases.iter().step_by(8).chain(bases.last()) {
            let mut want = b.clone();
            want.join(whole.clone());
            for rev in [false, true] {
                if join_pieces(b, &pieces, rev) != want {
                    return Err(format!("seed {seed}: pieces joined differ (reversed {rev}) for root {}", hex(&i.root)));
                }
            }
        }
    }
    Ok(paged)
}

/// Per case: one text, one list of structs (all writers on one type, so the root is no
/// `Slots` and its sequence streams), or every encoding nested next to a register and a text.
fn types(k: u64) -> Vec<Ty> {
    let inner = Ty::Struct([(1, Ty::Register), (2, Ty::Set(Box::new(Ty::Register)))].into_iter().collect());
    match k % 3 {
        0 => vec![Ty::Text],
        1 => vec![Ty::List(Box::new(inner))],
        // the kitchen sink writer last: a root register write before it would reset it
        _ => vec![Ty::Register, Ty::Text, kitchen_sink()],
    }
}

/// Mutants per input: 6 in the default tests, 30 with `OSIS_SLOW`.
fn per() -> usize {
    if std::env::var_os("OSIS_SLOW").is_some() { 30 } else { 6 }
}

/// One case: the seed picks the types and the page parameters (one set per case keeps a case
/// well under a second).
fn case(seed: u64) -> Result<(usize, usize, usize, usize), String> {
    let types = types(seed);
    let params = [None, Some(TINY), Some(SMALL)][(seed / 3 % 3) as usize];
    let (ins, commits) = inputs(seed, &types, params);
    let (a, r, p) = differential(seed, &ins, params.is_some(), per())?;
    let pieces = if params.is_some() { joins_equal(seed, &ins, &commits)? } else { 0 };
    Ok((a, r, p, pieces))
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(12))]

    /// §3.3, §8: text, list and kitchen-sink deltas and snapshots, unpaged and paged, mutated
    /// in the root or a page: the streaming check decides as the whole re-encode; where they
    /// accept, joining the pieces equals joining the whole, into every kind of prior state.
    #[test]
    fn stream_check_matches_whole_spec_8(seed in any::<u64>()) {
        if let Err(e) = case(seed) {
            prop_assert!(false, "{}", e);
        }
    }
}

/// The differential pages often and rejects and accepts mutants both (else it tests nothing).
#[test]
fn stream_differential_covers_paging_spec_8() {
    let mut n = (0, 0, 0, 0);
    for seed in 0..18u64 {
        let m = case(seed).unwrap();
        n = (n.0 + m.0, n.1 + m.1, n.2 + m.2, n.3 + m.3);
    }
    assert!(n.0 > 30 && n.1 > 100 && n.2 > 8 && n.3 > 8, "accepted, rejected, paged inputs, streamed in pieces {n:?}");
}

/// `stream_check_matches_whole_spec_8` at size (a property).
#[test]
#[ignore = "property"]
fn stream_check_matches_whole_large_spec_8() {
    for seed in 0..600u64 {
        if let Err(e) = case(seed) {
            panic!("seed {seed}: {e}");
        }
    }
}

/// §8: leaf links swapped, a leaf dropped or repeated, a page's run split at a seam: rejected
/// by both (pages ascend across seams; runs stay maximal across them).
#[test]
fn stream_seams_spec_8() {
    let st = crate::tests_life::big_set(400, 5);
    let s = Snapshot { absorbed: Default::default(), nonce: [0; 16], fragment: st.clone(), frontiers: Frontiers::default() };
    let mut pages = Blobs::new(SMALL);
    let root = encode_snapshot(&s, &snap_cx(), Some(&mut pages)).unwrap();
    let ok = Input { root: root.clone(), pages: Some(pages.clone()), cx: snap_cx(), snapshot: true };
    assert!(ok.agree().unwrap());
    let top = osis_base::decode(&root, &osis_base::Limits::DEFAULT).unwrap();
    let with = |f: &dyn Fn(&mut Vec<osis_base::Value>)| {
        let osis_base::Value::List(mut a) = top.clone() else { panic!() };
        let Some(osis_base::Value::List(frag)) = a.get_mut(3) else { panic!() };
        let Some(osis_base::Value::List(links)) = frag.get_mut(3) else { panic!() };
        f(links);
        Input { root: osis_base::encode(&osis_base::Value::List(a)), pages: Some(pages.clone()), cx: snap_cx(), snapshot: true }
    };
    for (why, i) in [("swapped", with(&|l| l.swap(0, 1))), ("repeated", with(&|l| l.push(l[0].clone())))] {
        assert!(!i.agree().unwrap(), "{why}");
    }
    // a page left out is a canonical snapshot of fewer elements (pages cut by content)
    assert!(with(&|l| drop(l.remove(1))).agree().unwrap());
    // a text whose runs straddle a page seam: moving a page's first run onto the page before
    // splits nothing the old check accepted
    for seed in 0..4 {
        for i in inputs(seed, &[Ty::Text], Some(TINY)).0 {
            let Some(p) = &i.pages else { continue };
            for k in 1..p.pages.len() {
                let (Ok(osis_base::Value::List(a)), Ok(osis_base::Value::List(b))) = (osis_base::decode(&p.pages[k - 1], &osis_base::Limits::DEFAULT), osis_base::decode(&p.pages[k], &osis_base::Limits::DEFAULT)) else { continue };
                if b.len() < 2 || a.iter().chain(&b).any(|x| matches!(x, osis_base::Value::Link(_))) {
                    continue;
                }
                let mut q = p.clone();
                let mut a2 = a.clone();
                a2.push(b[0].clone());
                q.pages[k - 1] = osis_base::encode(&osis_base::Value::List(a2));
                q.pages[k] = osis_base::encode(&osis_base::Value::List(b[1..].to_vec()));
                assert!(!Input { root: i.root.clone(), pages: Some(q), cx: i.cx.clone(), snapshot: i.snapshot }.agree().unwrap());
            }
        }
    }
}


/// A page's items: an array's elements, or a field map's entries as pairs.
fn page_items(b: &[u8]) -> Option<(bool, Vec<osis_base::Value>)> {
    use osis_base::Value as V;
    match osis_base::decode(b, &osis_base::Limits::DEFAULT).ok()? {
        V::List(a) if !a.iter().any(|x| matches!(x, V::Link(_))) => Some((false, a)),
        V::Map(m) => Some((true, m.into_iter().map(|(k, v)| V::List(vec![k, v])).collect())),
        _ => None,
    }
}

fn page_bytes(map: bool, items: Vec<osis_base::Value>) -> Vec<u8> {
    use osis_base::Value as V;
    if !map {
        return osis_base::encode(&V::List(items));
    }
    let pairs = items.into_iter().filter_map(|x| match x {
        V::List(mut kv) if kv.len() == 2 => {
            let v = kv.pop()?;
            Some((kv.pop()?, v))
        }
        _ => None,
    });
    osis_base::encode(&V::Map(pairs.collect()))
}

/// §8 seams: leaf pages re-cut at random (items moved across a seam either way, copied across
/// it, a page emptied, two pages' contents swapped, a leaf turned into a link page): both
/// decoders decide alike.
#[test]
fn stream_recut_pages_spec_8() {
    use osis_base::Value as V;
    let mut n = (0, 0);
    for seed in 0..24u64 {
        let mut r = crate::testutil::rng(seed ^ 0x5ea3);
        let params = if seed % 2 == 0 { TINY } else { SMALL };
        for i in inputs(seed, &types(seed), Some(params)).0 {
            let Some(p) = &i.pages else { continue };
            if p.pages.len() < 2 {
                continue;
            }
            for _ in 0..12 {
                let mut q = p.clone();
                let k = 1 + r.below(q.pages.len() - 1);
                let (Some((ma, mut a)), Some((mb, mut b))) = (page_items(&q.pages[k - 1]), page_items(&q.pages[k])) else { continue };
                match r.below(6) {
                    0 if !b.is_empty() => {
                        let t = 1 + r.below(b.len());
                        a.extend(b.drain(..t));
                    }
                    1 if !a.is_empty() => {
                        let t = 1 + r.below(a.len());
                        let tail = a.split_off(a.len() - t);
                        b.splice(0..0, tail);
                    }
                    2 if !a.is_empty() => b.insert(0, a[a.len() - 1].clone()),
                    3 => b.clear(),
                    4 => std::mem::swap(&mut a, &mut b),
                    _ => {
                        let l = Link { hash: osis_base::hash::hash(&q.pages[k]), blob: BlobId([0; 32]), suite: 1, key: [0; 32] };
                        q.pages[k - 1] = osis_base::encode(&V::List(vec![V::link(l)]));
                        let m = Input { root: i.root.clone(), pages: Some(q), cx: i.cx.clone(), snapshot: i.snapshot };
                        if m.agree().unwrap() { n.0 += 1 } else { n.1 += 1 }
                        continue;
                    }
                }
                q.pages[k - 1] = page_bytes(ma, a);
                q.pages[k] = page_bytes(mb, b);
                let m = Input { root: i.root.clone(), pages: Some(q), cx: i.cx.clone(), snapshot: i.snapshot };
                if m.agree().unwrap() { n.0 += 1 } else { n.1 += 1 }
            }
        }
    }
    assert!(n.1 > 100, "accepted, rejected {n:?}");
}

/// §3.3 rule 1: a `Commits` entry no stamp uses is refused, whatever its `base` (the check's
/// "none seen" mark, `u64::MAX`, lies above every counter a `Value` holds).
#[test]
fn unused_commit_entry_refused_spec_3_3() {
    use osis_base::Value as V;
    let mut n = 0;
    for seed in 0..6 {
        for i in inputs(seed, &types(seed), None).0 {
            let V::List(top) = osis_base::decode(&i.root, &osis_base::Limits::DEFAULT).unwrap() else { panic!() };
            let Some(V::List(groups)) = top.get(2) else { panic!() };
            let Some(V::List(g)) = groups.last() else { continue };
            let Some(V::List(entries)) = g.get(1) else { panic!() };
            for base in [1, i64::MAX] {
                let mut e = entries.clone();
                e.push(V::List(vec![V::Int(1), V::Int(0), V::Int(base)]));
                let mut t = top.clone();
                let V::List(gs) = &mut t[2] else { panic!() };
                let last = gs.len() - 1;
                let V::List(g) = &mut gs[last] else { panic!() };
                g[1] = V::List(e);
                let m = Input { root: osis_base::encode(&V::List(t)), pages: None, cx: i.cx.clone(), snapshot: i.snapshot };
                assert_eq!(m.agree(), Ok(false), "seed {seed} base {base}");
                n += 1;
            }
        }
    }
    assert!(n > 4, "{n} cases");
}

/// §3.3 rule 1, 3: in a list run cut at `CHUNK_MAX`, sources count as if it were not cut: a
/// source first in the second chunk's content precedes one first in the first chunk's position
/// writes. The model's bytes, accepted by both decoders.
#[test]
fn sources_order_ignores_chunk_cut_spec_3_3() {
    chunk_cut_case(false);
    chunk_cut_case(true);
}

/// `nested`: each element also holds a text before the edited register (its runs close inside
/// the outer run's later chunk).
fn chunk_cut_case(nested: bool) {
    use crdt_model::value::Value as MV;
    let mut fields = vec![(1, Ty::Register), (2, Ty::Register)];
    if nested {
        fields.push((0, Ty::Text));
    }
    let ty = Ty::List(Box::new(Ty::Struct(fields.into_iter().collect())));
    let elem = |i: usize, tag: i64| {
        let mut f = vec![(1, MV::Str(format!("{i}{}", "x".repeat(128 * 1024 - 16)))), (2, MV::Int(tag))];
        if nested {
            f.push((0, MV::Str("ab".into())));
        }
        MV::fields(f)
    };
    let mut a = crdt_model::ops::Writer::new(MSource::session(1, 0), 5 << 16, 1);
    let mut state = None;
    let d = crdt_model::ops::create(&mut a, &ty, &MV::List((0..6).map(|i| elem(i, 0)).collect()));
    mapply(&mut state, d);
    // node 2 moves the first element (a position write in the first chunk)
    let mut b = crdt_model::ops::Writer::new(MSource::session(2, 0), 6 << 16, 1);
    let d = crdt_model::ops::seq_move(&mut b, state.as_ref().unwrap(), 0, 1, 2).unwrap();
    mapply(&mut state, d);
    // node 3 edits the fifth element's register (content of the second chunk)
    let mut c = crdt_model::ops::Writer::new(MSource::session(3, 0), 7 << 16, 1);
    let mut v = state.as_ref().unwrap().read().unwrap();
    let MV::List(items) = &mut v else { panic!() };
    let MV::Map(m) = &mut items[4] else { panic!("{:?}", items[4]) };
    for (k, x) in m.iter_mut() {
        if *k == MV::Int(2) {
            *x = MV::Int(9);
        }
    }
    let d = crdt_model::diff::diff(&mut c, state.as_ref(), &ty, &v).unwrap();
    mapply(&mut state, d);
    let st = state.unwrap();
    let mbytes = crdt_model::wire::encode_snapshot(&st, &[], [3; 16], &mut crdt_model::wire::Ctx::new(1 << 40, MSource::session(250, 0), 1));
    let s = Snapshot { absorbed: Default::default(), nonce: [3; 16], fragment: frag(&st), frontiers: Frontiers::default() };
    let mut flat = Blobs::new(PageParams { target: usize::MAX, ..PageParams::FORMAT });
    let bytes = encode_snapshot(&s, &snap_cx(), Some(&mut flat)).unwrap();
    assert_eq!(bytes, mbytes, "the model's bytes");
    let i = Input { root: bytes, pages: Some(flat), cx: snap_cx(), snapshot: true };
    assert_eq!(i.streamed().unwrap(), s.fragment);
    assert!(i.agree().unwrap());
    // the run was cut, and session 3 precedes session 2 in `Sources`
    let osis_base::Value::List(top) = osis_base::decode(&i.root, &osis_base::Limits { max_bytes: usize::MAX, ..osis_base::Limits::DEFAULT }).unwrap() else { panic!() };
    let osis_base::Value::List(srcs) = &top[1] else { panic!() };
    let src = |n: u8| match crate::testutil::source(&MSource::session(n, 0)).kind() {
        crate::SourceKind::Session(s) => osis_base::Value::Bytes(s.to_bytes().to_vec()),
        _ => panic!(),
    };
    assert_eq!(srcs, &vec![src(1), src(3), src(2)]);
    let osis_base::Value::List(f) = &top[3] else { panic!() };
    let osis_base::Value::List(runs) = &f[3] else { panic!() };
    assert!(runs.len() >= 2, "one run cut at CHUNK_MAX: {} runs", runs.len());
}

/// Peak resident set (KiB) since the last `reset_peak` (Linux `VmHWM`).
fn peak_kib() -> u64 {
    let s = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
    s.lines().find_map(|l| l.strip_prefix("VmHWM:")).and_then(|v| v.split_whitespace().next()?.parse().ok()).unwrap_or(0)
}

fn rss_kib() -> u64 {
    let s = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
    s.lines().find_map(|l| l.strip_prefix("VmRSS:")).and_then(|v| v.split_whitespace().next()?.parse().ok()).unwrap_or(0)
}

/// Memory of one decode step (a child process per step, so no step reuses another's freed
/// memory): `OSIS_STREAM_PHASE=<phase>:<delta|snapshot>:<dir>` with the inputs
/// `stream_memory_big_map` wrote there.
fn stream_memory_child(arg: &str) {
    let mut parts = arg.splitn(3, ':');
    let (phase, name, dir) = (parts.next().unwrap(), parts.next().unwrap(), parts.next().unwrap());
    let read = |n: &str| std::fs::read(format!("{dir}/{n}")).unwrap();
    let range: Vec<u64> = String::from_utf8(read("range")).unwrap().split(' ').map(|x| x.parse().unwrap()).collect();
    let n: usize = String::from_utf8(read("pages")).unwrap().parse().unwrap();
    let mut pages = Blobs::new(PageParams::FORMAT);
    pages.pages = (0..n).map(|k| read(&format!("p{k}"))).collect();
    let node = sess(osis_base::Tid::from_bytes([1; 15]));
    let snapshot = name == "snapshot";
    let cx = if snapshot { snap_cx() } else { DeltaCtx { ts: crate::testutil::ts(1 << 20), own: node, range: crate::CounterRange { lo: range[0], hi: range[1] }, kind: crate::DeltaKind::Writer } };
    if let Some(old) = phase.strip_prefix("encode-").map(|x| x == "old") {
        // the delta re-made, then encoded (the whole encoder or the streaming one)
        let (d, cx, _map) = big_map();
        let delta = Delta { nonce: [0; 16], fragment: d };
        let mut sink = Blobs::new(PageParams::FORMAT);
        let _ = std::fs::write("/proc/self/clear_refs", "5");
        let start = rss_kib();
        let ok = if old { oracle::encode_delta(&delta, &cx, Some(&mut sink)) } else { crate::codec::encode_delta_in(&delta, &cx, Some(&mut sink)) };
        assert_eq!(ok.unwrap(), read("delta"));
        println!("MEM {phase} delta: peak {} KiB above start", peak_kib().saturating_sub(start));
        return;
    }
    let root = read(name);
    let src = Some(&mut pages as &mut dyn PageSource);
    let mut interner = Interner::new();
    let _ = std::fs::write("/proc/self/clear_refs", "5");
    let start = rss_kib();
    let mut piece_max = 0usize;
    let mut each = |x: Piece| {
        let f = match &x {
            Piece::Skeleton(f) | Piece::Page { fragment: f, .. } => f,
        };
        piece_max = piece_max.max(f.approx_bytes());
        Ok(())
    };
    let ok = match (phase, snapshot) {
        ("old", false) => oracle::decode_delta(&root, &cx, &mut interner, src).is_ok(),
        ("old", true) => oracle::decode_snapshot(&root, &cx, &mut interner, src).is_ok(),
        ("whole", false) => decode_delta(&root, &cx, &mut interner, src).is_ok(),
        ("whole", true) => decode_snapshot(&root, &cx, &mut interner, src).is_ok(),
        (_, false) => stream_delta(&root, &cx, &mut interner, src, &mut each).is_ok(),
        (_, true) => stream_snapshot(&root, &cx, &mut interner, src, &mut each).is_ok(),
    };
    assert!(ok, "{phase} {name}");
    println!("MEM {phase} {name}: peak {} KiB above start; largest piece's approx_bytes {} KB", peak_kib().saturating_sub(start), piece_max / 1000);
}

/// A writer's delta creating a 10^5-key map, its context, and the map value (an encode step
/// keeps it: freed, its memory would hide the encoder's peak).
fn big_map() -> (Fragment, DeltaCtx, osis_base::Value) {
    let node = sess(osis_base::Tid::from_bytes([1; 15]));
    let map = osis_base::Value::Map((0..100_000).map(|i| (osis_base::Value::Str(format!("key {i}")), osis_base::Value::Int(i))).collect());
    let mut w = crate::Writer::new(crate::testutil::ts(1 << 20), node.clone(), 1);
    let d = crate::create(&mut w, &crate::testutil::TyView(Ty::Map(Box::new(Ty::Register), Box::new(Ty::Register))), &map).unwrap();
    (d, DeltaCtx { ts: crate::testutil::ts(1 << 20), own: node, range: w.range(), kind: crate::DeltaKind::Writer }, map)
}

/// Memory per decode step of a 10^5-key map, as a writer's delta and as a snapshot (by hand,
/// run alone): the whole decode holds the whole map; the stream holds one page; and of
/// encoding the delta: the whole encoder (`codec::oracle`) holds every element's value and
/// bytes and the collecting pass's tree, the streaming one a page (`MEM` lines, with
/// `--nocapture`; peaks above the delta itself).
#[test]
#[ignore = "by hand: memory, run alone"]
fn stream_memory_big_map() {
    if let Ok(arg) = std::env::var("OSIS_STREAM_PHASE") {
        return stream_memory_child(&arg);
    }
    let dir = std::env::temp_dir().join(format!("osis-stream-mem-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let (d, cx, _) = big_map();
    let mut pages = Blobs::new(PageParams::FORMAT);
    let delta = encode_delta(&Delta { nonce: [0; 16], fragment: d.clone() }, &cx, Some(&mut pages)).unwrap();
    let snap = encode_snapshot(&Snapshot { absorbed: Default::default(), nonce: [0; 16], fragment: d, frontiers: Frontiers::default() }, &snap_cx(), Some(&mut pages)).unwrap();
    let largest = pages.pages.iter().map(Vec::len).max().unwrap_or(0);
    println!("MEM inputs: delta {} B, snapshot {} B, {} pages, largest {} B", delta.len(), snap.len(), pages.pages.len(), largest);
    std::fs::write(dir.join("delta"), &delta).unwrap();
    std::fs::write(dir.join("snapshot"), &snap).unwrap();
    std::fs::write(dir.join("range"), format!("{} {}", cx.range.lo, cx.range.hi)).unwrap();
    std::fs::write(dir.join("pages"), pages.pages.len().to_string()).unwrap();
    for (k, p) in pages.pages.iter().enumerate() {
        std::fs::write(dir.join(format!("p{k}")), p).unwrap();
    }
    let mut peaks = std::collections::BTreeMap::new();
    let steps = ["stream", "whole", "old"].into_iter().flat_map(|p| [(p, "delta"), (p, "snapshot")]);
    for (phase, name) in steps.chain([("encode-new", "delta"), ("encode-old", "delta")]) {
        let out = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--ignored", "--exact", "tests_stream::stream_memory_big_map", "--nocapture"])
            .env("OSIS_STREAM_PHASE", format!("{phase}:{name}:{}", dir.display()))
            .output()
            .unwrap();
        let text = String::from_utf8_lossy(&out.stdout);
        assert!(out.status.success(), "{phase}: {text}{}", String::from_utf8_lossy(&out.stderr));
        for l in text.lines().filter(|l| l.starts_with("MEM")) {
            println!("{l}");
            let kib: u64 = l.split("peak ").nth(1).and_then(|x| x.split(' ').next()).and_then(|x| x.parse().ok()).unwrap();
            peaks.insert((phase, name), kib);
        }
    }
    // the stream holds a page, the whole decode the map: several times more
    for name in ["delta", "snapshot"] {
        assert!(peaks[&("stream", name)] * 3 < peaks[&("whole", name)], "{peaks:?}");
    }
    assert!(peaks[&("encode-new", "delta")] * 3 < peaks[&("encode-old", "delta")], "{peaks:?}");
    let _ = std::fs::remove_dir_all(&dir);
}

/// §3.3 rule 7, §5.6: the records of one map dot prune each other across a page seam (the
/// key-erased record's reset above the keyed record's content): the stream rejects what the
/// whole-delta oracle rejects however the pages cut, and accepts the reset below the content.
#[test]
fn map_dot_prunes_across_pages_spec_3_3() {
    use crate::fragment::{Eid, Entry, Map, Meta, RegWrite, Register};
    use crate::stamp::{Dot, Stamp};
    use osis_base::{Tid, Value};
    let node = sess(Tid::from_bytes([1; 15]));
    let st = |t: u64, c: u64| Stamp::new(crate::testutil::ts(t << 16), node.clone(), c);
    let reg = |s: Stamp| Box::new(Fragment::Register(Register { reset: None, write: Some(RegWrite { stamp: s, value: Some(Value::Int(1)) }) }));
    let (mut straddled, mut seen) = (0, 0);
    for n in 20..80u64 {
        for reset_t in [6, 4] {
            let mut entries: std::collections::BTreeMap<Eid, Entry> = (1..=n).map(|k| (Eid::new(Dot::new(node.clone(), k), Some(Value::Str(format!("filler entry number {k} of the map")))), Entry { reset: None, frag: Some(reg(st(5, k))), created: Some(st(5, k)) })).collect();
            let x = Dot::new(node.clone(), n + 1);
            entries.insert(Eid::erased(x.clone()), Entry { reset: Some(st(reset_t, 1)), frag: None, created: None });
            entries.insert(Eid::new(x.clone(), Some(Value::Str("k".into()))), Entry { reset: None, frag: Some(reg(st(5, n + 1))), created: Some(st(5, n + 1)) });
            let s = Snapshot { absorbed: Default::default(), nonce: [0; 16], fragment: Fragment::Map(Map::new(Meta::default(), entries)), frontiers: Frontiers::default() };
            let mut pages = Blobs::new(TINY);
            let bytes = encode_snapshot(&s, &snap_cx(), Some(&mut pages)).unwrap();
            let streamed = decode_snapshot(&bytes, &snap_cx(), &mut Interner::new(), Some(&mut pages.clone())).is_ok();
            let whole = oracle::decode_snapshot(&bytes, &snap_cx(), &mut Interner::new(), Some(&mut pages.clone())).is_ok();
            assert_eq!((streamed, whole), (reset_t == 4, reset_t == 4), "{n} fillers, reset at {reset_t}");
            // a seam between the two records: one page ends with the dot's first record
            let firsts: Vec<_> = pages.pages.iter().filter_map(|p| page_items(p)).filter_map(|(_, a)| a.first().cloned()).collect();
            seen += usize::from(!pages.pages.is_empty());
            straddled += usize::from(firsts.iter().any(|f| matches!(f, Value::List(e) if e.first() == Some(&Value::List(vec![Value::Int(1), Value::Int((n + 1) as i64)])) && e.len() == 5)));
        }
    }
    assert!(seen > 60 && straddled > 0, "paged {seen}, straddled {straddled}");
}
