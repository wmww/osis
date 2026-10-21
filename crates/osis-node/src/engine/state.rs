//! Local encoding of aspect states: the snapshot grammar (spec/crdt.md §8: deltas, states and
//! snapshots share it) under a context no write can match, with its pages kept beside it. A state
//! above `PAGE_TARGET` keeps its large collections, at any depth below struct fields, enum
//! payloads and map entries, as pages of consecutive elements in the aspect's table, the rest as
//! a skeleton in the unit; a join rewrites only the pages it touched (notes/local-store.md, Units).

use crate::error::{Error, Result};
use osis_core::format::PAGE_TARGET;
use osis_core::{Ak, BlobId, CommitId, Link, Tid, Ts, Value};
use osis_crdt::{CounterRange, DeltaCtx, DeltaKind, Dot, Encoding, Fragment, Frontiers, Interner, PageError, PageSink, PageSource, PagedTouch, Paths, Snapshot, Source, SourceKind, Step, decode_snapshot, encode_snapshot};
use osis_store::{Shred, Table, Transaction};
use std::collections::{BTreeMap, BTreeSet};
use std::ops::Bound;

/// Pages of a locally stored state: link hash = BLAKE3 of the plaintext, key zero, blob ID
/// distinct per put (a decode refuses one blob linked twice, and equal pages can recur).
#[derive(Default)]
pub struct LocalPages(pub BTreeMap<[u8; 32], Vec<u8>>, u64);

impl PageSink for LocalPages {
    fn put(&mut self, plaintext: &[u8]) -> std::result::Result<Link, PageError> {
        let hash = osis_core::hash::hash(plaintext);
        self.0.insert(hash, plaintext.to_vec());
        self.1 += 1;
        let mut id = hash.to_vec();
        id.extend(self.1.to_le_bytes());
        Ok(Link { hash, blob: BlobId(osis_core::hash::hash(&id)), suite: 1, key: [0; 32] })
    }
}

impl PageSource for LocalPages {
    fn get(&mut self, link: &Link) -> std::result::Result<Vec<u8>, PageError> {
        let p = self.0.get(&link.hash).ok_or(PageError::Missing)?;
        if osis_core::hash::hash(p) != link.hash {
            return Err(PageError::Corrupt);
        }
        Ok(p.clone())
    }
}

fn ctx() -> DeltaCtx {
    DeltaCtx { ts: Ts::default(), own: Source::commit(CommitId([0; 32])), range: CounterRange::EMPTY, kind: DeltaKind::Snapshot }
}

/// `[snapshot bytes, [page*]]`.
pub fn encode(f: &Fragment) -> Result<Vec<u8>> {
    let mut pages = LocalPages::default();
    let snap = Snapshot { nonce: [0; 16], fragment: f.clone(), frontiers: Frontiers::default() };
    let bytes = encode_snapshot(&snap, &ctx(), Some(&mut pages))?;
    let v = Value::List(vec![Value::Bytes(bytes), Value::List(pages.0.into_values().map(Value::Bytes).collect())]);
    Ok(osis_core::encode(&v))
}

pub fn decode(b: &[u8]) -> Result<Fragment> {
    let lim = osis_core::Limits { max_depth: 4, max_bytes: b.len() };
    let v = osis_core::decode(b, &lim).map_err(|_| Error::Corrupt("state"))?;
    let Value::List(items) = v else { return Err(Error::Corrupt("state")) };
    let [Value::Bytes(snap), Value::List(pages)] = items.as_slice() else { return Err(Error::Corrupt("state")) };
    let mut lp = LocalPages::default();
    for p in pages {
        if let Value::Bytes(p) = p {
            lp.0.insert(osis_core::hash::hash(p), p.clone());
        }
    }
    let mut interner = Interner::new();
    let s = decode_snapshot(snap, &ctx(), &mut interner, Some(&mut lp)).map_err(|_| Error::Corrupt("state"))?;
    Ok(s.fragment)
}

// ---- paged states (notes/local-store.md, Units)

/// Encoded bytes per local page, about (a store unit is 8 KB; a larger page is split).
const PAGE_BYTES: usize = 8 * 1024;
/// A collection with fewer elements is not paged; a paged one shrinking below it makes the
/// state be written whole again (and unpaged if small).
const MIN_PAGED: usize = 64;
/// The aspect table holding its state pages.
const STATE_TABLE: u8 = 0;

/// A path with the keys of its entry steps (to rebuild an entry's key from a page alone).
type KeyedPath = Vec<(Step, Option<Value>)>;

/// Pages of one paged collection: the first dot of each page's range -> page ID. The first page
/// (`None`, ID 0) covers everything below the second and is never dropped. A page holds exactly
/// the collection's root elements in its range, collections paged below them reduced to their
/// reset and `W`; the collection's own reset and `W` live in the skeleton.
#[derive(Clone, Debug)]
struct PageSet {
    id: u32,
    path: KeyedPath,
    pages: BTreeMap<Option<Dot>, u64>,
    next: u64,
    enc: Encoding,
}

impl PageSet {
    fn page_of(&self, d: &Dot) -> Option<Dot> {
        self.pages.range(..=Some(d.clone())).next_back().and_then(|(k, _)| k.clone())
    }
    fn next_key(&self, k: &Option<Dot>) -> Option<Dot> {
        self.pages.range((Bound::Excluded(k), Bound::Unbounded)).next().and_then(|(k, _)| k.clone())
    }
}

/// The paged collections of a state, at any depth below struct fields, enum payloads and map
/// entries (keyed by path); everything else is the skeleton kept in the aspect's unit.
#[derive(Clone, Debug)]
pub struct PageIndex {
    sets: BTreeMap<Vec<Step>, PageSet>,
    paths: Paths,
}

impl PageIndex {
    /// The paths below a paged collection's elements (what its pages reduce).
    fn nested(&self, p: &[Step]) -> Paths {
        Paths { here: false, next: self.paths.below(p).map(|x| x.next.clone()).unwrap_or_default() }
    }
}

/// What joining a delta can change in a paged state (`None`: write whole).
pub type Touch = Option<PagedTouch>;

/// What joining `delta` can change in the state of `(tid, ak)` with page index `idx`.
pub fn touch_of(delta: &Fragment, idx: Option<&PageIndex>) -> Touch {
    delta.touched_paths(&idx?.paths)
}

/// Whether a unit's state field says the state lives in the aspect's page table: its first
/// item is an integer, not the snapshot bytes.
pub fn is_paged(b: &[u8]) -> bool {
    b.get(1).is_some_and(|x| *x < 0x18)
}

fn row_key(set: u32, id: u64) -> Vec<u8> {
    [&set.to_be_bytes()[..], &id.to_be_bytes()].concat()
}

fn parse_row_key(k: &[u8]) -> Result<(u32, u64)> {
    let bad = || Error::Corrupt("state page key");
    let (a, b) = (k.get(..4).ok_or_else(bad)?, k.get(4..).ok_or_else(bad)?);
    Ok((u32::from_be_bytes(a.try_into().map_err(|_| bad())?), u64::from_be_bytes(b.try_into().map_err(|_| bad())?)))
}

fn uint(n: u64) -> Value {
    Value::Int(i64::try_from(n).unwrap_or(i64::MAX))
}

fn dot_value(d: &Dot) -> Value {
    let src = match d.src.kind() {
        SourceKind::Node(t) => Value::List(vec![Value::Int(0), Value::Bytes(t.as_bytes().to_vec())]),
        SourceKind::Commit(c) => Value::List(vec![Value::Int(1), Value::Bytes(c.0.to_vec())]),
        SourceKind::Derived(x) => Value::List(vec![Value::Int(2), dot_value(x)]),
    };
    Value::List(vec![src, uint(d.ctr)])
}

fn dot_of(v: &Value) -> Result<Dot> {
    let bad = || Error::Corrupt("state page path");
    let Value::List(items) = v else { return Err(bad()) };
    let [Value::List(src), Value::Int(ctr)] = items.as_slice() else { return Err(bad()) };
    let src = match src.as_slice() {
        [Value::Int(0), Value::Bytes(t)] => Source::node(Tid::from_bytes(t.as_slice().try_into().map_err(|_| bad())?)),
        [Value::Int(1), Value::Bytes(c)] => Source::commit(CommitId(c.as_slice().try_into().map_err(|_| bad())?)),
        [Value::Int(2), x] => Source::derived(dot_of(x)?).ok_or_else(bad)?,
        _ => return Err(bad()),
    };
    Ok(Dot::new(src, u64::try_from(*ctr).map_err(|_| bad())?))
}

fn path_value(p: &KeyedPath) -> Value {
    Value::List(
        p.iter()
            .map(|(s, k)| match s {
                Step::Field(id) => Value::List(vec![Value::Int(0), uint(*id)]),
                Step::Case(id) => Value::List(vec![Value::Int(1), uint(*id)]),
                Step::Entry(d) => Value::List(vec![Value::Int(2), dot_value(d), k.clone().map_or(Value::List(Vec::new()), |k| Value::List(vec![k]))]),
            })
            .collect(),
    )
}

fn path_of(v: &Value) -> Result<KeyedPath> {
    let bad = || Error::Corrupt("state page path");
    let Value::List(steps) = v else { return Err(bad()) };
    let n = |x: &i64| u64::try_from(*x).map_err(|_| bad());
    steps
        .iter()
        .map(|s| match s {
            Value::List(x) => match x.as_slice() {
                [Value::Int(0), Value::Int(id)] => Ok((Step::Field(n(id)?), None)),
                [Value::Int(1), Value::Int(id)] => Ok((Step::Case(n(id)?), None)),
                [Value::Int(2), d, Value::List(k)] => Ok((Step::Entry(dot_of(d)?), k.first().cloned())),
                _ => Err(bad()),
            },
            _ => Err(bad()),
        })
        .collect()
}

/// Unit state of a paged state: `[3, skeleton, [[set ID, path]*]]`. Unpaged states start
/// `[bytes, ...]`.
fn unit_state(skeleton: &Fragment, idx: &PageIndex) -> Result<Vec<u8>> {
    let sets = idx.sets.values().map(|s| Value::List(vec![uint(u64::from(s.id)), path_value(&s.path)])).collect();
    Ok(osis_core::encode(&Value::List(vec![Value::Int(3), Value::Bytes(encode(skeleton)?), Value::List(sets)])))
}

/// A page row: `[first dot or [], page]` (the first dot keys the page in the index; a page's
/// first element may be reduced away).
fn page_row(first: Option<&Dot>, p: &Fragment) -> Result<Vec<u8>> {
    let d = first.map_or(Value::List(Vec::new()), dot_value);
    Ok(osis_core::encode(&Value::List(vec![d, Value::Bytes(encode(p)?)])))
}

fn parse_page_row(b: &[u8]) -> Result<(Option<Dot>, Fragment)> {
    let lim = osis_core::Limits { max_depth: osis_core::format::MAX_OBJECT_DEPTH, max_bytes: b.len() };
    let v = osis_core::decode(b, &lim).map_err(|_| Error::Corrupt("state page"))?;
    let Value::List(items) = v else { return Err(Error::Corrupt("state page")) };
    let [d, Value::Bytes(p)] = items.as_slice() else { return Err(Error::Corrupt("state page")) };
    let first = match d {
        Value::List(x) if x.is_empty() => None,
        d => Some(dot_of(d)?),
    };
    Ok((first, decode(p)?))
}

fn steps(p: &KeyedPath) -> Vec<Step> {
    p.iter().map(|(s, _)| s.clone()).collect()
}

/// Loads a paged state: the skeleton joined with every page placed at its collection's path,
/// and the index.
pub fn load_paged(txn: &mut Transaction<'_>, tid: &Tid, ak: &Ak, unit_state: &[u8]) -> Result<(Fragment, PageIndex)> {
    let lim = osis_core::Limits { max_depth: osis_core::format::MAX_OBJECT_DEPTH, max_bytes: unit_state.len() };
    let v = osis_core::decode(unit_state, &lim).map_err(|_| Error::Corrupt("state"))?;
    let Value::List(items) = v else { return Err(Error::Corrupt("state")) };
    let [Value::Int(3), Value::Bytes(skel), Value::List(list)] = items.as_slice() else { return Err(Error::Corrupt("state")) };
    let mut f = decode(skel)?;
    let mut by_id: BTreeMap<u32, KeyedPath> = BTreeMap::new();
    for x in list {
        let Value::List(x) = x else { return Err(Error::Corrupt("state")) };
        let [Value::Int(id), p] = x.as_slice() else { return Err(Error::Corrupt("state")) };
        by_id.insert(u32::try_from(*id).map_err(|_| Error::Corrupt("state"))?, path_of(p)?);
    }
    let t = txn.table(tid, ak, STATE_TABLE)?.ok_or(Error::Corrupt("state pages missing"))?;
    let mut sets: BTreeMap<u32, (BTreeMap<Option<Dot>, u64>, u64)> = BTreeMap::new();
    let mut from = Vec::new();
    loop {
        let rows = txn.table_range(t, &from, None, 256)?;
        let n = rows.len();
        for (k, v) in rows {
            let (set, id) = parse_row_key(&k)?;
            from = [k.as_slice(), &[0]].concat();
            let path = by_id.get(&set).ok_or(Error::Corrupt("state page of no set"))?;
            let (key, p) = parse_page_row(&v)?;
            if (id == 0) != key.is_none() {
                return Err(Error::Corrupt("state page key"));
            }
            let e = sets.entry(set).or_default();
            e.0.insert(key, id);
            e.1 = e.1.max(id + 1);
            f.join(Fragment::wrap(path, p));
        }
        if n < 256 {
            break;
        }
    }
    let mut idx = PageIndex { sets: BTreeMap::new(), paths: Paths::default() };
    for (id, path) in by_id {
        let (pages, next) = sets.remove(&id).unwrap_or_default();
        if !pages.contains_key(&None) {
            return Err(Error::Corrupt("first state page missing"));
        }
        let p = steps(&path);
        let enc = f.at_steps(&p).map(Fragment::encoding).ok_or(Error::Corrupt("state pages"))?;
        idx.paths.insert(&p);
        idx.sets.insert(p, PageSet { id, path, pages, next, enc });
    }
    Ok((f, idx))
}

/// A page: the collection's root elements in `[lo, hi)`, collections paged below reduced.
fn page(c: &Fragment, nested: &Paths, lo: Option<&Dot>, hi: Option<&Dot>) -> Result<Fragment> {
    Ok(c.elem_range(lo, hi, false).ok_or(Error::Corrupt("state page"))?.reduced(nested))
}

/// Writes one collection's pages from scratch, about `PAGE_BYTES` each.
fn write_set(txn: &mut Transaction<'_>, t: Table, set: &mut PageSet, c: &Fragment, nested: &Paths) -> Result<()> {
    let n = c.elem_count().unwrap_or(0).max(1);
    let size = encode(&c.reduced(&Paths { here: false, next: nested.next.clone() }))?.len().max(1);
    let per = (n * PAGE_BYTES / size).max(1);
    let dots = c.elem_dots(None, None);
    set.pages.clear();
    let chunks: Vec<&[Dot]> = if dots.is_empty() { vec![&[]] } else { dots.chunks(per).collect() };
    for (i, chunk) in chunks.into_iter().enumerate() {
        let lo = if i == 0 { None } else { chunk.first().cloned() };
        let hi = dots.get((i + 1) * per);
        txn.table_put(t, &row_key(set.id, i as u64), page_row(lo.as_ref(), &page(c, nested, lo.as_ref(), hi)?)?, Shred::No)?;
        set.pages.insert(lo, i as u64);
    }
    set.next = set.pages.len() as u64;
    Ok(())
}

fn big(c: &Fragment) -> bool {
    c.elem_count().is_some_and(|n| n >= MIN_PAGED)
}

/// The collections of a large state to page: every collection of at least `MIN_PAGED` elements
/// encoding to more than `PAGE_BYTES`, at any depth below struct fields, enum payloads and map
/// entries (inside a paged collection's elements too).
fn paged_paths(f: &Fragment) -> Result<Vec<Vec<Step>>> {
    let mut out = Vec::new();
    for (p, c) in f.collections() {
        if big(c) && encode(c)?.len() > PAGE_BYTES {
            out.push(p);
        }
    }
    Ok(out)
}

/// The path of `p` in `f` with the keys of its entry steps.
fn keyed(f: &Fragment, p: &[Step]) -> KeyedPath {
    let mut out = Vec::with_capacity(p.len());
    let mut cur = Some(f);
    for s in p {
        let key = match s {
            Step::Entry(d) => cur.and_then(|c| c.entry_key(d)).cloned(),
            _ => None,
        };
        out.push((s.clone(), key));
        cur = cur.and_then(|c| c.step(s));
    }
    out
}

/// Writes a whole state: the unit's state field, and the pages when the state is above
/// `PAGE_TARGET` and holds large collections (the old pages, if any, are dropped shredded).
pub fn write_full(txn: &mut Transaction<'_>, tid: &Tid, ak: &Ak, f: Option<&Fragment>, old_paged: bool) -> Result<(Vec<u8>, Option<PageIndex>)> {
    if old_paged {
        txn.drop_table(tid, ak, STATE_TABLE)?;
    }
    let Some(f) = f else { return Ok((Vec::new(), None)) };
    let bytes = encode(f)?;
    if bytes.len() <= PAGE_TARGET {
        return Ok((bytes, None));
    }
    let paged = paged_paths(f)?;
    if paged.is_empty() {
        return Ok((bytes, None));
    }
    let t = txn.create_table(tid, ak, STATE_TABLE)?;
    let mut idx = PageIndex { sets: BTreeMap::new(), paths: Paths::default() };
    for p in &paged {
        idx.paths.insert(p);
    }
    for (i, p) in paged.into_iter().enumerate() {
        let c = f.at_steps(&p).ok_or(Error::Corrupt("state collection"))?;
        let mut set = PageSet { id: u32::try_from(i).map_err(|_| Error::Corrupt("state sets"))?, path: keyed(f, &p), pages: BTreeMap::new(), next: 0, enc: c.encoding() };
        write_set(txn, t, &mut set, c, &idx.nested(&p))?;
        idx.sets.insert(p, set);
    }
    let unit = unit_state(&f.reduced(&idx.paths), &idx)?;
    Ok((unit, Some(idx)))
}

/// Rewrites the pages of one collection holding `dots`: splits a page grown past twice
/// `PAGE_BYTES`, drops an emptied one. `Ok(false)`: an element alone outgrew a page (re-layout).
fn rewrite_set(txn: &mut Transaction<'_>, t: Table, set: &mut PageSet, c: &Fragment, nested: &Paths, dots: &[Dot], shred: Shred) -> Result<bool> {
    let mut dirty: BTreeSet<Option<Dot>> = BTreeSet::new();
    if matches!(set.enc, Encoding::List | Encoding::Text) {
        // (first, last) per delta record: a range record touches every page between
        for pair in dots.chunks(2) {
            let (Some(a), Some(b)) = (pair.first(), pair.last()) else { continue };
            let (pa, pb) = (set.page_of(a), set.page_of(b));
            if pa <= pb {
                dirty.extend(set.pages.range(pa..=pb).map(|(k, _)| k.clone()));
            }
        }
    } else {
        dirty = dots.iter().map(|d| set.page_of(d)).collect();
    }
    for key in dirty {
        let Some(id) = set.pages.get(&key).copied() else { continue };
        let hi = set.next_key(&key);
        let ds = c.elem_dots(key.as_ref(), hi.as_ref());
        if key.is_some() && ds.is_empty() {
            txn.table_remove(t, &row_key(set.id, id), shred)?;
            set.pages.remove(&key);
            continue;
        }
        let bytes = page_row(key.as_ref(), &page(c, nested, key.as_ref(), hi.as_ref())?)?;
        if bytes.len() <= 2 * PAGE_BYTES {
            txn.table_put(t, &row_key(set.id, id), bytes, shred)?;
            continue;
        }
        if ds.len() < 2 {
            // one element above a page: page what grew inside it (a whole rewrite re-lays out)
            if bytes.len() > PAGE_TARGET {
                return Ok(false);
            }
            txn.table_put(t, &row_key(set.id, id), bytes, shred)?;
            continue;
        }
        let per = ds.len().div_ceil(bytes.len().div_ceil(PAGE_BYTES)).max(1);
        for (i, chunk) in ds.chunks(per).enumerate() {
            let lo = if i == 0 { key.clone() } else { chunk.first().cloned() };
            let end = ds.get((i + 1) * per).or(hi.as_ref());
            let pid = if i == 0 {
                id
            } else {
                let p = set.next;
                set.next += 1;
                set.pages.insert(lo.clone(), p);
                p
            };
            txn.table_put(t, &row_key(set.id, pid), page_row(lo.as_ref(), &page(c, nested, lo.as_ref(), end)?)?, shred)?;
        }
    }
    Ok(true)
}

/// Rewrites what `touch` says changed in the paged state `f`. `Ok(None)`: it does not fit the
/// pages (write whole); `Ok(Some(unit))`: done, with the unit's new state field if the skeleton
/// changed.
pub fn write_touched(txn: &mut Transaction<'_>, idx: &mut PageIndex, tid: &Tid, ak: &Ak, f: &Fragment, touch: &PagedTouch, shred: Shred) -> Result<Option<Option<Vec<u8>>>> {
    // a touched collection that moved, changed encoding or shrank: lay out again
    for p in touch.elems.keys() {
        let (Some(set), Some(c)) = (idx.sets.get(p), f.at_steps(p)) else { return Ok(None) };
        if c.encoding() != set.enc || !big(c) {
            return Ok(None);
        }
    }
    let t = txn.table(tid, ak, STATE_TABLE)?.ok_or(Error::Corrupt("state pages missing"))?;
    for (p, dots) in &touch.elems {
        let nested = idx.nested(p);
        let (Some(set), Some(c)) = (idx.sets.get_mut(p), f.at_steps(p)) else { return Ok(None) };
        if !rewrite_set(txn, t, set, c, &nested, dots, shred)? {
            return Ok(None);
        }
    }
    if !touch.skeleton {
        return Ok(Some(None));
    }
    let unit = unit_state(&f.reduced(&idx.paths), idx)?;
    // unpaged parts grown large: written whole, which pages them
    Ok((unit.len() <= PAGE_TARGET).then_some(Some(unit)))
}

#[cfg(test)]
mod tests {
    use osis_core::{Tid, Ts, Value};
    use osis_crdt::{Encoding, Source, View, Writer, create};
    use std::borrow::Cow;

    /// A map of structs of registers.
    struct V(u8);

    impl View for V {
        fn encoding(&self) -> Option<Encoding> {
            Some([Encoding::Map, Encoding::Struct, Encoding::Register][usize::from(self.0)])
        }
        fn project<'a>(&self, v: &'a Value) -> Option<Cow<'a, Value>> {
            Some(Cow::Borrowed(v))
        }
        fn field(&self, _: u64) -> Option<V> {
            (self.0 == 1).then_some(V(2))
        }
        fn field_default(&self, _: u64) -> Option<Value> {
            None
        }
        fn case(&self, _: u64) -> Option<V> {
            None
        }
        fn element(&self) -> Option<V> {
            (self.0 == 0).then_some(V(1))
        }
        fn key(&self) -> Option<V> {
            (self.0 == 0).then_some(V(2))
        }
    }

    /// The value of `n` ints keyed 0..n.
    fn ints(n: i64, x: i64) -> Value {
        Value::Map((0..n).map(|i| (Value::Int(i), Value::Int(i * x))).collect())
    }

    // spec/requirements.md, Scale (a change costs O(change) at any depth); notes/local-store.md
    // (Units): a state with large collections inside map entries and struct-like maps pages each
    // of them; after random edits written page by page (or whole where they do not fit), loading
    // from the store gives the state back, and an edit deep inside rewrites a few rows only.
    #[test]
    fn nested_paging_round_trips_spec_requirements_scale() {
        use osis_crdt::{AnyView, Batch, Op, PathOp, PathSeg};
        use osis_store::{MemoryBackend, MemoryRoot, Shred, Store, StoreConfig};
        let mut rng = osis_crypto::SeededRng::from_u64(77);
        let mut store = Store::create(Box::new(MemoryBackend::new()), Box::new(MemoryRoot::new()), StoreConfig::default(), &mut rng).unwrap();
        let (tid, ak) = (Tid::from_bytes([3; 15]), osis_core::Ak::new("/app/nested").unwrap());
        let node = Source::node(Tid::from_bytes([1; 15]));
        // a map of a big inner map, a small one, a big set and a register
        let big_set = Value::Set((0..2000).map(|i| Value::Str(format!("s{i}"))).collect());
        let v = Value::Map(
            [
                (Value::Str("big".into()), ints(2500, 1)),
                (Value::Str("small".into()), ints(3, 1)),
                (Value::Str("tags".into()), big_set),
                (Value::Str("x".into()), Value::Int(1)),
            ]
            .into_iter()
            .collect(),
        );
        let mut ctr = 1;
        let mut ts = 1u64 << 16;
        let mut w = Writer::new(Ts::from_u64(ts).unwrap(), node.clone(), ctr);
        let mut st = create(&mut w, &AnyView, &v).unwrap();
        ctr = w.range().hi;
        let mut txn = store.transaction(&mut rng).unwrap();
        let (unit, idx) = super::write_full(&mut txn, &tid, &ak, Some(&st), false).unwrap();
        let mut idx = idx.expect("paged");
        assert!(idx.sets.len() >= 2, "{:?}", idx.sets.keys().collect::<Vec<_>>());
        let mut unit = unit;
        let (back, _) = super::load_paged(&mut txn, &tid, &ak, &unit).unwrap();
        assert_eq!(back, st);
        let mut orng = osis_crypto::SeededRng::from_u64(78);
        let mut r = |n: u64| osis_crypto::RngCore::next_u64(&mut orng) % n;
        let mut in_place = 0;
        for step in 0..30 {
            ts += 1 << 16;
            let op = match r(6) {
                0 => PathOp { path: vec![PathSeg::Key(Value::Str("big".into())), PathSeg::Key(Value::Int(r(3000) as i64))], op: Op::Set(Value::Int(-(step as i64))) },
                1 => PathOp { path: vec![PathSeg::Key(Value::Str("big".into()))], op: Op::Remove(Value::Int(r(2500) as i64)) },
                2 => PathOp { path: vec![PathSeg::Key(Value::Str("tags".into()))], op: Op::Add(Value::Str(format!("n{step}"))) },
                3 => PathOp { path: vec![PathSeg::Key(Value::Str("small".into())), PathSeg::Key(Value::Int(r(10) as i64))], op: Op::Set(Value::Int(7)) },
                4 => PathOp { path: vec![PathSeg::Key(Value::Str(format!("k{}", r(5))))], op: Op::Set(ints(3, 2)) },
                _ => PathOp { path: vec![PathSeg::Key(Value::Str("x".into()))], op: Op::Set(Value::Int(step as i64)) },
            };
            let mut b = Batch::new(&st, Writer::new(Ts::from_u64(ts).unwrap(), node.clone(), ctr));
            if b.apply(&op, &AnyView).is_err() {
                continue;
            }
            let Some((delta, range)) = b.finish() else { continue };
            ctr = range.hi;
            let touch = super::touch_of(&delta, Some(&idx));
            st.join(delta);
            let done = match &touch {
                Some(t) => super::write_touched(&mut txn, &mut idx, &tid, &ak, &st, t, Shred::No).unwrap(),
                None => None,
            };
            in_place += usize::from(done.is_some());
            match done {
                Some(Some(u)) => unit = u,
                Some(None) => {}
                None => {
                    let (u, i) = super::write_full(&mut txn, &tid, &ak, Some(&st), true).unwrap();
                    unit = u;
                    idx = i.expect("still paged");
                }
            }
            let (back, _) = super::load_paged(&mut txn, &tid, &ak, &unit).unwrap();
            assert_eq!(back, st, "step {step}: {op:?}");
        }
        assert!(in_place >= 20, "{in_place} of 30 written in place");
    }

    /// spec/crdt.md §8: equal structs written in one commit page into equal field-map pages;
    /// the local state round-trips (each put is its own blob, never one blob linked twice).
    #[test]
    fn equal_pages_round_trip_spec_8() {
        let s = Value::Map((0..4).map(|i| (Value::Int(i), Value::Str("x".repeat(30_000)))).collect());
        let v = Value::Map((0..2).map(|k| (Value::Int(k), s.clone())).collect());
        let mut w = Writer::new(Ts::from_u64(1 << 16).unwrap(), Source::node(Tid::from_bytes([1; 15])), 1);
        let st = create(&mut w, &V(0), &v).unwrap();
        assert_eq!(super::decode(&super::encode(&st).unwrap()).unwrap(), st);
    }
}
