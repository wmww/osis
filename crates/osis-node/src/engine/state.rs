//! Local encoding of aspect states: the snapshot grammar (spec/crdt.md §8: deltas, states and
//! snapshots share it) under a context no write can match, with its pages kept beside it. A root
//! collection above `PAGE_TARGET` is kept as pages of consecutive elements in the aspect's table
//! instead, and a join rewrites only the pages it touched (notes/local-store.md, Units).

use crate::error::{Error, Result};
use osis_core::format::PAGE_TARGET;
use osis_core::{Ak, BlobId, CommitId, Link, Tid, Ts, Value};
use osis_crdt::{CounterRange, DeltaCtx, DeltaKind, Dot, Encoding, Fragment, Frontiers, Interner, PageError, PageSink, PageSource, Snapshot, Source, decode_snapshot, encode_snapshot};
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

/// Where a paged collection sits: the root (`None`) or a field of a root struct.
type Slot = Option<u64>;

/// Pages of one collection: the first dot of each page's range -> page ID. The first page
/// (`None`, ID 0) covers everything below the second and is never dropped; a root
/// collection's first page holds its reset and `W` (a field's live in the unit's skeleton). A
/// page holds exactly the collection's elements in its range.
#[derive(Clone, Debug)]
struct PageSet {
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

/// The page sets of a paged state: one for a root collection, or one per paged field of a root
/// struct (whose other fields and own stamps live in the unit as a skeleton).
#[derive(Clone, Debug)]
pub struct PageIndex {
    sets: BTreeMap<Slot, PageSet>,
}

/// What joining a delta can change in one collection: its own stamps, and elements by dot.
pub type ElemTouch = (bool, Vec<Dot>);

/// What joining a delta can change, for `write_touched` (`touch_of`).
pub enum Touch {
    /// Anything: write whole.
    All,
    /// Root collection elements by dot, and whether its reset or `W`.
    Root(bool, Vec<Dot>),
    /// Root struct fields: whether its own `W`, and per field what changes in it (`None`:
    /// anything).
    Fields(bool, Vec<(u64, Option<ElemTouch>)>),
}

/// What joining `delta` can change in a state.
pub fn touch_of(delta: &Fragment) -> Touch {
    if let Some((meta, dots)) = delta.touched_elems() {
        return Touch::Root(meta, dots);
    }
    match delta.touched_fields() {
        Some((w, fields)) => Touch::Fields(w, fields.into_iter().map(|(k, f)| (k, f.touched_elems())).collect()),
        None => Touch::All,
    }
}

/// Unit state of a paged root collection: `[1]`; of a struct with paged fields:
/// `[2, skeleton]`. Unpaged states start `[bytes, ...]`.
fn root_marker() -> Vec<u8> {
    osis_core::encode(&Value::List(vec![Value::Int(1)]))
}

fn struct_marker(skeleton: &Fragment) -> Result<Vec<u8>> {
    Ok(osis_core::encode(&Value::List(vec![Value::Int(2), Value::Bytes(encode(skeleton)?)])))
}

/// Whether a unit's state field says the state lives in the aspect's page table: its first
/// item is an integer, not the snapshot bytes.
pub fn is_paged(b: &[u8]) -> bool {
    b.get(1).is_some_and(|x| *x < 0x18)
}

fn row_key(slot: Slot, id: u64) -> Vec<u8> {
    match slot {
        None => [&[0u8][..], &id.to_be_bytes()].concat(),
        Some(f) => [&[1u8][..], &f.to_be_bytes(), &id.to_be_bytes()].concat(),
    }
}

fn parse_row_key(k: &[u8]) -> Result<(Slot, u64)> {
    let bad = || Error::Corrupt("state page key");
    let n = |b: &[u8]| -> Result<u64> { Ok(u64::from_be_bytes(b.try_into().map_err(|_| bad())?)) };
    match (k.first(), k.len()) {
        (Some(0), 9) => Ok((None, n(k.get(1..9).ok_or_else(bad)?)?)),
        (Some(1), 17) => Ok((Some(n(k.get(1..9).ok_or_else(bad)?)?), n(k.get(9..17).ok_or_else(bad)?)?)),
        _ => Err(bad()),
    }
}

/// The collection at `slot` of `f`.
fn coll(f: &Fragment, slot: Slot) -> Option<&Fragment> {
    match slot {
        None => Some(f),
        Some(id) => f.fields().into_iter().find(|(k, _)| *k == id).map(|(_, x)| x),
    }
}

/// A page's fragment: the collection's elements in `[lo, hi)` (with the root's own stamps on
/// its first page), as a struct holding the field for a field slot.
fn page(c: &Fragment, slot: Slot, lo: Option<&Dot>, hi: Option<&Dot>) -> Result<Fragment> {
    let first = slot.is_none() && lo.is_none();
    let x = c.elem_range(lo, hi, first).ok_or(Error::Corrupt("state page"))?;
    Ok(match slot {
        None => x,
        Some(id) => Fragment::struct_of(vec![(id, x)]),
    })
}

/// Loads a paged state: the skeleton (struct mode) joined with every page, and the index.
pub fn load_paged(txn: &mut Transaction<'_>, tid: &Tid, ak: &Ak, unit_state: &[u8]) -> Result<(Fragment, PageIndex)> {
    let lim = osis_core::Limits { max_depth: 4, max_bytes: unit_state.len() };
    let v = osis_core::decode(unit_state, &lim).map_err(|_| Error::Corrupt("state"))?;
    let mut f = match v {
        Value::List(items) => match items.as_slice() {
            [Value::Int(1)] => None,
            [Value::Int(2), Value::Bytes(s)] => Some(decode(s)?),
            _ => return Err(Error::Corrupt("state")),
        },
        _ => return Err(Error::Corrupt("state")),
    };
    let t = txn.table(tid, ak, STATE_TABLE)?.ok_or(Error::Corrupt("state pages missing"))?;
    let mut sets: BTreeMap<Slot, PageSet> = BTreeMap::new();
    let mut from = Vec::new();
    loop {
        let rows = txn.table_range(t, &from, None, 256)?;
        let n = rows.len();
        for (k, v) in rows {
            let (slot, id) = parse_row_key(&k)?;
            from = [k.as_slice(), &[0]].concat();
            let p = decode(&v)?;
            let c = coll(&p, slot).ok_or(Error::Corrupt("state page"))?;
            let key = match id {
                0 => None,
                _ => Some(c.elem_dots(None, None).into_iter().next().ok_or(Error::Corrupt("empty state page"))?),
            };
            let enc = c.encoding();
            let set = sets.entry(slot).or_insert(PageSet { pages: BTreeMap::new(), next: 0, enc });
            set.pages.insert(key, id);
            set.next = set.next.max(id + 1);
            match &mut f {
                None => f = Some(p),
                Some(f) => {
                    f.join(p);
                }
            }
        }
        if n < 256 {
            break;
        }
    }
    let f = f.ok_or(Error::Corrupt("state pages missing"))?;
    if sets.is_empty() || sets.values().any(|s| !s.pages.contains_key(&None)) {
        return Err(Error::Corrupt("first state page missing"));
    }
    // the enc of a field set is the field's, read off the joined state
    for (slot, set) in sets.iter_mut() {
        set.enc = coll(&f, *slot).map(Fragment::encoding).ok_or(Error::Corrupt("state pages"))?;
    }
    Ok((f, PageIndex { sets }))
}

/// Writes one collection's pages from scratch, about `PAGE_BYTES` each.
fn write_set(txn: &mut Transaction<'_>, t: Table, slot: Slot, c: &Fragment) -> Result<PageSet> {
    let n = c.elem_count().unwrap_or(0).max(1);
    let size = encode(c)?.len().max(1);
    let per = (n * PAGE_BYTES / size).max(1);
    let dots = c.elem_dots(None, None);
    let mut pages = BTreeMap::new();
    for (i, chunk) in dots.chunks(per).enumerate() {
        let lo = if i == 0 { None } else { chunk.first().cloned() };
        let hi = dots.get((i + 1) * per);
        txn.table_put(t, &row_key(slot, i as u64), encode(&page(c, slot, lo.as_ref(), hi)?)?, Shred::No)?;
        pages.insert(lo, i as u64);
    }
    let next = pages.len() as u64;
    Ok(PageSet { pages, next, enc: c.encoding() })
}

fn big(c: &Fragment) -> bool {
    c.elem_count().is_some_and(|n| n >= MIN_PAGED)
}

/// Writes a whole state: the unit's state field, and the pages when the state is above
/// `PAGE_TARGET` and is a large collection or a struct with large collection fields (the old
/// pages, if any, are dropped shredded).
pub fn write_full(txn: &mut Transaction<'_>, tid: &Tid, ak: &Ak, f: Option<&Fragment>, old_paged: bool) -> Result<(Vec<u8>, Option<PageIndex>)> {
    if old_paged {
        txn.drop_table(tid, ak, STATE_TABLE)?;
    }
    let Some(f) = f else { return Ok((Vec::new(), None)) };
    let bytes = encode(f)?;
    if bytes.len() <= PAGE_TARGET {
        return Ok((bytes, None));
    }
    if big(f) {
        let t = txn.create_table(tid, ak, STATE_TABLE)?;
        let set = write_set(txn, t, None, f)?;
        return Ok((root_marker(), Some(PageIndex { sets: BTreeMap::from([(None, set)]) })));
    }
    let paged: BTreeSet<u64> = f.fields().into_iter().filter(|(_, c)| big(c)).map(|(k, _)| k).collect();
    let Some(skeleton) = f.struct_skeleton(&|k| paged.contains(&k)).filter(|_| !paged.is_empty()) else { return Ok((bytes, None)) };
    let t = txn.create_table(tid, ak, STATE_TABLE)?;
    let mut sets = BTreeMap::new();
    for (k, c) in f.fields() {
        if paged.contains(&k) {
            sets.insert(Some(k), write_set(txn, t, Some(k), c)?);
        }
    }
    Ok((struct_marker(&skeleton)?, Some(PageIndex { sets })))
}

/// Rewrites the pages of one collection holding `dots` (and its first page if `first`): splits
/// a page grown past twice `PAGE_BYTES`, drops an emptied one.
#[allow(clippy::too_many_arguments)]
fn rewrite_set(txn: &mut Transaction<'_>, t: Table, slot: Slot, set: &mut PageSet, c: &Fragment, first: bool, dots: &[Dot], shred: Shred) -> Result<()> {
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
    if first {
        dirty.insert(None);
    }
    for key in dirty {
        let Some(id) = set.pages.get(&key).copied() else { continue };
        let hi = set.next_key(&key);
        let n = c.elem_dots(key.as_ref(), hi.as_ref()).len();
        if key.is_some() && n == 0 {
            txn.table_remove(t, &row_key(slot, id), shred)?;
            set.pages.remove(&key);
            continue;
        }
        let bytes = encode(&page(c, slot, key.as_ref(), hi.as_ref())?)?;
        if bytes.len() <= 2 * PAGE_BYTES || n < 2 {
            txn.table_put(t, &row_key(slot, id), bytes, shred)?;
            continue;
        }
        let ds = c.elem_dots(key.as_ref(), hi.as_ref());
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
            txn.table_put(t, &row_key(slot, pid), encode(&page(c, slot, lo.as_ref(), end)?)?, shred)?;
        }
    }
    Ok(())
}

/// Rewrites what `touch` says changed in the paged state `f`. `Ok(None)`: it does not fit the
/// pages (write whole); `Ok(Some(unit))`: done, with the unit's new state field if the struct
/// skeleton changed.
pub fn write_touched(txn: &mut Transaction<'_>, idx: &mut PageIndex, tid: &Tid, ak: &Ak, f: &Fragment, touch: &Touch, shred: Shred) -> Result<Option<Option<Vec<u8>>>> {
    let fits = |slot: Slot, set: &PageSet| coll(f, slot).is_some_and(|c| c.encoding() == set.enc && big(c));
    if idx.sets.iter().any(|(s, set)| !fits(*s, set)) {
        return Ok(None);
    }
    let t = txn.table(tid, ak, STATE_TABLE)?.ok_or(Error::Corrupt("state pages missing"))?;
    match touch {
        Touch::Root(meta, dots) if idx.sets.contains_key(&None) => {
            let Some(set) = idx.sets.get_mut(&None) else { return Ok(None) };
            rewrite_set(txn, t, None, set, f, *meta, dots, shred)?;
            Ok(Some(None))
        }
        Touch::Fields(w, fields) if !idx.sets.contains_key(&None) => {
            // a field reset or encoding change could touch any of its elements
            if fields.iter().any(|(k, x)| x.is_none() && idx.sets.contains_key(&Some(*k))) {
                return Ok(None);
            }
            let mut skeleton = *w;
            for (k, x) in fields {
                let slot = Some(*k);
                match (idx.sets.get_mut(&slot), x, coll(f, slot)) {
                    (Some(set), Some((meta, dots)), Some(c)) => {
                        rewrite_set(txn, t, slot, set, c, false, dots, shred)?;
                        skeleton |= *meta;
                    }
                    _ => skeleton = true,
                }
            }
            if !skeleton {
                return Ok(Some(None));
            }
            let s = f.struct_skeleton(&|k| idx.sets.contains_key(&Some(k))).ok_or(Error::Corrupt("state skeleton"))?;
            let unit = struct_marker(&s)?;
            // unpaged fields grown large: written whole, which pages them
            Ok((unit.len() <= PAGE_TARGET).then_some(Some(unit)))
        }
        _ => Ok(None),
    }
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
