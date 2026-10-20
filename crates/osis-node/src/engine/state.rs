//! Local encoding of aspect states: the snapshot grammar (spec/crdt.md §8: deltas, states and
//! snapshots share it) under a context no write can match, with its pages kept beside it. A root
//! collection above `PAGE_TARGET` is kept as pages of consecutive elements in the aspect's table
//! instead, and a join rewrites only the pages it touched (notes/local-store.md, Units).

use crate::error::{Error, Result};
use osis_core::format::PAGE_TARGET;
use osis_core::{Ak, BlobId, CommitId, Link, Tid, Ts, Value};
use osis_crdt::{CounterRange, DeltaCtx, DeltaKind, Dot, Encoding, Fragment, Frontiers, Interner, PageError, PageSink, PageSource, Snapshot, Source, decode_snapshot, encode_snapshot};
use osis_store::{Shred, Transaction};
use std::collections::{BTreeMap, BTreeSet};
use std::ops::Bound;

/// Pages of a locally stored state: link hash = BLAKE3 of the plaintext, key zero.
#[derive(Default)]
pub struct LocalPages(pub BTreeMap<[u8; 32], Vec<u8>>);

impl PageSink for LocalPages {
    fn put(&mut self, plaintext: &[u8]) -> std::result::Result<Link, PageError> {
        let hash = osis_core::hash::hash(plaintext);
        self.0.insert(hash, plaintext.to_vec());
        Ok(Link { hash, blob: BlobId(hash), suite: 1, key: [0; 32] })
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
/// A paged state with fewer root elements is written whole again (and unpaged if small).
const MIN_PAGED: usize = 64;
/// The aspect table holding its state pages.
const STATE_TABLE: u8 = 0;

/// Pages of a paged root collection: the first dot of each page's range -> page ID (row key).
/// The first page (`None`, ID 0) covers everything below the second and holds the collection's
/// reset and `W`. A page holds exactly the state's elements in its range.
#[derive(Clone, Debug)]
pub struct PageIndex {
    pages: BTreeMap<Option<Dot>, u64>,
    next: u64,
    enc: Encoding,
}

impl PageIndex {
    fn page_of(&self, d: &Dot) -> Option<Dot> {
        self.pages.range(..=Some(d.clone())).next_back().and_then(|(k, _)| k.clone())
    }
    fn next_key(&self, k: &Option<Dot>) -> Option<Dot> {
        self.pages.range((Bound::Excluded(k), Bound::Unbounded)).next().and_then(|(k, _)| k.clone())
    }
}

fn marker() -> Vec<u8> {
    osis_core::encode(&Value::List(vec![Value::Int(1)]))
}

/// Whether a unit's state field says the state lives in the aspect's page table.
pub fn is_paged(b: &[u8]) -> bool {
    b == marker().as_slice()
}

fn page_id(k: &[u8]) -> Result<u64> {
    Ok(u64::from_be_bytes(k.try_into().map_err(|_| Error::Corrupt("state page key"))?))
}

/// Loads a paged state: the join of its pages, and the page index.
pub fn load_paged(txn: &mut Transaction<'_>, tid: &Tid, ak: &Ak) -> Result<(Fragment, PageIndex)> {
    let t = txn.table(tid, ak, STATE_TABLE)?.ok_or(Error::Corrupt("state pages missing"))?;
    let mut f: Option<Fragment> = None;
    let mut pages = BTreeMap::new();
    let mut next = 0;
    let mut from = Vec::new();
    loop {
        let rows = txn.table_range(t, &from, None, 256)?;
        let n = rows.len();
        for (k, v) in rows {
            let id = page_id(&k)?;
            next = next.max(id + 1);
            from = [k.as_slice(), &[0]].concat();
            let p = decode(&v)?;
            let key = match id {
                0 => None,
                _ => Some(p.elem_dots(None, None).into_iter().next().ok_or(Error::Corrupt("empty state page"))?),
            };
            pages.insert(key, id);
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
    if !pages.contains_key(&None) {
        return Err(Error::Corrupt("first state page missing"));
    }
    let enc = f.encoding();
    Ok((f, PageIndex { pages, next, enc }))
}

/// Writes a whole state: the unit's state field, and the pages when it is a collection above
/// `PAGE_TARGET` (the old pages, if any, are dropped shredded).
pub fn write_full(txn: &mut Transaction<'_>, tid: &Tid, ak: &Ak, f: Option<&Fragment>, old_paged: bool) -> Result<(Vec<u8>, Option<PageIndex>)> {
    if old_paged {
        txn.drop_table(tid, ak, STATE_TABLE)?;
    }
    let Some(f) = f else { return Ok((Vec::new(), None)) };
    let bytes = encode(f)?;
    let n = f.elem_count().unwrap_or(0);
    if bytes.len() <= PAGE_TARGET || n < MIN_PAGED {
        return Ok((bytes, None));
    }
    let per = (n * PAGE_BYTES / bytes.len()).max(1);
    let dots = f.elem_dots(None, None);
    let t = txn.create_table(tid, ak, STATE_TABLE)?;
    let mut pages = BTreeMap::new();
    for (i, chunk) in dots.chunks(per).enumerate() {
        let lo = if i == 0 { None } else { chunk.first().cloned() };
        let hi = dots.get((i + 1) * per);
        let page = f.elem_range(lo.as_ref(), hi, i == 0).ok_or(Error::Corrupt("state page"))?;
        txn.table_put(t, &(i as u64).to_be_bytes(), encode(&page)?, Shred::No)?;
        pages.insert(lo, i as u64);
    }
    let next = pages.len() as u64;
    Ok((marker(), Some(PageIndex { pages, next, enc: f.encoding() })))
}

/// Rewrites the pages holding `dots` (and the first page if `meta`) from `f`: splits a page
/// grown past twice `PAGE_BYTES`, drops an emptied one. `None` if `f` no longer fits paging
/// here (the caller writes it whole).
pub fn write_touched(txn: &mut Transaction<'_>, idx: &mut PageIndex, tid: &Tid, ak: &Ak, f: &Fragment, (meta, dots): &(bool, Vec<Dot>), shred: Shred) -> Result<Option<()>> {
    if f.encoding() != idx.enc || f.elem_count().is_none_or(|n| n < MIN_PAGED) {
        return Ok(None);
    }
    let t = txn.table(tid, ak, STATE_TABLE)?.ok_or(Error::Corrupt("state pages missing"))?;
    let mut dirty: BTreeSet<Option<Dot>> = dots.iter().map(|d| idx.page_of(d)).collect();
    if *meta {
        dirty.insert(None);
    }
    for key in dirty {
        let Some(id) = idx.pages.get(&key).copied() else { continue };
        let hi = idx.next_key(&key);
        let page = f.elem_range(key.as_ref(), hi.as_ref(), key.is_none()).ok_or(Error::Corrupt("state page"))?;
        let n = page.elem_count().unwrap_or(0);
        if key.is_some() && n == 0 {
            txn.table_remove(t, &id.to_be_bytes(), shred)?;
            idx.pages.remove(&key);
            continue;
        }
        let bytes = encode(&page)?;
        if bytes.len() <= 2 * PAGE_BYTES || n < 2 {
            txn.table_put(t, &id.to_be_bytes(), bytes, shred)?;
            continue;
        }
        let ds = f.elem_dots(key.as_ref(), hi.as_ref());
        let per = ds.len().div_ceil(bytes.len().div_ceil(PAGE_BYTES)).max(1);
        for (i, chunk) in ds.chunks(per).enumerate() {
            let lo = if i == 0 { key.clone() } else { chunk.first().cloned() };
            let end = ds.get((i + 1) * per).or(hi.as_ref());
            let pid = if i == 0 {
                id
            } else {
                let p = idx.next;
                idx.next += 1;
                idx.pages.insert(lo.clone(), p);
                p
            };
            let page = f.elem_range(lo.as_ref(), end, lo.is_none()).ok_or(Error::Corrupt("state page"))?;
            txn.table_put(t, &pid.to_be_bytes(), encode(&page)?, shred)?;
        }
    }
    Ok(Some(()))
}
