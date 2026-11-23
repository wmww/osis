//! Rows packed into pages (`PagedRows`): an ordered store of many small rows kept as few larger
//! ones, each holding a run of consecutive rows with their keys' shared prefixes left out. A
//! write rewrites the page holding its key, so rows lying together (one position's writes, its
//! top and its steps in `held::Held`) cost one page, and a row costs its own bytes, not a
//! store row's key beside them.
//!
//! A page is the row `P` + its first key; the first page's key is `P` alone, so every key has
//! a page at or below it. Nothing is kept in memory between calls: each reads the page it
//! needs and writes the page it changed.

use crate::held::{Corrupt, Row, Rows};
use std::collections::BTreeMap;

/// Bytes a page is split above (its rows' keys and values). At 0 every row is its own page;
/// unbounded, one page holds every row and each write rewrites them all. As a state page: over
/// a store's inline limit, so a page is rewritten alone.
pub const PAGE_BYTES: usize = 3072;

/// `Rows` over pages kept in `inner`.
#[derive(Clone, Debug)]
pub struct PagedRows<R: Rows> {
    pub inner: R,
}

type Page = BTreeMap<Vec<u8>, Vec<u8>>;

fn page_key(first: &[u8]) -> Vec<u8> {
    [b"P", first].concat()
}

fn encode(p: &Page) -> Vec<u8> {
    let mut out = Vec::new();
    let mut last: &[u8] = &[];
    for (k, v) in p {
        let shared = k.iter().zip(last).take_while(|(a, b)| a == b).count().min(u16::MAX as usize);
        out.extend_from_slice(&(shared as u16).to_be_bytes());
        out.extend_from_slice(&((k.len() - shared) as u16).to_be_bytes());
        out.extend_from_slice(k.get(shared..).unwrap_or_default());
        out.extend_from_slice(&(v.len() as u32).to_be_bytes());
        out.extend_from_slice(v);
        last = k;
    }
    out
}

fn decode(mut b: &[u8]) -> Result<Page, Corrupt> {
    let bad = Corrupt("row page");
    let mut out = Page::new();
    let mut last: Vec<u8> = Vec::new();
    let take = |b: &mut &[u8], n: usize| -> Result<Vec<u8>, Corrupt> {
        let (a, rest) = b.split_at_checked(n).ok_or(bad)?;
        *b = rest;
        Ok(a.to_vec())
    };
    while !b.is_empty() {
        let shared = u16::from_be_bytes(take(&mut b, 2)?.try_into().map_err(|_| bad)?) as usize;
        let n = u16::from_be_bytes(take(&mut b, 2)?.try_into().map_err(|_| bad)?) as usize;
        let mut k = last.get(..shared).ok_or(bad)?.to_vec();
        k.extend_from_slice(&take(&mut b, n)?);
        let vn = u32::from_be_bytes(take(&mut b, 4)?.try_into().map_err(|_| bad)?) as usize;
        let v = take(&mut b, vn)?;
        last.clone_from(&k);
        out.insert(k, v);
    }
    Ok(out)
}

fn size(p: &Page) -> usize {
    p.iter().map(|(k, v)| k.len() + v.len()).sum()
}

impl<R: Rows> PagedRows<R> {
    pub fn new(inner: R) -> PagedRows<R> {
        PagedRows { inner }
    }

    /// The page holding `key`'s place: its first key and rows; none kept yet: an empty first
    /// page.
    fn page_of(&mut self, key: &[u8]) -> Result<(Vec<u8>, Page), R::Err> {
        // the greatest page key at or below `P` + key
        let to = [b"P".as_slice(), key, &[0]].concat();
        match self.inner.scan_back(b"P", &to, 1)?.pop() {
            Some((k, v)) => Ok((k.get(1..).unwrap_or_default().to_vec(), decode(&v)?)),
            None => Ok((Vec::new(), Page::new())),
        }
    }

    /// The first page after the one keyed `first`.
    fn next_page(&mut self, first: &[u8]) -> Result<Option<(Vec<u8>, Page)>, R::Err> {
        let from = [b"P".as_slice(), first, &[0]].concat();
        match self.inner.scan(&from, b"Q", 1)?.pop() {
            Some((k, v)) => Ok(Some((k.get(1..).unwrap_or_default().to_vec(), decode(&v)?))),
            None => Ok(None),
        }
    }

    /// Writes page `first` as `p`: gone when empty, split in two past `PAGE_BYTES` (a page of
    /// one row is whole whatever its size).
    fn write(&mut self, first: &[u8], mut p: Page) -> Result<(), R::Err> {
        if p.is_empty() {
            return self.inner.del(&page_key(first));
        }
        while size(&p) > PAGE_BYTES && p.len() > 1 {
            // the upper half leaves as pages of its own
            // from the first row past half the bytes, never the first row
            let half = size(&p) / 2;
            let mut acc = 0;
            let at = p.iter().skip(1).find(|(k, v)| {
                acc += k.len() + v.len();
                acc >= half
            });
            let Some(at) = at.or(p.iter().nth(1)).map(|x| x.0.clone()) else { break };
            let upper = p.split_off(&at);
            self.write(&at, upper)?;
        }
        self.inner.put(&page_key(first), &encode(&p))
    }

    /// Writes `rows` where nothing is kept: whole pages, each written once.
    pub fn fill(&mut self, rows: &BTreeMap<Vec<u8>, Vec<u8>>) -> Result<(), R::Err> {
        let mut first: Vec<u8> = Vec::new();
        let mut page = Page::new();
        for (k, v) in rows {
            if size(&page) + k.len() + v.len() > PAGE_BYTES && !page.is_empty() {
                self.inner.put(&page_key(&first), &encode(&page))?;
                first.clone_from(k);
                page = Page::new();
            }
            page.insert(k.clone(), v.clone());
        }
        if !page.is_empty() {
            self.inner.put(&page_key(&first), &encode(&page))?;
        }
        Ok(())
    }
}

impl<R: Rows> Rows for PagedRows<R> {
    type Err = R::Err;
    fn get(&mut self, key: &[u8]) -> Result<Option<Vec<u8>>, R::Err> {
        Ok(self.page_of(key)?.1.remove(key))
    }
    fn put(&mut self, key: &[u8], val: &[u8]) -> Result<(), R::Err> {
        let (first, mut p) = self.page_of(key)?;
        p.insert(key.to_vec(), val.to_vec());
        self.write(&first, p)
    }
    fn del(&mut self, key: &[u8]) -> Result<(), R::Err> {
        let (first, mut p) = self.page_of(key)?;
        if p.remove(key).is_some() {
            self.write(&first, p)?;
        }
        Ok(())
    }
    fn scan(&mut self, from: &[u8], to: &[u8], limit: usize) -> Result<Vec<Row>, R::Err> {
        let mut out = Vec::new();
        if from >= to {
            return Ok(out);
        }
        let (mut first, mut p) = self.page_of(from)?;
        loop {
            for (k, v) in p.range(from.to_vec()..) {
                if k.as_slice() >= to || out.len() >= limit {
                    return Ok(out);
                }
                out.push((k.clone(), v.clone()));
            }
            match self.next_page(&first)? {
                Some((f, next)) if f.as_slice() < to => (first, p) = (f, next),
                _ => return Ok(out),
            }
        }
    }
    fn scan_back(&mut self, from: &[u8], to: &[u8], limit: usize) -> Result<Vec<Row>, R::Err> {
        let mut out = Vec::new();
        if from >= to {
            return Ok(out);
        }
        // the page of the last key below `to`, then the pages before it
        let mut at = [b"P".as_slice(), to].concat();
        loop {
            let Some((k, v)) = self.inner.scan_back(b"P", &at, 1)?.pop() else { return Ok(out) };
            let p = decode(&v)?;
            for (key, val) in p.range(from.to_vec()..to.to_vec()).rev() {
                if out.len() >= limit {
                    return Ok(out);
                }
                out.push((key.clone(), val.clone()));
            }
            // a page starting at or below `from` holds the range's start
            if k.get(1..).unwrap_or_default() <= from || out.len() >= limit {
                return Ok(out);
            }
            at = k;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::held::MemRows;

    /// spec: none (internal: how a node stores an index's rows). Random puts, deletes and scans
    /// both ways read as an unpaged store's, pages stay under
    /// the bound (but one row over it), and no page is left once every row is gone.
    #[test]
    fn paged_rows_read_as_plain_rows() {
        let mut r = crate::testutil::rng(41);
        let mut paged = PagedRows::new(MemRows::default());
        let mut plain = MemRows::default();
        let key = |r: &mut crate::testutil::SeedRng| {
            let n = 1 + r.below(4);
            let mut k: Vec<u8> = (0..n).map(|_| r.below(5) as u8).collect();
            k.push(r.below(250) as u8);
            k
        };
        for step in 0..4000 {
            let k = key(&mut r);
            match r.below(10) {
                0..=5 => {
                    let big = r.chance(1, 50);
                    let v = vec![step as u8; r.below(if big { 5000 } else { 300 })];
                    paged.put(&k, &v).unwrap();
                    plain.put(&k, &v).unwrap();
                }
                6..=7 => {
                    paged.del(&k).unwrap();
                    plain.del(&k).unwrap();
                }
                _ => {
                    let (a, b) = (key(&mut r), key(&mut r));
                    let limit = 1 + r.below(40);
                    assert!(paged.scan(&a, &b, limit).unwrap() == plain.scan(&a, &b, limit).unwrap(), "scan at step {step}");
                    assert!(paged.scan_back(&a, &b, limit).unwrap() == plain.scan_back(&a, &b, limit).unwrap(), "scan back at step {step}");
                }
            }
            assert_eq!(paged.get(&k).unwrap(), plain.get(&k).unwrap(), "step {step}");
        }
        assert!(paged.scan(&[], &[0xff; 9], usize::MAX).unwrap() == plain.scan(&[], &[0xff; 9], usize::MAX).unwrap());
        for (k, v) in &paged.inner.0 {
            let p = decode(v).unwrap();
            assert!(size(&p) <= PAGE_BYTES || p.len() == 1, "page {k:?} of {} B", size(&p));
        }
        assert!(paged.inner.0.len() > 10 && paged.inner.0.len() < plain.0.len() / 4, "{} pages of {} rows", paged.inner.0.len(), plain.0.len());
        let mut filled = PagedRows::new(MemRows::default());
        filled.fill(&plain.0).unwrap();
        assert!(filled.scan(&[], &[0xff; 9], usize::MAX).unwrap() == plain.scan(&[], &[0xff; 9], usize::MAX).unwrap());
        let keys: Vec<Vec<u8>> = plain.0.keys().cloned().collect();
        for k in keys {
            paged.del(&k).unwrap();
        }
        assert!(paged.inner.0.is_empty(), "pages left with no row");
    }
}
