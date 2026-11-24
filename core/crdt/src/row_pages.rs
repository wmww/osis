//! Rows packed into pages (`PagedRows`): an ordered store of many small rows kept as few larger
//! ones, each holding a run of consecutive rows with their keys' shared prefixes left out and
//! its bytes' repeats written once (`pack`: the sources, commit IDs, stamps and position hashes
//! that `held::Held`'s rows of one neighbourhood share). A
//! write rewrites the page holding its key, so rows lying together (one position's writes, its
//! top and its steps in `held::Held`) cost one page, and a row costs its own bytes, not a
//! store row's key beside them.
//!
//! Pages lie in levels, as a store bounds its keys and a row's key has no bound. A level holds
//! the rows whose keys start with its prefix (the top level's is empty); its pages are keyed by
//! the level (`LEVEL` bytes of the prefix's hash) and a chunk: the next `key_max - LEVEL` bytes
//! of a key past the prefix. A page holds the rows of its level whose chunk is at or above its
//! own and below the next page's. One stored past twice `PAGE_BYTES` splits in two where the
//! chunk changes; one whose rows all share one chunk (a subtree deeper than a chunk) becomes the
//! empty page naming the level of prefix + chunk, which holds those rows. So pages split by key
//! range at any key length, and a row's page is found a level at a time. A level left with no
//! page goes with the page naming it. The pages a caller changes are held until `Rows::flush`
//! writes each once (`held::Held` flushes at the end of a body's join or leave).
//!
//! Pages read are kept in a `PageCache` the caller may keep past this `PagedRows` (a
//! transaction's), each decoded once, with the key of the stored page after it once known: a
//! directory, so a read of a key in a page whose next is known goes straight to it, not to the
//! store. Every write keeps it exact; the caller empties it where the store changes otherwise
//! (a rollback, a table dropped).

use crate::held::{Corrupt, Row, Rows, end_of};
use std::borrow::BorrowMut;
use std::collections::{BTreeMap, BTreeSet};
use std::ops::Bound;

/// Bytes of a page as stored: one grown past twice this is split in two. At 0 every row is its
/// own page; unbounded, one page holds every row and each write rewrites them all. Half a
/// store's inline limit, so a page never passes it and a write hands the store a few KB: about
/// 4 KB of rows before their repeats go.
pub const PAGE_BYTES: usize = 1024;

/// Bytes of a page's key naming its level: 16 bytes of a hash stand for a prefix of any length.
const LEVEL: usize = 16;

/// `Rows` over pages kept in `inner`, pages read kept decoded in `cache`.
#[derive(Clone, Debug)]
pub struct PagedRows<R: Rows, C: BorrowMut<PageCache> = PageCache> {
    pub inner: R,
    /// Bytes of a key past its level's prefix in a page's key (its chunk).
    chunk: usize,
    /// Pages changed and not written yet, by key (`None`: gone).
    changed: BTreeMap<Vec<u8>, Option<Page>>,
    /// The levels reached, by key: their prefix's length and the page naming them (the top
    /// level: none).
    levels: BTreeMap<Vec<u8>, (usize, Option<Vec<u8>>)>,
    /// Levels a page left since the last `flush`.
    emptied: BTreeSet<Vec<u8>>,
    cache: C,
}

type Page = BTreeMap<Vec<u8>, Vec<u8>>;

/// Stored pages read, by key (module doc): exact while every write of the pages goes through a
/// `PagedRows` holding it.
#[derive(Clone, Debug, Default)]
pub struct PageCache {
    pages: BTreeMap<Vec<u8>, Cached>,
    /// The key of the first stored page (`Some(None)`: none), once known.
    first: Option<Option<Vec<u8>>>,
}

impl PageCache {
    /// Forgets every page: the store changed under it.
    pub fn clear(&mut self) {
        *self = PageCache::default();
    }
}

#[derive(Clone, Debug)]
struct Cached {
    /// As stored (empty: a page naming a level).
    raw: Vec<u8>,
    /// Decoded, once read.
    page: Option<Page>,
    /// The key of the next stored page (`Some(None)`: none), once known.
    next: Option<Option<Vec<u8>>>,
}

static EMPTY: Page = BTreeMap::new();

fn page_key(first: &[u8]) -> Vec<u8> {
    [b"P", first].concat()
}

/// The key of the level of rows starting with `prefix`.
fn level_of(prefix: &[u8]) -> Vec<u8> {
    osis_base::hash::hash(prefix).get(..LEVEL).unwrap_or_default().to_vec()
}

/// What page `id` of the level of `prefix` covers: the keys starting with `prefix` + its chunk.
fn span(prefix: &[u8], id: &[u8]) -> Vec<u8> {
    [prefix, id.get(LEVEL..).unwrap_or_default()].concat()
}

/// `b` with each repeat of four bytes or more written as its distance back and length: ops of
/// a tag byte, below 128 a run of tag + 1 bytes as they are, else a copy of (tag - 128) + 4
/// bytes from a two-byte distance back. Greedy, the last place each four bytes were seen.
fn pack(b: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(b.len() / 2);
    let mut last = vec![usize::MAX; 1 << 12];
    let run = |out: &mut Vec<u8>, from: usize, to: usize| {
        for chunk in b.get(from..to).unwrap_or_default().chunks(128) {
            out.push(chunk.len() as u8 - 1);
            out.extend_from_slice(chunk);
        }
    };
    let (mut i, mut plain) = (0, 0);
    while let Some(four) = b.get(i..i + 4) {
        let h = (u32::from_le_bytes(four.try_into().unwrap_or([0; 4])).wrapping_mul(2654435761) >> 20) as usize;
        let seen = last.get(h).copied().unwrap_or(usize::MAX);
        if let Some(x) = last.get_mut(h) {
            *x = i;
        }
        if seen != usize::MAX && i - seen <= u16::MAX as usize && b.get(seen..seen + 4) == Some(four) {
            let len = (4..131).find(|n| b.get(i + n).is_none() || b.get(seen + n) != b.get(i + n)).unwrap_or(131);
            run(&mut out, plain, i);
            out.push(128 + (len - 4) as u8);
            out.extend_from_slice(&((i - seen) as u16).to_be_bytes());
            i += len;
            plain = i;
        } else {
            i += 1;
        }
    }
    run(&mut out, plain, b.len());
    out
}

/// `pack` undone.
fn unpack(mut b: &[u8]) -> Result<Vec<u8>, Corrupt> {
    let bad = Corrupt("row page");
    let mut out = Vec::with_capacity(b.len() * 2);
    while let Some((tag, rest)) = b.split_first() {
        if *tag < 128 {
            let (run, rest) = rest.split_at_checked(*tag as usize + 1).ok_or(bad)?;
            out.extend_from_slice(run);
            b = rest;
        } else {
            let (back, rest) = rest.split_at_checked(2).ok_or(bad)?;
            let back = u16::from_be_bytes(back.try_into().map_err(|_| bad)?) as usize;
            let from = out.len().checked_sub(back).filter(|_| back > 0).ok_or(bad)?;
            // byte by byte: a copy may run into what it writes
            for k in 0..(*tag as usize - 128 + 4) {
                let x = *out.get(from + k).ok_or(bad)?;
                out.push(x);
            }
            b = rest;
        }
    }
    Ok(out)
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
    pack(&out)
}

fn decode(b: &[u8]) -> Result<Page, Corrupt> {
    let bad = Corrupt("row page");
    let plain = unpack(b)?;
    let mut b = plain.as_slice();
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
    pub fn new(inner: R, key_max: usize) -> PagedRows<R> {
        PagedRows::with_cache(inner, key_max, PageCache::default())
    }
}

impl<R: Rows, C: BorrowMut<PageCache>> PagedRows<R, C> {
    /// Pages keyed by at most `key_max` bytes (a chunk of at least one).
    pub fn with_cache(inner: R, key_max: usize, cache: C) -> PagedRows<R, C> {
        let levels = BTreeMap::from([(level_of(&[]), (0, None))]);
        PagedRows { inner, chunk: key_max.saturating_sub(LEVEL).max(1), changed: BTreeMap::new(), levels, emptied: BTreeSet::new(), cache }
    }

    /// Page `first` as stored: only for a key the directory gave (decoded there) or `write` wrote.
    fn read(&self, first: &[u8]) -> Option<&Page> {
        self.cache.borrow().pages.get(first).and_then(|x| x.page.as_ref())
    }

    /// Stored page `key` (its bytes `v`) in the directory.
    fn learn(&mut self, key: &[u8], v: Vec<u8>) {
        let cache = &mut self.cache.borrow_mut().pages;
        if cache.get(key).is_none_or(|x| x.raw != v) {
            cache.insert(key.to_vec(), Cached { raw: v, page: None, next: None });
        }
    }

    /// Stored page `key`, decoded.
    fn decoded(&mut self, key: Vec<u8>) -> Result<Vec<u8>, R::Err> {
        if let Some(c) = self.cache.borrow_mut().pages.get_mut(&key)
            && c.page.is_none()
        {
            c.page = Some(decode(&c.raw)?);
        }
        Ok(key)
    }

    /// The key of the first stored page after `first`: the directory's, else the store's.
    fn stored_after(&mut self, first: &[u8]) -> Result<Option<Vec<u8>>, R::Err> {
        if let Some(Some(next)) = self.cache.borrow().pages.get(first).map(|c| c.next.clone()) {
            return Ok(next);
        }
        let found = self.inner.scan(&[b"P", first, &[0]].concat(), b"Q", 1)?.pop();
        let next = found.map(|(k, v)| {
            let key = k.get(1..).unwrap_or_default().to_vec();
            self.learn(&key, v);
            key
        });
        if let Some(c) = self.cache.borrow_mut().pages.get_mut(first) {
            c.next = Some(next.clone());
        }
        Ok(next)
    }

    /// The key of the last stored page keyed below `bound`: the directory's where the page
    /// before it knows its next, else the store's (its next then learnt).
    fn stored_below(&mut self, bound: &[u8]) -> Result<Option<Vec<u8>>, R::Err> {
        let known = {
            let cache = self.cache.borrow();
            match cache.pages.range::<[u8], _>((Bound::Unbounded, Bound::Excluded(bound))).next_back() {
                Some((k, c)) => match &c.next {
                    Some(n) if n.as_ref().is_none_or(|n| n.as_slice() >= bound) => Some(Some(k.clone())),
                    _ => None,
                },
                // none read below it: none stored where the first stored is at or above it
                None => cache.first.as_ref().filter(|f| f.as_ref().is_none_or(|f| f.as_slice() >= bound)).map(|_| None),
            }
        };
        if let Some(known) = known {
            return Ok(known);
        }
        let Some((k, v)) = self.inner.scan_back(b"P", &page_key(bound), 1)?.pop() else {
            // the first stored page learnt
            let first = self.inner.scan(b"P", b"Q", 1)?.pop().map(|(k, v)| {
                let key = k.get(1..).unwrap_or_default().to_vec();
                self.learn(&key, v);
                key
            });
            self.cache.borrow_mut().first = Some(first);
            return Ok(None);
        };
        let key = k.get(1..).unwrap_or_default().to_vec();
        self.learn(&key, v);
        self.stored_after(&key)?;
        Ok(Some(key))
    }

    /// Page `first` written as `raw`, `p` (`None`: gone), the directory kept exact: a new page
    /// takes its place after the page before it.
    fn wrote(&mut self, first: &[u8], now: Option<(Vec<u8>, Page)>) {
        let PageCache { pages: cache, first: known_first } = self.cache.borrow_mut();
        let was = cache.remove(first);
        let mut next = was.as_ref().and_then(|w| w.next.clone());
        match (&now, known_first.as_ref()) {
            (None, Some(Some(f))) if f.as_slice() == first => *known_first = next.clone(),
            (Some(_), Some(f)) if f.as_ref().is_none_or(|f| f.as_slice() > first) => {
                next = Some(f.clone());
                *known_first = Some(Some(first.to_vec()));
            }
            _ => {}
        }
        let before = cache.range_mut::<[u8], _>((Bound::Unbounded, Bound::Excluded(first))).next_back().map(|x| x.1);
        if let Some(b) = before {
            match (&now, &b.next) {
                // gone: the page before it now leads to its next
                (None, Some(Some(n))) if n.as_slice() == first => b.next = next.clone(),
                // new: between the page before it and that one's next
                (Some(_), Some(n)) if was.is_none() && n.as_ref().is_none_or(|n| n.as_slice() > first) => {
                    next = Some(n.clone());
                    b.next = Some(Some(first.to_vec()));
                }
                _ => {}
            }
        }
        if let Some((raw, p)) = now {
            cache.insert(first.to_vec(), Cached { raw, page: Some(p), next });
        }
    }

    /// `key`'s chunk past a prefix of `at` bytes.
    fn chunk_of<'k>(&self, key: &'k [u8], at: usize) -> &'k [u8] {
        let rest = key.get(at..).unwrap_or_default();
        rest.get(..self.chunk).unwrap_or(rest)
    }

    /// Whether page `id` names a level (no page of rows is stored empty).
    fn nests(&self, id: &[u8]) -> bool {
        !self.changed.contains_key(id) && self.cache.borrow().pages.get(id).is_some_and(|c| c.raw.is_empty())
    }

    /// Page `first` as it stands: changed, else as read.
    fn page(&self, first: &[u8]) -> &Page {
        match self.changed.get(first) {
            Some(p) => p.as_ref().unwrap_or(&EMPTY),
            None => self.read(first).unwrap_or(&EMPTY),
        }
    }

    /// Page `first`, held as changed until `flush`.
    fn page_mut(&mut self, first: &[u8]) -> &mut Page {
        let read = self.cache.borrow().pages.get(first).and_then(|x| x.page.as_ref());
        self.changed.entry(first.to_vec()).or_insert_with(|| Some(read.cloned().unwrap_or_default())).get_or_insert_with(Page::new)
    }

    /// The key of the last page of `level` keyed below `bound` (above `level`), changed or
    /// stored.
    fn page_below(&mut self, level: &[u8], bound: &[u8]) -> Result<Option<Vec<u8>>, R::Err> {
        let held = self.changed.range::<[u8], _>((Bound::Included(level), Bound::Excluded(bound))).rev().find(|x| x.1.is_some());
        let held = held.map(|(k, _)| k.clone());
        let mut to = bound.to_vec();
        // the last stored page below it that no change replaced
        loop {
            let Some(key) = self.stored_below(&to)? else { return Ok(held) };
            if key.as_slice() < level || held.as_ref().is_some_and(|h| *h >= key) {
                return Ok(held);
            }
            if !self.changed.contains_key(&key) {
                return self.decoded(key).map(Some);
            }
            to = key;
        }
    }

    /// The key of the first page of `level` after the one keyed `first`, changed or stored.
    fn next_page(&mut self, level: &[u8], first: &[u8]) -> Result<Option<Vec<u8>>, R::Err> {
        let after = [first, &[0]].concat();
        let held = self.changed.range(after..).find(|x| x.1.is_some()).map(|(k, _)| k.clone()).filter(|k| k.starts_with(level));
        let mut from = first.to_vec();
        loop {
            let Some(key) = self.stored_after(&from)? else { return Ok(held) };
            if !key.starts_with(level) || held.as_ref().is_some_and(|h| *h <= key) {
                return Ok(held);
            }
            if !self.changed.contains_key(&key) {
                return self.decoded(key).map(Some);
            }
            from = key;
        }
    }

    /// The key of the page of rows holding `key`'s place, a level at a time: the last page of
    /// the level at or below `key`'s chunk, into the level it names where that is `key`'s
    /// chunk's; none, or one naming another level, leaves it to a new page keyed by the chunk.
    fn page_of(&mut self, key: &[u8]) -> Result<Vec<u8>, R::Err> {
        let (mut at, mut level) = (0, level_of(&[]));
        loop {
            let id = [level.as_slice(), self.chunk_of(key, at)].concat();
            match self.page_below(&level, &[id.as_slice(), &[0]].concat())? {
                Some(f) if !self.nests(&f) => return Ok(f),
                Some(f) if f == id => {
                    at += self.chunk;
                    level = level_of(key.get(..at).unwrap_or(key));
                    self.levels.insert(level.clone(), (at, Some(f)));
                }
                _ => return Ok(id),
            }
        }
    }

    /// Writes page `id` as `p`: gone when empty, split in two past twice `PAGE_BYTES` where
    /// the chunk changes, its rows moved a level down where they share one (a lone row stays,
    /// whatever its size).
    fn write(&mut self, id: &[u8], mut p: Page) -> Result<(), R::Err> {
        let level = id.get(..LEVEL).unwrap_or_default().to_vec();
        if p.is_empty() {
            self.wrote(id, None);
            self.emptied.insert(level);
            return self.inner.del(&page_key(id));
        }
        let at = self.levels.get(&level).map_or(0, |l| l.0);
        let mut stored = encode(&p);
        while stored.len() > 2 * PAGE_BYTES && p.len() > 1 {
            // the upper half leaves as pages of its own, from the first row past half the
            // bytes whose chunk is not the row before it's (never the first row)
            let half = size(&p) / 2;
            let (mut acc, mut last, mut ends) = (0, None, Vec::new());
            for (k, v) in p.iter() {
                let c = self.chunk_of(k, at);
                if last.is_some_and(|l| l != c) {
                    ends.push((acc, k.clone()));
                }
                last = Some(c);
                acc += k.len() + v.len();
            }
            let Some(from) = ends.iter().find(|x| x.0 >= half).or(ends.last()).map(|x| x.1.clone()) else {
                return self.nest(id, at, p);
            };
            let upper = p.split_off(&from);
            let key = [level.as_slice(), self.chunk_of(&from, at)].concat();
            self.write(&key, upper)?;
            stored = encode(&p);
        }
        self.inner.put(&page_key(id), &stored)?;
        self.wrote(id, Some((stored, p)));
        Ok(())
    }

    /// Writes `p`, page `id`'s rows of one chunk past a prefix of `at` bytes, in the level of
    /// prefix + chunk, named by the empty page keyed by the chunk (`id` itself unless its rows
    /// start past it).
    fn nest(&mut self, id: &[u8], at: usize, p: Page) -> Result<(), R::Err> {
        let first = p.keys().next().cloned().unwrap_or_default();
        let named = [id.get(..LEVEL).unwrap_or_default(), self.chunk_of(&first, at)].concat();
        if named != id {
            self.write(id, Page::new())?;
        }
        self.inner.put(&page_key(&named), &[])?;
        self.wrote(&named, Some((Vec::new(), Page::new())));
        let below = at + self.chunk;
        let level = level_of(first.get(..below).unwrap_or(&first));
        self.levels.insert(level.clone(), (below, Some(named)));
        let key = [level.as_slice(), self.chunk_of(&first, below)].concat();
        self.write(&key, p)
    }

    /// The rows of the level of `prefix` in `from..to`, least first, onto `out` up to `limit`.
    fn scan_in(&mut self, prefix: &[u8], from: &[u8], to: &[u8], limit: usize, out: &mut Vec<Row>) -> Result<(), R::Err> {
        let from = from.max(prefix);
        if !from.starts_with(prefix) {
            return Ok(());
        }
        let level = level_of(prefix);
        let id = [level.as_slice(), self.chunk_of(from, prefix.len())].concat();
        let mut at = match self.page_below(&level, &[id.as_slice(), &[0]].concat())? {
            Some(f) => Some(f),
            None => self.next_page(&level, &id)?,
        };
        while let Some(f) = at {
            let span = span(prefix, &f);
            if out.len() >= limit || span.as_slice() >= to {
                break;
            }
            if self.nests(&f) {
                self.scan_in(&span, from, to, limit, out)?;
            } else {
                for (k, v) in self.page(&f).range::<[u8], _>((Bound::Included(from), Bound::Unbounded)) {
                    if k.as_slice() >= to || out.len() >= limit {
                        return Ok(());
                    }
                    out.push((k.clone(), v.clone()));
                }
            }
            at = self.next_page(&level, &f)?;
        }
        Ok(())
    }

    /// The rows of the level of `prefix` in `from..to` (`from < to`), greatest first, onto
    /// `out` up to `limit`.
    fn scan_back_in(&mut self, prefix: &[u8], from: &[u8], to: &[u8], limit: usize, out: &mut Vec<Row>) -> Result<(), R::Err> {
        if to <= prefix {
            return Ok(());
        }
        let level = level_of(prefix);
        // the page of the last key below `to`, then the pages before it
        let mut bound = match to.starts_with(prefix) {
            true => [level.as_slice(), self.chunk_of(to, prefix.len()), &[0]].concat(),
            false => end_of(&level),
        };
        while out.len() < limit {
            let Some(f) = self.page_below(&level, &bound)? else { break };
            let span = span(prefix, &f);
            if self.nests(&f) {
                self.scan_back_in(&span, from, to, limit, out)?;
            } else {
                for (k, v) in self.page(&f).range::<[u8], _>((Bound::Included(from), Bound::Excluded(to))).rev() {
                    if out.len() >= limit {
                        break;
                    }
                    out.push((k.clone(), v.clone()));
                }
            }
            // a page covering keys from `from` or below holds the range's start
            if span.as_slice() <= from {
                break;
            }
            bound = f;
        }
        Ok(())
    }

    /// Writes `rows` where nothing is kept: a run of rows at a time (eight pages of bytes before
    /// their repeats go, which store as about one; `write` splits what stores larger), cut
    /// where the chunk changes.
    pub fn fill(&mut self, rows: &BTreeMap<Vec<u8>, Vec<u8>>) -> Result<(), R::Err> {
        let top = level_of(&[]);
        let mut page = Page::new();
        let mut bytes = 0;
        for (k, v) in rows {
            let new = page.keys().next_back().is_some_and(|l| self.chunk_of(l, 0) != self.chunk_of(k, 0));
            if bytes + k.len() + v.len() > 8 * PAGE_BYTES && new {
                let first = page.keys().next().cloned().unwrap_or_default();
                self.write(&[top.as_slice(), self.chunk_of(&first, 0)].concat(), std::mem::take(&mut page))?;
                bytes = 0;
            }
            bytes += k.len() + v.len();
            page.insert(k.clone(), v.clone());
        }
        let Some(first) = page.keys().next().cloned() else { return Ok(()) };
        self.write(&[top.as_slice(), self.chunk_of(&first, 0)].concat(), page)
    }
}

impl<R: Rows, C: BorrowMut<PageCache>> Rows for PagedRows<R, C> {
    type Err = R::Err;
    fn get(&mut self, key: &[u8]) -> Result<Option<Vec<u8>>, R::Err> {
        let first = self.page_of(key)?;
        Ok(self.page(&first).get(key).cloned())
    }
    fn put(&mut self, key: &[u8], val: &[u8]) -> Result<(), R::Err> {
        let first = self.page_of(key)?;
        self.page_mut(&first).insert(key.to_vec(), val.to_vec());
        Ok(())
    }
    fn flush(&mut self) -> Result<(), R::Err> {
        for (first, p) in std::mem::take(&mut self.changed) {
            self.write(&first, p.unwrap_or_default())?;
        }
        // a level left with no page goes with the page naming it, which may leave its own empty
        while let Some(level) = self.emptied.pop_first() {
            let Some((_, Some(named))) = self.levels.get(&level).cloned() else { continue };
            if self.page_below(&level, &end_of(&level))?.is_none() {
                self.write(&named, Page::new())?;
            }
        }
        Ok(())
    }
    fn del(&mut self, key: &[u8]) -> Result<(), R::Err> {
        let first = self.page_of(key)?;
        if self.page(&first).contains_key(key) {
            let p = self.page_mut(&first);
            p.remove(key);
            if p.is_empty() {
                self.changed.insert(first, None);
            }
        }
        Ok(())
    }
    fn scan(&mut self, from: &[u8], to: &[u8], limit: usize) -> Result<Vec<Row>, R::Err> {
        let mut out = Vec::new();
        if from < to {
            self.scan_in(&[], from, to, limit, &mut out)?;
        }
        Ok(out)
    }
    fn scan_back(&mut self, from: &[u8], to: &[u8], limit: usize) -> Result<Vec<Row>, R::Err> {
        let mut out = Vec::new();
        if from < to {
            self.scan_back_in(&[], from, to, limit, &mut out)?;
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::held::MemRows;

    /// spec: none (internal: how a node stores an index's rows). `pack` gives back its input
    /// through `unpack` for random and repeating bytes and shrinks repeats; damaged or random bytes
    /// are an error as a page, never a panic.
    #[test]
    fn packed_bytes_unpack_as_they_were() {
        let mut r = crate::testutil::rng(43);
        for round in 0..300 {
            let n = r.below(3000);
            let words: Vec<Vec<u8>> = (0..1 + r.below(6)).map(|_| (0..1 + r.below(40)).map(|_| r.below(256) as u8).collect()).collect();
            let mut b: Vec<u8> = Vec::new();
            while b.len() < n {
                if r.chance(2, 3) {
                    b.extend_from_slice(&words[r.below(words.len())]);
                } else {
                    b.push(r.below(256) as u8);
                }
            }
            let packed = pack(&b);
            assert!(unpack(&packed).unwrap() == b, "round {round}");
            let mut bad = packed.clone();
            if !bad.is_empty() {
                let at = r.below(bad.len());
                bad[at] ^= 1 << r.below(8);
                bad.truncate(1 + r.below(bad.len()));
                let _ = decode(&bad);
            }
            let noise: Vec<u8> = (0..r.below(200)).map(|_| r.below(256) as u8).collect();
            let _ = decode(&noise);
        }
        let repeating: Vec<u8> = (0..4000u32).map(|i| (i % 37) as u8).collect();
        assert!(pack(&repeating).len() < 200, "{} B", pack(&repeating).len());
    }

    /// `MemRows` counting its reads, and its rows and bytes written.
    #[derive(Default)]
    struct Counted(MemRows, usize, usize, usize);

    impl Rows for Counted {
        type Err = Corrupt;
        fn get(&mut self, key: &[u8]) -> Result<Option<Vec<u8>>, Corrupt> {
            self.1 += 1;
            self.0.get(key)
        }
        fn put(&mut self, key: &[u8], val: &[u8]) -> Result<(), Corrupt> {
            self.2 += 1;
            self.3 += key.len() + val.len();
            self.0.put(key, val)
        }
        fn del(&mut self, key: &[u8]) -> Result<(), Corrupt> {
            self.2 += 1;
            self.0.del(key)
        }
        fn scan(&mut self, from: &[u8], to: &[u8], limit: usize) -> Result<Vec<Row>, Corrupt> {
            self.1 += 1;
            self.0.scan(from, to, limit)
        }
        fn scan_back(&mut self, from: &[u8], to: &[u8], limit: usize) -> Result<Vec<Row>, Corrupt> {
            self.1 += 1;
            self.0.scan_back(from, to, limit)
        }
    }

    /// spec: none (internal: how a node stores an index's rows). Random puts, deletes and scans
    /// both ways read as an unpaged store's, through one page cache kept across `PagedRows`
    /// (as a transaction keeps it) or a fresh one, with keys sharing prefixes of up to three
    /// pages' chunks; pages stay under the bound (but a lone row over it), no page is left once
    /// every row is gone, and once every page is read a read goes to no stored page.
    #[test]
    fn paged_rows_read_as_plain_rows() {
        let mut r = crate::testutil::rng(41);
        let mut cache = PageCache::default();
        // a chunk of 3 bytes
        let key_max = LEVEL + 3;
        let mut paged = PagedRows::with_cache(Counted::default(), key_max, &mut cache);
        let mut plain = MemRows::default();
        let key = |r: &mut crate::testutil::SeedRng| {
            let n = 1 + r.below(8);
            let mut k: Vec<u8> = (0..n).map(|_| r.below(3) as u8).collect();
            k.push(r.below(250) as u8);
            k
        };
        for step in 0..4000 {
            let k = key(&mut r);
            match r.below(10) {
                0..=5 => {
                    let big = r.chance(1, 50);
                    let v: Vec<u8> = (0..r.below(if big { 5000 } else { 300 })).map(|_| r.below(256) as u8).collect();
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
            if r.chance(1, 7) {
                paged.flush().unwrap();
                let inner = std::mem::take(&mut paged.inner);
                drop(paged);
                if r.chance(1, 4) {
                    cache.clear();
                }
                paged = PagedRows::with_cache(inner, key_max, &mut cache);
            }
        }
        paged.flush().unwrap();
        // every page read, each one's next known: reads go to none
        paged.scan(&[], &[0xff; 9], usize::MAX).unwrap();
        let before = paged.inner.1;
        for k in plain.0.keys() {
            assert!(paged.get(k).unwrap() == plain.0.get(k).cloned());
        }
        assert_eq!(paged.inner.1, before, "reads of the store once every page is known");
        assert!(paged.scan(&[], &[0xff; 9], usize::MAX).unwrap() == plain.scan(&[], &[0xff; 9], usize::MAX).unwrap());
        let sized = |pages: &BTreeMap<Vec<u8>, Vec<u8>>| {
            for (k, v) in pages {
                assert!(v.len() <= 2 * PAGE_BYTES || decode(v).unwrap().len() == 1, "page {k:?} of {} B stored", v.len());
            }
            let levels = pages.values().filter(|v| v.is_empty()).count();
            assert!(levels > 3 && pages.len() < plain.0.len() / 4, "{} pages ({levels} naming levels) of {} rows", pages.len(), plain.0.len());
        };
        sized(&paged.inner.0.0);
        let mut filled = PagedRows::new(MemRows::default(), key_max);
        filled.fill(&plain.0).unwrap();
        sized(&filled.inner.0);
        let mut filled = PagedRows::new(std::mem::take(&mut filled.inner), key_max);
        assert!(filled.scan(&[], &[0xff; 9], usize::MAX).unwrap() == plain.scan(&[], &[0xff; 9], usize::MAX).unwrap());
        for k in plain.0.keys() {
            assert!(filled.get(k).unwrap() == plain.0.get(k).cloned());
        }
        let keys: Vec<Vec<u8>> = plain.0.keys().cloned().collect();
        for k in keys {
            paged.del(&k).unwrap();
        }
        paged.flush().unwrap();
        assert!(paged.inner.0.0.is_empty(), "pages left with no row");
    }

    /// spec/crdt.md §4.8; spec/requirements.md, Scale: a change inside a huge value costs O(change). Held-writes
    /// rows (a 16-byte hash per path step, `held`) below a path deeper than a page's key holds,
    /// n and 10n of them: an edit of one row, in a fresh transaction's pages (engine
    /// `bounds::PAGE_KEY`), writes and reads about the same pages and bytes at both sizes.
    #[test]
    fn deep_edit_is_flat() {
        let hash = |b: &[u8]| osis_base::hash::hash(b).get(..16).unwrap().to_vec();
        let key = |i: u32| -> Vec<u8> {
            // a bucket row of a text nine steps down
            let steps: Vec<u8> = (0..9u8).flat_map(|s| hash(&[s])).collect();
            [&[0][..], &steps, &hash(&i.to_be_bytes()), &[0; 16], b"B"].concat()
        };
        let edit = |n: u32| -> (usize, usize, usize) {
            let mut paged = PagedRows::new(Counted::default(), 120);
            for i in 0..n {
                paged.put(&key(i), &osis_base::hash::hash(&i.to_le_bytes())).unwrap();
            }
            paged.flush().unwrap();
            let mut paged = PagedRows::new(std::mem::take(&mut paged.inner), 120);
            (paged.inner.1, paged.inner.2, paged.inner.3) = (0, 0, 0);
            let at = key(n / 2);
            let was = paged.get(&at).unwrap().unwrap();
            paged.put(&at, &[was, vec![1]].concat()).unwrap();
            paged.flush().unwrap();
            (paged.inner.1, paged.inner.2, paged.inner.3)
        };
        let (small, big) = (edit(300), edit(3000));
        eprintln!("store reads, rows written, bytes written: {small:?} at n, {big:?} at 10n");
        assert!(big.0 <= 2 * small.0 + 2 && big.1 <= 2 * small.1 + 2 && big.2 <= 2 * small.2 + 2, "{small:?} at n, {big:?} at 10n");
    }
}
