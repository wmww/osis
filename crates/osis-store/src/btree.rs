//! Tables: ordered byte maps as B+trees whose pages are units (notes/local-store.md,
//! Implementation). Pages split and merge by encoded size; interior entries carry the child's
//! first key exactly and its entry count (rank and position queries). Values above a quarter
//! page live in their own unit. A root keeps its slot for the table's life.
//!
//! `shred` on an operation applies to every unit it writes or deletes: the removed or replaced
//! bytes, and every copy of a removed key in the interior path, become unrecoverable at commit.

use crate::codec::{R, W};
use crate::Error;

pub(crate) trait Units {
    fn read(&mut self, slot: u64) -> Result<Option<Vec<u8>>, Error>;
    fn write(&mut self, slot: u64, data: Vec<u8>, shred: bool) -> Result<(), Error>;
    fn delete(&mut self, slot: u64, shred: bool);
    fn alloc(&mut self) -> Result<u64, Error>;
    fn page_max(&self) -> usize;
}

#[derive(Clone)]
enum Val {
    Inline(Vec<u8>),
    Overflow { slot: u64, len: u64 },
}

#[derive(Clone)]
struct LeafE {
    key: Vec<u8>,
    val: Val,
}

#[derive(Clone)]
struct InnerE {
    key: Vec<u8>,
    child: u64,
    count: u64,
}

enum Page {
    Leaf(Vec<LeafE>),
    Inner(Vec<InnerE>),
}

const HEADER: usize = 5;

fn leaf_size(e: &LeafE) -> usize {
    4 + e.key.len()
        + 1
        + match &e.val {
            Val::Inline(v) => 4 + v.len(),
            Val::Overflow { .. } => 16,
        }
}
fn inner_size(e: &InnerE) -> usize {
    4 + e.key.len() + 16
}

impl Page {
    fn size(&self) -> usize {
        HEADER
            + match self {
                Page::Leaf(es) => es.iter().map(leaf_size).sum::<usize>(),
                Page::Inner(es) => es.iter().map(inner_size).sum::<usize>(),
            }
    }
    fn count(&self) -> u64 {
        match self {
            Page::Leaf(es) => es.len() as u64,
            Page::Inner(es) => es.iter().map(|e| e.count).sum(),
        }
    }
    fn first_key(&self) -> Vec<u8> {
        match self {
            Page::Leaf(es) => es.first().map(|e| e.key.clone()),
            Page::Inner(es) => es.first().map(|e| e.key.clone()),
        }
        .unwrap_or_default()
    }
    fn is_empty(&self) -> bool {
        match self {
            Page::Leaf(es) => es.is_empty(),
            Page::Inner(es) => es.is_empty(),
        }
    }
    fn encode(&self) -> Vec<u8> {
        let mut w = W::new();
        match self {
            Page::Leaf(es) => {
                w.u8(0).u32(es.len() as u32);
                for e in es {
                    w.bytes(&e.key);
                    match &e.val {
                        Val::Inline(v) => w.u8(0).bytes(v),
                        Val::Overflow { slot, len } => w.u8(1).u64(*slot).u64(*len),
                    };
                }
            }
            Page::Inner(es) => {
                w.u8(1).u32(es.len() as u32);
                for e in es {
                    w.bytes(&e.key).u64(e.child).u64(e.count);
                }
            }
        }
        w.take()
    }
    fn decode(b: &[u8]) -> Result<Page, Error> {
        let mut r = R::new(b);
        let kind = r.u8()?;
        let n = r.u32()?;
        let page = match kind {
            0 => {
                let mut es = Vec::new();
                for _ in 0..n {
                    let key = r.bytes()?.to_vec();
                    let val = match r.u8()? {
                        0 => Val::Inline(r.bytes()?.to_vec()),
                        1 => Val::Overflow { slot: r.u64()?, len: r.u64()? },
                        _ => return Err(Error::Corrupt("table page")),
                    };
                    es.push(LeafE { key, val });
                }
                Page::Leaf(es)
            }
            1 => {
                let mut es = Vec::new();
                for _ in 0..n {
                    es.push(InnerE { key: r.bytes()?.to_vec(), child: r.u64()?, count: r.u64()? });
                }
                Page::Inner(es)
            }
            _ => return Err(Error::Corrupt("table page")),
        };
        r.end()?;
        Ok(page)
    }
}

fn load(u: &mut dyn Units, slot: u64) -> Result<Page, Error> {
    Page::decode(&u.read(slot)?.ok_or(Error::Corrupt("table page missing"))?)
}

fn save(u: &mut dyn Units, slot: u64, p: &Page, shred: bool) -> Result<(), Error> {
    u.write(slot, p.encode(), shred)
}

fn resolve(u: &mut dyn Units, v: &Val) -> Result<Vec<u8>, Error> {
    match v {
        Val::Inline(b) => Ok(b.clone()),
        Val::Overflow { slot, .. } => u.read(*slot)?.ok_or(Error::Corrupt("overflow value missing")),
    }
}

fn free_val(u: &mut dyn Units, v: &Val, shred: bool) {
    if let Val::Overflow { slot, .. } = v {
        u.delete(*slot, shred);
    }
}

/// Index of the child whose key range holds `key`.
fn child_index(es: &[InnerE], key: &[u8]) -> usize {
    es.partition_point(|e| e.key.as_slice() <= key).saturating_sub(1)
}

/// Splits entries in two at the byte midpoint (both halves non-empty when `es.len() >= 2`).
fn halves<T>(mut es: Vec<T>, size: impl Fn(&T) -> usize) -> (Vec<T>, Vec<T>) {
    let total: usize = es.iter().map(&size).sum();
    let mut acc = 0;
    let mut at = es.len().saturating_sub(1);
    for (i, e) in es.iter().enumerate() {
        acc += size(e);
        if acc * 2 >= total {
            at = i + 1;
            break;
        }
    }
    let at = at.clamp(1, es.len().saturating_sub(1).max(1));
    let right = es.split_off(at.min(es.len()));
    (es, right)
}

fn split(p: Page) -> (Page, Page) {
    match p {
        Page::Leaf(es) => {
            let (a, b) = halves(es, leaf_size);
            (Page::Leaf(a), Page::Leaf(b))
        }
        Page::Inner(es) => {
            let (a, b) = halves(es, inner_size);
            (Page::Inner(a), Page::Inner(b))
        }
    }
}

fn entry(p: &Page, slot: u64) -> InnerE {
    InnerE { key: p.first_key(), child: slot, count: p.count() }
}

/// Creates an empty table; returns its root slot.
pub(crate) fn create(u: &mut dyn Units) -> Result<u64, Error> {
    let slot = u.alloc()?;
    save(u, slot, &Page::Leaf(Vec::new()), false)?;
    Ok(slot)
}

fn check_key(u: &dyn Units, key: &[u8]) -> Result<(), Error> {
    if key.len() > u.page_max() / 4 { Err(Error::Misuse("table key too long")) } else { Ok(()) }
}

pub(crate) fn get(u: &mut dyn Units, root: u64, key: &[u8]) -> Result<Option<Vec<u8>>, Error> {
    let mut slot = root;
    loop {
        match load(u, slot)? {
            Page::Inner(es) => slot = es.get(child_index(&es, key)).ok_or(Error::Corrupt("empty interior page"))?.child,
            Page::Leaf(es) => {
                return match es.binary_search_by(|e| e.key.as_slice().cmp(key)) {
                    Ok(i) => es.get(i).map(|e| resolve(u, &e.val)).transpose(),
                    Err(_) => Ok(None),
                };
            }
        }
    }
}

/// Inserts or replaces; true if the key was new.
pub(crate) fn put(u: &mut dyn Units, root: u64, key: &[u8], val: Vec<u8>, shred: bool) -> Result<bool, Error> {
    check_key(u, key)?;
    let val = if val.len() > u.page_max() / 4 {
        let slot = u.alloc()?;
        let len = val.len() as u64;
        u.write(slot, val, false)?;
        Val::Overflow { slot, len }
    } else {
        Val::Inline(val)
    };
    let (added, pieces) = insert(u, root, key, val, shred)?;
    if pieces.len() > 1 {
        // Keep the root's slot: move its first piece out.
        let first = load(u, root)?;
        let moved = u.alloc()?;
        save(u, moved, &first, shred)?;
        let mut es = pieces;
        if let Some(e) = es.first_mut() {
            e.child = moved;
        }
        save(u, root, &Page::Inner(es), shred)?;
    }
    Ok(added)
}

/// Returns whether the key was new and this node's entries after the op (itself, then new
/// right siblings).
fn insert(u: &mut dyn Units, slot: u64, key: &[u8], val: Val, shred: bool) -> Result<(bool, Vec<InnerE>), Error> {
    let mut page = load(u, slot)?;
    let added = match &mut page {
        Page::Leaf(es) => match es.binary_search_by(|e| e.key.as_slice().cmp(key)) {
            Ok(i) => {
                if let Some(e) = es.get_mut(i) {
                    let old = std::mem::replace(&mut e.val, val);
                    free_val(u, &old, shred);
                }
                false
            }
            Err(i) => {
                es.insert(i, LeafE { key: key.to_vec(), val });
                true
            }
        },
        Page::Inner(es) => {
            let i = child_index(es, key);
            let child = es.get(i).ok_or(Error::Corrupt("empty interior page"))?.child;
            let (added, pieces) = insert(u, child, key, val, shred)?;
            es.splice(i..=i, pieces);
            added
        }
    };
    if page.size() <= u.page_max() {
        save(u, slot, &page, shred)?;
        return Ok((added, vec![entry(&page, slot)]));
    }
    let (a, b) = split(page);
    let right = u.alloc()?;
    save(u, slot, &a, shred)?;
    save(u, right, &b, shred)?;
    Ok((added, vec![entry(&a, slot), entry(&b, right)]))
}

/// Removes `key`; true if it was present.
pub(crate) fn remove(u: &mut dyn Units, root: u64, key: &[u8], shred: bool) -> Result<bool, Error> {
    match del(u, root, key, shred)? {
        None => return Ok(false),
        Some(p) if p.is_empty() => save(u, root, &Page::Leaf(Vec::new()), shred)?,
        Some(_) => {}
    }
    // Collapse a root with one child into the root's slot.
    loop {
        match load(u, root)? {
            Page::Inner(es) if es.len() == 1 => {
                let child = es.first().map(|e| e.child).ok_or(Error::Corrupt("empty interior page"))?;
                let page = load(u, child)?;
                save(u, root, &page, shred)?;
                u.delete(child, shred);
            }
            _ => return Ok(true),
        }
    }
}

/// Removes `key` below `slot`; `None` if absent, else the node's page after the op (already
/// saved unless empty).
fn del(u: &mut dyn Units, slot: u64, key: &[u8], shred: bool) -> Result<Option<Page>, Error> {
    let mut page = load(u, slot)?;
    match &mut page {
        Page::Leaf(es) => {
            let Ok(i) = es.binary_search_by(|e| e.key.as_slice().cmp(key)) else { return Ok(None) };
            let e = es.remove(i);
            free_val(u, &e.val, shred);
        }
        Page::Inner(es) => {
            let i = child_index(es, key);
            let child_slot = es.get(i).ok_or(Error::Corrupt("empty interior page"))?.child;
            let Some(child) = del(u, child_slot, key, shred)? else { return Ok(None) };
            if child.is_empty() {
                es.remove(i);
                u.delete(child_slot, shred);
            } else {
                if let Some(e) = es.get_mut(i) {
                    *e = entry(&child, child_slot);
                }
                if child.size() < u.page_max() / 4 && es.len() > 1 {
                    let (l, r) = if i + 1 < es.len() { (i, i + 1) } else { (i - 1, i) };
                    rebalance(u, es, l, r, shred)?;
                }
            }
        }
    }
    if !page.is_empty() {
        save(u, slot, &page, shred)?;
    }
    Ok(Some(page))
}

/// Merges siblings `l` and `l + 1` or, if too big for one page, splits them evenly.
fn rebalance(u: &mut dyn Units, es: &mut Vec<InnerE>, l: usize, r: usize, shred: bool) -> Result<(), Error> {
    let (ls, rs) = match (es.get(l), es.get(r)) {
        (Some(a), Some(b)) => (a.child, b.child),
        _ => return Err(Error::Corrupt("rebalance")),
    };
    let merged = match (load(u, ls)?, load(u, rs)?) {
        (Page::Leaf(mut a), Page::Leaf(b)) => {
            a.extend(b);
            Page::Leaf(a)
        }
        (Page::Inner(mut a), Page::Inner(b)) => {
            a.extend(b);
            Page::Inner(a)
        }
        _ => return Err(Error::Corrupt("uneven table")),
    };
    if merged.size() <= u.page_max() {
        save(u, ls, &merged, shred)?;
        u.delete(rs, shred);
        es.splice(l..=r, [entry(&merged, ls)]);
    } else {
        let (a, b) = split(merged);
        save(u, ls, &a, shred)?;
        save(u, rs, &b, shred)?;
        es.splice(l..=r, [entry(&a, ls), entry(&b, rs)]);
    }
    Ok(())
}

/// Up to `limit` entries with `start <= key` and `key < end` (`None`: unbounded), ascending.
pub(crate) fn range(u: &mut dyn Units, root: u64, start: &[u8], end: Option<&[u8]>, limit: usize) -> Result<Vec<(Vec<u8>, Vec<u8>)>, Error> {
    let mut out = Vec::new();
    collect(u, root, start, end, limit, &mut out)?;
    Ok(out)
}

fn collect(u: &mut dyn Units, slot: u64, start: &[u8], end: Option<&[u8]>, limit: usize, out: &mut Vec<(Vec<u8>, Vec<u8>)>) -> Result<(), Error> {
    match load(u, slot)? {
        Page::Leaf(es) => {
            for e in es.iter().skip(es.partition_point(|e| e.key.as_slice() < start)) {
                if out.len() >= limit || end.is_some_and(|end| e.key.as_slice() >= end) {
                    break;
                }
                out.push((e.key.clone(), resolve(u, &e.val)?));
            }
        }
        Page::Inner(es) => {
            for e in es.iter().skip(child_index(&es, start)) {
                if out.len() >= limit || end.is_some_and(|end| e.key.as_slice() >= end) {
                    break;
                }
                collect(u, e.child, start, end, limit, out)?;
            }
        }
    }
    Ok(())
}

/// Entries in the table.
pub(crate) fn len(u: &mut dyn Units, root: u64) -> Result<u64, Error> {
    Ok(load(u, root)?.count())
}

/// Number of keys below `key`.
pub(crate) fn rank(u: &mut dyn Units, root: u64, key: &[u8]) -> Result<u64, Error> {
    let mut slot = root;
    let mut acc = 0u64;
    loop {
        match load(u, slot)? {
            Page::Leaf(es) => return Ok(acc + es.partition_point(|e| e.key.as_slice() < key) as u64),
            Page::Inner(es) => {
                let i = child_index(&es, key);
                acc += es.iter().take(i).map(|e| e.count).sum::<u64>();
                slot = es.get(i).ok_or(Error::Corrupt("empty interior page"))?.child;
            }
        }
    }
}

/// The entry at position `i` (0-based) in key order.
pub(crate) fn nth(u: &mut dyn Units, root: u64, mut i: u64) -> Result<Option<(Vec<u8>, Vec<u8>)>, Error> {
    let mut slot = root;
    loop {
        match load(u, slot)? {
            Page::Leaf(es) => {
                let Some(e) = usize::try_from(i).ok().and_then(|i| es.get(i)) else { return Ok(None) };
                return Ok(Some((e.key.clone(), resolve(u, &e.val)?)));
            }
            Page::Inner(es) => {
                let mut next = None;
                for e in &es {
                    if i < e.count {
                        next = Some(e.child);
                        break;
                    }
                    i -= e.count;
                }
                let Some(n) = next else { return Ok(None) };
                slot = n;
            }
        }
    }
}

/// Deletes every unit of the table, its root included.
pub(crate) fn drop_all(u: &mut dyn Units, root: u64, shred: bool) -> Result<(), Error> {
    match load(u, root)? {
        Page::Leaf(es) => es.iter().for_each(|e| free_val(u, &e.val, shred)),
        Page::Inner(es) => {
            for e in &es {
                drop_all(u, e.child, shred)?;
            }
        }
    }
    u.delete(root, shred);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use std::collections::{BTreeMap, HashMap};

    /// Units in a map, for testing the tree alone.
    #[derive(Default)]
    struct Mem {
        units: HashMap<u64, Vec<u8>>,
        next: u64,
        max: usize,
        shredded: Vec<u64>,
    }

    impl Units for Mem {
        fn read(&mut self, slot: u64) -> Result<Option<Vec<u8>>, Error> {
            Ok(self.units.get(&slot).cloned())
        }
        fn write(&mut self, slot: u64, data: Vec<u8>, shred: bool) -> Result<(), Error> {
            if shred {
                self.shredded.push(slot);
            }
            self.units.insert(slot, data);
            Ok(())
        }
        fn delete(&mut self, slot: u64, shred: bool) {
            if shred {
                self.shredded.push(slot);
            }
            self.units.remove(&slot);
        }
        fn alloc(&mut self) -> Result<u64, Error> {
            self.next += 1;
            Ok(self.next)
        }
        fn page_max(&self) -> usize {
            self.max
        }
    }

    fn check(u: &mut Mem, root: u64, model: &BTreeMap<Vec<u8>, Vec<u8>>) {
        let all = range(u, root, b"", None, usize::MAX).unwrap();
        let want: Vec<_> = model.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
        assert_eq!(all, want);
        assert_eq!(len(u, root).unwrap(), model.len() as u64);
        // Every page within budget; no orphan units.
        let mut reachable = 0;
        let mut stack = vec![root];
        while let Some(s) = stack.pop() {
            reachable += 1;
            let p = load(u, s).unwrap();
            assert!(p.size() <= u.max, "page {} > {}", p.size(), u.max);
            match p {
                Page::Inner(es) => {
                    for e in es {
                        assert_eq!(load(u, e.child).unwrap().first_key(), e.key, "separator is the child's first key");
                        assert_eq!(load(u, e.child).unwrap().count(), e.count);
                        stack.push(e.child);
                    }
                }
                Page::Leaf(es) => reachable += es.iter().filter(|e| matches!(e.val, Val::Overflow { .. })).count(),
            }
        }
        assert_eq!(reachable, u.units.len(), "orphan units");
    }

    // notes/local-store.md, Units: a large state is pages plus an index; ops match a map model.
    proptest! {
        #[test]
        fn matches_model(ops in proptest::collection::vec((any::<bool>(), 0u16..300, 0usize..80), 1..400)) {
            let mut u = Mem { max: 256, ..Mem::default() };
            let root = create(&mut u).unwrap();
            let mut model = BTreeMap::new();
            for (ins, k, vlen) in ops {
                let key = format!("key{k:05}").into_bytes();
                if ins {
                    let v = vec![k as u8; vlen];
                    assert_eq!(put(&mut u, root, &key, v.clone(), false).unwrap(), model.insert(key, v).is_none());
                } else {
                    assert_eq!(remove(&mut u, root, &key, false).unwrap(), model.remove(&key).is_some());
                }
            }
            check(&mut u, root, &model);
            for (i, (k, _)) in model.iter().enumerate() {
                prop_assert_eq!(rank(&mut u, root, k).unwrap(), i as u64);
                prop_assert_eq!(nth(&mut u, root, i as u64).unwrap().map(|e| e.0), Some(k.clone()));
                prop_assert_eq!(get(&mut u, root, k).unwrap(), model.get(k).cloned());
            }
            prop_assert_eq!(nth(&mut u, root, model.len() as u64).unwrap(), None);
            let mid = b"key00150".as_slice();
            let want: Vec<_> = model.range(mid.to_vec()..b"key00200".to_vec()).take(7).map(|(k, v)| (k.clone(), v.clone())).collect();
            prop_assert_eq!(range(&mut u, root, mid, Some(b"key00200"), 7).unwrap(), want);
            drop_all(&mut u, root, false).unwrap();
            prop_assert!(u.units.is_empty());
        }
    }

    // notes/local-store.md, Units: a million-key map write rewrites one page plus its index path.
    #[test]
    fn edit_touches_path_only() {
        let mut u = Mem { max: 1024, ..Mem::default() };
        let root = create(&mut u).unwrap();
        let mut model = BTreeMap::new();
        for k in 0..5000u32 {
            put(&mut u, root, &k.to_be_bytes(), vec![1; 20], false).unwrap();
            model.insert(k.to_be_bytes().to_vec(), vec![1; 20]);
        }
        check(&mut u, root, &model);
        let before = u.units.clone();
        remove(&mut u, root, &1234u32.to_be_bytes(), true).unwrap();
        let changed = u.units.iter().filter(|(s, v)| before.get(s) != Some(v)).count();
        let mut depth = 0;
        let mut s = root;
        while let Page::Inner(es) = load(&mut u, s).unwrap() {
            depth += 1;
            s = es[0].child;
        }
        assert!(changed <= depth + 2, "changed {changed} pages at depth {depth}");
        assert!(!u.shredded.is_empty() && u.shredded.len() <= 2 * (depth + 2));
    }

    // spec/commits.md §5: a removed key leaves no copy in the interior path.
    #[test]
    fn removed_key_leaves_no_separator() {
        let mut u = Mem { max: 256, ..Mem::default() };
        let root = create(&mut u).unwrap();
        for k in 0..200u32 {
            put(&mut u, root, format!("k{k:04}").as_bytes(), vec![0; 10], false).unwrap();
        }
        for k in (0..200u32).step_by(3) {
            let key = format!("k{k:04}");
            remove(&mut u, root, key.as_bytes(), true).unwrap();
            assert!(u.units.values().all(|p| !p.windows(key.len()).any(|w| w == key.as_bytes())), "{key}");
        }
    }

    // notes/local-store.md, Units: a table emptied and refilled stays consistent.
    #[test]
    fn empty_and_refill() {
        let mut u = Mem { max: 256, ..Mem::default() };
        let root = create(&mut u).unwrap();
        for round in 0..3 {
            let mut model = BTreeMap::new();
            for k in 0..100u32 {
                put(&mut u, root, &k.to_be_bytes(), vec![round; 9], false).unwrap();
                model.insert(k.to_be_bytes().to_vec(), vec![round; 9]);
            }
            check(&mut u, root, &model);
            for k in 0..100u32 {
                assert!(remove(&mut u, root, &k.to_be_bytes(), round == 1).unwrap());
            }
            check(&mut u, root, &BTreeMap::new());
        }
    }

    // notes/local-store.md, Units: values above a quarter page live in their own unit.
    #[test]
    fn overflow_values() {
        let mut u = Mem { max: 256, ..Mem::default() };
        let root = create(&mut u).unwrap();
        put(&mut u, root, b"big", vec![7; 10_000], false).unwrap();
        assert_eq!(u.units.len(), 2);
        assert_eq!(get(&mut u, root, b"big").unwrap(), Some(vec![7; 10_000]));
        put(&mut u, root, b"big", vec![8; 3], false).unwrap();
        assert_eq!(u.units.len(), 1);
        assert!(matches!(put(&mut u, root, &[0; 65], vec![], false), Err(Error::Misuse(_))));
    }
}
