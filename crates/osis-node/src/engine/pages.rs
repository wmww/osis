//! Paged states (notes/local-store.md, Units). A state above `PAGE_TARGET` keeps its large
//! collections, at any depth below struct fields, enum payloads and map entries, as pages of
//! consecutive root elements in the aspect's table, the rest as a skeleton in the unit. The
//! store's B+tree is the index: a page's row key is its collection's set ID and the
//! order-preserving bytes of its first dot, so the page holding a dot is the last row at or below
//! it (`table_rank`, `table_nth`), and a map key's entries are found through a key index (set ID,
//! keyed hash of the key under a node-local secret, dot). In memory a state is loaded lazily: the skeleton first, then the pages a read,
//! write or join needs (`ensure_*`), or all of them (`load_all`) where the whole state is needed.

use super::state::{decode, encode};
use crate::error::{Error, Result};
use osis_core::format::PAGE_TARGET;
use osis_core::{Ak, Tid, Value};
use osis_crdt::{Dot, Encoding, Fragment, PagedTouch, PathSeg, Paths, SourceKind, Step};
use osis_store::{Shred, Table, Transaction};
use std::collections::BTreeMap;

/// Encoded bytes per local page, about (a store unit is 8 KB; a larger page is split).
const PAGE_BYTES: usize = 8 * 1024;
/// A collection with fewer elements is not paged.
const MIN_PAGED: usize = 64;
/// The aspect table holding its state pages.
const STATE_TABLE: u8 = 0;
/// The aspect table holding the key index of its paged maps.
const KEY_TABLE: u8 = 1;

/// A path with the keys of its entry steps (to rebuild an entry's key from a page alone).
type KeyedPath = Vec<(Step, Option<Value>)>;

/// The range of a page: its first dot (`None`: the collection's first page) and the next page's.
type Range = (Option<Dot>, Option<Dot>);

/// A paged collection.
#[derive(Clone, Debug)]
struct PageSet {
    id: u32,
    /// The key index's hash key (`Core::key_salt`).
    salt: [u8; 32],
    path: KeyedPath,
    enc: Encoding,
    /// Pages in the in-memory state: row key -> range.
    loaded: BTreeMap<Vec<u8>, Range>,
    /// Every page of the set is loaded.
    whole: bool,
}

impl PageSet {
    fn prefix(&self) -> Vec<u8> {
        self.id.to_be_bytes().to_vec()
    }
    fn row_key(&self, first: Option<&Dot>) -> Vec<u8> {
        let mut k = self.prefix();
        if let Some(d) = first {
            dot_key(d, &mut k);
        }
        k
    }
    /// The loaded page holding `d`, if any.
    fn loaded_page(&self, d: &Dot) -> Option<(&Vec<u8>, &Range)> {
        let k = self.row_key(Some(d));
        let (pk, r) = self.loaded.range(..=k.clone()).next_back()?;
        r.1.as_ref().is_none_or(|hi| d < hi).then_some((pk, r))
    }
}

/// The paged collections of a state (keyed by path) and which of their pages are loaded.
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
    /// Whether every page is loaded.
    pub fn whole(&self) -> bool {
        self.sets.values().all(|s| s.whole)
    }
    /// How many collections are paged.
    #[cfg(test)]
    pub fn sets(&self) -> usize {
        self.sets.len()
    }
}

/// What joining a delta can change in a paged state (`None`: write whole).
pub type Touch = Option<PagedTouch>;

/// What joining `delta` can change in a state with page index `idx`.
pub fn touch_of(delta: &Fragment, idx: Option<&PageIndex>) -> Touch {
    delta.touched_paths(&idx?.paths)
}

/// Whether a unit's state field says the state lives in the aspect's page table: its first
/// item is an integer, not the snapshot bytes.
pub fn is_paged(b: &[u8]) -> bool {
    b.get(1).is_some_and(|x| *x < 0x18)
}

// ---- encodings

fn uint(n: u64) -> Value {
    Value::Int(i64::try_from(n).unwrap_or(i64::MAX))
}

/// Order-preserving bytes of a dot (spec/crdt.md §2.2: source kind, source bytes, counter; a
/// `Derived(d)` dot `i` orders as `(d.source, d.ctr, i)`): fixed-width parts, so byte order is
/// dot order.
fn dot_key(d: &Dot, out: &mut Vec<u8>) {
    match d.src.kind() {
        SourceKind::Node(t) => {
            out.push(0);
            out.extend_from_slice(t.as_bytes());
        }
        SourceKind::Commit(c) => {
            out.push(1);
            out.extend_from_slice(&c.0);
        }
        SourceKind::Derived(x) => dot_key(x, out),
    }
    out.extend_from_slice(&d.ctr.to_be_bytes());
}

use super::records::{dot_of, dot_value};

fn opt_dot_value(d: Option<&Dot>) -> Value {
    d.map_or(Value::List(Vec::new()), dot_value)
}

fn opt_dot_of(v: &Value) -> Result<Option<Dot>> {
    match v {
        Value::List(x) if x.is_empty() => Ok(None),
        v => dot_of(v).map(Some),
    }
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

fn steps(p: &KeyedPath) -> Vec<Step> {
    p.iter().map(|(s, _)| s.clone()).collect()
}

/// Unit state of a paged state: `[4, skeleton, [[set ID, path, encoding]*]]` (`3`: an earlier
/// build's, its key index hashed unkeyed). Unpaged states start `[bytes, ...]`.
fn unit_state(skeleton: &Fragment, idx: &PageIndex) -> Result<Vec<u8>> {
    let sets = idx.sets.values().map(|s| Value::List(vec![uint(u64::from(s.id)), path_value(&s.path), uint(u64::from(s.enc.id()))])).collect();
    Ok(osis_core::encode(&Value::List(vec![Value::Int(4), Value::Bytes(encode(skeleton)?), Value::List(sets)])))
}

/// A page row: `[first dot or [], next page's first dot or [], page]`.
fn page_row(r: &Range, p: &Fragment) -> Result<Vec<u8>> {
    Ok(osis_core::encode(&Value::List(vec![opt_dot_value(r.0.as_ref()), opt_dot_value(r.1.as_ref()), Value::Bytes(encode(p)?)])))
}

fn parse_page_row(b: &[u8]) -> Result<(Range, Fragment)> {
    let lim = osis_core::Limits { max_depth: osis_core::format::MAX_OBJECT_DEPTH, max_bytes: b.len() };
    let v = osis_core::decode(b, &lim).map_err(|_| Error::Corrupt("state page"))?;
    let Value::List(items) = v else { return Err(Error::Corrupt("state page")) };
    let [lo, hi, Value::Bytes(p)] = items.as_slice() else { return Err(Error::Corrupt("state page")) };
    Ok(((opt_dot_of(lo)?, opt_dot_of(hi)?), decode(p)?))
}

/// A key index row of a paged map: set ID, the key's hash, the entry's dot.
fn key_row(set: &PageSet, k: &Value, d: Option<&Dot>) -> Vec<u8> {
    let mut out = set.id.to_be_bytes().to_vec();
    out.extend_from_slice(&osis_core::hash::keyed_hash(&set.salt, &osis_core::encode(k)));
    if let Some(d) = d {
        out.extend_from_slice(&osis_core::encode(&dot_value(d)));
    }
    out
}

// ---- loading

/// Opens a paged state: its skeleton and index, no page loaded yet.
pub fn open(unit_state: &[u8], salt: &[u8; 32]) -> Result<(Fragment, PageIndex)> {
    open_tagged(unit_state, salt, 4)
}

fn open_tagged(unit_state: &[u8], salt: &[u8; 32], tag: i64) -> Result<(Fragment, PageIndex)> {
    let bad = || Error::Corrupt("state");
    let lim = osis_core::Limits { max_depth: osis_core::format::MAX_OBJECT_DEPTH, max_bytes: unit_state.len() };
    let v = osis_core::decode(unit_state, &lim).map_err(|_| bad())?;
    let Value::List(items) = v else { return Err(bad()) };
    let [Value::Int(t), Value::Bytes(skel), Value::List(list)] = items.as_slice() else { return Err(bad()) };
    if *t != tag {
        return Err(bad());
    }
    let f = decode(skel)?;
    let mut idx = PageIndex { sets: BTreeMap::new(), paths: Paths::default() };
    for x in list {
        let Value::List(x) = x else { return Err(bad()) };
        let [Value::Int(id), p, Value::Int(enc)] = x.as_slice() else { return Err(bad()) };
        let path = path_of(p)?;
        let enc = u64::try_from(*enc).ok().and_then(Encoding::from_id).ok_or_else(bad)?;
        let s = steps(&path);
        idx.paths.insert(&s);
        idx.sets.insert(s, PageSet { id: u32::try_from(*id).map_err(|_| bad())?, salt: *salt, path, enc, loaded: BTreeMap::new(), whole: false });
    }
    Ok((f, idx))
}

/// A paged state in an earlier build's layout (`[1]`: a root collection; `[2, skeleton]`: a
/// struct with paged fields; pages in the state table, each a fragment; `[3, ...]`: this layout
/// with an unkeyed key index), joined whole; `None` for any other unit state.
pub fn legacy(txn: &mut Transaction<'_>, tid: &Tid, ak: &Ak, unit_state: &[u8]) -> Result<Option<Fragment>> {
    // the tag is the array's first byte item
    if !matches!(unit_state.get(1), Some(1..=3)) {
        return Ok(None);
    }
    let lim = osis_core::Limits { max_depth: 4, max_bytes: unit_state.len() };
    let Ok(Value::List(items)) = osis_core::decode(unit_state, &lim) else { return Ok(None) };
    let mut f = match items.as_slice() {
        [Value::Int(1)] => Fragment::default(),
        [Value::Int(2), Value::Bytes(s)] => decode(s)?,
        [Value::Int(3), ..] => {
            let (mut f, mut idx) = open_tagged(unit_state, &[0; 32], 3)?;
            load_all(txn, tid, ak, &mut idx, &mut f)?;
            return Ok(Some(f));
        }
        _ => return Ok(None),
    };
    let t = table(txn, tid, ak)?;
    let mut from = Vec::new();
    loop {
        let rows = txn.table_range(t, &from, None, 256)?;
        let n = rows.len();
        for (k, v) in rows {
            from = [k.as_slice(), &[0]].concat();
            f.join(decode(&v)?);
        }
        if n < 256 {
            return Ok(Some(f));
        }
    }
}

fn table(txn: &mut Transaction<'_>, tid: &Tid, ak: &Ak) -> Result<Table> {
    txn.table(tid, ak, STATE_TABLE)?.ok_or(Error::Corrupt("state pages missing"))
}

/// Joins one page row into `f` and notes it loaded.
fn join_row(f: &mut Fragment, set: &mut PageSet, key: Vec<u8>, row: &[u8]) -> Result<()> {
    if set.loaded.contains_key(&key) {
        return Ok(());
    }
    let (range, p) = parse_page_row(row)?;
    if set.row_key(range.0.as_ref()) != key {
        return Err(Error::Corrupt("state page key"));
    }
    f.join(Fragment::wrap(&set.path, p));
    set.loaded.insert(key, range);
    Ok(())
}

/// Loads every page not loaded yet: the whole state.
pub fn load_all(txn: &mut Transaction<'_>, tid: &Tid, ak: &Ak, idx: &mut PageIndex, f: &mut Fragment) -> Result<()> {
    if idx.whole() {
        return Ok(());
    }
    let t = table(txn, tid, ak)?;
    for set in idx.sets.values_mut() {
        if set.whole {
            continue;
        }
        let end = (set.id.saturating_add(1)).to_be_bytes();
        let mut from = set.prefix();
        loop {
            let rows = txn.table_range(t, &from, Some(&end), 256)?;
            let n = rows.len();
            for (k, v) in rows {
                from = [k.as_slice(), &[0]].concat();
                join_row(f, set, k, &v)?;
            }
            if n < 256 {
                break;
            }
        }
        if !set.loaded.contains_key(&set.prefix()) {
            return Err(Error::Corrupt("first state page missing"));
        }
        set.whole = true;
    }
    Ok(())
}

/// Loads the page of `set` holding `d` (the last row at or below it).
fn ensure_dot(txn: &mut Transaction<'_>, t: Table, set: &mut PageSet, f: &mut Fragment, d: &Dot) -> Result<()> {
    if set.whole || set.loaded_page(d).is_some() {
        return Ok(());
    }
    let below = txn.table_rank(t, &[set.row_key(Some(d)), vec![0]].concat())?;
    let (k, v) = txn.table_nth(t, below.checked_sub(1).ok_or(Error::Corrupt("state page missing"))?)?.ok_or(Error::Corrupt("state page missing"))?;
    if !k.starts_with(&set.prefix()) {
        return Err(Error::Corrupt("state page missing"));
    }
    join_row(f, set, k, &v)
}

/// Loads the first page of `set` (it holds records as long as the collection is paged:
/// records are never dropped but by a whole rewrite, which lays the pages out again).
fn ensure_first(txn: &mut Transaction<'_>, t: Table, set: &mut PageSet, f: &mut Fragment) -> Result<()> {
    let k = set.prefix();
    if set.whole || set.loaded.contains_key(&k) {
        return Ok(());
    }
    let v = txn.table_get(t, &k)?.ok_or(Error::Corrupt("first state page missing"))?;
    join_row(f, set, k, &v)
}

/// Loads every page of the set at `p`.
fn ensure_set(txn: &mut Transaction<'_>, t: Table, set: &mut PageSet, f: &mut Fragment) -> Result<()> {
    if set.whole {
        return Ok(());
    }
    let end = (set.id.saturating_add(1)).to_be_bytes();
    let mut from = set.prefix();
    loop {
        let rows = txn.table_range(t, &from, Some(&end), 256)?;
        let n = rows.len();
        for (k, v) in rows {
            from = [k.as_slice(), &[0]].concat();
            join_row(f, set, k, &v)?;
        }
        if n < 256 {
            break;
        }
    }
    set.whole = true;
    Ok(())
}

/// Loads the pages joining a delta touches (`touch_of`): those holding its dots, every page of
/// a touched sequence (its records join across pages).
pub fn ensure_touch(txn: &mut Transaction<'_>, tid: &Tid, ak: &Ak, idx: &mut PageIndex, f: &mut Fragment, touch: &PagedTouch) -> Result<bool> {
    let t = table(txn, tid, ak)?;
    for (p, dots) in &touch.elems {
        let Some(set) = idx.sets.get_mut(p) else { return Ok(false) };
        if matches!(set.enc, Encoding::List | Encoding::Text) {
            ensure_set(txn, t, set, f)?;
            continue;
        }
        for d in dots {
            ensure_dot(txn, t, set, f, d)?;
        }
    }
    Ok(true)
}

/// Removes the key index rows of the map entries `bodies` hold that the state no longer holds
/// under that key (shredded: a dropped body leaves no local entry derived from it,
/// spec/commits.md §5). The pages holding the bodies' dots are loaded.
pub fn unindex(txn: &mut Transaction<'_>, idx: &PageIndex, tid: &Tid, ak: &Ak, f: &Fragment, bodies: &[Fragment]) -> Result<()> {
    let Some(kt) = txn.table(tid, ak, KEY_TABLE)? else { return Ok(()) };
    for (p, set) in idx.sets.iter().filter(|(_, s)| s.enc == Encoding::Map) {
        let c = f.at_steps(p);
        for b in bodies {
            let Some(Fragment::Map(m)) = b.at_steps(p) else { continue };
            for (d, _, k, _) in m.entries() {
                if let Some(k) = k
                    && c.and_then(|c| c.entry_key(d)) != Some(k)
                {
                    txn.table_remove(kt, &key_row(set, k, Some(d)), Shred::Yes)?;
                }
            }
        }
    }
    Ok(())
}

/// The dots of key `k`'s entries in the paged map `set` (a superset: the index is never pruned).
fn key_dots(txn: &mut Transaction<'_>, tid: &Tid, ak: &Ak, set: &PageSet, k: &Value) -> Result<Vec<Dot>> {
    let Some(t) = txn.table(tid, ak, KEY_TABLE)? else { return Ok(Vec::new()) };
    let start = key_row(set, k, None);
    // every row of the key: the dot after the prefix is a CBOR array (first byte below 0xff)
    let end = [start.as_slice(), &[0xff]].concat();
    let mut out = Vec::new();
    let mut from = start.clone();
    loop {
        let rows = txn.table_range(t, &from, Some(&end), 256)?;
        let n = rows.len();
        for (key, _) in rows {
            from = [key.as_slice(), &[0]].concat();
            let Some(tail) = key.get(start.len()..) else { continue };
            let lim = osis_core::Limits { max_depth: 8, max_bytes: tail.len() };
            let v = osis_core::decode(tail, &lim).map_err(|_| Error::Corrupt("state key index"))?;
            out.push(dot_of(&v)?);
        }
        if n < 256 {
            break;
        }
    }
    Ok(out)
}

/// Loads what reading or writing at `path` (op path segments) needs: the pages of the map keys
/// along it (through the key index), every page of a sequence it indexes into, and at its end
/// everything paged below. `Ok(false)`: not addressable that way (load whole).
pub fn ensure_path(txn: &mut Transaction<'_>, tid: &Tid, ak: &Ak, idx: &mut PageIndex, f: &mut Fragment, path: &[PathSeg]) -> Result<bool> {
    let t = table(txn, tid, ak)?;
    // positions reached so far, as steps from the root
    let mut at: Vec<Vec<Step>> = vec![Vec::new()];
    for seg in path {
        let mut next = Vec::new();
        for p in at {
            let paged = idx.sets.contains_key(&p);
            if paged {
                let Some(set) = idx.sets.get_mut(&p) else { continue };
                // the first page restores the entries leading here (the skeleton reduced them
                // away) even when the key has none: a write then finds the collection
                ensure_first(txn, t, set, f)?;
                match seg {
                    PathSeg::Key(k) if set.enc == Encoding::Map => {
                        let ds = key_dots(txn, tid, ak, set, k)?;
                        for d in &ds {
                            ensure_dot(txn, t, set, f, d)?;
                        }
                    }
                    _ => ensure_set(txn, t, set, f)?,
                }
            }
            match seg {
                PathSeg::Field(id) => next.push([p.clone(), vec![Step::Field(*id)]].concat()),
                PathSeg::Case(id) => next.push([p.clone(), vec![Step::Case(*id)]].concat()),
                PathSeg::Key(k) => {
                    // the key's live entries loaded so far, and the entries the skeleton reduced
                    // away that lead to paged collections (their keys are on the sets' paths)
                    if let Some(Fragment::Map(m)) = f.at_steps(&p) {
                        next.extend(m.live(k).into_iter().map(|(d, _)| [p.clone(), vec![Step::Entry(d.clone())]].concat()));
                    }
                    for set in idx.sets.values() {
                        if set.path.len() > p.len()
                            && set.path.iter().zip(&p).all(|((s, _), q)| s == q)
                            && let Some((s @ Step::Entry(_), Some(key))) = set.path.get(p.len())
                            && key == k
                        {
                            let q = [p.clone(), vec![s.clone()]].concat();
                            if !next.contains(&q) {
                                next.push(q);
                            }
                        }
                    }
                }
                // a list element's content is never paged apart from its list
                PathSeg::Index(_) => {}
            }
        }
        at = next;
    }
    // everything paged at or below the positions reached
    for p in at {
        let below: Vec<Vec<Step>> = idx.sets.keys().filter(|k| k.starts_with(&p)).cloned().collect();
        for q in below {
            if let Some(set) = idx.sets.get_mut(&q) {
                ensure_set(txn, t, set, f)?;
            }
        }
    }
    Ok(true)
}

// ---- writing

/// A page: the collection's root elements in `[lo, hi)`, collections paged below reduced.
fn page(c: &Fragment, nested: &Paths, r: &Range) -> Result<Fragment> {
    Ok(c.elem_range(r.0.as_ref(), r.1.as_ref(), false).ok_or(Error::Corrupt("state page"))?.reduced(nested))
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

/// Adds the keys of the entries at `dots` of the map `c` to its key index.
/// Adds the key index rows of the map entries `dots` (`fresh`: the table is new, no row exists).
fn index_keys(txn: &mut Transaction<'_>, kt: Table, set: &PageSet, c: &Fragment, dots: &mut dyn Iterator<Item = &Dot>, fresh: bool) -> Result<()> {
    if set.enc != Encoding::Map {
        return Ok(());
    }
    for d in dots {
        if let Some(k) = c.entry_key(d) {
            // rows are never removed (a superset), so most are there already: a read, not a write
            let row = key_row(set, k, Some(d));
            if fresh || txn.table_get(kt, &row)?.is_none() {
                txn.table_put(kt, &row, Vec::new(), Shred::No)?;
            }
        }
    }
    Ok(())
}

/// Writes one collection's pages (and key index) from scratch, about `PAGE_BYTES` each.
fn write_set(txn: &mut Transaction<'_>, t: Table, kt: Table, set: &mut PageSet, c: &Fragment, nested: &Paths) -> Result<()> {
    let n = c.elem_count().unwrap_or(0).max(1);
    let size = encode(&c.reduced(nested))?.len().max(1);
    let per = (n * PAGE_BYTES / size).max(1);
    let dots = c.elem_dots(None, None);
    set.loaded.clear();
    let chunks: Vec<&[Dot]> = if dots.is_empty() { vec![&[]] } else { dots.chunks(per).collect() };
    for (i, chunk) in chunks.into_iter().enumerate() {
        let lo = if i == 0 { None } else { chunk.first().cloned() };
        let r = (lo, dots.get((i + 1) * per).cloned());
        let key = set.row_key(r.0.as_ref());
        txn.table_put(t, &key, page_row(&r, &page(c, nested, &r)?)?, Shred::No)?;
        set.loaded.insert(key, r);
    }
    set.whole = true;
    // the tables were created for this write
    index_keys(txn, kt, set, c, &mut dots.iter(), true)
}

/// Writes a whole state: the unit's state field, and the pages when the state is above
/// `PAGE_TARGET` and holds large collections (the old pages, if any, are dropped shredded).
/// `f` must be the whole state.
pub fn write_full(txn: &mut Transaction<'_>, tid: &Tid, ak: &Ak, f: Option<&Fragment>, old_paged: bool, salt: &[u8; 32]) -> Result<(Vec<u8>, Option<PageIndex>)> {
    if old_paged {
        txn.drop_table(tid, ak, STATE_TABLE)?;
        txn.drop_table(tid, ak, KEY_TABLE)?;
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
    let kt = txn.create_table(tid, ak, KEY_TABLE)?;
    let mut idx = PageIndex { sets: BTreeMap::new(), paths: Paths::default() };
    for p in &paged {
        idx.paths.insert(p);
    }
    for (i, p) in paged.into_iter().enumerate() {
        let c = f.at_steps(&p).ok_or(Error::Corrupt("state collection"))?;
        let mut set = PageSet { id: u32::try_from(i).map_err(|_| Error::Corrupt("state sets"))?, salt: *salt, path: keyed(f, &p), enc: c.encoding(), loaded: BTreeMap::new(), whole: false };
        write_set(txn, t, kt, &mut set, c, &idx.nested(&p))?;
        idx.sets.insert(p, set);
    }
    let unit = unit_state(&f.reduced(&idx.paths), &idx)?;
    Ok((unit, Some(idx)))
}

/// Points the page before row `key` at `hi` (its successor went).
fn relink_prev(txn: &mut Transaction<'_>, t: Table, set: &mut PageSet, key: &[u8], hi: Option<Dot>, shred: Shred) -> Result<()> {
    let below = txn.table_rank(t, key)?;
    let (pk, v) = txn.table_nth(t, below.checked_sub(1).ok_or(Error::Corrupt("state page missing"))?)?.ok_or(Error::Corrupt("state page missing"))?;
    let ((lo, _), p) = parse_page_row(&v)?;
    let r = (lo, hi);
    txn.table_put(t, &pk, page_row(&r, &p)?, shred)?;
    if let Some(x) = set.loaded.get_mut(&pk) {
        *x = r;
    }
    Ok(())
}

/// Rewrites the loaded pages of one collection holding `dots`: splits a page grown past twice
/// `PAGE_BYTES`, drops an emptied one. `Ok(false)`: an element alone outgrew a page, or a dot's
/// page is not loaded (write whole).
#[allow(clippy::too_many_arguments)]
fn rewrite_set(txn: &mut Transaction<'_>, t: Table, kt: Table, set: &mut PageSet, c: &Fragment, nested: &Paths, dots: &[Dot], shred: Shred) -> Result<bool> {
    let mut dirty: BTreeMap<Vec<u8>, Range> = BTreeMap::new();
    if matches!(set.enc, Encoding::List | Encoding::Text) {
        // (first, last) per delta record: a range record touches every page between
        if !set.whole {
            return Ok(false);
        }
        for pair in dots.chunks(2) {
            let (Some(a), Some(b)) = (pair.first(), pair.last()) else { continue };
            let (Some((ka, _)), Some((kb, _))) = (set.loaded_page(a), set.loaded_page(b)) else { return Ok(false) };
            if ka <= kb {
                dirty.extend(set.loaded.range(ka.clone()..=kb.clone()).map(|(k, r)| (k.clone(), r.clone())));
            }
        }
    } else {
        for d in dots {
            let Some((k, r)) = set.loaded_page(d) else { return Ok(false) };
            dirty.insert(k.clone(), r.clone());
        }
    }
    index_keys(txn, kt, set, c, &mut dots.iter(), false)?;
    for (key, r) in dirty {
        let ds = c.elem_dots(r.0.as_ref(), r.1.as_ref());
        if r.0.is_some() && ds.is_empty() {
            txn.table_remove(t, &key, shred)?;
            set.loaded.remove(&key);
            relink_prev(txn, t, set, &key, r.1.clone(), shred)?;
            continue;
        }
        let bytes = page_row(&r, &page(c, nested, &r)?)?;
        if bytes.len() <= 2 * PAGE_BYTES {
            txn.table_put(t, &key, bytes, shred)?;
            continue;
        }
        if ds.len() < 2 {
            // one element above a page: page what grew inside it (a whole rewrite re-lays out)
            if bytes.len() > PAGE_TARGET {
                return Ok(false);
            }
            txn.table_put(t, &key, bytes, shred)?;
            continue;
        }
        let per = ds.len().div_ceil(bytes.len().div_ceil(PAGE_BYTES)).max(1);
        let pieces: Vec<&[Dot]> = ds.chunks(per).collect();
        let n = pieces.len();
        for (i, chunk) in pieces.into_iter().enumerate() {
            let lo = if i == 0 { r.0.clone() } else { chunk.first().cloned() };
            let hi = if i + 1 == n { r.1.clone() } else { ds.get((i + 1) * per).cloned() };
            let pr = (lo, hi);
            let pk = set.row_key(pr.0.as_ref());
            // elements moving to another row: the old versions go shredded, so a later shred of
            // a moved element's row reaches every copy
            txn.table_put(t, &pk, page_row(&pr, &page(c, nested, &pr)?)?, Shred::Yes)?;
            set.loaded.insert(pk, pr);
        }
    }
    Ok(true)
}

/// Rewrites what `touch` says changed in the paged state `f` (holding at least the pages
/// `ensure_touch` loaded for it). `Ok(None)`: it does not fit the pages (write whole);
/// `Ok(Some(unit))`: done, with the unit's new state field if the skeleton changed.
pub fn write_touched(txn: &mut Transaction<'_>, idx: &mut PageIndex, tid: &Tid, ak: &Ak, f: &Fragment, touch: &PagedTouch, shred: Shred) -> Result<Option<Option<Vec<u8>>>> {
    // a touched collection that moved or changed encoding: lay out again
    for p in touch.elems.keys() {
        let (Some(set), Some(c)) = (idx.sets.get(p), f.at_steps(p)) else { return Ok(None) };
        if c.encoding() != set.enc {
            return Ok(None);
        }
    }
    let t = table(txn, tid, ak)?;
    let kt = txn.create_table(tid, ak, KEY_TABLE)?;
    for (p, dots) in &touch.elems {
        let nested = idx.nested(p);
        let (Some(set), Some(c)) = (idx.sets.get_mut(p), f.at_steps(p)) else { return Ok(None) };
        if !rewrite_set(txn, t, kt, set, c, &nested, dots, shred)? {
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

/// Holds value-less, in the paged state `f`, the writes `pred` names, which lie in the pages
/// `touches` say (those of the deltas owning them, loaded by `ensure_touch`): strips them in
/// memory, rewrites those pages shredded and drops the key index rows of map entries left
/// without their key (an index entry derived from a dropped write, spec/commits.md §5).
/// `Ok(false)`: it does not fit the pages (strip and write whole).
pub fn strip_touched(txn: &mut Transaction<'_>, idx: &mut PageIndex, tid: &Tid, ak: &Ak, f: &mut Fragment, touches: &[PagedTouch], pred: &dyn Fn(&Dot) -> bool) -> Result<bool> {
    let mut before: Vec<(Vec<Step>, Dot, Value)> = Vec::new();
    for t in touches {
        for (p, dots) in &t.elems {
            if idx.sets.get(p).is_some_and(|s| s.enc == Encoding::Map)
                && let Some(c) = f.at_steps(p)
            {
                before.extend(dots.iter().filter_map(|d| Some((p.clone(), d.clone(), c.entry_key(d)?.clone()))));
            }
        }
    }
    f.strip(pred);
    for t in touches {
        if write_touched(txn, idx, tid, ak, f, t, Shred::Yes)?.is_none() {
            return Ok(false);
        }
    }
    if let Some(kt) = txn.table(tid, ak, KEY_TABLE)? {
        for (p, d, k) in before {
            let (Some(set), Some(c)) = (idx.sets.get(&p), f.at_steps(&p)) else { continue };
            if c.entry_key(&d) != Some(&k) {
                txn.table_remove(kt, &key_row(set, &k, Some(&d)), Shred::Yes)?;
            }
        }
    }
    Ok(true)
}

/// The unit state of the paged state `f` (its skeleton and sets).
pub fn skeleton_unit(f: &Fragment, idx: &PageIndex) -> Result<Vec<u8>> {
    unit_state(&f.reduced(&idx.paths), idx)
}

/// The paths of the ops of a mutation if each addresses map keys or fields only (a write there
/// reads only what it addresses); `None` when one needs the whole position (a write of a whole
/// collection, a sequence op, a set element by value).
pub fn op_paths(ops: &[osis_crdt::PathOp]) -> Option<Vec<Vec<PathSeg>>> {
    use osis_crdt::Op;
    let mut out = Vec::new();
    for o in ops {
        if o.path.iter().any(|s| matches!(s, PathSeg::Index(_))) {
            return None;
        }
        match (&o.op, o.path.last()) {
            (Op::Remove(k), _) => out.push([o.path.clone(), vec![PathSeg::Key(k.clone())]].concat()),
            (Op::Set(_) | Op::Replace(_) | Op::Put(_), Some(PathSeg::Key(_) | PathSeg::Field(_))) => out.push(o.path.clone()),
            _ => return None,
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing)]
    use super::*;
    const SALT: [u8; 32] = [9; 32];
    use osis_core::Ts;
    use osis_crdt::{AnyView, Batch, Op, PathOp, PathSeg, Source, Writer, create};
    use osis_store::{MemoryBackend, MemoryRoot, Store, StoreConfig};

    /// The value of `n` ints keyed 0..n.
    fn ints(n: i64, x: i64) -> Value {
        Value::Map((0..n).map(|i| (Value::Int(i), Value::Int(i * x))).collect())
    }

    // spec/commits.md §5 (a dropped body leaves no local index entry derived from it): the key
    // index rows of a removed key's entry go (shredded) when the bodies holding it are dropped;
    // the other keys' rows stay; rows are keyed hashes (another salt finds nothing).
    #[test]
    fn dropped_body_unindexed_spec_commits_5() {
        let mut rng = osis_crypto::SeededRng::from_u64(80);
        let mut store = Store::create(Box::new(MemoryBackend::new()), Box::new(MemoryRoot::new()), StoreConfig::default(), &mut rng).unwrap();
        let (tid, ak) = (Tid::from_bytes([5; 15]), osis_core::Ak::new("/app/keys").unwrap());
        let node = Source::node(Tid::from_bytes([1; 15]));
        let mut w = Writer::new(Ts::from_u64(1 << 16).unwrap(), node.clone(), 1);
        let body = create(&mut w, &AnyView, &ints(6000, 1)).unwrap();
        let mut txn = store.transaction(&mut rng).unwrap();
        let (unit, idx) = write_full(&mut txn, &tid, &ak, Some(&body), false, &SALT).unwrap();
        assert!(idx.is_some());
        let rows = |txn: &mut Transaction<'_>| txn.table(&tid, &ak, KEY_TABLE).unwrap().map_or(0, |t| txn.table_range(t, &[], None, 10_000).unwrap().len());
        assert_eq!(rows(&mut txn), 6000);
        let (mut f, mut idx) = open(&unit, &SALT).unwrap();
        load_all(&mut txn, &tid, &ak, &mut idx, &mut f).unwrap();
        let mut b = Batch::new(&f, Writer::new(Ts::from_u64(2 << 16).unwrap(), node, w.range().hi));
        b.apply(&PathOp { path: Vec::new(), op: Op::Remove(Value::Int(5)) }, &AnyView).unwrap();
        let (d, _) = b.finish().unwrap();
        f.join(d);
        let set = idx.sets.values().next().unwrap().clone();
        let k5 = key_row(&set, &Value::Int(5), None);
        assert_eq!(key_dots(&mut txn, &tid, &ak, &set, &Value::Int(5)).unwrap().len(), 1, "a superset until the body goes");
        unindex(&mut txn, &idx, &tid, &ak, &f, std::slice::from_ref(&body)).unwrap();
        assert_eq!(rows(&mut txn), 5999);
        assert!(key_dots(&mut txn, &tid, &ak, &set, &Value::Int(5)).unwrap().is_empty());
        assert_eq!(key_dots(&mut txn, &tid, &ak, &set, &Value::Int(6)).unwrap().len(), 1);
        let other = PageSet { salt: [8; 32], ..set };
        assert!(key_dots(&mut txn, &tid, &ak, &other, &Value::Int(6)).unwrap().is_empty(), "keyed");
        assert_ne!(k5, key_row(&other, &Value::Int(5), None));
    }

    // notes/local-store.md (Units): a state paged in an earlier build's layout (`[1]` with pages
    // of the root collection by page ID) is read whole and laid out anew.
    #[test]
    fn legacy_layout_relaid_spec_requirements_scale() {
        let mut rng = osis_crypto::SeededRng::from_u64(79);
        let mut store = Store::create(Box::new(MemoryBackend::new()), Box::new(MemoryRoot::new()), StoreConfig::default(), &mut rng).unwrap();
        let (tid, ak) = (Tid::from_bytes([4; 15]), osis_core::Ak::new("/app/old").unwrap());
        let mut w = Writer::new(Ts::from_u64(1 << 16).unwrap(), Source::node(Tid::from_bytes([1; 15])), 1);
        let st = create(&mut w, &AnyView, &ints(6000, 1)).unwrap();
        let mut txn = store.transaction(&mut rng).unwrap();
        let t = txn.create_table(&tid, &ak, STATE_TABLE).unwrap();
        let dots = st.elem_dots(None, None);
        let mid = dots.get(dots.len() / 2).cloned();
        let halves = [st.elem_range(None, mid.as_ref(), true).unwrap(), st.elem_range(mid.as_ref(), None, false).unwrap()];
        for (i, h) in halves.iter().enumerate() {
            txn.table_put(t, &[&[0u8][..], &(i as u64).to_be_bytes()].concat(), encode(h).unwrap(), Shred::No).unwrap();
        }
        let old = osis_core::encode(&Value::List(vec![Value::Int(1)]));
        assert!(is_paged(&old));
        let whole = legacy(&mut txn, &tid, &ak, &old).unwrap().unwrap();
        assert_eq!(whole, st);
        let (unit, idx) = write_full(&mut txn, &tid, &ak, Some(&whole), true, &SALT).unwrap();
        assert!(idx.is_some());
        assert_eq!(legacy(&mut txn, &tid, &ak, &unit).unwrap(), None, "the new layout is not legacy");
        let (mut f, mut idx) = open(&unit, &SALT).unwrap();
        load_all(&mut txn, &tid, &ak, &mut idx, &mut f).unwrap();
        assert_eq!(f, st);
    }

    // spec/requirements.md, Scale (a change costs O(change) at any depth, peer input never causes
    // unbounded work); notes/local-store.md (Units): a state with large collections inside map
    // entries pages each of them. Random edits, each made in a fresh session that loads only the
    // pages the edit touches (or everything where it does not fit), written page by page: a
    // whole load from the store always gives the reference state back, and reads by key in a
    // fresh session load the pages of that key only and read what the whole state reads.
    #[test]
    fn lazy_nested_paging_spec_requirements_scale() {
        let mut rng = osis_crypto::SeededRng::from_u64(77);
        let mut store = Store::create(Box::new(MemoryBackend::new()), Box::new(MemoryRoot::new()), StoreConfig::default(), &mut rng).unwrap();
        let (tid, ak) = (Tid::from_bytes([3; 15]), osis_core::Ak::new("/app/nested").unwrap());
        let node = Source::node(Tid::from_bytes([1; 15]));
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
        let mut ts = 1u64 << 16;
        let mut w = Writer::new(Ts::from_u64(ts).unwrap(), node.clone(), 1);
        let mut st = create(&mut w, &AnyView, &v).unwrap();
        let mut ctr = w.range().hi;
        let mut txn = store.transaction(&mut rng).unwrap();
        let (mut unit, idx) = write_full(&mut txn, &tid, &ak, Some(&st), false, &SALT).unwrap();
        assert!(idx.unwrap().sets() >= 2);
        let whole = |txn: &mut Transaction<'_>, unit: &[u8]| {
            let (mut f, mut idx) = open(unit, &SALT).unwrap();
            load_all(txn, &tid, &ak, &mut idx, &mut f).unwrap();
            f
        };
        assert_eq!(whole(&mut txn, &unit), st);
        let mut orng = osis_crypto::SeededRng::from_u64(78);
        let mut r = |n: u64| osis_crypto::RngCore::next_u64(&mut orng) % n;
        let (mut in_place, mut partial) = (0, 0);
        for step in 0..30 {
            ts += 1 << 16;
            let key = |s: &str| PathSeg::Key(Value::Str(s.into()));
            let op = match r(6) {
                0 => PathOp { path: vec![key("big"), PathSeg::Key(Value::Int(r(3000) as i64))], op: Op::Set(Value::Int(-(step as i64))) },
                1 => PathOp { path: vec![key("big")], op: Op::Remove(Value::Int(r(2500) as i64)) },
                2 => PathOp { path: vec![key("tags")], op: Op::Add(Value::Str(format!("n{step}"))) },
                3 => PathOp { path: vec![key("small"), PathSeg::Key(Value::Int(r(10) as i64))], op: Op::Set(Value::Int(7)) },
                4 => PathOp { path: vec![PathSeg::Key(Value::Str(format!("k{}", r(5))))], op: Op::Set(ints(3, 2)) },
                _ => PathOp { path: vec![key("x")], op: Op::Set(Value::Int(step as i64)) },
            };
            // a fresh session: the skeleton, then the pages the op addresses
            let (mut f, mut idx) = open(&unit, &SALT).unwrap();
            match op_paths(std::slice::from_ref(&op)) {
                Some(paths) => {
                    for p in &paths {
                        assert!(ensure_path(&mut txn, &tid, &ak, &mut idx, &mut f, p).unwrap());
                    }
                    partial += usize::from(!idx.whole());
                }
                None => load_all(&mut txn, &tid, &ak, &mut idx, &mut f).unwrap(),
            }
            let mut b = Batch::new(&f, Writer::new(Ts::from_u64(ts).unwrap(), node.clone(), ctr));
            let mut full = Batch::new(&st, Writer::new(Ts::from_u64(ts).unwrap(), node.clone(), ctr));
            let (ok, ok_full) = (b.apply(&op, &AnyView).is_ok(), full.apply(&op, &AnyView).is_ok());
            assert_eq!(ok, ok_full, "step {step}");
            if !ok {
                continue;
            }
            // the op over the loaded pages writes what it writes over the whole state
            let (got, want) = (b.finish(), full.finish());
            assert_eq!(got.as_ref().map(|x| &x.0), want.as_ref().map(|x| &x.0), "step {step}: {op:?}");
            let Some((delta, range)) = got else { continue };
            ctr = range.hi;
            let touch = touch_of(&delta, Some(&idx));
            match &touch {
                Some(t) => assert!(ensure_touch(&mut txn, &tid, &ak, &mut idx, &mut f, t).unwrap()),
                None => load_all(&mut txn, &tid, &ak, &mut idx, &mut f).unwrap(),
            }
            st.join(delta.clone());
            f.join(delta);
            let done = match &touch {
                Some(t) => write_touched(&mut txn, &mut idx, &tid, &ak, &f, t, Shred::No).unwrap(),
                None => None,
            };
            in_place += usize::from(done.is_some());
            match done {
                Some(Some(u)) => unit = u,
                Some(None) => {}
                None => {
                    load_all(&mut txn, &tid, &ak, &mut idx, &mut f).unwrap();
                    assert_eq!(f, st, "step {step}");
                    let (u, i) = write_full(&mut txn, &tid, &ak, Some(&f), true, &SALT).unwrap();
                    unit = u;
                    assert!(i.is_some(), "still paged");
                }
            }
            assert_eq!(whole(&mut txn, &unit), st, "step {step}: {op:?}");
            // a read by key in a fresh session
            let k = PathSeg::Key(Value::Int(r(2600) as i64));
            let (mut f, mut idx) = open(&unit, &SALT).unwrap();
            assert!(ensure_path(&mut txn, &tid, &ak, &mut idx, &mut f, &[key("big"), k.clone()]).unwrap());
            assert!(!idx.whole(), "one key loads a page or two");
            assert_eq!(f.at(&[key("big"), k.clone()]).and_then(|x| x.read()), st.at(&[key("big"), k]).and_then(|x| x.read()));
        }
        assert!(in_place >= 20, "{in_place} of 30 written in place");
        assert!(partial >= 10, "{partial} of 30 made over some pages only");
    }
}
