//! Paged states (notes/local-store.md, Units). A state above `PAGE_TARGET` keeps its large
//! collections, at any depth below struct fields, enum payloads and map entries, as pages of
//! consecutive root elements in the aspect's table, the rest as a skeleton in the unit. The
//! store's B+tree is the index: a page's row key is its collection's set ID and the
//! order-preserving bytes of its first dot, so the page holding a dot is the last row at or below
//! it (`table_rank`, `table_nth`), and a map key's entries and a set value's elements are found
//! through an index (set ID, keyed hash of the key or value under a node-local secret, dot). In
//! memory a state is loaded lazily: the skeleton first, then the pages a read, write or join
//! needs (`ensure_*`), or all of them (`load_all`) where the whole state is needed.

use super::state::{decode, encode};
use crate::error::{Error, Result};
use osis_core::format::PAGE_TARGET;
use osis_core::{Ak, Tid, Value};
use osis_crdt::{Dot, Encoding, Fragment, PagedTouch, PathSeg, Paths, PlacedBlock, SourceKind, Step};
use osis_store::{Shred, Table, Transaction};
use std::collections::BTreeMap;
use std::ops::Range as Span;

/// Encoded bytes per local page, about (a store unit is 8 KB; a larger page is split).
const PAGE_BYTES: usize = 8 * 1024;
/// A collection with fewer elements is not paged.
const MIN_PAGED: usize = 64;
/// The aspect table holding its state pages.
const STATE_TABLE: u8 = 0;
/// The aspect table holding the index of its paged maps (by key) and sets (by value).
const KEY_TABLE: u8 = 1;
/// The aspect table holding the placement of its paged sequences (`write_placement`).
const PLACE_TABLE: u8 = 2;
/// The unit state tag of this layout (`legacy` reads the earlier ones).
const TAG: i64 = 6;

/// A path with the keys of its entry steps (to rebuild an entry's key from a page alone).
type KeyedPath = Vec<(Step, Option<Value>, Option<osis_crdt::Stamp>)>;

/// The range of a page: its first dot (`None`: the collection's first page) and the next page's.
type Range = (Option<Dot>, Option<Dot>);

/// A paged collection.
#[derive(Clone, Debug)]
struct PageSet {
    id: u32,
    /// The index's hash key (`Core::key_salt`).
    salt: [u8; 32],
    path: KeyedPath,
    enc: Encoding,
    /// Pages in the in-memory state: row key -> range.
    loaded: BTreeMap<Vec<u8>, Range>,
    /// Every page of the set is loaded.
    whole: bool,
    /// A sequence's stored placement was invalidated in this session (its summary removed).
    stale: bool,
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
            .map(|(s, k, c)| match s {
                Step::Field(id) => Value::List(vec![Value::Int(0), uint(*id)]),
                Step::Case(id) => Value::List(vec![Value::Int(1), uint(*id)]),
                Step::Entry(d) => Value::List(vec![
                    Value::Int(2),
                    dot_value(d),
                    k.clone().map_or(Value::List(Vec::new()), |k| Value::List(vec![k])),
                    Value::List(c.iter().map(|c| uint(c.ts.to_u64())).collect()),
                ]),
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
                [Value::Int(0), Value::Int(id)] => Ok((Step::Field(n(id)?), None, None)),
                [Value::Int(1), Value::Int(id)] => Ok((Step::Case(n(id)?), None, None)),
                [Value::Int(2), d, Value::List(k)] => Ok((Step::Entry(dot_of(d)?), k.first().cloned(), None)),
                [Value::Int(2), d, Value::List(k), Value::List(c)] => {
                    let d = dot_of(d)?;
                    let created = match c.as_slice() {
                        [] => None,
                        [Value::Int(ts)] => Some(osis_crdt::Stamp::new(osis_core::Ts::from_u64(n(ts)?).ok_or_else(bad)?, d.src.clone(), d.ctr)),
                        _ => return Err(bad()),
                    };
                    Ok((Step::Entry(d), k.first().cloned(), created))
                }
                _ => Err(bad()),
            },
            _ => Err(bad()),
        })
        .collect()
}

fn steps(p: &KeyedPath) -> Vec<Step> {
    p.iter().map(|(s, _, _)| s.clone()).collect()
}

/// Unit state of a paged state: `[6, skeleton, [[set ID, path, encoding]*]]` (earlier builds':
/// `3`, the key index hashed unkeyed; `4`, no set values indexed, link keys hashed whole; `5`,
/// no sequence placement).
/// Unpaged states start `[bytes, ...]`.
fn unit_state(skeleton: &Fragment, idx: &PageIndex) -> Result<Vec<u8>> {
    let sets = idx.sets.values().map(|s| Value::List(vec![uint(u64::from(s.id)), path_value(&s.path), uint(u64::from(s.enc.id()))])).collect();
    Ok(osis_core::encode(&Value::List(vec![Value::Int(TAG), Value::Bytes(encode(skeleton)?), Value::List(sets)])))
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

/// What an index row finds a key or value by: equal values (links by content hash alone,
/// spec/data-model.md §6) give equal results.
fn ident(v: &Value) -> Value {
    match v {
        Value::Link(l) => Value::Bytes(l.hash.to_vec()),
        Value::List(x) => Value::List(x.iter().map(ident).collect()),
        Value::Set(x) => Value::Set(x.iter().map(ident).collect()),
        Value::Map(x) => Value::Map(x.iter().map(|(k, v)| (ident(k), ident(v))).collect()),
        Value::Enum(c, p) => Value::Enum(*c, p.as_deref().map(|p| Box::new(ident(p)))),
        v => v.clone(),
    }
}

/// What the index of a paged collection finds element `d` by: a map entry's key, the value of
/// a set element (and of any `Derived` element sorting right after it: a superset). Empty for
/// a keyless or value-less element and other encodings.
fn indexed(c: &Fragment, enc: Encoding, d: &Dot) -> Vec<Value> {
    match enc {
        Encoding::Map => c.entry_key(d).cloned().into_iter().collect(),
        Encoding::Set => {
            let next = d.ctr.checked_add(1).map(|ctr| Dot { src: d.src.clone(), ctr });
            match c.elem_range(Some(d), next.as_ref(), false).and_then(|x| x.read()) {
                Some(Value::Set(vs)) => vs.into_iter().collect(),
                _ => Vec::new(),
            }
        }
        _ => Vec::new(),
    }
}

/// An index row of a paged map or set: set ID, the hash of the key or value, the element's dot.
fn key_row(set: &PageSet, k: &Value, d: Option<&Dot>) -> Vec<u8> {
    let mut out = set.id.to_be_bytes().to_vec();
    out.extend_from_slice(&osis_core::hash::keyed_hash(&set.salt, &osis_core::encode(&ident(k))));
    if let Some(d) = d {
        out.extend_from_slice(&osis_core::encode(&dot_value(d)));
    }
    out
}

// ---- loading

/// Opens a paged state: its skeleton and index, no page loaded yet.
pub fn open(unit_state: &[u8], salt: &[u8; 32]) -> Result<(Fragment, PageIndex)> {
    open_tagged(unit_state, salt, TAG)
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
        idx.sets.insert(s, PageSet { id: u32::try_from(*id).map_err(|_| bad())?, salt: *salt, path, enc, loaded: BTreeMap::new(), whole: false, stale: false });
    }
    Ok((f, idx))
}

/// A paged state in an earlier build's layout (`[1]`: a root collection; `[2, skeleton]`: a
/// struct with paged fields; pages in the state table, each a fragment; `[3, ...]` to
/// `[5, ...]`: this layout with an earlier index), joined whole; `None` for any other unit state.
pub fn legacy(txn: &mut Transaction<'_>, tid: &Tid, ak: &Ak, unit_state: &[u8]) -> Result<Option<Fragment>> {
    // the tag is the array's first byte item
    if !matches!(unit_state.get(1), Some(1..=5)) {
        return Ok(None);
    }
    // set paths nest (fields, entries)
    let lim = osis_core::Limits { max_depth: osis_core::format::MAX_OBJECT_DEPTH, max_bytes: unit_state.len() };
    let Ok(Value::List(items)) = osis_core::decode(unit_state, &lim) else { return Ok(None) };
    let mut f = match items.as_slice() {
        [Value::Int(1)] => Fragment::default(),
        [Value::Int(2), Value::Bytes(s)] => decode(s)?,
        [Value::Int(t @ (3..=5)), ..] => {
            // loading reads pages only, never the index
            let (mut f, mut idx) = open_tagged(unit_state, &[0; 32], *t)?;
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
    // counted: scale tests read the number of pages loaded
    let _s = crate::costs::span("state page load");
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

/// Removes the index rows of the map entries and set elements `bodies` hold that the state no
/// longer holds under that key or value (shredded: a dropped body leaves no local entry derived
/// from it, spec/commits.md §5). The pages holding the bodies' dots are loaded.
pub fn unindex(txn: &mut Transaction<'_>, idx: &PageIndex, tid: &Tid, ak: &Ak, f: &Fragment, bodies: &[Fragment]) -> Result<()> {
    let Some(kt) = txn.table(tid, ak, KEY_TABLE)? else { return Ok(()) };
    for (p, set) in idx.sets.iter().filter(|(_, s)| matches!(s.enc, Encoding::Map | Encoding::Set)) {
        let c = f.at_steps(p);
        for b in bodies {
            let Some(bc) = b.at_steps(p).filter(|x| x.encoding() == set.enc) else { continue };
            for d in bc.elem_dots(None, None) {
                let now = c.map(|c| indexed(c, set.enc, &d)).unwrap_or_default();
                for k in indexed(bc, set.enc, &d) {
                    if !now.contains(&k) {
                        txn.table_remove(kt, &key_row(set, &k, Some(&d)), Shred::Yes)?;
                    }
                }
            }
        }
    }
    Ok(())
}

/// The dots of key `k`'s entries in the paged map `set`, or of value `k`'s elements in the paged
/// set `set` (a superset: the index is never pruned).
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
    let at = walk(txn, tid, ak, t, idx, f, path)?;
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

/// The positions `path` (op path segments) reaches, as steps from the root, with the pages of
/// the map keys along it loaded (through the key index) and every page of a sequence it indexes
/// into.
fn walk(txn: &mut Transaction<'_>, tid: &Tid, ak: &Ak, t: Table, idx: &mut PageIndex, f: &mut Fragment, path: &[PathSeg]) -> Result<Vec<Vec<Step>>> {
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
                    // a key of a map; a value of a set (`op_paths` of an op by value)
                    PathSeg::Key(k) if matches!(set.enc, Encoding::Map | Encoding::Set) => {
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
                            && set.path.iter().zip(&p).all(|((s, _, _), q)| s == q)
                            && let Some((s @ Step::Entry(_), Some(key), _)) = set.path.get(p.len())
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
    Ok(at)
}

// ---- placement of paged sequences (spec/crdt.md §6)
//
// A paged sequence keeps its placement in the aspect's placement table, so a read by index
// loads only the pages holding the elements it reads: a summary row (`[[block ID, visible
// count]*]` in order) and per block a row of its visible elements in order (runs `[[first dot,
// count]*]` of consecutive counters of one source), the crdt's placement blocks
// (`Fragment::placement`) holding visible elements. Invalidated on write, rebuilt on read: a
// layout (`write_full`) writes it whole; the first write of the sequence's pages in a session
// removes the summary (`invalidate_placement`); a read by index finding no summary (or a
// damaged row) reads the sequence whole and lays the placement out anew (`Ranged::Damaged`,
// `rebuild_placement`). So it is exact whenever present, and costs an edit one leaf per
// session. Rebuildable: the unit tag names its rules.

fn is_seq(set: &PageSet) -> bool {
    matches!(set.enc, Encoding::List | Encoding::Text)
}

/// A placement row key: the summary (`None`) or a block.
fn place_key(set: &PageSet, block: Option<u64>) -> Vec<u8> {
    let mut k = set.prefix();
    match block {
        None => k.push(0),
        Some(id) => {
            k.push(1);
            k.extend_from_slice(&id.to_be_bytes());
        }
    }
    k
}

fn block_row(b: &PlacedBlock) -> Vec<u8> {
    let mut runs: Vec<(&Dot, u64)> = Vec::new();
    for d in b.visible() {
        match runs.last_mut() {
            Some((f, n)) if f.src == d.src && f.ctr.checked_add(*n) == Some(d.ctr) => *n += 1,
            _ => runs.push((d, 1)),
        }
    }
    osis_core::encode(&Value::List(runs.into_iter().map(|(d, n)| Value::List(vec![dot_value(d), uint(n)])).collect()))
}

/// A block row's visible elements (`None`: damaged; a block holds at most a few hundred).
fn parse_block(b: &[u8]) -> Option<Vec<Dot>> {
    let lim = osis_core::Limits { max_depth: osis_core::format::MAX_OBJECT_DEPTH, max_bytes: b.len() };
    let Value::List(runs) = osis_core::decode(b, &lim).ok()? else { return None };
    let mut out = Vec::new();
    for r in runs {
        let Value::List(x) = r else { return None };
        let [d, Value::Int(n)] = x.as_slice() else { return None };
        let d = dot_of(d).ok()?;
        let n = u64::try_from(*n).ok().filter(|n| (1..=1 << 16).contains(n))?;
        for i in 0..n {
            out.push(Dot { src: d.src.clone(), ctr: d.ctr.checked_add(i)? });
        }
    }
    Some(out)
}

fn summary_row(blocks: &[(PlacedBlock, u64)]) -> Vec<u8> {
    osis_core::encode(&Value::List(blocks.iter().map(|(b, id)| Value::List(vec![uint(*id), uint(b.shown() as u64)])).collect()))
}

fn parse_summary(b: &[u8]) -> Option<Vec<(u64, usize)>> {
    let lim = osis_core::Limits { max_depth: 4, max_bytes: b.len() };
    let Value::List(xs) = osis_core::decode(b, &lim).ok()? else { return None };
    xs.iter()
        .map(|x| match x {
            Value::List(x) => match x.as_slice() {
                [Value::Int(id), Value::Int(n)] => Some((u64::try_from(*id).ok()?, usize::try_from(*n).ok()?)),
                _ => None,
            },
            _ => None,
        })
        .collect()
}

/// Lays out the placement of the paged sequence `set` (`c`, loaded whole): every block holding
/// visible elements, then the summary (`fresh`: the table holds no row of the set; else the old
/// rows go first).
fn write_placement(txn: &mut Transaction<'_>, tid: &Tid, ak: &Ak, set: &mut PageSet, c: &Fragment, fresh: bool, shred: Shred) -> Result<()> {
    if !set.whole {
        return Err(Error::Corrupt("state sequence not loaded"));
    }
    let pt = txn.create_table(tid, ak, PLACE_TABLE)?;
    if !fresh {
        clear_placement(txn, pt, set, shred)?;
    }
    let blocks = c.placement().ok_or(Error::Corrupt("state sequence"))?;
    let mut out = Vec::new();
    for (id, b) in (0u64..).zip(blocks.into_iter().filter(|b| b.shown() > 0)) {
        // counted: scale tests read the number of blocks written
        let _s = crate::costs::span("placement block write");
        txn.table_put(pt, &place_key(set, Some(id)), block_row(&b), shred)?;
        out.push((b, id));
    }
    txn.table_put(pt, &place_key(set, None), summary_row(&out), shred)?;
    set.stale = false;
    Ok(())
}

/// Invalidates the stored placement of the paged sequence `set` (a write changed it): removes
/// its summary, once per session; the next read by index finds none and lays it out anew
/// (`Ranged::Damaged`, `rebuild_placement`). The block rows stay until then (dots only).
fn invalidate_placement(txn: &mut Transaction<'_>, tid: &Tid, ak: &Ak, set: &mut PageSet, shred: Shred) -> Result<()> {
    if set.stale {
        return Ok(());
    }
    if let Some(pt) = txn.table(tid, ak, PLACE_TABLE)? {
        txn.table_remove(pt, &place_key(set, None), shred)?;
    }
    set.stale = true;
    Ok(())
}

/// Drops every placement row of `set`.
fn clear_placement(txn: &mut Transaction<'_>, pt: Table, set: &PageSet, shred: Shred) -> Result<()> {
    let end = (set.id.saturating_add(1)).to_be_bytes();
    loop {
        let rows = txn.table_range(pt, &set.prefix(), Some(&end), 256)?;
        if rows.is_empty() {
            return Ok(());
        }
        for (k, _) in rows {
            txn.table_remove(pt, &k, shred)?;
        }
    }
}

/// What a read of a paged sequence's elements by index found (`seq_range`).
pub enum Ranged {
    /// The sequence's path; the elements' dots, in order, with the pages holding them loaded;
    /// the sequence's visible length.
    Read(Vec<Step>, Vec<Dot>, usize),
    /// The path does not lead to one paged sequence (read as usual).
    Unpaged,
    /// The sequence's placement is missing or damaged: read whole, then `rebuild_placement`.
    Damaged(Vec<Step>),
}

/// The visible elements `r` (by index, clamped) of the paged sequence at `path` (op path
/// segments) through its placement: the summary, the blocks holding them and the pages holding
/// their records, nothing else of the sequence.
pub fn seq_range(txn: &mut Transaction<'_>, tid: &Tid, ak: &Ak, idx: &mut PageIndex, f: &mut Fragment, path: &[PathSeg], r: Span<usize>) -> Result<Ranged> {
    let t = table(txn, tid, ak)?;
    let at = walk(txn, tid, ak, t, idx, f, path)?;
    let [p] = at.as_slice() else { return Ok(Ranged::Unpaged) };
    let Some(set) = idx.sets.get_mut(p).filter(|s| is_seq(s)) else { return Ok(Ranged::Unpaged) };
    let damaged = || Ok(Ranged::Damaged(p.clone()));
    let Some(pt) = txn.table(tid, ak, PLACE_TABLE)? else { return damaged() };
    let Some(sum) = txn.table_get(pt, &place_key(set, None))?.as_deref().and_then(parse_summary) else { return damaged() };
    let total: usize = sum.iter().map(|x| x.1).sum();
    // a reversed range is empty
    let lo = r.start.min(total);
    let hi = r.end.min(total).max(lo);
    let (mut dots, mut base) = (Vec::with_capacity(hi.saturating_sub(lo)), 0);
    for (id, n) in sum {
        if base >= hi {
            break;
        }
        if base + n > lo {
            let Some(b) = txn.table_get(pt, &place_key(set, Some(id)))?.as_deref().and_then(parse_block).filter(|b| b.len() == n) else { return damaged() };
            dots.extend(b.into_iter().skip(lo.saturating_sub(base)).take(hi.min(base + n) - base.max(lo)));
        }
        base += n;
    }
    for d in &dots {
        ensure_dot(txn, t, set, f, d)?;
    }
    Ok(Ranged::Read(p.clone(), dots, total))
}

/// Lays the placement of the paged sequence at `p` out anew (its pages loaded whole).
pub fn rebuild_placement(txn: &mut Transaction<'_>, tid: &Tid, ak: &Ak, idx: &mut PageIndex, f: &Fragment, p: &[Step]) -> Result<()> {
    let (Some(set), Some(c)) = (idx.sets.get_mut(p), f.at_steps(p)) else { return Ok(()) };
    write_placement(txn, tid, ak, set, c, false, Shred::No)
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
        let (key, created) = match s {
            Step::Entry(d) => (cur.and_then(|c| c.entry_key(d)).cloned(), cur.and_then(|c| c.entry_created(d)).cloned()),
            _ => (None, None),
        };
        out.push((s.clone(), key, created));
        cur = cur.and_then(|c| c.step(s));
    }
    out
}

/// Adds the index rows of the map entries or set elements `dots` of `c` (`fresh`: the table is
/// new, no row exists).
fn index_keys(txn: &mut Transaction<'_>, kt: Table, set: &PageSet, c: &Fragment, dots: &mut dyn Iterator<Item = &Dot>, fresh: bool) -> Result<()> {
    if !matches!(set.enc, Encoding::Map | Encoding::Set) {
        return Ok(());
    }
    for d in dots {
        for k in indexed(c, set.enc, d) {
            // rows are never removed (a superset), so most are there already: a read, not a write
            let row = key_row(set, &k, Some(d));
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
        txn.drop_table(tid, ak, PLACE_TABLE)?;
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
        let mut set = PageSet { id: u32::try_from(i).map_err(|_| Error::Corrupt("state sets"))?, salt: *salt, path: keyed(f, &p), enc: c.encoding(), loaded: BTreeMap::new(), whole: false, stale: false };
        write_set(txn, t, kt, &mut set, c, &idx.nested(&p))?;
        if is_seq(&set) {
            write_placement(txn, tid, ak, &mut set, c, true, Shred::No)?;
        }
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
        if is_seq(set) {
            invalidate_placement(txn, tid, ak, set, shred)?;
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
/// memory, rewrites those pages shredded and drops the index rows of map entries left without
/// their key and set elements without their value (an index entry derived from a dropped write,
/// spec/commits.md §5).
/// `Ok(false)`: it does not fit the pages (strip and write whole).
pub fn strip_touched(txn: &mut Transaction<'_>, idx: &mut PageIndex, tid: &Tid, ak: &Ak, f: &mut Fragment, touches: &[PagedTouch], pred: &dyn Fn(&Dot) -> bool) -> Result<bool> {
    let mut before: Vec<(Vec<Step>, Dot, Value)> = Vec::new();
    for t in touches {
        for (p, dots) in &t.elems {
            if let Some(set) = idx.sets.get(p)
                && let Some(c) = f.at_steps(p)
            {
                before.extend(dots.iter().flat_map(|d| indexed(c, set.enc, d).into_iter().map(|k| (p.clone(), d.clone(), k))));
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
            if !indexed(c, set.enc, &d).contains(&k) {
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

/// The paths of the ops of a mutation if each addresses map keys, fields or set values only (a
/// write there reads only what it addresses; an add or remove by value addresses its value as
/// a key step); `None` when one needs the whole position (a write of a whole collection, a
/// sequence op).
/// `key`: the form a key or value is looked up by (a large one: its link).
pub fn op_paths(ops: &[osis_crdt::PathOp], key: &mut dyn FnMut(&Value) -> Result<Value>) -> Result<Option<Vec<Vec<PathSeg>>>> {
    use osis_crdt::Op;
    let mut out = Vec::new();
    for o in ops {
        let mut path = o.path.clone();
        match &o.op {
            Op::Add(k) | Op::Remove(k) => path.push(PathSeg::Key(k.clone())),
            Op::Set(_) | Op::Replace(_) | Op::Put(_) if matches!(o.path.last(), Some(PathSeg::Key(_) | PathSeg::Field(_))) => {}
            _ => return Ok(None),
        }
        for s in &mut path {
            match s {
                PathSeg::Index(_) => return Ok(None),
                // the crdt matches keys and elements as the writer's type projects them; only
                // a value without struct (map) parts projects from itself alone
                PathSeg::Key(k) if has_map(k) => return Ok(None),
                PathSeg::Key(k) => *k = key(k)?,
                _ => {}
            }
        }
        out.push(path);
    }
    Ok(Some(out))
}

/// Whether `v` holds a map (a struct or map value) anywhere.
fn has_map(v: &Value) -> bool {
    match v {
        Value::Map(_) => true,
        Value::List(x) => x.iter().any(has_map),
        Value::Set(x) => x.iter().any(has_map),
        Value::Enum(_, Some(p)) => has_map(p),
        _ => false,
    }
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

    // spec/crdt.md §5.5 (add and remove by value), spec/data-model.md §6 (links compare by
    // content hash), spec/commits.md §5 (a dropped body leaves no index entry derived from it):
    // a paged set's value index finds a value's elements, a link by its hash alone; the rows of
    // a removed value go with the bodies holding it.
    #[test]
    fn set_value_index_spec_crdt_5_5() {
        let mut rng = osis_crypto::SeededRng::from_u64(81);
        let mut store = Store::create(Box::new(MemoryBackend::new()), Box::new(MemoryRoot::new()), StoreConfig::default(), &mut rng).unwrap();
        let (tid, ak) = (Tid::from_bytes([6; 15]), osis_core::Ak::new("/app/set").unwrap());
        let node = Source::node(Tid::from_bytes([1; 15]));
        let mut w = Writer::new(Ts::from_u64(1 << 16).unwrap(), node.clone(), 1);
        let body = create(&mut w, &AnyView, &Value::Set((0..6000).map(Value::Int).collect())).unwrap();
        let mut txn = store.transaction(&mut rng).unwrap();
        let (unit, idx) = write_full(&mut txn, &tid, &ak, Some(&body), false, &SALT).unwrap();
        assert!(idx.is_some());
        let rows = |txn: &mut Transaction<'_>| txn.table(&tid, &ak, KEY_TABLE).unwrap().map_or(0, |t| txn.table_range(t, &[], None, 10_000).unwrap().len());
        assert_eq!(rows(&mut txn), 6000);
        // a value's page alone, then the op over it writes what it writes over the whole set
        let (mut f, mut idx) = open(&unit, &SALT).unwrap();
        let op = PathOp { path: Vec::new(), op: Op::Remove(Value::Int(5)) };
        for p in op_paths(std::slice::from_ref(&op), &mut |v| Ok(v.clone())).unwrap().unwrap() {
            assert!(ensure_path(&mut txn, &tid, &ak, &mut idx, &mut f, &p).unwrap());
        }
        assert!(!idx.whole());
        let mut b = Batch::new(&f, Writer::new(Ts::from_u64(2 << 16).unwrap(), node.clone(), w.range().hi));
        b.apply(&op, &AnyView).unwrap();
        let (d, _) = b.finish().unwrap();
        let mut full = Batch::new(&body, Writer::new(Ts::from_u64(2 << 16).unwrap(), node, w.range().hi));
        full.apply(&op, &AnyView).unwrap();
        assert_eq!(full.finish().unwrap().0, d);
        load_all(&mut txn, &tid, &ak, &mut idx, &mut f).unwrap();
        f.join(d);
        let set = idx.sets.values().next().unwrap().clone();
        unindex(&mut txn, &idx, &tid, &ak, &f, std::slice::from_ref(&body)).unwrap();
        assert_eq!(rows(&mut txn), 5999);
        assert!(key_dots(&mut txn, &tid, &ak, &set, &Value::Int(5)).unwrap().is_empty());
        assert_eq!(key_dots(&mut txn, &tid, &ak, &set, &Value::Int(6)).unwrap().len(), 1);
        // links: by content hash, whatever blob holds the value
        let link = |b: u8| Value::Link(osis_core::Link { hash: [7; 32], blob: osis_core::BlobId([b; 32]), suite: 1, key: [b; 32] });
        assert_eq!(link(1), link(2));
        assert_eq!(key_row(&set, &link(1), None), key_row(&set, &link(2), None));
        assert_eq!(key_row(&set, &Value::List(vec![link(1)]), None), key_row(&set, &Value::List(vec![link(2)]), None));
        // a value with struct parts is matched as projected: not by the index
        let st = Value::Map(BTreeMap::from([(Value::Int(0), Value::Int(1))]));
        assert_eq!(op_paths(&[PathOp { path: Vec::new(), op: Op::Add(Value::List(vec![st.clone()])) }], &mut |v| Ok(v.clone())).unwrap(), None);
        assert_eq!(op_paths(&[PathOp { path: vec![PathSeg::Key(st.clone()), PathSeg::Key(Value::Int(1))], op: Op::Set(Value::Int(2)) }], &mut |v| Ok(v.clone())).unwrap(), None);
        assert_eq!(op_paths(&[PathOp { path: vec![PathSeg::Key(st)], op: Op::Put(Value::Int(2)) }], &mut |v| Ok(v.clone())).unwrap(), None);
    }

    // spec/crdt.md §5.5 (add and remove by value), spec/data-model.md §6 (links equal by
    // content hash): ops by value over the pages a paged set's index finds write what they write
    // over the whole state, for floats, links (alone and nested), enums, empty values, with a
    // concurrent writer's elements joined in.
    #[test]
    fn set_index_differential_spec_crdt_5_5() {
        use osis_core::Float;
        let mut rng = osis_crypto::SeededRng::from_u64(177);
        let mut store = Store::create(Box::new(MemoryBackend::new()), Box::new(MemoryRoot::new()), StoreConfig::default(), &mut rng).unwrap();
        let (tid, ak) = (Tid::from_bytes([3; 15]), osis_core::Ak::new("/app/s").unwrap());
        let nodes = [Source::node(Tid::from_bytes([1; 15])), Source::node(Tid::from_bytes([2; 15]))];
        let link = |h: u8, b: u8| Value::Link(osis_core::Link { hash: [h; 32], blob: osis_core::BlobId([b; 32]), suite: 1, key: [b; 32] });
        let pool = |i: u64| -> Value {
            match i % 14 {
                0 => Value::Float(Float::new(0.0)),
                1 => Value::Float(Float::new(-0.0)),
                2 => Value::Float(Float::new(f64::NAN)),
                3 => Value::Int(0),
                4 => Value::Bool(true),
                5 => Value::Bool(false),
                6 => link(1, (i % 3) as u8),
                7 => Value::Bytes(vec![1; 32]),
                8 => Value::List(vec![link(2, (i % 5) as u8), Value::Int(1)]),
                9 => Value::Enum(3, Some(Box::new(link(1, (i % 4) as u8)))),
                10 => Value::Enum(3, None),
                11 => Value::Set([link(4, (i % 2) as u8), Value::Int(9)].into_iter().collect()),
                12 => Value::Str(String::new()),
                _ => Value::Int(i as i64 % 50),
            }
        };
        let base = Value::Set((0..3000).map(|i| Value::Str(format!("padding-padding-{i:05}"))).chain((0..200).map(pool)).collect());
        let mut ts = 1u64 << 16;
        let mut w = Writer::new(Ts::from_u64(ts).unwrap(), nodes[0].clone(), 1);
        let mut st = create(&mut w, &AnyView, &base).unwrap();
        let mut ctrs = [w.range().hi, 1];
        let mut txn = store.transaction(&mut rng).unwrap();
        let (mut unit, i0) = write_full(&mut txn, &tid, &ak, Some(&st), false, &SALT).unwrap();
        assert!(i0.is_some());
        let mut orng = osis_crypto::SeededRng::from_u64(179);
        let mut r = |n: u64| osis_crypto::RngCore::next_u64(&mut orng) % n;
        let mut old = st.clone();
        let (mut mism, mut writes) = (0, 0);
        for step in 0..60 {
            ts += 1 << 16;
            let v = pool(r(1000));
            let op = PathOp { path: vec![], op: if r(2) == 0 { Op::Add(v) } else { Op::Remove(v) } };
            let wi = r(2) as usize;
            // writer 1 writes against an old snapshot (concurrent), writer 0 against the paged state
            if wi == 1 {
                let mut b = Batch::new(&old, Writer::new(Ts::from_u64(ts).unwrap(), nodes[1].clone(), ctrs[1]));
                if b.apply(&op, &AnyView).is_err() { continue; }
                let Some((delta, range)) = b.finish() else { continue };
                ctrs[1] = range.hi;
                let (mut f, mut idx) = open(&unit, &SALT).unwrap();
                let touch = touch_of(&delta, Some(&idx));
                match &touch { Some(t) => { ensure_touch(&mut txn, &tid, &ak, &mut idx, &mut f, t).unwrap(); } None => load_all(&mut txn, &tid, &ak, &mut idx, &mut f).unwrap() }
                st.join(delta.clone()); f.join(delta);
                match touch.as_ref().and_then(|t| write_touched(&mut txn, &mut idx, &tid, &ak, &f, t, Shred::No).unwrap()) {
                    Some(Some(u)) => unit = u,
                    Some(None) => {}
                    None => { load_all(&mut txn, &tid, &ak, &mut idx, &mut f).unwrap(); unit = write_full(&mut txn, &tid, &ak, Some(&f), true, &SALT).unwrap().0; }
                }
                if r(4) == 0 { old = st.clone(); }
                continue;
            }
            let (mut f, mut idx) = open(&unit, &SALT).unwrap();
            match op_paths(std::slice::from_ref(&op), &mut |v| Ok(v.clone())).unwrap() {
                Some(paths) => for p in &paths { ensure_path(&mut txn, &tid, &ak, &mut idx, &mut f, p).unwrap(); },
                None => load_all(&mut txn, &tid, &ak, &mut idx, &mut f).unwrap(),
            }
            let mut b = Batch::new(&f, Writer::new(Ts::from_u64(ts).unwrap(), nodes[0].clone(), ctrs[0]));
            let mut full = Batch::new(&st, Writer::new(Ts::from_u64(ts).unwrap(), nodes[0].clone(), ctrs[0]));
            let (ok, ok_full) = (b.apply(&op, &AnyView).is_ok(), full.apply(&op, &AnyView).is_ok());
            assert_eq!(ok, ok_full);
            if !ok { continue; }
            let (got, want) = (b.finish(), full.finish());
            if got.as_ref().map(|x| &x.0) != want.as_ref().map(|x| &x.0) {
                mism += 1;
                println!("mismatch at step {step}: {op:?}");
            }
            let Some((delta, range)) = want else { continue };
            writes += 1;
            ctrs[0] = range.hi;
            load_all(&mut txn, &tid, &ak, &mut idx, &mut f).unwrap();
            st.join(delta.clone()); f.join(delta);
            unit = write_full(&mut txn, &tid, &ak, Some(&f), true, &SALT).unwrap().0;
        }
        assert!(writes > 10, "{writes} writes");
        assert_eq!(mism, 0);
    }
    // spec: none (local store layout); notes/local-store.md (Units): a state paged in an earlier build's layout (`[1]` with pages
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
        // the layout before set values were indexed (`[4, ...]`) is read whole too
        let mut old4 = unit.clone();
        assert_eq!(old4[1], TAG as u8);
        old4[1] = 4;
        assert!(open(&old4, &SALT).is_err());
        // its index rows (an earlier hashing) go; the new layout indexes anew
        let kt = txn.table(&tid, &ak, KEY_TABLE).unwrap().unwrap();
        txn.table_put(kt, &[0, 0, 0, 0, 1, 2, 3], Vec::new(), Shred::No).unwrap();
        let rows = |txn: &mut Transaction<'_>| txn.table(&tid, &ak, KEY_TABLE).unwrap().map_or(0, |t| txn.table_range(t, &[], None, 10_000).unwrap().len());
        assert_eq!(rows(&mut txn), 6001);
        let whole4 = legacy(&mut txn, &tid, &ak, &old4).unwrap().unwrap();
        assert_eq!(whole4, st);
        let (unit5, _) = write_full(&mut txn, &tid, &ak, Some(&whole4), true, &SALT).unwrap();
        assert_eq!(rows(&mut txn), 6000);
        let (mut f, mut idx) = open(&unit5, &SALT).unwrap();
        let k = PathSeg::Key(Value::Int(4321));
        assert!(ensure_path(&mut txn, &tid, &ak, &mut idx, &mut f, std::slice::from_ref(&k)).unwrap());
        assert!(!idx.whole());
        assert_eq!(f.at(&[k]).and_then(|x| x.read()), Some(Value::Int(4321)));
    }

    // spec: none (local store paging, for the Scale requirements: a change costs O(change) at any
    // depth, peer input never causes unbounded work); notes/local-store.md (Units): a state with large collections inside map
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
                2 if r(2) == 0 => PathOp { path: vec![key("tags")], op: Op::Add(Value::Str(format!("n{step}"))) },
                2 => PathOp { path: vec![key("tags")], op: Op::Remove(Value::Str(format!("s{}", r(2000)))) },
                3 => PathOp { path: vec![key("small"), PathSeg::Key(Value::Int(r(10) as i64))], op: Op::Set(Value::Int(7)) },
                4 => PathOp { path: vec![PathSeg::Key(Value::Str(format!("k{}", r(5))))], op: Op::Set(ints(3, 2)) },
                _ => PathOp { path: vec![key("x")], op: Op::Set(Value::Int(step as i64)) },
            };
            // a fresh session: the skeleton, then the pages the op addresses
            let (mut f, mut idx) = open(&unit, &SALT).unwrap();
            match op_paths(std::slice::from_ref(&op), &mut |v| Ok(v.clone())).unwrap() {
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

    /// A struct with a padding map (field 0) and a sequence (field 1): a text, or a list of strings.
    #[derive(Clone, Copy)]
    enum SeqView {
        Root(bool),
        Seq(bool),
        Any,
    }

    impl osis_crdt::View for SeqView {
        fn encoding(&self) -> Option<Encoding> {
            match self {
                SeqView::Root(_) => Some(Encoding::Struct),
                SeqView::Seq(true) => Some(Encoding::Text),
                SeqView::Seq(false) => Some(Encoding::List),
                SeqView::Any => None,
            }
        }
        fn project<'a>(&self, v: &'a Value) -> Option<std::borrow::Cow<'a, Value>> {
            Some(std::borrow::Cow::Borrowed(v))
        }
        fn field(&self, id: u64) -> Option<SeqView> {
            match self {
                SeqView::Root(text) if id == 1 => Some(SeqView::Seq(*text)),
                _ => Some(SeqView::Any),
            }
        }
        fn field_default(&self, _: u64) -> Option<Value> {
            None
        }
        fn case(&self, _: u64) -> Option<SeqView> {
            None
        }
        fn element(&self) -> Option<SeqView> {
            Some(SeqView::Any)
        }
        fn key(&self) -> Option<SeqView> {
            Some(SeqView::Any)
        }
    }

    /// Items of the sequence: 4-byte chars (a text) or 30-byte strings (a list).
    fn seq_items(text: bool, from: u64, n: u64) -> Vec<Value> {
        (from..from + n)
            .map(|i| if text { Value::Str(char::from_u32(0x1F600 + (i % 64) as u32).unwrap().to_string()) } else { Value::Str(format!("item-{i:08}-padding-padding")) })
            .collect()
    }

    fn seq_value(text: bool, n: u64) -> Value {
        let items = seq_items(text, 0, n);
        let seq = if text { Value::Str(items.iter().map(|v| if let Value::Str(x) = v { x.as_str() } else { "" }).collect()) } else { Value::List(items) };
        // padding: the state above `PAGE_TARGET`, in pages of its own
        let pad = Value::Map((0..300).map(|i| (Value::Int(i), Value::Str("p".repeat(250)))).collect());
        Value::Map([(Value::Int(0), pad), (Value::Int(1), seq)].into_iter().collect())
    }

    /// The visible elements of the sequence (field 1) of `f` by a whole pass of a fresh copy.
    fn vis_whole(f: &Fragment) -> Vec<Dot> {
        let fresh = decode(&encode(&f.at(&[PathSeg::Field(1)]).unwrap()).unwrap()).unwrap();
        fresh.visible_range(0..usize::MAX).unwrap()
    }

    // spec/crdt.md §5.7 (ops by index), §6 (the placement is a function of state), §8: a paged
    // text or list keeps its placement in the store, exactly a whole pass of the state's: random
    // inserts, deletes and moves by two writers (one writing against an old state: concurrent,
    // joined as received), each in the running session or a fresh one, written page by page;
    // after each, the placement read from the store equals a whole pass over the state loaded
    // whole, and a read by index in a fresh session loads a few pages and reads what the whole
    // state reads.
    #[test]
    fn seq_placement_differential_text_spec_crdt_6() {
        seq_placement_run(true, 6_000);
    }

    // As `seq_placement_differential_text_spec_crdt_6`, for a list.
    #[test]
    fn seq_placement_differential_list_spec_crdt_6() {
        seq_placement_run(false, 1_000);
    }

    fn seq_placement_run(text: bool, n: u64) {
        let mut rng = osis_crypto::SeededRng::from_u64(181);
        let mut store = Store::create(Box::new(MemoryBackend::new()), Box::new(MemoryRoot::new()), StoreConfig::default(), &mut rng).unwrap();
        let (tid, ak) = (Tid::from_bytes([7; 15]), osis_core::Ak::new("/app/seq").unwrap());
        let nodes = [Source::node(Tid::from_bytes([1; 15])), Source::node(Tid::from_bytes([2; 15]))];
        let view = SeqView::Root(text);
        let field = || vec![PathSeg::Field(1)];
        let mut ts = 1u64 << 16;
        let mut w = Writer::new(Ts::from_u64(ts).unwrap(), nodes[0].clone(), 1);
        let mut st = create(&mut w, &view, &seq_value(text, n)).unwrap();
        let mut ctrs = [w.range().hi, 1];
        let mut txn = store.transaction(&mut rng).unwrap();
        let (mut unit, i0) = write_full(&mut txn, &tid, &ak, Some(&st), false, &SALT).unwrap();
        let i0 = i0.unwrap();
        assert!(i0.sets.values().any(is_seq), "the sequence is paged");
        let mut session = Some((st.clone(), i0));
        let whole = |txn: &mut Transaction<'_>, unit: &[u8]| {
            let (mut f, mut idx) = open(unit, &SALT).unwrap();
            load_all(txn, &tid, &ak, &mut idx, &mut f).unwrap();
            f
        };
        let mut orng = osis_crypto::SeededRng::from_u64(183);
        let mut r = |n: u64| osis_crypto::RngCore::next_u64(&mut orng) % n.max(1);
        let mut old = st.clone();
        // writer 1's deltas, for strips and shreds of their bodies
        let mut received: Vec<(Fragment, osis_crdt::CounterRange)> = Vec::new();
        let (mut in_place, mut kept, mut fresh_item, mut rebuilt) = (0, 0, n, 0);
        let mut kinds = [0usize; 4];
        for step in 0..18 {
            ts += 1 << 16;
            // the running session (its placement invalidated already, or not) or a fresh one
            let (mut f, mut idx) = match session.take() {
                Some(x) if r(2) == 0 => {
                    kept += 1;
                    x
                }
                _ => open(&unit, &SALT).unwrap(),
            };
            let kind = r(12);
            if kind >= 8 && !received.is_empty() || kind >= 10 {
                let k = (kind - 8) as usize;
                kinds[k] += 1;
                match k {
                    // an expiry or purge of a received body: its writes held value-less
                    0 | 1 => {
                        let (body, range) = received[r(received.len() as u64) as usize].clone();
                        let pred = move |d: &Dot| d.owner().src == Source::node(Tid::from_bytes([2; 15])) && (range.lo..range.hi).contains(&d.owner().ctr);
                        let touch = touch_of(&body, Some(&idx));
                        let t = touch.clone().unwrap();
                        assert!(ensure_touch(&mut txn, &tid, &ak, &mut idx, &mut f, &t).unwrap());
                        let done = if k == 0 {
                            strip_touched(&mut txn, &mut idx, &tid, &ak, &mut f, std::slice::from_ref(&t), &pred).unwrap()
                        } else {
                            // a dropped body: the same content, pages rewritten shredded
                            write_touched(&mut txn, &mut idx, &tid, &ak, &f, &t, Shred::Yes).unwrap().is_some()
                        };
                        if k == 0 {
                            st.strip(&pred);
                        }
                        if !done {
                            load_all(&mut txn, &tid, &ak, &mut idx, &mut f).unwrap();
                            let (u, i) = write_full(&mut txn, &tid, &ak, Some(&f), true, &SALT).unwrap();
                            unit = u;
                            idx = i.unwrap();
                        } else if let Some(u) = (k == 0).then(|| skeleton_unit(&f, &idx).unwrap()) {
                            unit = u;
                        }
                    }
                    // a validity rebuild: the whole state written again
                    2 => {
                        load_all(&mut txn, &tid, &ak, &mut idx, &mut f).unwrap();
                        let (u, i) = write_full(&mut txn, &tid, &ak, Some(&f), true, &SALT).unwrap();
                        unit = u;
                        idx = i.unwrap();
                    }
                    // the layout before the placement (tag 5): laid out anew, then edited on
                    _ => {
                        let mut old5 = unit.clone();
                        old5[1] = 5;
                        txn.drop_table(&tid, &ak, PLACE_TABLE).unwrap();
                        let w5 = legacy(&mut txn, &tid, &ak, &old5).unwrap().unwrap();
                        let (u, i) = write_full(&mut txn, &tid, &ak, Some(&w5), true, &SALT).unwrap();
                        unit = u;
                        f = w5;
                        idx = i.unwrap();
                    }
                }
            } else {
                let wi = r(3) as usize % 2;
                let base = if wi == 1 { &old } else { &st };
                let len = base.at(&field()).and_then(|s| s.visible_range(0..usize::MAX)).map_or(0, |v| v.len()) as u64;
                let op = match r(8) {
                    0..=2 => {
                        let k = 1 + r(3);
                        fresh_item += k;
                        Op::Insert { at: r(len + 1) as usize, items: seq_items(text, fresh_item, k) }
                    }
                    3 | 4 => {
                        let most = if r(5) == 0 { 600 } else { 20 };
                        Op::Delete { at: r(len) as usize, len: 1 + r(most) as usize }
                    }
                    5 | 6 => {
                        let l = 1 + r(10);
                        Op::Move { at: r(len) as usize, len: l as usize, to: r(len.saturating_sub(l) + 1) as usize }
                    }
                    _ => Op::Insert { at: 0, items: seq_items(text, fresh_item, 1) },
                };
                let op = PathOp { path: field(), op };
                let mut b = Batch::new(base, Writer::new(Ts::from_u64(ts).unwrap(), nodes[wi].clone(), ctrs[wi]));
                let Some((delta, range)) = b.apply(&op, &view).ok().and_then(|_| b.finish()) else {
                    session = Some((f, idx));
                    continue;
                };
                ctrs[wi] = range.hi;
                if wi == 1 {
                    received.push((delta.clone(), range));
                }
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
                        let (u, i) = write_full(&mut txn, &tid, &ak, Some(&f), true, &SALT).unwrap();
                        unit = u;
                        idx = i.unwrap();
                    }
                }
                if wi == 0 && r(3) == 0 {
                    old = st.clone();
                }
            }
            session = Some((f, idx));
            // pages hold what a snapshot carries (deleted chars dropped): compare those bytes
            if step % 6 == 5 {
                assert!(encode(&whole(&mut txn, &unit)).unwrap() == encode(&st).unwrap(), "step {step}");
            }
            // the stored placement, when present, is a whole pass's; when invalidated, a read
            // lays it out anew from the whole sequence (in the one session, as the engine does)
            let want = vis_whole(&st);
            let read_all = |txn: &mut Transaction<'_>, unit: &[u8]| {
                let (mut f, mut idx) = open(unit, &SALT).unwrap();
                seq_range(txn, &tid, &ak, &mut idx, &mut f, &field(), 0..usize::MAX).unwrap()
            };
            if let Ranged::Damaged(p) = read_all(&mut txn, &unit) {
                rebuilt += 1;
                let (mut f, mut idx) = session.take().unwrap();
                ensure_path(&mut txn, &tid, &ak, &mut idx, &mut f, &field()).unwrap();
                rebuild_placement(&mut txn, &tid, &ak, &mut idx, &f, &p).unwrap();
                session = Some((f, idx));
            }
            let Ranged::Read(p, dots, total) = read_all(&mut txn, &unit) else { panic!("step {step}: no placement after a rebuild") };
            assert_eq!((dots.len(), total), (want.len(), want.len()), "step {step}");
            assert!(dots == want, "step {step}: placement differs from a whole pass");
            assert_eq!(p, vec![Step::Field(1)]);
            // a read by index in a fresh session: a few pages
            let lo = r(want.len() as u64) as usize;
            let (mut f, mut idx) = open(&unit, &SALT).unwrap();
            let Ranged::Read(p, dots, _) = seq_range(&mut txn, &tid, &ak, &mut idx, &mut f, &field(), lo..lo + 40).unwrap() else { panic!() };
            let pages = idx.sets.get(&p).unwrap().loaded.len();
            let total_pages = whole_pages(&mut txn, &tid, &ak, idx.sets.get(&p).unwrap());
            // the pages holding the elements read (dot order is not placement order)
            assert!(pages < total_pages, "step {step}: {pages} of {total_pages} pages loaded");
            let ref_seq = st.at(&field()).unwrap();
            assert_eq!(f.at_steps(&p).unwrap().read_elems(&dots), ref_seq.read_elems(&ref_seq.visible_range(lo..lo + 40).unwrap()), "step {step}");
            // a reversed range reads empty
            let (mut f, mut idx) = open(&unit, &SALT).unwrap();
            let Ranged::Read(_, dots, _) = seq_range(&mut txn, &tid, &ak, &mut idx, &mut f, &field(), std::ops::Range { start: 10, end: 5 }).unwrap() else { panic!() };
            assert!(dots.is_empty());
        }
        assert!(in_place >= 8, "{in_place} written in place");
        assert!(kept >= 4, "{kept} steps in a running session");
        assert!(rebuilt >= 4, "{rebuilt} placements rebuilt");
        assert!(kinds.iter().all(|k| *k >= 1), "strip, shred, validity rebuild, legacy: {kinds:?}");
    }

    /// The number of pages of `set` in the store.
    fn whole_pages(txn: &mut Transaction<'_>, tid: &Tid, ak: &Ak, set: &PageSet) -> usize {
        let t = table(txn, tid, ak).unwrap();
        txn.table_range(t, &set.prefix(), Some(&set.id.saturating_add(1).to_be_bytes()), 10_000).unwrap().len()
    }

    // spec/crdt.md §6 (the placement is a function of state); notes/local-store.md (Units): a
    // sequence's stored placement is rebuildable: a state of the layout before it (unit tag 5) is laid out anew
    // with it; a damaged or missing summary or block row reads as damaged, and laid out anew
    // from the whole sequence it reads by index again.
    #[test]
    fn seq_placement_rebuilt_spec_crdt_6() {
        let mut rng = osis_crypto::SeededRng::from_u64(185);
        let mut store = Store::create(Box::new(MemoryBackend::new()), Box::new(MemoryRoot::new()), StoreConfig::default(), &mut rng).unwrap();
        let (tid, ak) = (Tid::from_bytes([8; 15]), osis_core::Ak::new("/app/seq").unwrap());
        let mut w = Writer::new(Ts::from_u64(1 << 16).unwrap(), Source::node(Tid::from_bytes([1; 15])), 1);
        let st = create(&mut w, &SeqView::Root(true), &seq_value(true, 6_000)).unwrap();
        let want = vis_whole(&st);
        let field = [PathSeg::Field(1)];
        let mut txn = store.transaction(&mut rng).unwrap();
        let (unit, _) = write_full(&mut txn, &tid, &ak, Some(&st), false, &SALT).unwrap();
        let read = |txn: &mut Transaction<'_>, unit: &[u8]| {
            let (mut f, mut idx) = open(unit, &SALT).unwrap();
            match seq_range(txn, &tid, &ak, &mut idx, &mut f, &field, 100..200).unwrap() {
                Ranged::Read(_, dots, _) => Some(dots),
                Ranged::Damaged(p) => {
                    assert_eq!(p, vec![Step::Field(1)]);
                    None
                }
                Ranged::Unpaged => panic!("paged"),
            }
        };
        assert_eq!(read(&mut txn, &unit).as_deref(), Some(&want[100..200]));
        // the layout before (tag 5, no placement table) is read whole and laid out anew
        let mut old5 = unit.clone();
        old5[1] = 5;
        txn.drop_table(&tid, &ak, PLACE_TABLE).unwrap();
        assert!(open(&old5, &SALT).is_err());
        let whole5 = legacy(&mut txn, &tid, &ak, &old5).unwrap().unwrap();
        assert_eq!(whole5, st);
        let (unit, _) = write_full(&mut txn, &tid, &ak, Some(&whole5), true, &SALT).unwrap();
        assert_eq!(read(&mut txn, &unit).as_deref(), Some(&want[100..200]));
        // damaged rows: the summary, then a block row gone
        let pt = txn.table(&tid, &ak, PLACE_TABLE).unwrap().unwrap();
        let (mut f, mut idx) = open(&unit, &SALT).unwrap();
        let set = idx.sets.values().find(|s| is_seq(s)).unwrap().clone();
        let p = vec![Step::Field(1)];
        for damage in 0..2 {
            if damage == 0 {
                txn.table_put(pt, &place_key(&set, None), vec![0xff, 1], Shred::No).unwrap();
            } else {
                // the block holding element 150
                let sum = parse_summary(&txn.table_get(pt, &place_key(&set, None)).unwrap().unwrap()).unwrap();
                let mut base = 0;
                let (id, _) = sum.into_iter().find(|(_, n)| {
                    base += n;
                    base > 150
                }).unwrap();
                txn.table_remove(pt, &place_key(&set, Some(id)), Shred::No).unwrap();
            }
            assert_eq!(read(&mut txn, &unit), None, "damage {damage}");
            ensure_path(&mut txn, &tid, &ak, &mut idx, &mut f, &field).unwrap();
            rebuild_placement(&mut txn, &tid, &ak, &mut idx, &f, &p).unwrap();
            assert_eq!(read(&mut txn, &unit).as_deref(), Some(&want[100..200]), "damage {damage}");
        }
    }
}
