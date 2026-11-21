//! Paged states (notes/local-store.md, Units). A state keeps its large collections (a page or
//! more of elements), at any depth below struct fields, enum payloads and map entries, as pages of
//! consecutive root elements in the aspect's table, the rest as a skeleton in the unit. The
//! store's B+tree is the index: a page's row key is its collection's set ID and the
//! order-preserving bytes of its first dot, so the page holding a dot is the last row at or below
//! it (`table_rank`, `table_nth`), and a map key's entries and a set value's elements are found
//! through an index (set ID, keyed hash of the key or value under a node-local secret, dot). In
//! memory a state is loaded lazily: the skeleton first, then the pages a read, write or join
//! needs (`ensure_*`), or all of them (`load_all`) where the whole state is needed.

use super::state::{decode, encode};
use super::{clear_table, scan_table};
use crate::error::{Error, Result};
use crate::retention::Killed;
use osis_base::{Ak, Tid, Value};
use osis_crdt::{Changes, Dot, Eid, Encoding, Fragment, PagedTouch, PathSeg, Paths, PlaceBlock, PlaceDiff, PlaceMisses, PlaceRow, PlaceTop, SeqPlace, SourceKind, Step};
use osis_store::{Shred, Table, Transaction};
use std::collections::{BTreeMap, BTreeSet};
use std::ops::Range as Span;

/// Encoded bytes per local page, about; a collection above it pages, a page grown past twice
/// it splits. A write decodes and rewrites the pages it touches (and an unpaged collection
/// whole), so this is what a one-element write costs at most. Performance switch: at 0 every
/// element is a page of its own (a row and its overhead each), at infinity a write rewrites
/// its whole state. Above the store's inline limit (a quarter of its 8 KiB page), so a page
/// write leaves its neighbours' leaf alone.
const PAGE_BYTES: usize = 3 * 1024;
/// The aspect table holding its state pages.
const STATE_TABLE: u8 = 0;
/// The aspect table holding the index of its paged maps (by key) and sets (by value).
const KEY_TABLE: u8 = 1;
/// The aspect table holding the placement of its paged sequences (`write_placement`).
const PLACE_TABLE: u8 = 2;
/// The unit state tag of a paged state (`state::stored`).
pub const TAG: i64 = 1;

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
    /// Invariant: `keyed(state, steps)` of the whole state as of this set's last write. The
    /// skeleton drops a record reduced to nothing (`Fragment::reduced`), so a record on the path
    /// holding only paged content keeps its creation here alone (`Fragment::wrap` gives it back
    /// to each page): every write of this set takes it again from the joined state, which holds
    /// it through a loaded page (`ensure_touch` loads one for each set touched; `write_touched`,
    /// `join_reset`), else a creation arriving after the content is lost to the store. Another
    /// set below the same record may lag a creation a later write brought: loading joins every
    /// set's path, and a creation leaves the state only by a reset the skeleton keeps (loading
    /// prunes it again) or with its record (a whole rewrite).
    path: KeyedPath,
    enc: Encoding,
    /// Pages in the in-memory state: row key -> range.
    loaded: BTreeMap<Vec<u8>, Range>,
    /// Every page of the set is loaded.
    whole: bool,
    /// A sequence's stored placement.
    place: Place,
    /// Its block list's group rows as stored (`write_place` writes those that change).
    groups: Vec<Vec<u8>>,
    /// A change of the sequence may be under way (`ensure_touch`, until `write_touched`): the
    /// stored placement may no longer be the records' (`place_whole` leaves it).
    pending: bool,
    /// Its placement is missing or damaged, to be laid out anew by the next transaction that
    /// writes the state, at its end (`unplaced`, `rebuild_placement`): a read never writes.
    relay: bool,
}

impl PageSet {
    /// A set with no page loaded and its placement not read.
    fn new(id: u32, salt: [u8; 32], path: KeyedPath, enc: Encoding) -> PageSet {
        PageSet { id, salt, path, enc, loaded: BTreeMap::new(), whole: false, place: Place::Unread, groups: Vec::new(), pending: false, relay: false }
    }
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
pub struct StatePages {
    sets: BTreeMap<Vec<Step>, PageSet>,
    paths: Paths,
    /// What the running read may still load of the state (`Tx::bound`, set by `Tx::with_pages`).
    pub(crate) bound: Bound,
}

impl StatePages {
    /// The paths below a paged collection's elements (what its pages reduce).
    fn nested(&self, p: &[Step]) -> Paths {
        Paths { here: false, next: self.paths.below(p).map(|x| x.next.clone()).unwrap_or_default() }
    }
    /// Notes no page loaded (the state reduced to its skeleton).
    fn unload(&mut self) {
        for set in self.sets.values_mut() {
            set.loaded.clear();
            set.whole = false;
        }
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

/// What a bounded read may still hold of the states it loads, in bytes (`Tx::bound`); `None`:
/// unbounded (every write and join: what they load is bounded by the commits they apply).
pub type Bound = Option<usize>;

/// Decodes a stored piece of a state (a unit, a body, a page) of `stored` bytes under `bound`:
/// refused before decoding when its bytes exceed what is left, then charged the greater of its
/// bytes and its decode (`Fragment::approx_bytes`, as a link is, notes/decode-bounds.md), so a
/// read holds at most its bound plus one piece. Past the bound: `TooLarge` (local).
pub fn charge(bound: &mut Bound, stored: usize, decode: impl FnOnce() -> Result<Fragment>) -> Result<Fragment> {
    let too_large = || Error::Data(osis_commit::Error::TooLarge("state above the read bound"));
    if bound.is_some_and(|b| stored > b) {
        return Err(too_large());
    }
    let f = decode()?;
    if let Some(b) = bound {
        *b = b.checked_sub(stored.max(f.approx_bytes())).ok_or_else(too_large)?;
    }
    Ok(f)
}

/// What joining a delta can change in a paged state (`None`: write whole).
pub type Touch = Option<PagedTouch>;

/// What joining `delta` can change in a state with page index `idx`.
pub fn touch_of(delta: &Fragment, idx: Option<&StatePages>) -> Touch {
    delta.touched_paths(&idx?.paths)
}

// ---- encodings

/// Order-preserving bytes of a dot (spec/crdt.md §2.2: source kind, source bytes, counter; a
/// `Derived(d)` dot `i` orders as `(d.source, d.ctr, i)`): fixed-width parts, so byte order is
/// dot order.
fn dot_key(d: &Dot, out: &mut Vec<u8>) {
    match d.src.kind() {
        SourceKind::Session(s) => {
            out.push(0);
            out.extend_from_slice(&s.to_bytes());
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
                Step::Field(id) => Value::List(vec![Value::Int(0), Value::uint(*id)]),
                Step::Case(id) => Value::List(vec![Value::Int(1), Value::uint(*id)]),
                Step::Entry(id) => Value::List(vec![
                    Value::Int(2),
                    dot_value(&id.dot),
                    k.clone().map_or(Value::List(Vec::new()), |k| Value::List(vec![k])),
                    Value::List(c.iter().map(|c| Value::uint(c.ts.to_u64())).collect()),
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
                [Value::Int(2), d, Value::List(k)] => Ok((Step::Entry(Eid::new(dot_of(d)?, k.first().cloned())), k.first().cloned(), None)),
                [Value::Int(2), d, Value::List(k), Value::List(c)] => {
                    let d = dot_of(d)?;
                    let created = match c.as_slice() {
                        [] => None,
                        [Value::Int(ts)] => Some(osis_crdt::Stamp::new(osis_base::Ts::from_u64(n(ts)?).ok_or_else(bad)?, d.src.clone(), d.ctr)),
                        _ => return Err(bad()),
                    };
                    Ok((Step::Entry(Eid::new(d, k.first().cloned())), k.first().cloned(), created))
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

/// Unit state of a paged state: `[1, skeleton, [[set ID, path, encoding]*]]`.
/// Unpaged states start `[bytes, ...]`.
fn unit_state(skeleton: &Fragment, idx: &StatePages) -> Result<Vec<u8>> {
    let sets = idx.sets.values().map(|s| Value::List(vec![Value::uint(u64::from(s.id)), path_value(&s.path), Value::uint(u64::from(s.enc.id()))])).collect();
    Ok(osis_base::encode(&Value::List(vec![Value::Int(TAG), Value::Bytes(encode(skeleton)?), Value::List(sets)])))
}

/// A page row: `[first dot or [], next page's first dot or [], page]`.
fn page_row(r: &Range, p: &Fragment) -> Result<Vec<u8>> {
    Ok(osis_base::encode(&Value::List(vec![opt_dot_value(r.0.as_ref()), opt_dot_value(r.1.as_ref()), Value::Bytes(encode(p)?)])))
}

fn parse_page_row(b: &[u8]) -> Result<(Range, Fragment)> {
    let lim = osis_base::Limits::new(osis_base::format::MAX_OBJECT_DEPTH, b.len());
    let v = osis_base::decode(b, &lim).map_err(|_| Error::Corrupt("state page"))?;
    let Value::List(items) = v else { return Err(Error::Corrupt("state page")) };
    let [lo, hi, Value::Bytes(p)] = items.as_slice() else { return Err(Error::Corrupt("state page")) };
    Ok(((opt_dot_of(lo)?, opt_dot_of(hi)?), decode(p)?))
}

/// What the index of a paged collection finds element `d` by: the keys of a map's records of
/// `d` holding content (a tombstone's key finds nothing live), the value of a set element, the
/// reference of a set's value removal. Empty for a key-erased or value-less element and other
/// encodings.
fn indexed(c: &Fragment, enc: Encoding, d: &Dot) -> Vec<Value> {
    match enc {
        Encoding::Map => c.entry_keys(d).into_iter().cloned().collect(),
        // an element's value, hidden or not, or the reference a value removal names (§5.5)
        Encoding::Set => c.set_record_value(d).into_iter().collect(),
        _ => Vec::new(),
    }
}

/// An index row of a paged map or set: set ID, the hash of the key or value (a link as its
/// content hash's bytes: equal values give equal rows, spec/data-model.md §6), the element's
/// dot.
fn key_row(set: &PageSet, k: &Value, d: Option<&Dot>) -> Vec<u8> {
    let mut out = set.id.to_be_bytes().to_vec();
    let ident = super::large::map_links(k, &|l| Value::Bytes(l.hash.to_vec()));
    out.extend_from_slice(&osis_base::hash::keyed_hash(&set.salt, &osis_base::encode(&ident)));
    if let Some(d) = d {
        out.extend_from_slice(&osis_base::encode(&dot_value(d)));
    }
    out
}

// ---- loading

/// Opens a paged state: its skeleton and index, no page loaded yet.
pub fn open(unit_state: &[u8], salt: &[u8; 32]) -> Result<(Fragment, StatePages)> {
    let bad = || Error::Corrupt("state");
    let lim = osis_base::Limits::new(osis_base::format::MAX_OBJECT_DEPTH, unit_state.len());
    let v = osis_base::decode(unit_state, &lim).map_err(|_| bad())?;
    let Value::List(items) = v else { return Err(bad()) };
    let [Value::Int(t), Value::Bytes(skel), Value::List(list)] = items.as_slice() else { return Err(bad()) };
    if *t != TAG {
        return Err(bad());
    }
    let f = decode(skel)?;
    let mut idx = StatePages { sets: BTreeMap::new(), paths: Paths::default(), bound: None };
    for x in list {
        let Value::List(x) = x else { return Err(bad()) };
        let [Value::Int(id), p, Value::Int(enc)] = x.as_slice() else { return Err(bad()) };
        let path = path_of(p)?;
        let enc = u64::try_from(*enc).ok().and_then(Encoding::from_id).ok_or_else(bad)?;
        let s = steps(&path);
        idx.paths.insert(&s);
        idx.sets.insert(s, PageSet::new(u32::try_from(*id).map_err(|_| bad())?, *salt, path, enc));
    }
    Ok((f, idx))
}

fn table(txn: &mut Transaction<'_>, tid: &Tid, ak: &Ak) -> Result<Table> {
    txn.table(tid, ak, STATE_TABLE)?.ok_or(Error::Corrupt("state pages missing"))
}

/// Joins one page row into `f` and notes it loaded.
fn join_row(f: &mut Fragment, set: &mut PageSet, bound: &mut Bound, key: Vec<u8>, row: &[u8]) -> Result<()> {
    if set.loaded.contains_key(&key) {
        return Ok(());
    }
    // counted: scale tests read the number of pages loaded
    let _s = osis_base::costs::span("state page load");
    let mut range = (None, None);
    let p = charge(bound, row.len(), || {
        let (r, p) = parse_page_row(row)?;
        range = r;
        Ok(p)
    })?;
    if set.row_key(range.0.as_ref()) != key {
        return Err(Error::Corrupt("state page key"));
    }
    // a page's records are the sequence's own, not a change its placement follows: detached
    // while it joins, then attached again with the page covered (any other cached placement of
    // a sequence held in part goes)
    let at = steps(&set.path);
    let pl = if is_seq(set) {
        f.at_steps_mut(&at).and_then(|x| {
            let c = x.seq_place_cached();
            x.set_seq_place(None);
            c
        })
    } else {
        None
    };
    f.join(Fragment::wrap(&set.path, p));
    set.loaded.insert(key, range);
    if let Some(pl) = pl.filter(SeqPlace::is_partial) {
        attach(f, set, Some(pl));
    }
    Ok(())
}

/// Loads every page not loaded yet: the whole state.
pub fn load_all(txn: &mut Transaction<'_>, tid: &Tid, ak: &Ak, idx: &mut StatePages, f: &mut Fragment) -> Result<()> {
    if idx.whole() {
        return Ok(());
    }
    let t = table(txn, tid, ak)?;
    for set in idx.sets.values_mut() {
        ensure_set(txn, tid, ak, t, set, &mut idx.bound, f)?;
    }
    Ok(())
}

/// Whether a collection is paged inside another's elements (its path runs through pages).
fn nested(idx: &StatePages) -> bool {
    idx.sets.keys().any(|p| idx.sets.keys().any(|q| q.len() < p.len() && p.starts_with(q)))
}

/// The pieces of the paged state with skeleton `f`, as a read of the whole sees each, one at a
/// time and never joined into `f`: the skeleton (`f` reduced), then each page below the
/// skeleton's spine along its path (`Fragment::spine`: what pruning and an enum's case there
/// depend on). With `keys`, a page of a map or set also holds the records of the keys or values
/// its records hold that lie on other pages (a key reads as the join of its records, spec/crdt.md
/// §5.6; a value's records hide each other, §5.5; found through the index), so each piece reads
/// as the whole does there; `Ok(None)` when a collection is paged inside another's elements (a
/// key's records then reach into pages below: the caller reads whole). Each page and what it
/// pulls is charged against what `idx.bound` leaves, then dropped: the walk holds the skeleton,
/// a page and its keys' records. `each` returns whether to stop; the result is whether it did.
pub fn each_piece(txn: &mut Transaction<'_>, tid: &Tid, ak: &Ak, idx: &StatePages, f: &Fragment, keys: bool, each: &mut dyn FnMut(&Fragment) -> Result<bool>) -> Result<Option<bool>> {
    if keys && nested(idx) {
        return Ok(None);
    }
    let s0 = f.reduced(&idx.paths);
    if each(&s0)? {
        return Ok(Some(true));
    }
    let t = table(txn, tid, ak)?;
    for (p, set) in &idx.sets {
        let spine = s0.spine(p, None);
        for key in set_rows(txn, t, set)? {
            let Some(row) = txn.table_get(t, &key)? else { continue };
            let mut bound = idx.bound;
            let mut range = (None, None);
            let pg = charge(&mut bound, row.len(), || {
                let (r, p) = parse_page_row(&row)?;
                range = r;
                Ok(p)
            })?;
            let mut g = spine.clone();
            if keys && is_keyed(set) {
                let inside = |d: &Dot| range.0.as_ref().is_none_or(|lo| d >= lo) && range.1.as_ref().is_none_or(|hi| d < hi);
                let vs: BTreeSet<Value> = pg.elem_dots(None, None).iter().flat_map(|d| indexed(&pg, set.enc, d)).collect();
                for v in &vs {
                    for d in key_dots(txn, tid, ak, set, v)?.into_iter().filter(|d| !inside(d)) {
                        let (_, other) = row_below(txn, t, &[set.row_key(Some(&d)), vec![0]].concat())?;
                        let mut b = bound;
                        let o = charge(&mut b, other.len(), || Ok(parse_page_row(&other)?.1))?;
                        if let Some(r) = o.key_records(&d, v) {
                            let r = charge(&mut bound, 0, || Ok(r))?;
                            g.join(Fragment::wrap(&set.path, r));
                        }
                    }
                }
            }
            g.join(Fragment::wrap(&set.path, pg));
            // counted: tests read the most a walk holds
            osis_base::costs::peak("paged state: piece held", g.approx_bytes() as u64);
            if each(&g)? {
                return Ok(Some(true));
            }
        }
    }
    Ok(Some(false))
}

/// Loads the page of `set` holding `d` (the last row at or below it).
fn ensure_dot(txn: &mut Transaction<'_>, t: Table, set: &mut PageSet, bound: &mut Bound, f: &mut Fragment, d: &Dot) -> Result<()> {
    if set.whole || set.loaded_page(d).is_some() {
        return Ok(());
    }
    let (k, v) = row_below(txn, t, &[set.row_key(Some(d)), vec![0]].concat())?;
    if !k.starts_with(&set.prefix()) {
        return Err(Error::Corrupt("state page missing"));
    }
    join_row(f, set, bound, k, &v)
}

/// The last row of `t` below `key`.
fn row_below(txn: &mut Transaction<'_>, t: Table, key: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    let below = txn.table_rank(t, key)?;
    txn.table_nth(t, below.checked_sub(1).ok_or(Error::Corrupt("state page missing"))?)?.ok_or(Error::Corrupt("state page missing"))
}

/// Loads the pages of `set` holding the elements from `a` to `b` (dot order).
fn ensure_span(txn: &mut Transaction<'_>, t: Table, set: &mut PageSet, bound: &mut Bound, f: &mut Fragment, a: &Dot, b: &Dot) -> Result<()> {
    ensure_dot(txn, t, set, bound, f, a)?;
    if set.whole || b <= a {
        return Ok(());
    }
    let from = [set.row_key(Some(a)), vec![0]].concat();
    let end = [set.row_key(Some(b)), vec![0]].concat();
    scan_table(txn, t, &from, Some(&end), |k, v| join_row(f, set, bound, k, &v))
}

/// Loads the first page of `set` (it holds records as long as the collection is paged:
/// records are never dropped but by a whole rewrite, which lays the pages out again).
fn ensure_first(txn: &mut Transaction<'_>, t: Table, set: &mut PageSet, bound: &mut Bound, f: &mut Fragment) -> Result<()> {
    let k = set.prefix();
    if set.whole || set.loaded.contains_key(&k) {
        return Ok(());
    }
    let v = txn.table_get(t, &k)?.ok_or(Error::Corrupt("first state page missing"))?;
    join_row(f, set, bound, k, &v)
}

/// Loads every page of `set`.
fn ensure_set(txn: &mut Transaction<'_>, tid: &Tid, ak: &Ak, t: Table, set: &mut PageSet, bound: &mut Bound, f: &mut Fragment) -> Result<()> {
    if set.whole {
        return Ok(());
    }
    let (start, end) = (set.prefix(), set.id.saturating_add(1).to_be_bytes());
    scan_table(txn, t, &start, Some(&end), |k, v| join_row(f, set, bound, k, &v))?;
    if !set.loaded.contains_key(&start) {
        return Err(Error::Corrupt("first state page missing"));
    }
    set.whole = true;
    if is_seq(set) {
        place_whole(txn, tid, ak, set, f)?;
    }
    Ok(())
}

/// Loads the pages joining a delta touches (`touch_of`): those holding its dots (a sequence's:
/// the pages its records span), and for a paged sequence what its placement's follow of the
/// join needs (a dry run, `Fragment::dry_follow`, loading what it misses, until it follows or has done about one pass of work; the
/// placement is then attached to the sequence, which the join follows).
pub fn ensure_touch(txn: &mut Transaction<'_>, tid: &Tid, ak: &Ak, idx: &mut StatePages, f: &mut Fragment, touch: &PagedTouch) -> Result<bool> {
    let t = table(txn, tid, ak)?;
    for (p, dots) in &touch.elems {
        let Some(set) = idx.sets.get_mut(p) else { return Ok(false) };
        if is_seq(set) {
            set.pending = true;
            if set.whole {
                continue;
            }
            for pair in dots.chunks(2) {
                if let (Some(a), Some(b)) = (pair.first(), pair.last()) {
                    ensure_span(txn, t, set, &mut idx.bound, f, a, b)?;
                }
            }
        } else {
            for d in dots {
                ensure_dot(txn, t, set, &mut idx.bound, f, d)?;
            }
        }
        // a page joins the set's keyed path into `f`, which `write_touched` takes again: a
        // delta reaching the set without elements (a `W`) would otherwise drop its creations
        if set.loaded.is_empty() {
            ensure_first(txn, t, set, &mut idx.bound, f)?;
        }
        if let Some(d) = touch.seqs.get(p) {
            prefetch(txn, tid, ak, t, set, &mut idx.bound, f, d)?;
        }
    }
    // every record of the values whose read the join may move (`PagedTouch::values`), through
    // the value index; also those the state's records of the delta's dots name (`dot_values`: a
    // map's keys, as a key-erased removal names none and resets every record of its dot; a set's
    // references, as a copy the join replaces may name others)
    let paths: BTreeSet<&Vec<Step>> = touch.values.keys().chain(touch.elems.keys()).collect();
    for p in paths {
        let Some(set) = idx.sets.get_mut(p) else { return Ok(false) };
        let mut vs: BTreeSet<Value> = touch.values.get(p).into_iter().flatten().cloned().collect();
        if let Some(m) = f.at_steps(p) {
            vs.extend(touch.elems.get(p).into_iter().flatten().flat_map(|d| m.dot_values(d)).cloned());
        }
        for v in &vs {
            for d in key_dots(txn, tid, ak, set, v)? {
                ensure_dot(txn, t, set, &mut idx.bound, f, &d)?;
            }
        }
    }
    Ok(true)
}

/// Loads what following the join of `d` into the paged sequence `set` needs into its stored
/// placement and the pages, and attaches the placement (none if missing).
#[allow(clippy::too_many_arguments)]
fn prefetch(txn: &mut Transaction<'_>, tid: &Tid, ak: &Ak, t: Table, set: &mut PageSet, bound: &mut Bound, f: &mut Fragment, d: &Fragment) -> Result<()> {
    let Some(mut pl) = held(txn, tid, ak, set)? else { return Ok(()) };
    let Some(pt) = txn.table(tid, ak, PLACE_TABLE)? else { return Ok(()) };
    let _s = osis_base::costs::span("placement prefetch");
    let at = steps(&set.path);
    // a dry run stops at its first miss, so a delta touching many places takes as many runs;
    // each costs its plans and follow work, about one whole pass's in all at most, then the join
    // drops the placement (laid out anew, a whole pass)
    let budget = pl.len().max(1024);
    let mut work = 0;
    loop {
        pl.cover(cover_of(set));
        let Some(s) = f.at_steps(&at) else { break };
        s.dry_follow(d, &pl);
        let m = pl.misses();
        work += m.work;
        if !m.any() || work > budget {
            break;
        }
        if !absorb_into(txn, t, pt, set, bound, f, &mut pl, &m)? {
            break;
        }
    }
    hold(f, set, pl);
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
    scan_table(txn, t, &start, Some(&end), |key, _| {
        let Some(tail) = key.get(start.len()..) else { return Ok(()) };
        let lim = osis_base::Limits::new(8, tail.len());
        let v = osis_base::decode(tail, &lim).map_err(|_| Error::Corrupt("state key index"))?;
        out.push(dot_of(&v)?);
        Ok(())
    })?;
    Ok(out)
}

/// Loads what reading or writing at `path` (op path segments) needs: the pages of the map keys
/// along it (through the key index), the element a sequence index steps into (`walk`), and at its end
/// everything paged below. `Ok(false)`: not addressable that way (load whole).
pub fn ensure_path(txn: &mut Transaction<'_>, tid: &Tid, ak: &Ak, idx: &mut StatePages, f: &mut Fragment, path: &[PathSeg]) -> Result<bool> {
    let t = table(txn, tid, ak)?;
    let at = walk(txn, tid, ak, t, idx, f, path)?;
    // everything paged at or below the positions reached
    for p in at {
        let below: Vec<Vec<Step>> = idx.sets.keys().filter(|k| k.starts_with(&p)).cloned().collect();
        for q in below {
            if let Some(set) = idx.sets.get_mut(&q) {
                ensure_set(txn, tid, ak, t, set, &mut idx.bound, f)?;
            }
        }
    }
    Ok(true)
}

/// The positions `path` (op path segments) reaches, as steps from the root, with the pages of
/// the map keys along it loaded (through the key index) and, of a sequence it indexes into, the
/// element's block and page through the stored placement (attached; without one every page).
fn walk(txn: &mut Transaction<'_>, tid: &Tid, ak: &Ak, t: Table, idx: &mut StatePages, f: &mut Fragment, path: &[PathSeg]) -> Result<Vec<Vec<Step>>> {
    // positions reached so far, as steps from the root
    let mut at: Vec<Vec<Step>> = vec![Vec::new()];
    for seg in path {
        let mut next = Vec::new();
        for p in at {
            // a field step into a map reads its integer key (`Fragment::read_at`)
            let map = idx.sets.get(&p).map_or(matches!(f.at_steps(&p), Some(Fragment::Map(_))), |s| s.enc == Encoding::Map);
            let key;
            let seg = match seg {
                PathSeg::Field(id) if map && let Ok(i) = i64::try_from(*id) => {
                    key = PathSeg::Key(Value::Int(i));
                    &key
                }
                seg => seg,
            };
            let paged = idx.sets.contains_key(&p);
            if paged {
                let Some(set) = idx.sets.get_mut(&p) else { continue };
                // the first page restores the entries leading here (the skeleton reduced them
                // away) even when the key has none: a write then finds the collection
                ensure_first(txn, t, set, &mut idx.bound, f)?;
                match seg {
                    // a key of a map; a value of a set (`op_paths` of an op by value)
                    PathSeg::Key(k) if is_keyed(set) => {
                        let ds = key_dots(txn, tid, ak, set, k)?;
                        for d in &ds {
                            ensure_dot(txn, t, set, &mut idx.bound, f, d)?;
                        }
                    }
                    // an element of a sequence: through its stored placement
                    PathSeg::Index(i) if is_seq(set) && !set.whole => {
                        if !step_index(txn, tid, ak, t, set, &mut idx.bound, f, &p, *i)? {
                            ensure_set(txn, tid, ak, t, set, &mut idx.bound, f)?;
                        }
                    }
                    _ => ensure_set(txn, tid, ak, t, set, &mut idx.bound, f)?,
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
                    // the key-erased records of those dots: a record's read joins its dot's
                    // (spec/crdt.md §5.6)
                    let dots: Vec<Dot> = next.iter().filter(|q| q.starts_with(&p)).filter_map(|q| match q.get(p.len()) {
                        Some(Step::Entry(id)) if id.key.is_some() => Some(id.dot.clone()),
                        _ => None,
                    }).collect();
                    for d in dots {
                        let q = [p.clone(), vec![Step::Entry(Eid::erased(d))]].concat();
                        let held = matches!(f.at_steps(&p), Some(Fragment::Map(_))) && f.at_steps(&q).is_some();
                        if (held || idx.sets.keys().any(|x| x.starts_with(&q))) && !next.contains(&q) {
                            next.push(q);
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
// A paged sequence keeps its placement (`osis_crdt::SeqPlace`: every node in order, hidden ones
// included, with its depth, parent and edge, in blocks with their visible counts and least
// depths, and a dot → block map in chunks by dot) in the aspect's placement table:
// - top (`set ‖ 0`): `[cap, map entries, [waiting dot*], [broken-cycle dot*], groups, newest]`,
//   newest `[ts, dot]` a stamp at or above every position write's, or `[]`;
// - group (`set ‖ 0 ‖ u32 index`): `[[block ID, rows, shown, least depth, shift]*]`, the blocks
//   in order, `GROUP` per row;
// - block (`set ‖ 1 ‖ u64 ID`): `[[source*], [row*]]`, a row `[source, ctr, span or n, flags,
//   parent, depth]` (flags: 1 created, 2 parent is HEAD, 4 shown, 8 a chain of `n` creations
//   each the only child of the one before; parent `[]` or `[source, ctr]`);
// - chunk list (`set ‖ 2`): `[[source*], [[source, ctr]*]]`, the first dots of the dot map's
//   chunks after the first;
// - chunk (`set ‖ 3 ‖ 0` the first, `set ‖ 3 ‖ 1 ‖ dot key` the others): `[[source*], [[source,
//   ctr, n, block ID]*]]` (`n` consecutive counters in one block).
// A session reads the top and chunk list once, then the blocks and chunks an operation misses
// (`SeqPlace::from_top`, `fill`): a join follows the placement attached to the sequence held in
// part (`ensure_touch` loads what a dry run of it misses first), an op by index resolves through
// it (`attach_ops`, `absorb`), a read by index reads its blocks (`seq_range`); `write_touched`
// writes what the join changed (`SeqPlace::diff`). A join or write it cannot follow (a reset, a
// strip, a rebuild fallback, a miss) removes the top (`invalidate_placement`), and the
// transaction laying it out anew at its end from the whole sequence (`unplaced`,
// `rebuild_placement`); a read by index finding none or a damaged one reads the sequence whole
// (`Ranged::Damaged`) and leaves the layout to the next transaction writing the state. So it is
// exact whenever present, and a read never writes. Rebuildable: the unit tag names its
// rules.

/// Blocks per group row of the block list.
const GROUP: usize = 32;

/// The page target of `set`'s pages.
fn is_seq(set: &PageSet) -> bool {
    matches!(set.enc, Encoding::List | Encoding::Text)
}

/// Whether `set` pages a map or set: its keys or values are indexed (`KEY_TABLE`).
fn is_keyed(set: &PageSet) -> bool {
    matches!(set.enc, Encoding::Map | Encoding::Set)
}

/// A paged sequence's stored placement, as far as this session knows it.
#[derive(Clone, Debug, Default)]
enum Place {
    /// Not read yet.
    #[default]
    Unread,
    /// Missing, damaged or removed: a read by index lays it out anew.
    Missing,
    /// As stored, loaded in part.
    Held(SeqPlace),
}

/// A placement row key: kind 0 the top, 1 a block, 2 the chunk list, 3 a chunk, 4 a group
/// (next to the top: an edit writes both).
fn place_key(set: &PageSet, kind: u8, id: u64) -> Vec<u8> {
    let mut k = set.prefix();
    k.push(if kind == 4 { 0 } else { kind });
    match kind {
        1 => k.extend_from_slice(&id.to_be_bytes()),
        4 => k.extend_from_slice(&u32::try_from(id).unwrap_or(u32::MAX).to_be_bytes()),
        _ => {}
    }
    k
}

/// The key of the dot-map chunk starting at `lo` (`None`: the first).
fn chunk_key(set: &PageSet, lo: Option<&Dot>) -> Vec<u8> {
    let mut k = place_key(set, 3, 0);
    match lo {
        None => k.push(0),
        Some(d) => {
            k.push(1);
            dot_key(d, &mut k);
        }
    }
    k
}

/// The sources of a row, written once each.
#[derive(Default)]
struct Srcs {
    list: Vec<Value>,
    at: std::collections::HashMap<osis_crdt::Source, usize>,
}

impl Srcs {
    fn of(&mut self, s: &osis_crdt::Source) -> Value {
        if let Some(i) = self.at.get(s) {
            return Value::uint(*i as u64);
        }
        let i = self.list.len();
        let v = match dot_value(&Dot::new(s.clone(), 0)) {
            Value::List(mut x) if !x.is_empty() => x.swap_remove(0),
            v => v,
        };
        self.list.push(v);
        self.at.insert(s.clone(), i);
        Value::uint(i as u64)
    }
    fn dot(&mut self, d: &Dot) -> Value {
        Value::List(vec![self.of(&d.src), Value::uint(d.ctr)])
    }
    fn row(self, items: Vec<Value>) -> Vec<u8> {
        osis_base::encode(&Value::List(vec![Value::List(self.list), Value::List(items)]))
    }
}

/// A row's sources and items (`None`: damaged).
fn parse_srcs(b: &[u8]) -> Option<(Vec<osis_crdt::Source>, Vec<Value>)> {
    let [Value::List(srcs), Value::List(items)] = <[Value; 2]>::try_from(decode_row(b)?).ok()? else { return None };
    let srcs = srcs.into_iter().map(|s| dot_of(&Value::List(vec![s, Value::Int(0)])).ok().map(|d| d.src)).collect::<Option<Vec<_>>>()?;
    Some((srcs, items))
}

fn src_at(srcs: &[osis_crdt::Source], v: &Value) -> Option<osis_crdt::Source> {
    let Value::Int(i) = v else { return None };
    srcs.get(usize::try_from(*i).ok()?).cloned()
}

fn dot_at(srcs: &[osis_crdt::Source], v: &Value) -> Option<Dot> {
    let Value::List(x) = v else { return None };
    let [s, Value::Int(c)] = x.as_slice() else { return None };
    Some(Dot::new(src_at(srcs, s)?, u64::try_from(*c).ok()?))
}

fn decode_row(b: &[u8]) -> Option<Vec<Value>> {
    let lim = osis_base::Limits::new(osis_base::format::MAX_OBJECT_DEPTH, b.len());
    match osis_base::decode(b, &lim).ok()? {
        Value::List(x) => Some(x),
        _ => None,
    }
}

fn int(v: &Value) -> Option<i64> {
    match v {
        Value::Int(x) => Some(*x),
        _ => None,
    }
}

fn block_row(rows: &[PlaceRow]) -> Vec<u8> {
    let mut t = Srcs::default();
    let mut out = Vec::new();
    let mut i = 0;
    while let Some(r) = rows.get(i) {
        // a chain: each next row a creation, the only child of the one before
        let mut n = 1;
        if r.span == 1 && r.created {
            while let (Some(x), Some(p)) = (rows.get(i + n), rows.get(i + n - 1)) {
                let next = x.span == 1 && x.created && !x.head && x.shown == r.shown && x.dot.src == p.dot.src && p.dot.ctr.checked_add(1) == Some(x.dot.ctr) && x.parent.as_ref() == Some(&p.dot) && x.depth == p.depth + 1;
                if !next {
                    break;
                }
                n += 1;
            }
        }
        let flags = u64::from(r.created) | (u64::from(r.head) << 1) | (u64::from(r.shown) << 2) | (u64::from(n > 1) << 3);
        let parent = r.parent.as_ref().map_or(Value::List(Vec::new()), |p| t.dot(p));
        out.push(Value::List(vec![t.of(&r.dot.src), Value::uint(r.dot.ctr), Value::uint(if n > 1 { n as u64 } else { r.span }), Value::uint(flags), parent, Value::Int(r.depth)]));
        i += n;
    }
    t.row(out)
}

fn parse_block(b: &[u8]) -> Option<Vec<PlaceRow>> {
    let (srcs, items) = parse_srcs(b)?;
    let mut out = Vec::new();
    for it in items {
        let Value::List(x) = it else { return None };
        let [s, Value::Int(ctr), Value::Int(n), Value::Int(flags), parent, Value::Int(depth)] = x.as_slice() else { return None };
        let (ctr, n, flags) = (u64::try_from(*ctr).ok()?, u64::try_from(*n).ok().filter(|n| *n >= 1)?, u64::try_from(*flags).ok().filter(|f| *f < 16)?);
        let dot = Dot::new(src_at(&srcs, s)?, ctr);
        ctr.checked_add(n)?;
        let parent = match parent {
            Value::List(p) if p.is_empty() => None,
            p => Some(dot_at(&srcs, p)?),
        };
        let (created, head, shown) = (flags & 1 != 0, flags & 2 != 0, flags & 4 != 0);
        if flags & 8 == 0 {
            out.push(PlaceRow { dot, span: n, created, parent, head, shown, depth: *depth });
            continue;
        }
        if !created || out.len() as u64 + n > 1 << 20 {
            return None;
        }
        let mut prev: Option<Dot> = None;
        for k in 0..n {
            let d = Dot::new(dot.src.clone(), ctr + k);
            let parent = if k == 0 { parent.clone() } else { prev.clone() };
            out.push(PlaceRow { dot: d.clone(), span: 1, created, parent, head: head && k == 0, shown, depth: depth.checked_add(i64::try_from(k).ok()?)? });
            prev = Some(d);
        }
    }
    Some(out)
}

fn chunk_row(e: &[(Dot, usize)]) -> Vec<u8> {
    let mut t = Srcs::default();
    let mut out = Vec::new();
    let mut i = 0;
    while let Some((d, b)) = e.get(i) {
        let mut n = 1;
        while let Some((x, c)) = e.get(i + n) {
            if c != b || x.src != d.src || d.ctr.checked_add(n as u64) != Some(x.ctr) {
                break;
            }
            n += 1;
        }
        out.push(Value::List(vec![t.of(&d.src), Value::uint(d.ctr), Value::uint(n as u64), Value::uint(*b as u64)]));
        i += n;
    }
    t.row(out)
}

fn parse_chunk(b: &[u8]) -> Option<Vec<(Dot, usize)>> {
    let (srcs, items) = parse_srcs(b)?;
    let mut out = Vec::new();
    for it in items {
        let Value::List(x) = it else { return None };
        let [s, Value::Int(ctr), Value::Int(n), Value::Int(b)] = x.as_slice() else { return None };
        let (src, ctr, n, b) = (src_at(&srcs, s)?, u64::try_from(*ctr).ok()?, u64::try_from(*n).ok().filter(|n| *n >= 1)?, usize::try_from(*b).ok()?);
        ctr.checked_add(n)?;
        if out.len() as u64 + n > 1 << 20 {
            return None;
        }
        out.extend((0..n).map(|k| (Dot::new(src.clone(), ctr + k), b)));
    }
    Some(out)
}

fn top_row(t: &PlaceTop, groups: usize) -> Vec<u8> {
    let dots = |x: &[Dot]| Value::List(x.iter().map(dot_value).collect());
    let newest = t.newest.as_ref().map_or(Value::List(Vec::new()), |s| Value::List(vec![Value::uint(s.ts.to_u64()), dot_value(&s.dot)]));
    osis_base::encode(&Value::List(vec![Value::uint(t.cap as u64), Value::uint(t.map_len as u64), dots(&t.waiting), dots(&t.cyc), Value::uint(groups as u64), newest]))
}

fn group_rows(t: &PlaceTop) -> Vec<Vec<u8>> {
    t.blocks.chunks(GROUP).map(|g| osis_base::encode(&Value::List(g.iter().map(|b| Value::List(vec![Value::uint(b.id as u64), Value::uint(b.len as u64), Value::uint(b.shown as u64), Value::Int(b.min), Value::Int(b.shift)])).collect()))).collect()
}

fn chunks_row(t: &PlaceTop) -> Vec<u8> {
    let mut s = Srcs::default();
    let items = t.chunks.iter().map(|d| s.dot(d)).collect();
    s.row(items)
}

/// The top and chunk list of a stored placement (`None`: damaged).
fn parse_top(top: &[u8], groups: &[Vec<u8>], chunks: &[u8]) -> Option<PlaceTop> {
    let row = decode_row(top)?;
    let [cap, map_len, Value::List(waiting), Value::List(cyc), ng, Value::List(newest)] = <[Value; 6]>::try_from(row).ok()? else { return None };
    // the newest position write's stamp
    let newest = match newest.as_slice() {
        [] => None,
        [Value::Int(ts), d] => Some(osis_crdt::Stamp { ts: osis_base::Ts::from_u64(u64::try_from(*ts).ok()?)?, dot: dot_of(d).ok()? }),
        _ => return None,
    };
    let n = |v: &Value| int(v).and_then(|x| usize::try_from(x).ok());
    let dots = |x: &[Value]| x.iter().map(|d| dot_of(d).ok()).collect::<Option<Vec<_>>>();
    if n(&ng)? != groups.len() {
        return None;
    }
    let mut all = Vec::new();
    for g in groups {
        all.extend(decode_row(g)?);
    }
    let blocks = all
        .iter()
        .map(|b| match b {
            Value::List(x) => match x.as_slice() {
                [id, len, shown, Value::Int(min), Value::Int(shift)] => Some(PlaceBlock { id: n(id)?, len: n(len)?, shown: n(shown)?, min: *min, shift: *shift }),
                _ => None,
            },
            _ => None,
        })
        .collect::<Option<Vec<_>>>()?;
    let (srcs, items) = parse_srcs(chunks)?;
    let chunks = items.iter().map(|d| dot_at(&srcs, d)).collect::<Option<Vec<_>>>()?;
    Some(PlaceTop { cap: n(&cap)?, map_len: n(&map_len)?, waiting: dots(&waiting)?, cyc: dots(&cyc)?, blocks, chunks, newest })
}

fn put_place(txn: &mut Transaction<'_>, pt: Table, key: Vec<u8>, block: bool, row: Vec<u8>) -> Result<()> {
    // counted: scale tests read the number of placement rows written
    let _s = osis_base::costs::span(if block { "placement block write" } else { "placement row write" });
    txn.table_put(pt, &key, row, Shred::No)?;
    Ok(())
}

/// The stored placement of the paged sequence `set`, read once per session (`None`: missing or
/// damaged).
fn held(txn: &mut Transaction<'_>, tid: &Tid, ak: &Ak, set: &mut PageSet) -> Result<Option<SeqPlace>> {
    match &set.place {
        Place::Held(p) => return Ok(Some(p.clone())),
        Place::Missing => return Ok(None),
        Place::Unread => {}
    }
    let _s = osis_base::costs::span("placement open");
    let mut p = None;
    set.groups.clear();
    if let Some(pt) = txn.table(tid, ak, PLACE_TABLE)?
        && let (Some(top), Some(chunks)) = (txn.table_get(pt, &place_key(set, 0, 0))?, txn.table_get(pt, &place_key(set, 2, 0))?)
    {
        let end = [set.prefix(), vec![1]].concat();
        let mut groups = Vec::new();
        scan_table(txn, pt, &place_key(set, 4, 0), Some(&end), |k, v| {
            groups.push((k, v));
            Ok(())
        })?;
        // in order, none missing
        let ok = groups.iter().enumerate().all(|(i, (k, _))| *k == place_key(set, 4, i as u64));
        let rows: Vec<Vec<u8>> = groups.into_iter().map(|x| x.1).collect();
        p = ok.then(|| parse_top(&top, &rows, &chunks)).flatten().and_then(|t| SeqPlace::from_top(&t));
        if p.is_some() {
            set.groups = rows;
        }
    }
    set.place = p.clone().map_or(Place::Missing, Place::Held);
    Ok(p)
}

/// Loads into `p` the blocks and chunks `m` names; `false` if a row is missing or damaged.
fn fill_place(txn: &mut Transaction<'_>, pt: Table, set: &PageSet, p: &mut SeqPlace, blocks: &[usize], chunks: &[Option<Dot>]) -> Result<bool> {
    for b in blocks {
        let _s = osis_base::costs::span("placement block load");
        let Some(rows) = txn.table_get(pt, &place_key(set, 1, *b as u64))?.as_deref().and_then(parse_block) else { return Ok(false) };
        if !p.fill(*b, rows) {
            return Ok(false);
        }
    }
    for c in chunks {
        let Some(e) = txn.table_get(pt, &chunk_key(set, c.as_ref()))?.as_deref().and_then(parse_chunk) else { return Ok(false) };
        if !p.fill_chunk(c.as_ref(), e) {
            return Ok(false);
        }
    }
    Ok(true)
}

/// The dot ranges of `set`'s loaded pages.
fn cover_of(set: &PageSet) -> Vec<(Option<Dot>, Option<Dot>)> {
    set.loaded.values().cloned().collect()
}

/// Notes `p` as `set`'s stored placement and attaches it.
fn hold(f: &mut Fragment, set: &mut PageSet, p: SeqPlace) {
    set.place = Place::Held(p.clone());
    attach(f, set, Some(p));
}

/// Attaches `p` to the sequence of `set` in `f`, its cover the pages loaded.
fn attach(f: &mut Fragment, set: &PageSet, p: Option<SeqPlace>) {
    if let Some(p) = &p {
        p.cover(cover_of(set));
    }
    if let Some(s) = f.at_steps_mut(&steps(&set.path)) {
        s.set_seq_place(p);
    }
}

/// Loads what `p` missed (blocks, chunks, the pages of records); `Ok(false)`: give up (a row
/// damaged, or every record looked at).
#[allow(clippy::too_many_arguments)]
fn absorb_into(txn: &mut Transaction<'_>, t: Table, pt: Table, set: &mut PageSet, bound: &mut Bound, f: &mut Fragment, p: &mut SeqPlace, m: &PlaceMisses) -> Result<bool> {
    if m.all || !fill_place(txn, pt, set, p, &m.blocks, &m.chunks)? {
        return Ok(false);
    }
    for (a, b) in &m.recs {
        ensure_span(txn, t, set, bound, f, a, b)?;
    }
    Ok(true)
}

/// Writes the placement `cur` of `set`: what changed against `old` (the placement as stored,
/// which `cur` descends from), else all of it (`cur` loaded whole). `false`: neither fits.
fn write_place(txn: &mut Transaction<'_>, tid: &Tid, ak: &Ak, set: &mut PageSet, cur: &SeqPlace, old: Option<&SeqPlace>, shred: Shred) -> Result<bool> {
    let _s = osis_base::costs::span("placement write");
    let top = cur.top();
    let pt = txn.create_table(tid, ak, PLACE_TABLE)?;
    let d = match old.and_then(|o| cur.diff(o)) {
        Some(d) => d,
        None if cur.is_partial() => return Ok(false),
        // all of it, over nothing
        None => {
            clear_placement(txn, pt, set, shred)?;
            set.groups.clear();
            let chunks = std::iter::once(None).chain(top.chunks.iter().cloned().map(Some)).collect();
            PlaceDiff { blocks: top.blocks.iter().map(|b| b.id).collect(), gone: Vec::new(), chunks, dir: true }
        }
    };
    for b in &d.blocks {
        let Some(rows) = cur.rows(*b) else { return Ok(false) };
        put_place(txn, pt, place_key(set, 1, *b as u64), true, block_row(&rows))?;
    }
    for b in &d.gone {
        txn.table_remove(pt, &place_key(set, 1, *b as u64), shred)?;
    }
    for c in &d.chunks {
        let Some(e) = cur.chunk(c.as_ref()) else { return Ok(false) };
        put_place(txn, pt, chunk_key(set, c.as_ref()), false, chunk_row(&e))?;
    }
    if d.dir {
        put_place(txn, pt, place_key(set, 2, 0), false, chunks_row(&top))?;
    }
    let groups = group_rows(&top);
    for (i, g) in groups.iter().enumerate() {
        if set.groups.get(i) != Some(g) {
            put_place(txn, pt, place_key(set, 4, i as u64), false, g.clone())?;
        }
    }
    for i in groups.len()..set.groups.len() {
        txn.table_remove(pt, &place_key(set, 4, i as u64), shred)?;
    }
    put_place(txn, pt, place_key(set, 0, 0), false, top_row(&top, groups.len()))?;
    set.groups = groups;
    set.place = Place::Held(cur.clone());
    Ok(true)
}

/// Lays out the placement of the paged sequence `set` (`c`, loaded whole) anew; the sequence
/// keeps it cached, so the session's joins follow it.
fn write_placement(txn: &mut Transaction<'_>, tid: &Tid, ak: &Ak, set: &mut PageSet, c: &Fragment, shred: Shred) -> Result<()> {
    if !set.whole {
        return Err(Error::Corrupt("state sequence not loaded"));
    }
    let p = c.seq_place().ok_or(Error::Corrupt("state sequence"))?;
    if !write_place(txn, tid, ak, set, &p, None, shred)? {
        return Err(Error::Corrupt("state sequence placement"));
    }
    Ok(())
}

/// Invalidates the stored placement of the paged sequence `set` (a write changed it in a way
/// not followed): removes its top; the writing transaction lays it out anew at its end
/// (`unplaced`, `rebuild_placement`). The other rows stay until then.
fn invalidate_placement(txn: &mut Transaction<'_>, tid: &Tid, ak: &Ak, set: &mut PageSet, shred: Shred) -> Result<()> {
    set.relay = true;
    if matches!(set.place, Place::Missing) {
        return Ok(());
    }
    if let Some(pt) = txn.table(tid, ak, PLACE_TABLE)? {
        txn.table_remove(pt, &place_key(set, 0, 0), shred)?;
    }
    set.place = Place::Missing;
    set.groups.clear();
    Ok(())
}

/// Drops every placement row of `set`.
fn clear_placement(txn: &mut Transaction<'_>, pt: Table, set: &PageSet, shred: Shred) -> Result<()> {
    clear_table(txn, pt, &set.prefix(), &set.id.saturating_add(1).to_be_bytes(), shred)
}

/// Once every page of the paged sequence `set` is loaded: its placement as stored, loaded whole
/// (its text's chars set), is the sequence's cached one, so a whole session's joins and ops
/// follow it and its writes keep it; none (missing or damaged) leaves the sequence to a whole
/// pass.
fn place_whole(txn: &mut Transaction<'_>, tid: &Tid, ak: &Ak, set: &mut PageSet, f: &mut Fragment) -> Result<()> {
    let _s = osis_base::costs::span("placement whole");
    let at = steps(&set.path);
    let held = if set.pending { None } else { held(txn, tid, ak, set)? };
    let Some(mut p) = held else {
        // a whole pass of the records as they are (the next write writes it whole)
        attach(f, set, None);
        return Ok(());
    };
    let (bs, cs) = p.stubs();
    let ok = match txn.table(tid, ak, PLACE_TABLE)? {
        Some(pt) => fill_place(txn, pt, set, &mut p, &bs, &cs)?,
        None => false,
    };
    if !ok || !p.complete() {
        attach(f, set, None);
        set.place = Place::Missing;
        set.relay = true;
        return Ok(());
    }
    if let Some(s) = f.at_steps(&at) {
        s.fill_chars(&mut p);
    }
    hold(f, set, p);
    Ok(())
}

/// Prepares the ops `ops` on paged sequences (by index, an edit, anything inside an element at
/// an index) to run on the pages loaded: loads the pages along their paths and attaches each
/// sequence's stored placement; the caller runs them and loads what they missed (`absorb`)
/// until nothing is. A list edit whose items have large parts (`edits`, by op) first loads the
/// elements at its window, whose links it takes (`large::window_links`). `false`: not that kind
/// (another op, a sequence not paged, loaded whole or without a placement, a list edit taking
/// links from the whole list): load whole.
pub(crate) fn attach_ops(txn: &mut Transaction<'_>, tid: &Tid, ak: &Ak, idx: &mut StatePages, f: &mut Fragment, ops: &[osis_crdt::PathOp], edits: &[Option<super::large::ListEdit>]) -> Result<bool> {
    use osis_crdt::Op;
    let t = table(txn, tid, ak)?;
    for (n, op) in ops.iter().enumerate() {
        // ops by index; an edit (resolved around its change when the read there matches its
        // base); anything inside an element at an index (never paged apart from its sequence)
        let k = op.path.iter().position(|s| matches!(s, PathSeg::Index(_)));
        let by_index = k.is_some() || matches!(op.op, Op::Insert { .. } | Op::Delete { .. } | Op::Move { .. } | Op::Paste { .. } | Op::Edit { .. });
        if !by_index {
            return Ok(false);
        }
        let at = walk(txn, tid, ak, t, idx, f, op.path.get(..k.unwrap_or(op.path.len())).unwrap_or_default())?;
        let [p] = at.as_slice() else { return Ok(false) };
        let Some(set) = idx.sets.get_mut(p).filter(|s| is_seq(s) && !s.whole) else { return Ok(false) };
        if let Some(PathSeg::Index(i)) = k.and_then(|k| op.path.get(k)) {
            // the element loaded up front: a large value's lookup (`chunk_ops`) finds it held
            if !step_index(txn, tid, ak, t, set, &mut idx.bound, f, p, *i)? {
                return Ok(false);
            }
            continue;
        }
        let Some(pl) = held(txn, tid, ak, set)? else { return Ok(false) };
        // the skeleton holds no sequence without a reset or `W`: its first page restores it
        if f.at_steps(p).is_none() {
            ensure_first(txn, t, set, &mut idx.bound, f)?;
        }
        match (&op.op, edits.get(n).and_then(Option::as_ref)) {
            (Op::Edit { new: Value::Str(_), .. }, _) => {}
            (Op::Edit { new: Value::List(_), .. }, e) if e.is_none_or(|e| !e.large) => {}
            (Op::Edit { new: Value::List(_), .. }, Some(e)) => {
                // the elements at its window, whose links it takes; else the whole list's
                let Some(w) = e.win else { return Ok(false) };
                if pl.shown() != e.base_len() || load_range(txn, tid, ak, t, set, &mut idx.bound, f, pl, w.lo..w.hi)?.is_none() {
                    return Ok(false);
                }
                let Place::Held(pl) = &set.place else { return Ok(false) };
                let pl = pl.clone();
                attach(f, set, Some(pl.clone()));
                let lends = f.at(&op.path).is_some_and(|l| super::large::window_links(&l, e).is_some());
                if !lends || pl.misses().any() {
                    return Ok(false);
                }
                continue;
            }
            (Op::Edit { .. }, _) => return Ok(false),
            _ => {}
        }
        attach(f, set, Some(pl));
    }
    Ok(true)
}

/// Loads what the placements attached to the paged sequences missed since the last call, adding
/// the run's work to `work` (its follows' and plans', at least one per sequence that missed).
/// `Some(true)`: something was (run again), `Some(false)`: nothing, `None`: give up (load whole):
/// the runs so far looked at every record, or their work passed about one whole pass of the
/// paged sequences (a run stops at its first miss, so ops touching many places take as many
/// runs; a count of runs is no bound).
pub fn absorb(txn: &mut Transaction<'_>, tid: &Tid, ak: &Ak, idx: &mut StatePages, f: &mut Fragment, work: &mut usize) -> Result<Option<bool>> {
    let t = table(txn, tid, ak)?;
    let mut any = false;
    let budget: usize = idx.sets.values().filter(|s| is_seq(s) && !s.whole).filter_map(|s| if let Place::Held(p) = &s.place { Some(p.len().max(1024)) } else { None }).sum();
    for set in idx.sets.values_mut().filter(|s| is_seq(s) && !s.whole) {
        let Place::Held(p) = &set.place else { continue };
        let mut p = p.clone();
        let m = p.misses();
        if !m.any() {
            continue;
        }
        any = true;
        *work += m.work.max(1);

        if *work > budget {
            let _s = osis_base::costs::span("paged op whole: runs");
            return Ok(None);
        }
        if m.all {
            // counted: how often an op on the pages loaded gives up and loads whole
            let _s = osis_base::costs::span(if m.whole { "paged op whole: whole pass" } else { "paged op whole: every record" });
            return Ok(None);
        }
        let Some(pt) = txn.table(tid, ak, PLACE_TABLE)? else { return Ok(None) };
        if !absorb_into(txn, t, pt, set, &mut idx.bound, f, &mut p, &m)? {
            return Ok(None);
        }
        hold(f, set, p);
    }
    Ok(Some(any))
}

/// What a read of a paged sequence's elements by index found (`seq_range`).
pub enum Ranged {
    /// The sequence's path; the elements' dots, in order, with the pages holding them loaded;
    /// the sequence's visible length.
    Read(Vec<Step>, Vec<Dot>, usize),
    /// The path does not lead to one paged sequence (read as usual).
    Unpaged,
    /// The sequence's placement is missing or damaged: read whole (the next transaction writing
    /// the state lays it out anew, `PageSet::relay`).
    Damaged,
}

/// The visible elements `r` (by index, clamped) of the paged sequence at `path` (op path
/// segments) through its placement: the top, the blocks holding them and the pages holding
/// their records, nothing else of the sequence.
pub fn seq_range(txn: &mut Transaction<'_>, tid: &Tid, ak: &Ak, idx: &mut StatePages, f: &mut Fragment, path: &[PathSeg], r: Span<usize>) -> Result<Ranged> {
    let t = table(txn, tid, ak)?;
    let at = walk(txn, tid, ak, t, idx, f, path)?;
    let [p] = at.as_slice() else { return Ok(Ranged::Unpaged) };
    let Some(set) = idx.sets.get_mut(p).filter(|s| is_seq(s)) else { return Ok(Ranged::Unpaged) };
    let Some(pl) = held(txn, tid, ak, set)? else { return Ok(Ranged::Damaged) };
    let total = pl.shown();
    match load_range(txn, tid, ak, t, set, &mut idx.bound, f, pl, r)? {
        Some(dots) => Ok(Ranged::Read(p.clone(), dots, total)),
        None => Ok(Ranged::Damaged),
    }
}

/// The visible elements `r` (by index, clamped) of the paged sequence `set` through its stored
/// placement `pl`: loads the blocks holding them and the pages holding their records; `None`
/// if a row is missing or damaged (then noted missing).
#[allow(clippy::too_many_arguments)]
fn load_range(txn: &mut Transaction<'_>, tid: &Tid, ak: &Ak, t: Table, set: &mut PageSet, bound: &mut Bound, f: &mut Fragment, mut pl: SeqPlace, r: Span<usize>) -> Result<Option<Vec<Dot>>> {
    let Some(pt) = txn.table(tid, ak, PLACE_TABLE)? else { return Ok(None) };
    let total = pl.shown();
    // a reversed range is empty
    let lo = r.start.min(total);
    let hi = r.end.min(total).max(lo);
    let mut dots = Vec::new();
    for _ in 0..2 {
        dots = pl.visible(lo..hi);
        let m = pl.misses();
        if !m.any() {
            break;
        }
        if !fill_place(txn, pt, set, &mut pl, &m.blocks, &m.chunks)? {
            set.place = Place::Missing;
            set.relay = true;
            return Ok(None);
        }
    }
    if dots.len() != hi - lo {
        return Ok(None);
    }
    set.place = Place::Held(pl);
    for d in &dots {
        ensure_dot(txn, t, set, bound, f, d)?;
    }
    Ok(Some(dots))
}

/// For a step at index `i` into the paged sequence `set`: loads the block and page holding
/// visible element `i` through the stored placement and attaches it, so what reads or writes
/// inside the element resolves on the pages loaded. `false`: no placement (load the sequence
/// whole).
#[allow(clippy::too_many_arguments)]
fn step_index(txn: &mut Transaction<'_>, tid: &Tid, ak: &Ak, t: Table, set: &mut PageSet, bound: &mut Bound, f: &mut Fragment, p: &[Step], i: usize) -> Result<bool> {
    let Some(pl) = held(txn, tid, ak, set)? else { return Ok(false) };
    if load_range(txn, tid, ak, t, set, bound, f, pl, i..i.saturating_add(1))?.is_none() {
        return Ok(false);
    }
    if f.at_steps(p).is_none() {
        ensure_first(txn, t, set, bound, f)?;
    }
    let pl = match &set.place {
        Place::Held(x) => x.clone(),
        _ => return Ok(false),
    };
    attach(f, set, Some(pl));
    Ok(true)
}

/// Notes the placement of the paged sequence at `p` damaged: missing, laid out anew by the next
/// transaction writing the state.
pub fn damaged(idx: &mut StatePages, p: &[Step]) {
    if let Some(set) = idx.sets.get_mut(p) {
        set.place = Place::Missing;
        set.relay = true;
    }
}

/// The paged sequences whose placement is to be laid out anew (`PageSet::relay`).
pub fn unplaced(idx: &StatePages) -> Vec<Vec<Step>> {
    idx.sets.iter().filter(|(_, s)| s.relay).map(|(p, _)| p.clone()).collect()
}

/// Lays the placement of the paged sequence at `p` out anew, its pages loaded whole (none for a
/// sequence no longer in the state: a removed entry's).
pub fn rebuild_placement(txn: &mut Transaction<'_>, tid: &Tid, ak: &Ak, idx: &mut StatePages, f: &mut Fragment, p: &[Step]) -> Result<()> {
    let t = table(txn, tid, ak)?;
    let Some(set) = idx.sets.get_mut(p) else { return Ok(()) };
    ensure_set(txn, tid, ak, t, set, &mut idx.bound, f)?;
    set.relay = false;
    match f.at_steps(p) {
        Some(c @ Fragment::Seq(_)) => write_placement(txn, tid, ak, set, c, Shred::No),
        _ => Ok(()),
    }
}

// ---- writing

/// A page: the collection's root elements in `[lo, hi)`, collections paged below reduced.
fn page(c: &Fragment, nested: &Paths, r: &Range) -> Result<Fragment> {
    Ok(c.elem_range(r.0.as_ref(), r.1.as_ref(), false).ok_or(Error::Corrupt("state page"))?.reduced(nested))
}

/// A collection that splits: two elements or more (one alone is a page whatever its size).
fn splits(c: &Fragment) -> bool {
    c.elem_count().is_some_and(|n| n >= 2)
}

/// Whether `f` (encoding to `len` bytes, about) holds a collection to page (`paged_paths`).
fn holds_large(f: &Fragment, len: usize) -> Result<bool> {
    Ok(len > PAGE_BYTES && !paged_paths(f)?.is_empty())
}

/// The collections of a state to page: every collection of two elements or more whose own
/// bytes, with the collections paged below it taken out, encode to more than `PAGE_BYTES`, at
/// any depth below struct fields, enum payloads and map entries (inside a paged collection's
/// elements too). By bytes alone, so a few large elements page as many small ones do, and a
/// collection holding one paged collection and little else stays in the skeleton.
fn paged_paths(f: &Fragment) -> Result<Vec<Vec<Step>>> {
    let mut paged = Paths::default();
    let mut out = Vec::new();
    // deepest first (`collections` is in pre-order): what pages below a collection is known
    // before its own bytes are counted
    for (p, c) in f.collections().into_iter().rev() {
        if !splits(c) {
            continue;
        }
        let below = Paths { here: false, next: paged.below(&p).map(|x| x.next.clone()).unwrap_or_default() };
        let own = if below.is_empty() { encode(c)?.len() } else { encode(&c.reduced(&below))?.len() };
        if own > PAGE_BYTES {
            paged.insert(&p);
            out.push(p);
        }
    }
    out.reverse();
    Ok(out)
}

/// The path of `p` in `f` with the keys of its entry steps.
fn keyed(f: &Fragment, p: &[Step]) -> KeyedPath {
    let mut out = Vec::with_capacity(p.len());
    let mut cur = Some(f);
    for s in p {
        let (key, created) = match s {
            Step::Entry(id) => (id.key().cloned(), cur.and_then(|c| c.entry_created(id)).cloned()),
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
    if !is_keyed(set) {
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
    write_pieces(txn, t, set, c, nested, &dots, per, &(None, None), Shred::No)?;
    set.whole = true;
    // the tables were created for this write
    index_keys(txn, kt, set, c, &mut dots.iter(), true)
}

/// Writes a whole state: the unit's state field, and the pages when it holds large collections
/// (`paged_paths`; the old pages, if any, are dropped shredded).
/// `f` must be the whole state.
pub fn write_full(txn: &mut Transaction<'_>, tid: &Tid, ak: &Ak, f: Option<&Fragment>, old_paged: bool, salt: &[u8; 32]) -> Result<(Vec<u8>, Option<StatePages>)> {
    if old_paged {
        txn.drop_table(tid, ak, STATE_TABLE)?;
        txn.drop_table(tid, ak, KEY_TABLE)?;
        txn.drop_table(tid, ak, PLACE_TABLE)?;
    }
    let Some(f) = f else { return Ok((Vec::new(), None)) };
    let bytes = encode(f)?;
    // no collection of it encodes to more than the whole
    if bytes.len() <= PAGE_BYTES {
        return Ok((bytes, None));
    }
    let paged = paged_paths(f)?;
    if paged.is_empty() {
        return Ok((bytes, None));
    }
    let t = txn.create_table(tid, ak, STATE_TABLE)?;
    let kt = txn.create_table(tid, ak, KEY_TABLE)?;
    let mut idx = StatePages { sets: BTreeMap::new(), paths: Paths::default(), bound: None };
    for p in &paged {
        idx.paths.insert(p);
    }
    for (i, p) in paged.into_iter().enumerate() {
        let c = f.at_steps(&p).ok_or(Error::Corrupt("state collection"))?;
        let mut set = PageSet::new(u32::try_from(i).map_err(|_| Error::Corrupt("state sets"))?, *salt, keyed(f, &p), c.encoding());
        write_set(txn, t, kt, &mut set, c, &idx.nested(&p))?;
        if is_seq(&set) {
            write_placement(txn, tid, ak, &mut set, c, Shred::No)?;
        }
        idx.sets.insert(p, set);
    }
    let unit = unit_state(&f.reduced(&idx.paths), &idx)?;
    Ok((unit, Some(idx)))
}

/// Points the page before row `key` at `hi` (its successor went).
fn relink_prev(txn: &mut Transaction<'_>, t: Table, set: &mut PageSet, key: &[u8], hi: Option<Dot>, shred: Shred) -> Result<()> {
    let (pk, v) = row_below(txn, t, key)?;
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
        // (first, last) per delta record: a range record touches every page between (all
        // loaded, or those its records span, `ensure_span`)
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
        // counted: scale tests read the number of pages written
        let _s = osis_base::costs::span("state page write");
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
            if holds_large(&page(c, nested, &r)?, bytes.len())? {
                return Ok(false);
            }
            txn.table_put(t, &key, bytes, shred)?;
            continue;
        }
        let per = ds.len().div_ceil(bytes.len().div_ceil(PAGE_BYTES)).max(1);
        // elements moving to another row: the old versions go shredded, so a later shred of a
        // moved element's row reaches every copy
        write_pieces(txn, t, set, c, nested, &ds, per, &r, Shred::Yes)?;
    }
    Ok(true)
}

/// Writes the elements `ds` of `c` (those of range `r`) as pages of `per` elements, noted
/// loaded; one empty page when there are none.
#[allow(clippy::too_many_arguments)]
fn write_pieces(txn: &mut Transaction<'_>, t: Table, set: &mut PageSet, c: &Fragment, nested: &Paths, ds: &[Dot], per: usize, r: &Range, shred: Shred) -> Result<()> {
    let pieces: Vec<&[Dot]> = if ds.is_empty() { vec![&[]] } else { ds.chunks(per).collect() };
    let n = pieces.len();
    for (i, chunk) in pieces.into_iter().enumerate() {
        let lo = if i == 0 { r.0.clone() } else { chunk.first().cloned() };
        let hi = if i + 1 == n { r.1.clone() } else { ds.get((i + 1) * per).cloned() };
        let pr = (lo, hi);
        let pk = set.row_key(pr.0.as_ref());
        txn.table_put(t, &pk, page_row(&pr, &page(c, nested, &pr)?)?, shred)?;
        set.loaded.insert(pk, pr);
    }
    Ok(())
}

/// Rewrites what `touch` says changed in the paged state `f` (holding at least the pages
/// `ensure_touch` loaded for it). `Ok(None)`: it does not fit the pages (write whole);
/// `Ok(Some(unit))`: done, with the unit's new state field if the skeleton changed.
pub fn write_touched(txn: &mut Transaction<'_>, idx: &mut StatePages, tid: &Tid, ak: &Ak, f: &Fragment, touch: &PagedTouch, shred: Shred) -> Result<Option<Option<Vec<u8>>>> {
    // a touched collection that moved or changed encoding: lay out again
    for p in touch.elems.keys() {
        let (Some(set), Some(c)) = (idx.sets.get(p), f.at_steps(p)) else { return Ok(None) };
        if c.encoding() != set.enc {
            return Ok(None);
        }
    }
    let t = table(txn, tid, ak)?;
    let kt = txn.create_table(tid, ak, KEY_TABLE)?;
    let mut path_changed = false;
    for (p, dots) in &touch.elems {
        let nested = idx.nested(p);
        let (Some(set), Some(c)) = (idx.sets.get_mut(p), f.at_steps(p)) else { return Ok(None) };
        if !rewrite_set(txn, t, kt, set, c, &nested, dots, shred)? {
            return Ok(None);
        }
        let path = keyed(f, p);
        if path != set.path {
            set.path = path;
            path_changed = true;
        }
        if is_seq(set) {
            // the placement the sequence followed through the join (attached, or cached when
            // loaded whole): what changed is written; else (dropped, or not followed from the
            // stored one) a whole one is written whole, or the stored one invalidated
            let cur = c.seq_place_cached();
            let old = match &set.place {
                Place::Held(o) => Some(o.clone()),
                _ => None,
            };
            let kept = match cur {
                Some(cur) if old.is_some() || set.whole => write_place(txn, tid, ak, set, &cur, old.as_ref(), shred)?,
                _ => false,
            };
            if !kept {
                invalidate_placement(txn, tid, ak, set, shred)?;
            }
            set.pending = false;
        }
    }
    if !touch.skeleton && !path_changed {
        return Ok(Some(None));
    }
    let skeleton = f.reduced(&idx.paths);
    let unit = unit_state(&skeleton, idx)?;
    // unpaged parts grown large: written whole, which pages them
    Ok((!holds_large(&skeleton, unit.len())?).then_some(Some(unit)))
}

/// Drops the loaded pages of the paged state `f` (written already: the store holds them),
/// keeping its skeleton, so a delta joined a page at a time holds about one page of its state
/// (issues/durable-decode-bound.md). Not while it pages a sequence: those stay loaded for their
/// placement.
pub fn evict(idx: &mut StatePages, f: &mut Fragment) {
    if idx.sets.values().any(is_seq) {
        return;
    }
    *f = f.reduced(&idx.paths);
    idx.unload();
}

/// What `join_reset` did.
pub enum Reset {
    /// It does not fit the pages: join the whole state.
    Whole,
    /// Pages rewritten: the new skeleton (no page loaded) and the unit's state field.
    Paged { skeleton: Fragment, unit: Vec<u8>, changes: Changes },
    /// The joined state, to write whole (its pages joined already): a paged collection's
    /// encoding changed, an element outgrew a page, the skeleton outgrew the unit, or nothing
    /// is left.
    Laid { state: Option<Fragment>, changes: Changes },
}

/// The pages of a paged collection, in order.
fn set_pages(txn: &mut Transaction<'_>, t: Table, set: &PageSet) -> Result<Vec<Fragment>> {
    let mut out = Vec::new();
    for key in set_rows(txn, t, set)? {
        if let Some(row) = txn.table_get(t, &key)? {
            out.push(parse_page_row(&row)?.1);
        }
    }
    Ok(out)
}

/// The row keys of a paged collection's pages, in order.
fn set_rows(txn: &mut Transaction<'_>, t: Table, set: &PageSet) -> Result<Vec<Vec<u8>>> {
    let mut out = Vec::new();
    scan_table(txn, t, &set.prefix(), Some(&set.id.saturating_add(1).to_be_bytes()), |k, _| {
        out.push(k);
        Ok(())
    })?;
    Ok(out)
}

/// Joins `d`, which may reset a paged collection or change its encoding (`touch_of` is `None`),
/// into the paged state `f` a page at a time instead of loading it whole: the skeleton joins
/// `d` (`j`); each page of a collection `d` reaches (`Fragment::reaches`) joins, below the
/// skeleton's and `d`'s spines along its path (`Fragment::spine`: all that a join's pruning
/// there depends on) with `d`'s elements in its range, and is written back; the new skeleton is
/// `j` reduced. That is the whole join: elements are independent per dot and a position is
/// pruned by the resets on its path alone (spec/crdt.md §4.2, §8). Not for a paged
/// sequence (its placement follows a join whole), a collection paged inside another's elements
/// (its path runs through pages) or `d` changing an encoding above a paged collection: `Whole`.
/// `moved`: the tids it adds and removes, for the reference index (meaningful for `Paged`; the
/// others write a whole state, which the index follows whole). `dead`: the writes it superseded,
/// noted per join as a whole join notes them (the skeleton's, then each page's).
#[allow(clippy::too_many_arguments)]
pub(crate) fn join_reset(txn: &mut Transaction<'_>, tid: &Tid, ak: &Ak, idx: &mut StatePages, f: &Fragment, d: &Fragment, moved: &mut super::refs::Delta, mut dead: Option<&mut Killed>) -> Result<Reset> {
    if nested(idx) || idx.sets.values().any(is_seq) || !idx.sets.keys().all(|p| d.steps_through(p)) {
        return Ok(Reset::Whole);
    }
    let s0 = f.reduced(&idx.paths);
    moved.add(&s0, -1);
    let mut j = s0.clone();
    let before = dead.as_ref().map(|_| Killed::before(&j, d));
    let mut changes = j.join(d.clone());
    if let (Some(k), Some(w)) = (dead.as_deref_mut(), before) {
        k.note(&w, &j, d)?;
    }
    let t = table(txn, tid, ak)?;
    let kt = txn.create_table(tid, ak, KEY_TABLE)?;
    let none = Paths::default();
    // `relay`: lay the state out again; `kept`: a reached collection keeps an element
    let (mut relay, mut kept, mut all) = (false, false, true);
    for (p, set) in idx.sets.iter_mut() {
        if !d.reaches(p) {
            all = false;
            continue;
        }
        let spine = s0.spine(p, None);
        // the path's creations as joined: every page's join holds the same resets on the path,
        // and `d`'s creations where it has elements in the page's range
        let mut path: Option<KeyedPath> = None;
        for key in set_rows(txn, t, set)? {
            let Some(row) = txn.table_get(t, &key)? else { continue };
            let (r, pg) = parse_page_row(&row)?;
            let mut g = spine.clone();
            // the state's own page under its own skeleton: nothing dies
            g.join(Fragment::wrap(&set.path, pg.clone()));
            // the page's elements as a load reads them (pruned by the skeleton), and after the join
            if let Some(x) = g.at_steps(p) {
                moved.add(x, -1);
            }
            let dp = d.spine(p, Some((r.0.as_ref(), r.1.as_ref())));
            let before = dead.as_ref().map(|_| Killed::before(&g, &dp));
            let ch = g.join(dp.clone());
            if let (Some(k), Some(w)) = (dead.as_deref_mut(), before) {
                k.note(&w, &g, &dp)?;
            }
            if let Some(x) = g.at_steps(p) {
                moved.add(x, 1);
            }
            if g.at_steps(p).is_some() {
                let k = keyed(&g, p);
                path = Some(match path {
                    Some(q) => q.into_iter().zip(k).map(|((s, key, a), (_, _, b))| (s, key, a.max(b))).collect(),
                    None => k,
                });
            }
            let empty = pg.emptied().ok_or(Error::Corrupt("state page"))?;
            let c = match g.at_steps(p).and_then(|x| x.slot(set.enc)) {
                Some(osis_crdt::SlotRef::Frag(c)) => c,
                _ => &empty,
            };
            let now = c.elem_dots(r.0.as_ref(), r.1.as_ref());
            kept |= !now.is_empty();
            if ch.is_changed() {
                let mut dots = pg.elem_dots(None, None);
                dots.extend(now);
                dots.sort();
                dots.dedup();
                set.loaded = BTreeMap::from([(key.clone(), r.clone())]);
                if !dots.is_empty() && !rewrite_set(txn, t, kt, set, c, &none, &dots, Shred::No)? {
                    // one element alone outgrew a page: written as it is, laid out again below
                    txn.table_put(t, &key, page_row(&r, &page(c, &none, &r)?)?, Shred::No)?;
                    relay = true;
                }
                set.loaded.clear();
            }
            changes.merge(ch);
        }
        // a collection whose position the join pruned (no page's join holds it; every set has
        // its first page) is no longer paged: laid out again, as a whole layout leaves no set
        // there (its emptied first page and stale path would stay otherwise)
        match path {
            Some(path) => set.path = path,
            None => relay = true,
        }
    }
    idx.unload();
    // a collection now under another encoding (a `Slots` leaf, or gone into a register's
    // embedding) is no longer paged there
    relay |= !idx.sets.iter().all(|(p, set)| j.at_steps(p).is_none_or(|x| x.encoding() == set.enc));
    let skeleton = j.reduced(&idx.paths);
    moved.add(&skeleton, 1);
    let unit = unit_state(&skeleton, idx)?;
    if relay || holds_large(&skeleton, unit.len())? || all && !kept && skeleton.is_empty() {
        let mut m = j;
        for set in idx.sets.values() {
            for pg in set_pages(txn, t, set)? {
                m.join(Fragment::wrap(&set.path, pg));
            }
        }
        return Ok(Reset::Laid { state: (!m.is_empty()).then_some(m), changes });
    }
    Ok(Reset::Paged { skeleton, unit, changes })
}

/// Tests: the writes the stored pages of the paged state `f` hold that their own skeleton
/// prunes (a page left unwritten by a join that changed it: the page's winners that do not win
/// joined under the skeleton's spine along its path). Loading prunes them again, so reads
/// never show them.
#[cfg(test)]
pub fn stale_in_pages(txn: &mut Transaction<'_>, tid: &Tid, ak: &Ak, idx: &StatePages, f: &Fragment) -> Result<usize> {
    let t = table(txn, tid, ak)?;
    let s0 = f.reduced(&idx.paths);
    let mut n = 0;
    for (p, set) in &idx.sets {
        let spine = s0.spine(p, None);
        for pg in set_pages(txn, t, set)? {
            let (mut g, p) = (spine.clone(), Fragment::wrap(&set.path, pg));
            let held = p.winners();
            g.join(p);
            n += held.minus(&g.winners()).len();
        }
    }
    Ok(n)
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
    use osis_base::Ts;
    use osis_crdt::{AnyView, DeltaBuilder, Op, PathOp, PathSeg, Source, Writer, create};
    use osis_store::{MemoryBackend, MemoryRoot, Store, StoreConfig};

    /// A session of the made-up node `n` (tid bytes all `n`).
    fn sess(n: u8) -> Source {
        Source::session(osis_crdt::Session { node: Tid::from_bytes([n; 15]), nonce: [0; osis_crdt::SESSION_NONCE_LEN] })
    }

    /// The value of `n` ints keyed 0..n.
    fn ints(n: i64, x: i64) -> Value {
        Value::Map((0..n).map(|i| (Value::Int(i), Value::Int(i * x))).collect())
    }

    // spec/commits.md §5 (every local index entry derived from it): the key
    // index rows of a removed key's entry go (shredded) when the bodies holding it are dropped;
    // the other keys' rows stay; rows are keyed hashes (another salt finds nothing).
    #[test]
    fn dropped_body_unindexed_spec_commits_5() {
        let mut rng = osis_crypto::SeededRng::from_u64(0);
        let mut store = Store::create(Box::new(MemoryBackend::new()), Box::new(MemoryRoot::new()), StoreConfig::default(), &mut rng).unwrap();
        let (tid, ak) = (Tid::from_bytes([5; 15]), osis_base::Ak::new("app:keys.0").unwrap());
        let node = sess(1);
        let mut w = Writer::new(Ts::from_u64(1 << 16).unwrap(), node.clone(), 1);
        let body = create(&mut w, &AnyView, &ints(6000, 1)).unwrap();
        let mut txn = store.transaction(&mut rng).unwrap();
        let (unit, idx) = write_full(&mut txn, &tid, &ak, Some(&body), false, &SALT).unwrap();
        assert!(idx.is_some());
        let rows = |txn: &mut Transaction<'_>| txn.table(&tid, &ak, KEY_TABLE).unwrap().map_or(0, |t| txn.table_range(t, &[], None, 10_000).unwrap().len());
        assert_eq!(rows(&mut txn), 6000);
        let (mut f, mut idx) = open(&unit, &SALT).unwrap();
        load_all(&mut txn, &tid, &ak, &mut idx, &mut f).unwrap();
        let mut b = DeltaBuilder::new(&f, Writer::new(Ts::from_u64(2 << 16).unwrap(), node, w.range().hi));
        b.apply(&PathOp { path: Vec::new(), op: Op::Remove(Value::Int(5)) }, &AnyView).unwrap();
        let (d, _) = b.finish().unwrap();
        f.join(d);
        let set = idx.sets.values().next().unwrap().clone();
        let k5 = key_row(&set, &Value::Int(5), None);
        assert_eq!(key_dots(&mut txn, &tid, &ak, &set, &Value::Int(5)).unwrap().len(), 1, "a superset until the state is rewritten whole");
        write_full(&mut txn, &tid, &ak, Some(&f), true, &SALT).unwrap();
        assert_eq!(rows(&mut txn), 5999);
        assert!(key_dots(&mut txn, &tid, &ak, &set, &Value::Int(5)).unwrap().is_empty());
        assert_eq!(key_dots(&mut txn, &tid, &ak, &set, &Value::Int(6)).unwrap().len(), 1);
        let other = PageSet { salt: [8; 32], ..set };
        assert!(key_dots(&mut txn, &tid, &ak, &other, &Value::Int(6)).unwrap().is_empty(), "keyed");
        assert_ne!(k5, key_row(&other, &Value::Int(5), None));
    }

    // spec/crdt.md §5.6 (Read: a key reads as the join of its live records): a paged map's join loads every
    // record of each key whose read it may move, so what it moves in the values as read (the
    // reference index's count) is what it moves over the whole state. Key 0 has a second record
    // (source 2), dot (3, 1) records under keys 1 and 250 (a forged copy), each key's first record
    // on an early page: key-erased removals of key 0's first record and of dot (3, 1).
    #[test]
    fn map_join_loads_its_reach_spec_crdt_5_6() {
        let mut rng = osis_crypto::SeededRng::from_u64(0);
        let mut store = Store::create(Box::new(MemoryBackend::new()), Box::new(MemoryRoot::new()), StoreConfig::default(), &mut rng).unwrap();
        let (tid, ak) = (Tid::from_bytes([7; 15]), osis_base::Ak::new("app:map.0").unwrap());
        let ts = |n: u64| Ts::from_u64(n << 16).unwrap();
        let mut w = Writer::new(ts(1), sess(1), 1);
        let base = create(&mut w, &AnyView, &ints(300, 1)).unwrap();
        let op = |base: &Fragment, src: u8, t: u64, lo: u64, path: Vec<PathSeg>, op: Op| {
            let mut b = DeltaBuilder::new(base, Writer::new(ts(t), sess(src), lo));
            b.apply(&PathOp { path, op }, &AnyView).unwrap();
            b.finish().unwrap().0
        };
        let put = |src: u8, k: i64| op(&base, src, 2, 1, vec![PathSeg::Key(Value::Int(k))], Op::Put(Value::Int(1000 + k)));
        // what the join moves in the values as read (`refs::Delta`): those of its reach after, less
        // those before
        let moved = |mut f: Fragment, d: &Fragment| {
            let mut n: BTreeMap<Value, i64> = BTreeMap::new();
            let pre = f.reach(d);
            pre.each_read_value(&mut |v| *n.entry(v.clone()).or_default() -= 1);
            f.join(d.clone());
            f.reach_after(d, &pre).each_read_value(&mut |v| *n.entry(v.clone()).or_default() += 1);
            n.retain(|_, c| *c != 0);
            n
        };
        let mut st = base.clone();
        for (src, k) in [(2, 0), (3, 1), (3, 250)] {
            st.join(put(src, k));
        }
        let mut txn = store.transaction(&mut rng).unwrap();
        let (unit, idx) = write_full(&mut txn, &tid, &ak, Some(&st), false, &SALT).unwrap();
        assert!(idx.is_some_and(|i| i.sets() == 1));
        let removals = [op(&base, 1, 3, w.range().hi, vec![], Op::Remove(Value::Int(0))), op(&put(3, 1), 4, 3, 1, vec![], Op::Remove(Value::Int(1)))];
        for d in removals {
            let (mut f, mut idx) = open(&unit, &SALT).unwrap();
            let touch = touch_of(&d, Some(&idx)).unwrap();
            assert!(ensure_touch(&mut txn, &tid, &ak, &mut idx, &mut f, &touch).unwrap());
            assert!(!idx.whole(), "loaded in part");
            assert_eq!(moved(f, &d), moved(st.clone(), &d));
        }
    }

    // spec/crdt.md §5.5 (add v; remove v), spec/data-model.md §6 (equality of a large value is equality of its keyed content hash), spec/commits.md §5 (every local index entry derived from it):
    // a paged set's value index finds a value's elements, a link by its hash alone; the rows of
    // a removed value go with the bodies holding it.
    #[test]
    fn set_value_index_spec_crdt_5_5() {
        let mut rng = osis_crypto::SeededRng::from_u64(0);
        let mut store = Store::create(Box::new(MemoryBackend::new()), Box::new(MemoryRoot::new()), StoreConfig::default(), &mut rng).unwrap();
        let (tid, ak) = (Tid::from_bytes([6; 15]), osis_base::Ak::new("app:set.0").unwrap());
        let node = sess(1);
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
        let mut b = DeltaBuilder::new(&f, Writer::new(Ts::from_u64(2 << 16).unwrap(), node.clone(), w.range().hi));
        b.apply(&op, &AnyView).unwrap();
        let (d, _) = b.finish().unwrap();
        let mut full = DeltaBuilder::new(&body, Writer::new(Ts::from_u64(2 << 16).unwrap(), node, w.range().hi));
        full.apply(&op, &AnyView).unwrap();
        assert_eq!(full.finish().unwrap().0, d);
        load_all(&mut txn, &tid, &ak, &mut idx, &mut f).unwrap();
        f.join(d);
        let set = idx.sets.values().next().unwrap().clone();
        write_full(&mut txn, &tid, &ak, Some(&f), true, &SALT).unwrap();
        assert_eq!(rows(&mut txn), 5999);
        assert!(key_dots(&mut txn, &tid, &ak, &set, &Value::Int(5)).unwrap().is_empty());
        assert_eq!(key_dots(&mut txn, &tid, &ak, &set, &Value::Int(6)).unwrap().len(), 1);
        // links: by content hash, whatever blob holds the value
        let link = |b: u8| Value::link(osis_base::Link { hash: [7; 32], blob: osis_base::BlobId([b; 32]), suite: 1, key: [b; 32], salt: [0; 16], del: osis_base::Del::NONE });
        assert_eq!(link(1), link(2));
        assert_eq!(key_row(&set, &link(1), None), key_row(&set, &link(2), None));
        assert_eq!(key_row(&set, &Value::List(vec![link(1)]), None), key_row(&set, &Value::List(vec![link(2)]), None));
        // a value with struct parts is matched as projected: not by the index
        let st = Value::Map(osis_base::ValueMap::from([(Value::Int(0), Value::Int(1))]));
        assert_eq!(op_paths(&[PathOp { path: Vec::new(), op: Op::Add(Value::List(vec![st.clone()])) }], &mut |v| Ok(v.clone())).unwrap(), None);
        assert_eq!(op_paths(&[PathOp { path: vec![PathSeg::Key(st.clone()), PathSeg::Key(Value::Int(1))], op: Op::Set(Value::Int(2)) }], &mut |v| Ok(v.clone())).unwrap(), None);
        assert_eq!(op_paths(&[PathOp { path: vec![PathSeg::Key(st)], op: Op::Put(Value::Int(2)) }], &mut |v| Ok(v.clone())).unwrap(), None);
    }

    // spec/crdt.md §5.5 (add v; remove v), spec/data-model.md §6 (equality of a large value is equality of its keyed content hash): ops by value over the pages a paged set's index finds write what they write
    // over the whole state, for floats, links (alone and nested), enums, empty values, with a
    // concurrent writer's elements joined in.
    #[test]
    fn set_index_differential_spec_crdt_5_5() {
        use osis_base::Float;
        let mut rng = osis_crypto::SeededRng::from_u64(0);
        let mut store = Store::create(Box::new(MemoryBackend::new()), Box::new(MemoryRoot::new()), StoreConfig::default(), &mut rng).unwrap();
        let (tid, ak) = (Tid::from_bytes([3; 15]), osis_base::Ak::new("app:s.0").unwrap());
        let nodes = [sess(1), sess(2)];
        let link = |h: u8, b: u8| Value::link(osis_base::Link { hash: [h; 32], blob: osis_base::BlobId([b; 32]), suite: 1, key: [b; 32], salt: [0; 16], del: osis_base::Del::NONE });
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
        let mut orng = osis_crypto::SeededRng::from_u64(0);
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
                let mut b = DeltaBuilder::new(&old, Writer::new(Ts::from_u64(ts).unwrap(), nodes[1].clone(), ctrs[1]));
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
            let mut b = DeltaBuilder::new(&f, Writer::new(Ts::from_u64(ts).unwrap(), nodes[0].clone(), ctrs[0]));
            let mut full = DeltaBuilder::new(&st, Writer::new(Ts::from_u64(ts).unwrap(), nodes[0].clone(), ctrs[0]));
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
    // spec: none (local store paging, for the Scale requirements: a change costs O(change) at any
    // depth, peer input never causes unbounded work); notes/local-store.md (Units): a state with large collections inside map
    // entries pages each of them. Random edits, each made in a fresh session that loads only the
    // pages the edit touches (or everything where it does not fit), written page by page: a
    // whole load from the store always gives the reference state back, and reads by key in a
    // fresh session load the pages of that key only and read what the whole state reads.
    #[test]
    fn lazy_nested_paging_spec_requirements_scale() {
        let mut rng = osis_crypto::SeededRng::from_u64(0);
        let mut store = Store::create(Box::new(MemoryBackend::new()), Box::new(MemoryRoot::new()), StoreConfig::default(), &mut rng).unwrap();
        let (tid, ak) = (Tid::from_bytes([3; 15]), osis_base::Ak::new("app:nested.0").unwrap());
        let node = sess(1);
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
        let mut orng = osis_crypto::SeededRng::from_u64(0);
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
            let mut b = DeltaBuilder::new(&f, Writer::new(Ts::from_u64(ts).unwrap(), node.clone(), ctr));
            let mut full = DeltaBuilder::new(&st, Writer::new(Ts::from_u64(ts).unwrap(), node.clone(), ctr));
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
            // a text not periodic (an edit's window repeated elsewhere matches whole)
            .map(|i| if text { Value::Str(char::from_u32(0x1F600 + (mix(i) % 64) as u32).unwrap().to_string()) } else { Value::Str(format!("item-{i:08}-padding-padding")) })
            .collect()
    }

    /// splitmix64's finalizer.
    fn mix(i: u64) -> u64 {
        let mut z = i.wrapping_add(0x9E37_79B9_7F4A_7C15);
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    fn seq_value(text: bool, n: u64) -> Value {
        let items = seq_items(text, 0, n);
        let seq = if text { Value::Str(items.iter().map(|v| if let Value::Str(x) = v { x.as_str() } else { "" }).collect()) } else { Value::List(items) };
        // padding: a large map, in pages of its own
        let pad = Value::Map((0..300).map(|i| (Value::Int(i), Value::Str("p".repeat(250)))).collect());
        Value::Map([(Value::Int(0), pad), (Value::Int(1), seq)].into_iter().collect())
    }

    /// The visible elements of the sequence (field 1) of `f` by a whole pass of a fresh copy.
    fn vis_whole(f: &Fragment) -> Vec<Dot> {
        let fresh = decode(&encode(&f.at(&[PathSeg::Field(1)]).unwrap()).unwrap()).unwrap();
        fresh.visible_range(0..usize::MAX).unwrap()
    }

    // spec/crdt.md §5.7 (index paths never go on the wire): ops by index, §6 (a deterministic function of state), §8: a paged
    // text or list keeps its placement in the store, exactly a whole pass of the state's: random
    // inserts, deletes and moves by two writers (one writing against an old state: concurrent,
    // joined as received), each in the running session or a fresh one, written page by page;
    // after each, the placement read from the store equals a whole pass over the state loaded
    // whole, and a read by index in a fresh session loads a few pages and reads what the whole
    // state reads.
    #[test]
    fn seq_placement_differential_text_spec_crdt_6() {
        seq_placement_run(true, 3_000);
    }

    // spec/crdt.md §5.7, §6, §8: as `seq_placement_differential_text_spec_crdt_6`, for a list.
    #[test]
    fn seq_placement_differential_list_spec_crdt_6() {
        seq_placement_run(false, 1_000);
    }

    // spec/crdt.md §4.2, §5.7 (`replace`: the old records go), §6, §8: as
    // `seq_placement_differential_text_spec_crdt_6` over a text replaced before the edits, with
    // long received inserts (strips of them leave value-less runs that span pages).
    #[test]
    fn seq_placement_differential_after_reset_spec_crdt_6() {
        seq_placement_run_with(true, 3_000, true);
    }

    fn seq_placement_run(text: bool, n: u64) {
        seq_placement_run_with(text, n, false)
    }

    fn seq_placement_run_with(text: bool, n: u64, reset: bool) {
        let mut rng = osis_crypto::SeededRng::from_u64(0);
        let mut store = Store::create(Box::new(MemoryBackend::new()), Box::new(MemoryRoot::new()), StoreConfig::default(), &mut rng).unwrap();
        let (tid, ak) = (Tid::from_bytes([7; 15]), osis_base::Ak::new("app:seq.0").unwrap());
        let nodes = [sess(1), sess(2)];
        let view = SeqView::Root(text);
        let field = || vec![PathSeg::Field(1)];
        let mut ts = 1u64 << 16;
        let mut w = Writer::new(Ts::from_u64(ts).unwrap(), nodes[0].clone(), 1);
        let mut st = create(&mut w, &view, &seq_value(text, n)).unwrap();
        let mut ctrs = [w.range().hi, 1];
        if reset {
            ts += 1 << 16;
            let items = seq_items(text, n, n);
            let v = if text { Value::Str(items.iter().map(|v| if let Value::Str(x) = v { x.as_str() } else { "" }).collect()) } else { Value::List(items) };
            let mut b = DeltaBuilder::new(&st, Writer::new(Ts::from_u64(ts).unwrap(), nodes[0].clone(), ctrs[0]));
            b.apply(&PathOp { path: field(), op: Op::Replace(v) }, &view).unwrap();
            let (d, range) = b.finish().unwrap();
            ctrs[0] = range.hi;
            st.join(d);
        }
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
        let mut orng = osis_crypto::SeededRng::from_u64(0);
        let mut r = |n: u64| osis_crypto::RngCore::next_u64(&mut orng) % n.max(1);
        let mut old = st.clone();
        // writer 1's deltas, for strips of their bodies: whether each is a long insert (a reset
        // run's: past a page), and its counters
        let mut received: Vec<(bool, osis_crdt::CounterRange)> = Vec::new();
        let mut long_strips = 0;
        let (mut in_place, mut kept, mut fresh_item, mut rebuilt, mut cold, mut kept_placement) = (0, 0, n, 0, 0, 0);
        let idx_of = |unit: &[u8]| open(unit, &SALT).unwrap().1;
        let mut kinds = [0usize; 3];
        for step in 0..36 {
            ts += 1 << 16;
            // the running session (its placement invalidated already, or not) or a fresh one
            let (mut f, mut idx) = match session.take() {
                Some(x) if r(2) == 0 => {
                    kept += 1;
                    x
                }
                _ => open(&unit, &SALT).unwrap(),
            };
            // every twelfth step a special kind in turn, the rest random: an invalidation (9),
            // a validity rebuild (11), a strip of a received body (8)
            let kind = if step % 12 == 11 { [9, 11, 8][(step / 12) as usize % 3] } else { r(12) };
            if kind >= 8 && !received.is_empty() || kind >= 10 {
                let k = match kind {
                    8 => 0,
                    9 | 10 => 1,
                    _ => 2,
                };
                kinds[k] += 1;
                match k {
                    // an expiry or purge of a received body: its writes held value-less, the
                    // whole state written again (a rebuild)
                    0 => {
                        // a reset run strips a long insert where one was received
                        let at = r(received.len() as u64) as usize;
                        let (long, range) = received.iter().rev().find(|x| reset && x.0).copied().unwrap_or(received[at]);
                        long_strips += usize::from(long);
                        let pred = move |d: &Dot| d.origin().src == sess(2) && (range.lo..range.hi).contains(&d.origin().ctr);
                        st.strip(&pred);
                        load_all(&mut txn, &tid, &ak, &mut idx, &mut f).unwrap();
                        f.strip(&pred);
                        let (u, i) = write_full(&mut txn, &tid, &ak, Some(&f), true, &SALT).unwrap();
                        unit = u;
                        idx = i.unwrap();
                    }
                    // a write the stored placement cannot follow (`write_touched`): invalidated,
                    // the writing transaction lays it out anew (`unplaced`)
                    1 => {
                        if let Some(set) = idx.sets.values_mut().find(|s| is_seq(s)) {
                            invalidate_placement(&mut txn, &tid, &ak, set, Shred::No).unwrap();
                        }
                        unit = unit_state(&f.reduced(&idx.paths), &idx).unwrap();
                    }
                    // a validity rebuild: the whole state written again
                    _ => {
                        load_all(&mut txn, &tid, &ak, &mut idx, &mut f).unwrap();
                        let (u, i) = write_full(&mut txn, &tid, &ak, Some(&f), true, &SALT).unwrap();
                        unit = u;
                        idx = i.unwrap();
                    }
                }
            } else {
                // writer 1 first, so a body to strip is received
                let wi = if received.is_empty() { 1 } else { r(3) as usize % 2 };
                let base = if wi == 1 { &old } else { &st };
                let len = base.at(&field()).and_then(|s| s.visible_range(0..usize::MAX)).map_or(0, |v| v.len()) as u64;
                let mut long = false;
                let op = match r(8) {
                    0..=2 => {
                        long = reset && wi == 1 && r(2) == 0;
                        let k = if long { 4000 } else { 1 + r(3) };
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
                let mut b = DeltaBuilder::new(base, Writer::new(Ts::from_u64(ts).unwrap(), nodes[wi].clone(), ctrs[wi]));
                let Some((delta, range)) = b.apply(&op, &view).ok().and_then(|_| b.finish()) else {
                    session = Some((f, idx));
                    continue;
                };
                // a local op by index in a session that has not loaded the sequence whole: run on
                // the pages loaded through the stored placement, it writes what it writes on the
                // whole state
                if wi == 0
                    && attach_ops(&mut txn, &tid, &ak, &mut idx, &mut f, std::slice::from_ref(&op), &[]).unwrap()
                {
                    let got = run_cold(&mut txn, &tid, &ak, &mut idx, &mut f, &op, &view, || Writer::new(Ts::from_u64(ts).unwrap(), nodes[0].clone(), ctrs[0]));
                    assert!(got == Some((delta.clone(), range)), "step {step}: {:?} on the pages loaded\n got {got:?}\n want {:?}", op.op, (&delta, range));
                    assert!(!idx.whole());
                    cold += 1;
                }
                ctrs[wi] = range.hi;
                if wi == 1 {
                    received.push((long, range));
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
            // every stored page holds whole records: none starts before its range or ends past it
            if let Some(set) = idx_of(&unit).sets.values().find(|s| is_seq(s)) {
                let t = table(&mut txn, &tid, &ak).unwrap();
                for (_, v) in txn.table_range(t, &set.prefix(), Some(&set.id.saturating_add(1).to_be_bytes()), 10_000).unwrap() {
                    let ((lo, hi), pf) = parse_page_row(&v).unwrap();
                    for (d, span) in pf.elem_spans() {
                        let last = Dot { src: d.src.clone(), ctr: d.ctr + span - 1 };
                        assert!(lo.as_ref().is_none_or(|l| *l <= d) && hi.as_ref().is_none_or(|h| last < *h), "step {step}: record {d:?}+{span} outside its page {lo:?}..{hi:?}");
                    }
                }
            }
            // pages hold what a snapshot carries (deleted chars dropped): compare those bytes
            if step % 6 == 5 {
                assert!(encode(&whole(&mut txn, &unit)).unwrap() == encode(&st).unwrap(), "step {step}");
            }
            // the stored placement, when present, is a whole pass's; when invalidated, it is laid
            // out anew from the whole sequence (in the one session, as the engine's transaction
            // end does)
            let want = vis_whole(&st);
            let read_all = |txn: &mut Transaction<'_>, unit: &[u8]| {
                let (mut f, mut idx) = open(unit, &SALT).unwrap();
                seq_range(txn, &tid, &ak, &mut idx, &mut f, &field(), 0..usize::MAX).unwrap()
            };
            if let Some(set) = idx_of(&unit).sets.values().find(|s| is_seq(s))
                && let Some(stored) = stored_place(&mut txn, &tid, &ak, set)
            {
                assert!(stored.order() == place_whole_pass(&st).order(), "step {step}: stored placement differs from a whole pass");
                kept_placement += 1;
            }
            let mut got = read_all(&mut txn, &unit);
            if let Ranged::Damaged = &got {
                let p = &[Step::Field(1)];
                rebuilt += 1;
                let (mut f, mut idx) = session.take().unwrap();
                ensure_path(&mut txn, &tid, &ak, &mut idx, &mut f, &field()).unwrap();
                rebuild_placement(&mut txn, &tid, &ak, &mut idx, &mut f, p).unwrap();
                session = Some((f, idx));
                got = read_all(&mut txn, &unit);
            }
            let Ranged::Read(p, dots, total) = got else { panic!("step {step}: no placement after a rebuild") };
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
        assert!(cold >= 4 && kept_placement >= 20, "{cold} edits through the stored placement, {kept_placement} writes kept it");
        assert!(kinds.iter().all(|k| *k >= 1), "strip, placement invalidated, validity rebuild: {kinds:?}");
        assert!(!reset || long_strips >= 1, "no long received insert stripped");
    }

    /// Whether the records of `d`'s sequence (field 1) fall on a node of a broken cycle (§6.2) in
    /// a whole pass of `st`'s.
    fn on_cycle(st: &Fragment, d: &Fragment) -> bool {
        let p = place_whole_pass(st);
        let top = p.top();
        let recs = d.at_steps(&[Step::Field(1)]).map(Fragment::elem_spans).unwrap_or_default();
        let overlaps = |r: &osis_crdt::PlaceRow| recs.iter().any(|(x, n)| x.src == r.dot.src && x.ctr < r.dot.ctr + r.span && r.dot.ctr < x.ctr + n);
        top.blocks.iter().flat_map(|b| p.rows(b.id).unwrap_or_default()).any(|r| top.cyc.contains(&r.dot) && overlaps(&r))
    }

    /// The placement of the sequence (field 1) of `f` by a whole pass of a fresh copy.
    fn place_whole_pass(f: &Fragment) -> SeqPlace {
        let fresh = decode(&encode(&f.at(&[PathSeg::Field(1)]).unwrap()).unwrap()).unwrap();
        fresh.seq_place().unwrap()
    }

    /// The stored placement of `set` read whole from the store, if present (its top not
    /// removed); its rows must fit.
    fn stored_place(txn: &mut Transaction<'_>, tid: &Tid, ak: &Ak, set: &PageSet) -> Option<SeqPlace> {
        let mut s = set.clone();
        s.place = Place::Unread;
        let mut p = held(txn, tid, ak, &mut s).unwrap()?;
        let pt = txn.table(tid, ak, PLACE_TABLE).unwrap()?;
        let (bs, cs) = p.stubs();
        assert!(fill_place(txn, pt, &s, &mut p, &bs, &cs).unwrap(), "stored rows fit their counts");
        assert!(p.complete());
        Some(p)
    }

    /// `run` on the pages loaded of a state prepared by `attach_ops`, loading what it misses and
    /// running again until it misses nothing (as `run_attached` does); `None` if the runs gave up
    /// (the engine then loads whole).
    fn run_ops<T>(txn: &mut Transaction<'_>, tid: &Tid, ak: &Ak, idx: &mut StatePages, f: &mut Fragment, run: impl Fn(&Fragment) -> T) -> Option<T> {
        let mut work = 0;
        loop {
            let got = run(f);
            match absorb(txn, tid, ak, idx, f, &mut work).unwrap() {
                Some(false) => return Some(got),
                Some(true) => {}
                None => return None,
            }
        }
    }

    /// Runs `op` on the pages loaded of a state prepared by `attach_ops`, loading what it misses
    /// until nothing is (as `commit_in` does).
    #[allow(clippy::too_many_arguments)]
    fn run_cold(txn: &mut Transaction<'_>, tid: &Tid, ak: &Ak, idx: &mut StatePages, f: &mut Fragment, op: &PathOp, view: &SeqView, w: impl Fn() -> Writer) -> Option<(Fragment, osis_crdt::CounterRange)> {
        let run = |f: &Fragment| {
            let mut b = DeltaBuilder::new(f, w());
            b.apply(op, view).ok().and_then(|_| b.finish())
        };
        run_ops(txn, tid, ak, idx, f, run).expect("gave up on the pages loaded")
    }

    /// A choice `seq_cold_edits` asks of its plan, at a step, among `n`.
    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    enum Pick {
        /// 0 (of 3): a received delta, made against an older state; else the writer's own.
        Writer,
        /// The op: 0, 1 insert; 2 insert at the start; 3 move; 4, 5 delete; 6 edit against the read
        /// (the step's first op), else insert.
        Kind,
        /// Where an op starts.
        At,
        /// An insert's items less one, a move's length less one, a delete's length less one.
        Len,
        /// 0: a long delete (up to 50), else a short one (up to 4).
        Long,
        /// An edit's deleted chars; its inserted ones.
        Cut,
    }

    // spec/crdt.md §5.7, §6, §8: ops by index into a paged text (inserts, deletes, moves, two in
    // one commit; edits against the read, as a text session writes) and received deltas from
    // another writer (concurrent: made against an older state), each in a new session, run on the
    // pages loaded through the stored placement and keeping it: after each, the stored placement
    // (rows, depths, waiting anchors) is a whole pass's, each loaded a few pages and blocks, and its
    // blocks split as they grow. 48 steps built on purpose: each kind of op at spread positions, a
    // received delta every third step, two ops every fourth.
    #[test]
    fn seq_cold_edits_keep_placement_spec_crdt_6_1() {
        // the kinds in turn, every op kind in each run of 12
        const KINDS: [u64; 12] = [0, 3, 4, 6, 2, 3, 6, 5, 1, 3, 6, 4];
        let mut ops = 0u64;
        let (received, moves, edits, relaid) = seq_cold_edits(0, 48, &mut |pick, step, n| {
            let x = match pick {
                Pick::Writer => u64::from(step % 3 != 1),
                Pick::Kind => {
                    ops += 1;
                    KINDS[(ops % 12) as usize]
                }
                // spread over the text, the start and the end included
                Pick::At => n * ((step * 5 + ops) % 9) / 8,
                Pick::Len | Pick::Cut => (step + ops) % n,
                Pick::Long => ops % 4,
            };
            x.min(n.saturating_sub(1))
        });
        assert!(received >= 16 && moves >= 15 && edits >= 12, "{received} received, {moves} moves, {edits} edits");
        assert_eq!(relaid, 0, "placements laid out anew");
    }

    // spec/crdt.md §5.7, §6, §8: a received delta moving a range and inserting far from both
    // ends, in a new session: its follow misses rows, dot-map chunks and records at three places
    // in the text, each dry run stopping at its first miss, so it takes many dry runs of little
    // work each; the join follows the stored placement and keeps it.
    #[test]
    fn seq_received_move_and_insert_keeps_placement_spec_crdt_6_1() {
        let mut rng = osis_crypto::SeededRng::from_u64(0);
        let mut store = Store::create(Box::new(MemoryBackend::new()), Box::new(MemoryRoot::new()), StoreConfig::default(), &mut rng).unwrap();
        let (tid, ak) = (Tid::from_bytes([9; 15]), osis_base::Ak::new("app:seq.0").unwrap());
        let view = SeqView::Root(true);
        let field = || vec![PathSeg::Field(1)];
        let mut w = Writer::new(Ts::from_u64(1 << 16).unwrap(), sess(1), 1);
        let mut st = create(&mut w, &view, &seq_value(true, 4_000)).unwrap();
        let mut txn = store.transaction(&mut rng).unwrap();
        let (unit, _) = write_full(&mut txn, &tid, &ak, Some(&st), false, &SALT).unwrap();
        let ops = [Op::Move { at: 2_000, len: 4, to: 100 }, Op::Insert { at: 3_500, items: seq_items(true, 0, 3) }];
        let mut b = DeltaBuilder::new(&st, Writer::new(Ts::from_u64(2 << 16).unwrap(), sess(2), 1));
        for op in ops {
            b.apply(&PathOp { path: field(), op }, &view).unwrap();
        }
        let (delta, _) = b.finish().unwrap();
        let (mut f, mut idx) = open(&unit, &SALT).unwrap();
        let t = touch_of(&delta, Some(&idx)).unwrap();
        assert!(ensure_touch(&mut txn, &tid, &ak, &mut idx, &mut f, &t).unwrap());
        f.join(delta.clone());
        st.join(delta);
        assert!(matches!(write_touched(&mut txn, &mut idx, &tid, &ak, &f, &t, Shred::No).unwrap(), Some(None)));
        let set = idx.sets.values().find(|s| is_seq(s)).unwrap();
        assert!(!set.whole && matches!(set.place, Place::Held(_)), "placement kept");
        let stored = stored_place(&mut txn, &tid, &ak, set).unwrap();
        assert!(stored.order() == place_whole_pass(&st).order());
    }

    // spec/crdt.md §5.7, §6, §8: an own commit of an insert and a move far apart, in a new session:
    // each run stops at its first miss, so it takes many runs of little work each (more than a
    // fixed count would allow); they go on until one misses nothing, and the commit writes what
    // it writes on the whole state, through the stored placement, which the join keeps.
    #[test]
    fn seq_ops_far_apart_run_until_done_spec_crdt_6_1() {
        let mut rng = osis_crypto::SeededRng::from_u64(0);
        let mut store = Store::create(Box::new(MemoryBackend::new()), Box::new(MemoryRoot::new()), StoreConfig::default(), &mut rng).unwrap();
        let (tid, ak) = (Tid::from_bytes([9; 15]), osis_base::Ak::new("app:seq.0").unwrap());
        let view = SeqView::Root(true);
        let field = || vec![PathSeg::Field(1)];
        let mut w = Writer::new(Ts::from_u64(1 << 16).unwrap(), sess(1), 1);
        let mut st = create(&mut w, &view, &seq_value(true, 4_000)).unwrap();
        let ctr = w.range().hi;
        let mut txn = store.transaction(&mut rng).unwrap();
        let (unit, _) = write_full(&mut txn, &tid, &ak, Some(&st), false, &SALT).unwrap();
        let ops: Vec<PathOp> = [Op::Insert { at: 3_114, items: seq_items(true, 0, 3) }, Op::Move { at: 1_167, len: 4, to: 3_603 }]
            .into_iter()
            .map(|op| PathOp { path: field(), op })
            .collect();
        let wr = || Writer::new(Ts::from_u64(2 << 16).unwrap(), sess(1), ctr);
        let runs = std::cell::Cell::new(0);
        let run = |f: &Fragment| {
            runs.set(runs.get() + 1);
            let mut b = DeltaBuilder::new(f, wr());
            ops.iter().try_for_each(|o| b.apply(o, &view).map(|_| ())).ok().and_then(|_| b.finish())
        };
        let want = run(&st).unwrap();
        runs.set(0);
        let (mut f, mut idx) = open(&unit, &SALT).unwrap();
        assert!(attach_ops(&mut txn, &tid, &ak, &mut idx, &mut f, &ops, &[]).unwrap());
        assert!(run_ops(&mut txn, &tid, &ak, &mut idx, &mut f, run).flatten().as_ref() == Some(&want), "same delta as on the whole state");
        assert!(runs.get() > 8, "{} runs", runs.get());
        let t = touch_of(&want.0, Some(&idx)).unwrap();
        assert!(ensure_touch(&mut txn, &tid, &ak, &mut idx, &mut f, &t).unwrap());
        f.join(want.0.clone());
        st.join(want.0);
        assert!(matches!(write_touched(&mut txn, &mut idx, &tid, &ak, &f, &t, Shred::No).unwrap(), Some(None)));
        let set = idx.sets.values().find(|s| is_seq(s)).unwrap();
        assert!(!set.whole && matches!(set.place, Place::Held(_)), "placement kept");
        assert!(stored_place(&mut txn, &tid, &ak, set).unwrap().order() == place_whole_pass(&st).order());
    }

    // spec/crdt.md §5.7, §6, §8: a stretch of a text split into rows of two chars (a char inserted
    // before every other one), then deleted in one commit, is one range record on the pages (the
    // chars dropped) over those rows; a received delta deleting every other pair cuts that record
    // only where a row already starts, many times: each cut costs the rows it looks at, not a
    // walk of the blocks, so the join follows the stored placement and keeps it.
    #[test]
    fn seq_cuts_where_rows_start_keep_placement_spec_crdt_6_1() {
        let mut rng = osis_crypto::SeededRng::from_u64(0);
        let mut store = Store::create(Box::new(MemoryBackend::new()), Box::new(MemoryRoot::new()), StoreConfig::default(), &mut rng).unwrap();
        let (tid, ak) = (Tid::from_bytes([9; 15]), osis_base::Ak::new("app:seq.0").unwrap());
        let view = SeqView::Root(true);
        let field = || vec![PathSeg::Field(1)];
        let mut w = Writer::new(Ts::from_u64(1 << 16).unwrap(), sess(1), 1);
        let mut st = create(&mut w, &view, &seq_value(true, 4_000)).unwrap();
        let commit = |st: &Fragment, ts: u64, node: u8, lo: u64, ops: Vec<Op>| {
            let mut b = DeltaBuilder::new(st, Writer::new(Ts::from_u64(ts << 16).unwrap(), sess(node), lo));
            for op in ops {
                b.apply(&PathOp { path: field(), op }, &view).unwrap();
            }
            b.finish().unwrap()
        };
        let base = st.clone();
        // a char before each even position 1000..1114 of the text as created
        let (ins, r) = commit(&st, 2, 1, w.range().hi, (0..58).map(|k| Op::Insert { at: 1_000 + 3 * k, items: seq_items(true, k as u64, 1) }).collect());
        st.join(ins);
        // the stretch and those chars deleted at once
        let (del, _) = commit(&st, 3, 1, r.hi, vec![Op::Delete { at: 1_000, len: 174 }]);
        st.join(del);
        let mut txn = store.transaction(&mut rng).unwrap();
        let (unit, _) = write_full(&mut txn, &tid, &ak, Some(&st), false, &SALT).unwrap();
        // concurrently, every other pair of the stretch: each record cuts at two row starts
        let (delta, _) = commit(&base, 4, 2, 1, (0..19).map(|j| Op::Delete { at: 1_000 + 2 * j, len: 2 }).collect());
        let (mut f, mut idx) = open(&unit, &SALT).unwrap();
        let t = touch_of(&delta, Some(&idx)).unwrap();
        assert!(ensure_touch(&mut txn, &tid, &ak, &mut idx, &mut f, &t).unwrap());
        f.join(delta.clone());
        st.join(delta);
        assert!(matches!(write_touched(&mut txn, &mut idx, &tid, &ak, &f, &t, Shred::No).unwrap(), Some(None)));
        let set = idx.sets.values().find(|s| is_seq(s)).unwrap();
        assert!(!set.whole && matches!(set.place, Place::Held(_)), "placement kept");
        assert!(stored_place(&mut txn, &tid, &ak, set).unwrap().order() == place_whole_pass(&st).order());
    }

    // spec/crdt.md §5.7, §6, §8: as above, the plan's choices random: `OSIS_SEQ_COLD_START`, `OSIS_SEQ_COLD_SEEDS` (2 at small
    // size), 160 steps a seed. Fails on some seeds: issues/seq-cold-edits-follow-gaps.md.
    #[test]
    #[ignore = "property"]
    fn seq_cold_edits_keep_placement_plain_spec_crdt_6_1() {
        use osis_base::testenv::{Seeds, large, reach_floor};
        let name = "engine::pages::tests::seq_cold_edits_keep_placement_plain_spec_crdt_6_1";
        let seeds = Seeds::from_env("OSIS_SEQ_COLD_START", "OSIS_SEQ_COLD_SEEDS", large(0..20));
        let replay = |s: u64| format!("OSIS_SEQ_COLD_START={s} OSIS_SEQ_COLD_SEEDS=1 cargo test -p osis-engine --lib -- --ignored --exact {name}");
        let tallies = seeds.run(name, replay, |seed| {
            let mut orng = osis_crypto::SeededRng::from_u64(seed);
            seq_cold_edits(seed, 160, &mut |_, _, n| osis_crypto::RngCore::next_u64(&mut orng) % n.max(1))
        });
        // per seed, well under the mean over seeds 0..20
        reach_floor("received deltas", tallies.iter().map(|t| t.0), 30, 1);
        reach_floor("moves", tallies.iter().map(|t| t.1), 20, 1);
        reach_floor("edits", tallies.iter().map(|t| t.2), 15, 1);
    }

    /// The edits of `seq_cold_edits_keep_placement`: `steps` steps, each choice `pick(choice,
    /// step, n)` (below `n`), on a store made with rng `seed`. The received deltas, moves and edits
    /// made, and the placements laid out anew (deltas writing on a broken cycle).
    fn seq_cold_edits(seed: u64, steps: u64, pick: &mut dyn FnMut(Pick, u64, u64) -> u64) -> (usize, usize, usize, usize) {
        let mut rng = osis_crypto::SeededRng::from_u64(seed);
        let mut store = Store::create(Box::new(MemoryBackend::new()), Box::new(MemoryRoot::new()), StoreConfig::default(), &mut rng).unwrap();
        let (tid, ak) = (Tid::from_bytes([9; 15]), osis_base::Ak::new("app:seq.0").unwrap());
        let nodes = [sess(1), sess(2)];
        let view = SeqView::Root(true);
        let field = || vec![PathSeg::Field(1)];
        let mut ts = 1u64 << 16;
        let mut w = Writer::new(Ts::from_u64(ts).unwrap(), nodes[0].clone(), 1);
        let mut st = create(&mut w, &view, &seq_value(true, 4_000)).unwrap();
        let mut ctrs = [w.range().hi, 1];
        let mut txn = store.transaction(&mut rng).unwrap();
        let (unit, _) = write_full(&mut txn, &tid, &ak, Some(&st), false, &SALT).unwrap();
        let (mut most, mut received, mut moves, mut blocks, mut edits, mut relaid) = (0, 0, 0, 0, 0, 0);
        let mut old = st.clone();
        for step in 0..steps {
            ts += 1 << 16;
            let mut r = |p: Pick, n: u64| pick(p, step, n.max(1));
            let wi = usize::from(r(Pick::Writer, 3) == 0);
            let base = if wi == 1 { &old } else { &st };
            let len = base.at(&field()).and_then(|s| s.visible_range(0..usize::MAX)).unwrap().len() as u64;
            let read = base.at(&field()).and_then(|s| s.read());
            let mut mk = |first: bool| match r(Pick::Kind, 7) {
                // what a text session writes: an edit against the read
                6 if first => {
                    let Some(Value::Str(x)) = read.clone() else { panic!() };
                    let mut c: Vec<char> = x.chars().collect();
                    let at = r(Pick::At, c.len() as u64 + 1) as usize;
                    let del = (r(Pick::Cut, 5) as usize).min(c.len() - at);
                    c.splice(at..at + del, "ed".chars().take(r(Pick::Cut, 3) as usize));
                    Op::Edit { base: Value::Str(x), new: Value::Str(c.into_iter().collect()) }
                }
                0 | 1 | 6 => Op::Insert { at: r(Pick::At, len + 1) as usize, items: seq_items(true, step, 1 + r(Pick::Len, 3)) },
                2 => Op::Insert { at: 0, items: seq_items(true, step, 1) },
                3 => {
                    let l = 1 + r(Pick::Len, 6);
                    Op::Move { at: r(Pick::At, len - l) as usize, len: l as usize, to: r(Pick::At, len - l + 1) as usize }
                }
                _ => {
                    let most = if r(Pick::Long, 8) == 0 { 50 } else { 4 };
                    Op::Delete { at: r(Pick::At, len) as usize, len: 1 + r(Pick::Len, most) as usize }
                }
            };
            let mut ops = vec![PathOp { path: field(), op: mk(true) }];
            if step % 4 == 3 {
                ops.push(PathOp { path: field(), op: mk(false) });
            }
            edits += ops.iter().filter(|o| matches!(o.op, Op::Edit { .. })).count();
            moves += ops.iter().filter(|o| matches!(o.op, Op::Move { .. })).count();
            let lo = ctrs[wi];
            let w = || Writer::new(Ts::from_u64(ts).unwrap(), nodes[wi].clone(), lo);
            let run = |f: &Fragment| {
                let mut b = DeltaBuilder::new(f, w());
                ops.iter().try_for_each(|o| b.apply(o, &view).map(|_| ())).ok().and_then(|_| b.finish())
            };
            let Some((delta, range)) = run(base) else { continue };
            ctrs[wi] = range.hi;
            let (mut f, mut idx) = open(&unit, &SALT).unwrap();
            if wi == 0 {
                assert!(attach_ops(&mut txn, &tid, &ak, &mut idx, &mut f, &ops, &[]).unwrap(), "step {step}: through the placement");
                let got = run_ops(&mut txn, &tid, &ak, &mut idx, &mut f, run).flatten();
                assert!(got == Some((delta.clone(), range)), "step {step}: same delta as on the whole state");
            } else {
                received += 1;
            }
            let t = touch_of(&delta, Some(&idx)).unwrap();
            assert!(ensure_touch(&mut txn, &tid, &ak, &mut idx, &mut f, &t).unwrap());
            f.join(delta.clone());
            // a delta writing on a node of a broken cycle, before or after it joins, may change
            // which edges are demoted (§6.2): its follow gives up and the placement is laid out anew
            let cyc = on_cycle(&st, &delta);
            st.join(delta.clone());
            let cyc = cyc || on_cycle(&st, &delta);
            assert!(matches!(write_touched(&mut txn, &mut idx, &tid, &ak, &f, &t, Shred::No).unwrap(), Some(None)), "step {step}: written in place");
            let set = idx.sets.values().find(|s| is_seq(s)).unwrap();
            assert!(!set.whole, "step {step}");
            match &set.place {
                Place::Held(p) => {
                    most = most.max(set.loaded.len());
                    // a move's follow looks for the end of the moved subtrees: in a text whose
                    // depths moves made uneven, at the rows of many blocks
                    if !ops.iter().any(|o| matches!(o.op, Op::Move { .. })) {
                        blocks = blocks.max(p.top().blocks.len() - p.stubs().0.len());
                    }
                }
                // laid out anew, as the transaction's end does
                _ => {
                    assert!(cyc, "step {step}: placement kept (writer {wi}: {:?})", ops.iter().map(|o| match &o.op { Op::Insert { at, items } => format!("insert {at} {}", items.len()), Op::Move { at, len, to } => format!("move {at} {len} {to}"), Op::Delete { at, len } => format!("delete {at} {len}"), _ => "edit".into() }).collect::<Vec<_>>());
                    relaid += 1;
                    rebuild_placement(&mut txn, &tid, &ak, &mut idx, &mut f, &[Step::Field(1)]).unwrap();
                }
            }
            let set = idx.sets.values().find(|s| is_seq(s)).unwrap();
            let stored = stored_place(&mut txn, &tid, &ak, set).unwrap_or_else(|| panic!("step {step}: placement kept"));
            assert!(stored.order() == place_whole_pass(&st).order(), "step {step}: stored placement differs from a whole pass");
            if wi == 0 && step % 3 == 0 {
                old = st.clone();
            }
        }
        assert!(most <= 8, "{most} pages loaded by one edit");
        // blocks split
        let (_, idx) = open(&unit, &SALT).unwrap();
        let set = idx.sets.values().find(|s| is_seq(s)).unwrap();
        let all = stored_place(&mut txn, &tid, &ak, set).unwrap().top().blocks.len();
        assert!(all > 8 && blocks * 4 <= all, "{blocks} of {all} blocks loaded by one edit (no move)");
        // an edit against a stale read (the text changed since) writes what it writes on the whole
        // state: on the pages where the read matches base near the change, else loaded whole
        let Some(Value::Str(x)) = old.at(&field()).and_then(|s| s.read()) else { panic!() };
        let stale = vec![PathOp { path: field(), op: Op::Edit { base: Value::Str(x.clone()), new: Value::Str(format!("{x}!")) } }];
        ts += 1 << 16;
        let w = || Writer::new(Ts::from_u64(ts).unwrap(), nodes[0].clone(), ctrs[0]);
        let run = |f: &Fragment| {
            let mut b = DeltaBuilder::new(f, w());
            stale.iter().try_for_each(|o| b.apply(o, &view).map(|_| ())).ok().and_then(|_| b.finish())
        };
        if Some(Value::Str(x.clone())) != st.at(&field()).and_then(|s| s.read()) {
            let (mut f, mut idx) = open(&unit, &SALT).unwrap();
            assert!(attach_ops(&mut txn, &tid, &ak, &mut idx, &mut f, &stale, &[]).unwrap());
            let got = run_ops(&mut txn, &tid, &ak, &mut idx, &mut f, run).unwrap_or_else(|| {
                load_all(&mut txn, &tid, &ak, &mut idx, &mut f).unwrap();
                run(&f)
            });
            assert!(got == run(&st), "stale edit on the whole state");
        }
        // and the whole read is the state's
        let whole = {
            let (mut f, mut idx) = open(&unit, &SALT).unwrap();
            load_all(&mut txn, &tid, &ak, &mut idx, &mut f).unwrap();
            f
        };
        assert_eq!(whole.read(), st.read());
        (received, moves, edits, relaid)
    }

    // spec/crdt.md §5.7 (list element edits; index paths never go on the wire), §6, §8: a path stepping into
    // a paged list's element by index, to read it (`ensure_path`, as `get_at`) or to write inside
    // it (`attach_ops`), each in a new session, loads the element's block and page through the
    // stored placement, not the list: what it reads and writes equals the whole state's, and the
    // placement is kept.
    #[test]
    fn seq_index_segment_on_pages_spec_crdt_5_7() {
        let mut rng = osis_crypto::SeededRng::from_u64(0);
        let mut store = Store::create(Box::new(MemoryBackend::new()), Box::new(MemoryRoot::new()), StoreConfig::default(), &mut rng).unwrap();
        let (tid, ak) = (Tid::from_bytes([9; 15]), osis_base::Ak::new("app:seq.0").unwrap());
        let node = sess(1);
        let view = SeqView::Root(false);
        let mut ts = 1u64 << 16;
        let mut w = Writer::new(Ts::from_u64(ts).unwrap(), node.clone(), 1);
        let mut st = create(&mut w, &view, &seq_value(false, 1_500)).unwrap();
        let mut ctr = w.range().hi;
        let mut txn = store.transaction(&mut rng).unwrap();
        let (unit, _) = write_full(&mut txn, &tid, &ak, Some(&st), false, &SALT).unwrap();
        let mut orng = osis_crypto::SeededRng::from_u64(0);
        let mut r = |n: u64| osis_crypto::RngCore::next_u64(&mut orng) % n.max(1);
        let (mut most, mut reads, mut writes) = (0, 0, 0);
        for step in 0..40u64 {
            ts += 1 << 16;
            let len = st.at(&[PathSeg::Field(1)]).and_then(|s| s.visible_range(0..usize::MAX)).unwrap().len() as u64;
            let path = vec![PathSeg::Field(1), PathSeg::Index(r(len + 2) as usize)];
            // a read inside an element (one past the end reads nothing)
            let (mut f, mut idx) = open(&unit, &SALT).unwrap();
            assert!(ensure_path(&mut txn, &tid, &ak, &mut idx, &mut f, &path).unwrap());
            assert_eq!(f.at(&path).and_then(|x| x.read()), st.at(&path).and_then(|x| x.read()), "step {step}: read");
            let set = idx.sets.values().find(|s| is_seq(s)).unwrap();
            assert!(!set.whole, "step {step}");
            most = most.max(set.loaded.len());
            reads += 1;
            // a write inside an element, or an insert or delete by index, in a new session
            let op = match r(3) {
                0 => Op::Insert { at: r(len + 1) as usize, items: seq_items(false, 10_000 + step, 1) },
                1 => Op::Delete { at: r(len) as usize, len: 1 },
                _ => Op::Set(Value::Str(format!("set-{step}"))),
            };
            let path = if matches!(op, Op::Set(_)) { vec![PathSeg::Field(1), PathSeg::Index(r(len) as usize)] } else { vec![PathSeg::Field(1)] };
            writes += usize::from(matches!(op, Op::Set(_)));
            let ops = vec![PathOp { path, op }];
            let lo = ctr;
            let w = || Writer::new(Ts::from_u64(ts).unwrap(), node.clone(), lo);
            let run = |f: &Fragment| {
                let mut b = DeltaBuilder::new(f, w());
                ops.iter().try_for_each(|o| b.apply(o, &view).map(|_| ())).ok().and_then(|_| b.finish())
            };
            let Some((delta, range)) = run(&st) else { continue };
            ctr = range.hi;
            let (mut f, mut idx) = open(&unit, &SALT).unwrap();
            assert!(attach_ops(&mut txn, &tid, &ak, &mut idx, &mut f, &ops, &[]).unwrap(), "step {step}: through the placement");
            let got = run_ops(&mut txn, &tid, &ak, &mut idx, &mut f, run).flatten();
            assert!(got == Some((delta.clone(), range)), "step {step}: same delta as on the whole state");
            let t = touch_of(&delta, Some(&idx)).unwrap();
            assert!(ensure_touch(&mut txn, &tid, &ak, &mut idx, &mut f, &t).unwrap());
            f.join(delta.clone());
            st.join(delta);
            assert!(matches!(write_touched(&mut txn, &mut idx, &tid, &ak, &f, &t, Shred::No).unwrap(), Some(None)), "step {step}: written in place");
            let set = idx.sets.values().find(|s| is_seq(s)).unwrap();
            most = most.max(set.loaded.len());
            let stored = stored_place(&mut txn, &tid, &ak, set).unwrap_or_else(|| panic!("step {step}: placement kept"));
            assert!(stored.order() == place_whole_pass(&st).order(), "step {step}: stored placement differs from a whole pass");
        }
        let (_, idx) = open(&unit, &SALT).unwrap();
        let pages = idx.sets.values().find(|s| is_seq(s)).map(|s| whole_pages(&mut txn, &tid, &ak, s)).unwrap();
        assert!(reads == 40 && writes >= 8 && most * 4 <= pages, "{writes} writes, {most} of {pages} pages loaded");
    }

    // spec/crdt.md §6.1, §6.2, §8: a paged text loaded whole keeps its stored placement through a
    // session's ops and joins (the sequence follows it in memory, what changed is written); a
    // hostile received delta (many single-element moves to HEAD) on one held in part costs about
    // one pass of follow work at most, then the placement is dropped (laid out anew on the next
    // read) or followed, and either way is never wrong.
    #[test]
    fn seq_whole_session_and_hostile_delta_spec_crdt_6_2() {
        let mut rng = osis_crypto::SeededRng::from_u64(0);
        let mut store = Store::create(Box::new(MemoryBackend::new()), Box::new(MemoryRoot::new()), StoreConfig::default(), &mut rng).unwrap();
        let (tid, ak) = (Tid::from_bytes([9; 15]), osis_base::Ak::new("app:seq.0").unwrap());
        let me = sess(1);
        let view = SeqView::Root(true);
        let field = || vec![PathSeg::Field(1)];
        let mut w = Writer::new(Ts::from_u64(1 << 16).unwrap(), me.clone(), 1);
        let mut st = create(&mut w, &view, &seq_value(true, 4_000)).unwrap();
        let mut ctr = w.range().hi;
        let mut txn = store.transaction(&mut rng).unwrap();
        let (unit, _) = write_full(&mut txn, &tid, &ak, Some(&st), false, &SALT).unwrap();
        let (mut f, mut idx) = open(&unit, &SALT).unwrap();
        load_all(&mut txn, &tid, &ak, &mut idx, &mut f).unwrap();
        // the stored placement, loaded whole, is the sequence's: what its writes follow
        let set = idx.sets.values().find(|s| is_seq(s)).unwrap();
        let Place::Held(p) = &set.place else { panic!("placement read") };
        assert!(!p.is_partial() && f.at(&field()).unwrap().seq_place_cached().unwrap().diff(p) == Some(Default::default()), "attached as stored");
        let mut orng = osis_crypto::SeededRng::from_u64(0);
        let mut r = |n: u64| osis_crypto::RngCore::next_u64(&mut orng) % n.max(1);
        for step in 0..30u64 {
            let ts = (2 + step) << 16;
            let len = st.at(&field()).and_then(|s| s.visible_range(0..usize::MAX)).unwrap().len() as u64;
            let op = match r(3) {
                0 => Op::Insert { at: r(len + 1) as usize, items: seq_items(true, step, 2) },
                1 => Op::Delete { at: r(len) as usize, len: 3 },
                _ => Op::Move { at: r(len - 4) as usize, len: 4, to: r(len - 3) as usize },
            };
            let mut b = DeltaBuilder::new(&f, Writer::new(Ts::from_u64(ts).unwrap(), me.clone(), ctr));
            b.apply(&PathOp { path: field(), op }, &view).unwrap();
            let (delta, range) = b.finish().unwrap();
            ctr = range.hi;
            let t = touch_of(&delta, Some(&idx)).unwrap();
            assert!(ensure_touch(&mut txn, &tid, &ak, &mut idx, &mut f, &t).unwrap());
            f.join(delta.clone());
            st.join(delta);
            assert!(write_touched(&mut txn, &mut idx, &tid, &ak, &f, &t, Shred::No).unwrap().is_some());
            let set = idx.sets.values().find(|s| is_seq(s)).unwrap();
            let stored = stored_place(&mut txn, &tid, &ak, set).unwrap_or_else(|| panic!("step {step}: kept"));
            assert!(stored.order() == place_whole_pass(&st).order(), "step {step}");
        }
        // hostile: 300 single-element moves to HEAD in one delta, received cold
        let len = st.at(&field()).and_then(|s| s.visible_range(0..usize::MAX)).unwrap().len();
        let mut b = DeltaBuilder::new(&st, Writer::new(Ts::from_u64(100 << 16).unwrap(), sess(2), 1));
        for k in 0..300 {
            b.apply(&PathOp { path: field(), op: Op::Move { at: (k * 13) % (len - 1) + 1, len: 1, to: 0 } }, &view).unwrap();
        }
        let (delta, _) = b.finish().unwrap();
        let (mut f, mut idx) = open(&unit, &SALT).unwrap();
        let t = touch_of(&delta, Some(&idx)).unwrap();
        assert!(ensure_touch(&mut txn, &tid, &ak, &mut idx, &mut f, &t).unwrap());
        f.join(delta.clone());
        st.join(delta);
        assert!(write_touched(&mut txn, &mut idx, &tid, &ak, &f, &t, Shred::No).unwrap().is_some());
        let set = idx.sets.values().find(|s| is_seq(s)).unwrap();
        if let Some(stored) = stored_place(&mut txn, &tid, &ak, set) {
            assert!(stored.order() == place_whole_pass(&st).order(), "hostile delta followed exactly");
        }
        let (mut f, mut idx) = open(&unit, &SALT).unwrap();
        load_all(&mut txn, &tid, &ak, &mut idx, &mut f).unwrap();
        assert_eq!(f.read(), st.read());
        // a join held in part whose pages do not fit is written whole (`set_state_touched`):
        // the placement written is the joined records', not the one stored before the join
        let mut b = DeltaBuilder::new(&st, Writer::new(Ts::from_u64(200 << 16).unwrap(), me.clone(), ctr));
        b.apply(&PathOp { path: field(), op: Op::Insert { at: 7, items: seq_items(true, 99, 3) } }, &view).unwrap();
        let (delta, _) = b.finish().unwrap();
        let (unit, _) = write_full(&mut txn, &tid, &ak, Some(&st), true, &SALT).unwrap();
        let (mut f, mut idx) = open(&unit, &SALT).unwrap();
        let t = touch_of(&delta, Some(&idx)).unwrap();
        assert!(ensure_touch(&mut txn, &tid, &ak, &mut idx, &mut f, &t).unwrap());
        f.join(delta.clone());
        st.join(delta);
        load_all(&mut txn, &tid, &ak, &mut idx, &mut f).unwrap();
        let (_, i) = write_full(&mut txn, &tid, &ak, Some(&f), true, &SALT).unwrap();
        let set = i.unwrap().sets.into_values().find(is_seq).unwrap();
        assert!(stored_place(&mut txn, &tid, &ak, &set).unwrap().order() == place_whole_pass(&st).order(), "written whole after the join");
    }

    /// The number of pages of `set` in the store.
    fn whole_pages(txn: &mut Transaction<'_>, tid: &Tid, ak: &Ak, set: &PageSet) -> usize {
        let t = table(txn, tid, ak).unwrap();
        txn.table_range(t, &set.prefix(), Some(&set.id.saturating_add(1).to_be_bytes()), 10_000).unwrap().len()
    }

    // spec/crdt.md §6 (a deterministic function of state); notes/local-store.md (Units): a
    // sequence's stored placement is rebuildable: a damaged or missing summary or block row reads as damaged, and laid out anew
    // from the whole sequence it reads by index again.
    #[test]
    fn seq_placement_rebuilt_spec_crdt_6() {
        let mut rng = osis_crypto::SeededRng::from_u64(0);
        let mut store = Store::create(Box::new(MemoryBackend::new()), Box::new(MemoryRoot::new()), StoreConfig::default(), &mut rng).unwrap();
        let (tid, ak) = (Tid::from_bytes([8; 15]), osis_base::Ak::new("app:seq.0").unwrap());
        let mut w = Writer::new(Ts::from_u64(1 << 16).unwrap(), sess(1), 1);
        let st = create(&mut w, &SeqView::Root(true), &seq_value(true, 6_000)).unwrap();
        let want = vis_whole(&st);
        let field = [PathSeg::Field(1)];
        let mut txn = store.transaction(&mut rng).unwrap();
        let (unit, _) = write_full(&mut txn, &tid, &ak, Some(&st), false, &SALT).unwrap();
        let read = |txn: &mut Transaction<'_>, unit: &[u8]| {
            let (mut f, mut idx) = open(unit, &SALT).unwrap();
            match seq_range(txn, &tid, &ak, &mut idx, &mut f, &field, 100..200).unwrap() {
                Ranged::Read(_, dots, _) => Some(dots),
                Ranged::Damaged => None,
                Ranged::Unpaged => panic!("paged"),
            }
        };
        assert_eq!(read(&mut txn, &unit).as_deref(), Some(&want[100..200]));
        // damaged rows: the summary, then a block row gone
        let pt = txn.table(&tid, &ak, PLACE_TABLE).unwrap().unwrap();
        let (mut f, mut idx) = open(&unit, &SALT).unwrap();
        let set = idx.sets.values().find(|s| is_seq(s)).unwrap().clone();
        let p = vec![Step::Field(1)];
        for damage in 0..2 {
            if damage == 0 {
                txn.table_put(pt, &place_key(&set, 0, 0), vec![0xff, 1], Shred::No).unwrap();
            } else {
                // the block holding element 150
                let top = stored_place(&mut txn, &tid, &ak, &set).unwrap().top();
                let mut seen = 0;
                let b = top.blocks.iter().find(|b| {
                    seen += b.shown;
                    seen > 150
                });
                txn.table_remove(pt, &place_key(&set, 1, b.unwrap().id as u64), Shred::No).unwrap();
            }
            assert_eq!(read(&mut txn, &unit), None, "damage {damage}");
            ensure_path(&mut txn, &tid, &ak, &mut idx, &mut f, &field).unwrap();
            rebuild_placement(&mut txn, &tid, &ak, &mut idx, &mut f, &p).unwrap();
            assert_eq!(read(&mut txn, &unit).as_deref(), Some(&want[100..200]), "damage {damage}");
        }
    }

    // spec/crdt.md §6 (a deterministic function of state); notes/local-store.md (Units): a
    // damaged stored block or dot-map chunk (garbage, truncated, another block's rows) never
    // panics or misplaces: a cold op writes what it writes on the whole state, a received join
    // keeps the state exact, and the next read by index reads the whole pass's order (laid out
    // anew if needed).
    #[test]
    fn seq_placement_damaged_rows_spec_crdt_6() {
        let mut rng = osis_crypto::SeededRng::from_u64(0);
        let mut store = Store::create(Box::new(MemoryBackend::new()), Box::new(MemoryRoot::new()), StoreConfig::default(), &mut rng).unwrap();
        let (tid, ak) = (Tid::from_bytes([7; 15]), osis_base::Ak::new("app:seq.0").unwrap());
        let me = sess(1);
        let view = SeqView::Root(true);
        let field = || vec![PathSeg::Field(1)];
        let mut w = Writer::new(Ts::from_u64(1 << 16).unwrap(), me.clone(), 1);
        let mut st = create(&mut w, &view, &seq_value(true, 6_000)).unwrap();
        let mut ctr = w.range().hi;
        let mut txn = store.transaction(&mut rng).unwrap();
        // every visible element by index through the stored placement, laid out anew if damaged
        let read_all = |txn: &mut Transaction<'_>, unit: &[u8]| {
            let (mut f, mut idx) = open(unit, &SALT).unwrap();
            match seq_range(txn, &tid, &ak, &mut idx, &mut f, &field(), 0..usize::MAX).unwrap() {
                Ranged::Read(_, dots, _) => dots,
                Ranged::Damaged => {
                    let p = vec![Step::Field(1)];
                    load_all(txn, &tid, &ak, &mut idx, &mut f).unwrap();
                    rebuild_placement(txn, &tid, &ak, &mut idx, &mut f, &p).unwrap();
                    let (mut f, mut idx) = open(unit, &SALT).unwrap();
                    let Ranged::Read(_, dots, _) = seq_range(txn, &tid, &ak, &mut idx, &mut f, &field(), 0..usize::MAX).unwrap() else { panic!("laid out anew") };
                    dots
                }
                Ranged::Unpaged => panic!("paged"),
            }
        };
        for damage in 0..4u64 {
            let (unit, idx) = write_full(&mut txn, &tid, &ak, Some(&st), true, &SALT).unwrap();
            let set = idx.unwrap().sets.into_values().find(is_seq).unwrap();
            let pt = txn.table(&tid, &ak, PLACE_TABLE).unwrap().unwrap();
            let top = stored_place(&mut txn, &tid, &ak, &set).unwrap().top();
            // the block holding element 150, and another with other counts
            let mut seen = 0;
            let b = top.blocks.iter().find(|b| {
                seen += b.shown;
                seen > 150
            });
            let b = b.unwrap().clone();
            let other = top.blocks.iter().find(|x| x.len != b.len || x.shown != b.shown || x.min != b.min).unwrap().id;
            let key = place_key(&set, 1, b.id as u64);
            let bytes = txn.table_get(pt, &key).unwrap().unwrap();
            match damage {
                0 => {
                    txn.table_put(pt, &key, vec![0xff, 1], Shred::No).unwrap();
                }
                1 => {
                    txn.table_put(pt, &key, bytes[..bytes.len() / 2].to_vec(), Shred::No).unwrap();
                }
                2 => {
                    let o = txn.table_get(pt, &place_key(&set, 1, other as u64)).unwrap().unwrap();
                    txn.table_put(pt, &key, o, Shred::No).unwrap();
                }
                3 => {
                    let c = chunk_key(&set, None);
                    let o = txn.table_get(pt, &c).unwrap().unwrap();
                    txn.table_put(pt, &c, o[..o.len() / 2].to_vec(), Shred::No).unwrap();
                }
                4.. => unreachable!(),
            }
            // a cold insert at element 150, then a received delete there
            let ops = [PathOp { path: field(), op: Op::Insert { at: 150, items: seq_items(true, damage, 2) } }];
            let lo = ctr;
            let wr = || Writer::new(Ts::from_u64((2 + damage) << 16).unwrap(), me.clone(), lo);
            let run = |f: &Fragment| {
                let mut b = DeltaBuilder::new(f, wr());
                ops.iter().try_for_each(|o| b.apply(o, &view).map(|_| ())).ok().and_then(|_| b.finish())
            };
            let want = run(&st).unwrap();
            ctr = want.1.hi;
            let (mut f, mut idx) = open(&unit, &SALT).unwrap();
            assert!(attach_ops(&mut txn, &tid, &ak, &mut idx, &mut f, &ops, &[]).unwrap());
            let got = run_ops(&mut txn, &tid, &ak, &mut idx, &mut f, run).unwrap_or_else(|| {
                load_all(&mut txn, &tid, &ak, &mut idx, &mut f).unwrap();
                run(&f)
            });
            assert!(got.as_ref() == Some(&want), "damage {damage}: same delta as on the whole state");
            let mut deltas = vec![want.0];
            let mut b = DeltaBuilder::new(&st, Writer::new(Ts::from_u64((2 + damage) << 16).unwrap(), sess(2), 1 + 10 * damage));
            b.apply(&PathOp { path: field(), op: Op::Delete { at: 140, len: 20 } }, &view).unwrap();
            deltas.push(b.finish().unwrap().0);
            for d in deltas {
                let t = touch_of(&d, Some(&idx)).unwrap();
                assert!(ensure_touch(&mut txn, &tid, &ak, &mut idx, &mut f, &t).unwrap());
                f.join(d.clone());
                st.join(d);
                if write_touched(&mut txn, &mut idx, &tid, &ak, &f, &t, Shred::No).unwrap().is_none() {
                    panic!("damage {damage}: written in place");
                }
            }
            assert_eq!(read_all(&mut txn, &unit), vis_whole(&st), "damage {damage}");
            let (mut g, mut i) = open(&unit, &SALT).unwrap();
            load_all(&mut txn, &tid, &ak, &mut i, &mut g).unwrap();
            assert_eq!(g.read(), st.read(), "damage {damage}");
        }
    }
}
