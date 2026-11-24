//! The reference index (notes/engine-refs.md): per (target, source thing, AK, kind) how many
//! times the source's held state on that aspect holds a reference of that kind to the target
//! (spec/data-model.md §8 Known references). Local and rebuildable (`write_all`), in two store
//! index tables, kept in the transaction that changes a state: a join counts the references at its
//! reach before and after (`Delta::reach`), a whole write (a rebuild: validity, expiry, purge,
//! destruction) the whole state against the stored rows (`resync`), a dropped aspect clears them.
//! An ephemeral aspect's rows are memory rows, as its state is. A row appearing or going is told
//! as `Event::References` once someone listens (`Engine::watch_references`).

pub(crate) mod kept;

use super::{Tx, records, scan_table};
use crate::error::{Error, Result};
use crate::events::Event;
use osis_base::{Ak, BlobId, CommitId, Link, RefKind, Tid, Value};
use osis_crdt::Fragment;
use osis_store::Shred;
use std::collections::BTreeMap;

/// Rows by target: target ‖ AK ‖ 0 ‖ source ‖ kind, empty: one aspect's rows naming a target
/// are one range.
pub(crate) const TO: &[u8] = b"node/refs to";
/// Rows by source: source ‖ AK length (u16) ‖ AK ‖ target ‖ kind, the count (u64).
pub(crate) const FROM: &[u8] = b"node/refs from";
/// The large values `(source, AK)` reads (spec/data-model.md §6), by content hash: source ‖ AK
/// length ‖ AK ‖ hash, a `LinkRow`. A large value's references count from its row, read once
/// when it is first read there (or when the blob it waited for came), never again.
pub(crate) const LINKS: &[u8] = b"node/refs links";
/// Large values whose references wait for a blob not held: blob ‖ source ‖ AK length ‖ AK ‖
/// hash, empty. Read again when the blob is stored (`fetched`).
pub(crate) const WAITS: &[u8] = b"node/refs waits";

/// Whether `ak` is indexed: every aspect with a state, and every durable signal by its held
/// valid fires (an ephemeral signal's fires are held by none).
pub fn indexed(ak: &Ak) -> bool {
    !(ak.signal() && ak.ephemeral())
}

/// What each held valid fire of signal `(tid, ak)` holds: each fire read (a rebuild's cost, as a
/// state aspect's rebuild reads its held bodies).
fn fires(tx: &mut Tx<'_>, tid: &Tid, ak: &Ak) -> Result<Vec<(CommitId, Delta)>> {
    let mut out = Vec::new();
    let held: Vec<CommitId> = tx.core.ix.by_aspect.get(&(*tid, ak.clone())).into_iter().flatten().map(|x| x.1).collect();
    for c in held {
        let Some(ai) = tx.core.ix.commits.get(&c).and_then(|m| m.aspect(tid, ak).filter(|ai| m.holds(*ai) && m.valid_at(*ai))) else { continue };
        let mut d = Delta::default();
        crate::apply::each_held_piece(tx, &c, ai, &mut |_, f| {
            d.add(&f, 1);
            Ok(())
        })?;
        out.push((c, d));
    }
    Ok(out)
}

/// Sets the rows of signal `(tid, ak)` to what its held valid fires hold (`apply::rebuild`: a
/// fire dropped, forgotten or judged again).
pub(crate) fn resync_fires(tx: &mut Tx<'_>, tid: &Tid, ak: &Ak) -> Result<()> {
    if !indexed(ak) {
        return Ok(());
    }
    let mut per = fires(tx, tid, ak)?;
    let mut want: BTreeMap<[u8; 32], (Link, i64)> = BTreeMap::new();
    for (_, f) in &per {
        for (h, (l, n)) in &f.1 {
            let e = want.entry(*h).or_insert((*l, 0));
            e.1 += n;
        }
    }
    let held = set_links(tx, tid, ak, &want)?;
    for (_, f) in &mut per {
        f.count_links(&held);
    }
    let old = stored(tx, tid, ak)?;
    let mut d = Delta::default();
    for (_, f) in &per {
        for (k, n) in &f.0 {
            *d.0.entry(*k).or_default() += n;
        }
    }
    d.sub(&old);
    note_rows(tx, tid, ak, d)
}

/// One row: `source` holds a `kind` reference to `target` `count` times in its values on `ak`.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Reference {
    pub target: Tid,
    pub source: Tid,
    pub ak: Ak,
    pub kind: RefKind,
    pub count: u64,
}

/// Count changes by target and kind, and of each large value read (by content hash, with a
/// link to it), whose references `note` counts from its row (`move_link`).
#[derive(Default, Debug, PartialEq, Eq)]
pub(crate) struct Delta(BTreeMap<(Tid, RefKind), i64>, BTreeMap<[u8; 32], (Link, i64)>);

impl Delta {
    /// Adds `sign` for every reference and large value in the values `f` reads as
    /// (`Fragment::each_read_value`).
    pub(crate) fn add(&mut self, f: &Fragment, sign: i64) {
        f.each_read_value(&mut |v| {
            drop(osis_base::costs::span("refs: value read"));
            v.each_reference_or_link(&mut |r| match r {
                Value::Link(l) => self.1.entry(l.hash).or_insert((**l, 0)).1 += sign,
                r => self.count(r, sign),
            });
        });
    }
    /// Adds `n` for reference `r`.
    fn count(&mut self, r: &Value, n: i64) {
        if let Some((k, t)) = RefKind::of(r) {
            *self.0.entry((t, k)).or_default() += n;
        }
    }
    /// Adds `n` for each of `refs`.
    fn count_all(&mut self, refs: &[Value], n: i64) {
        for r in refs {
            self.count(r, n);
        }
    }
    /// Counts each large value's references, `held` by content hash, as many times as it is read.
    fn count_links(&mut self, held: &BTreeMap<[u8; 32], Vec<Value>>) {
        for (h, (_, n)) in std::mem::take(&mut self.1) {
            self.count_all(held.get(&h).map(Vec::as_slice).unwrap_or_default(), n);
        }
    }
    /// The references at the reach of `delta` in `st` (`Fragment::reach`: all a join of it can
    /// change), taken off, and that reach: the state the join leaves adds its own at
    /// `Fragment::reach_after` of it (`Delta::after`).
    pub(crate) fn reach(st: &Fragment, delta: &Fragment) -> (Delta, Fragment) {
        let at = st.reach(delta);
        let mut d = Delta::default();
        d.add(&at, -1);
        (d, at)
    }
    /// `reach`'s count completed by the state `st` the join of `delta` left, `at` the reach before.
    pub(crate) fn after(&mut self, st: &Fragment, delta: &Fragment, at: &Fragment) {
        self.add(&st.reach_after(delta, at), 1);
    }
    /// What a whole `f` holds.
    pub(crate) fn of(f: Option<&Fragment>) -> Delta {
        let mut d = Delta::default();
        if let Some(f) = f {
            d.add(f, 1);
        }
        d
    }
    fn sub(&mut self, o: &BTreeMap<(Tid, RefKind), u64>) {
        for (t, n) in o {
            *self.0.entry(*t).or_default() -= *n as i64;
        }
    }
}

/// Calls `f` on every reference at any depth of `v` (`Value::each_reference_or_link`), with its
/// kind and the reference itself; not those inside a large value.
pub(crate) fn references(v: &Value, f: &mut dyn FnMut(RefKind, Tid, &Value)) {
    v.each_reference_or_link(&mut |r| {
        if let Some((k, t)) = RefKind::of(r) {
            f(k, t, r);
        }
    });
}

fn from_prefix(source: &Tid, ak: &Ak) -> Vec<u8> {
    records::aspect_key(&[], source, ak)
}

fn to_key(target: &Tid, source: &Tid, ak: &Ak, kind: RefKind) -> Vec<u8> {
    [to_prefix(target, Some(ak)).as_slice(), source.as_bytes(), &[kind.id()]].concat()
}

/// The `TO` keys of `target`'s rows, on `ak` alone where given: target ‖ AK ‖ 0 (no AK holds a
/// 0 byte, so one AK's rows are never another's).
fn to_prefix(target: &Tid, ak: Option<&Ak>) -> Vec<u8> {
    match ak {
        Some(ak) => [target.as_bytes().as_slice(), ak.as_str().as_bytes(), &[0]].concat(),
        None => target.as_bytes().to_vec(),
    }
}

/// A `TO` key's source, AK and kind, past the target.
fn parse_to(rest: &[u8]) -> Result<(Tid, Ak, RefKind)> {
    let bad = || Error::Corrupt("reference row");
    let z = rest.iter().position(|b| *b == 0).ok_or_else(bad)?;
    let (a, past) = (rest.get(..z).ok_or_else(bad)?, rest.get(z + 1..).ok_or_else(bad)?);
    let ak = std::str::from_utf8(a).ok().and_then(|a| Ak::new(a).ok()).ok_or_else(bad)?;
    let [s @ .., k] = past else { return Err(bad()) };
    let source = Tid::from_bytes(s.try_into().map_err(|_| bad())?);
    Ok((source, ak, RefKind::from_id(u64::from(*k)).ok_or_else(bad)?))
}

fn count_of(v: &[u8]) -> Result<u64> {
    Ok(u64::from_be_bytes(v.try_into().map_err(|_| Error::Corrupt("reference count"))?))
}

/// Applies the count changes `d` to the rows of `(source, ak)`.
pub(crate) fn note(tx: &mut Tx<'_>, source: &Tid, ak: &Ak, mut d: Delta) -> Result<()> {
    if !indexed(ak) {
        return Ok(());
    }
    for (_, (l, n)) in std::mem::take(&mut d.1).into_iter().filter(|x| x.1.1 != 0) {
        let (refs, earlier) = move_link(tx, source, ak, &l.hash, Some(&l), n, false)?;
        d.count_all(&refs, n + earlier as i64);
    }
    note_rows(tx, source, ak, d)
}

/// What a `LINKS` row holds: a link to the large value, how many times `(source, AK)`'s state
/// or held fires read it (`count`) and its held history counted by `kept` (`kept`), and its
/// references (`large::link_references`), or the blob they wait for.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct LinkRow {
    link: Link,
    count: u64,
    pub(super) kept: u64,
    pub(super) refs: std::result::Result<Vec<Value>, BlobId>,
}

impl LinkRow {
    fn encode(&self) -> Vec<u8> {
        let refs = match &self.refs {
            Ok(r) => Value::List(r.clone()),
            Err(b) => Value::Bytes(b.0.to_vec()),
        };
        osis_base::encode(&Value::List(vec![Value::link(self.link), Value::Int(self.count as i64), Value::Int(self.kept as i64), refs]))
    }
    fn decode(v: &[u8]) -> Result<LinkRow> {
        let bad = || Error::Corrupt("large value row");
        let lim = osis_base::Limits::new(osis_base::format::MAX_OBJECT_DEPTH, v.len());
        let Value::List(items) = osis_base::decode(v, &lim).map_err(|_| bad())? else { return Err(bad()) };
        let [Value::Link(link), Value::Int(n), Value::Int(kept), refs] = items.as_slice() else { return Err(bad()) };
        let refs = match refs {
            Value::List(r) => Ok(r.clone()),
            Value::Bytes(b) => Err(BlobId(b.as_slice().try_into().map_err(|_| bad())?)),
            _ => return Err(bad()),
        };
        Ok(LinkRow { link: **link, count: u64::try_from(*n).map_err(|_| bad())?, kept: u64::try_from(*kept).map_err(|_| bad())?, refs })
    }
}

fn link_key(source: &Tid, ak: &Ak, hash: &[u8; 32]) -> Vec<u8> {
    [from_prefix(source, ak).as_slice(), hash].concat()
}

fn wait_key(blob: &BlobId, lk: &[u8]) -> Vec<u8> {
    [blob.0.as_slice(), lk].concat()
}

/// Writes row `row` at `lk` (`None`: removes it), with the wait it names, `was` the wait before.
fn put_link(tx: &mut Tx<'_>, lk: &[u8], row: Option<&LinkRow>, was: Option<BlobId>) -> Result<()> {
    let (links, waits) = (tx.txn.index(LINKS)?, tx.txn.index(WAITS)?);
    let now = row.and_then(|r| r.refs.as_ref().err().copied());
    if was != now {
        if let Some(b) = was {
            tx.txn.table_remove(waits, &wait_key(&b, lk), Shred::Yes)?;
        }
        if let Some(b) = now {
            tx.txn.table_put(waits, &wait_key(&b, lk), Vec::new(), Shred::No)?;
        }
    }
    match row {
        Some(r) => drop(tx.txn.table_put(links, lk, r.encode(), Shred::No)?),
        None => drop(tx.txn.table_remove(links, lk, Shred::Yes)?),
    }
    Ok(())
}

/// Moves how many times `(source, ak)` reads the large value with content hash `h` (`l` a link
/// to it, needed for a first read) by `n`: its state's or held fires' reads, or, `kept`, its held
/// history's (`kept`). Its row made as it is first read (its references read then, or a wait
/// for the blob they lack; a row still waiting tries each link of that content given again),
/// gone with its last read of either. Returns the references it counts, and how many earlier
/// reads of the same side they count for first now; the other side's earlier reads are counted
/// here (`count_earlier`).
pub(super) fn move_link(tx: &mut Tx<'_>, source: &Tid, ak: &Ak, h: &[u8; 32], l: Option<&Link>, n: i64, kept: bool) -> Result<(Vec<Value>, u64)> {
    let moved = tx.in_class(ak.ephemeral(), |tx| {
        let lk = link_key(source, ak, h);
        let links = tx.txn.index(LINKS)?;
        let old = tx.txn.table_get(links, &lk)?.map(|v| LinkRow::decode(&v)).transpose()?;
        let was = old.as_ref().and_then(|r| r.refs.as_ref().err().copied());
        let mut row = match (old, l) {
            (Some(r), _) => r,
            (None, Some(l)) if n > 0 => LinkRow { link: *l, count: 0, kept: 0, refs: Err(l.blob) },
            // read nowhere: nothing counted
            _ => return Ok(None),
        };
        let mut earlier = None;
        if let Some(l) = l.filter(|l| n > 0 && row.refs.is_err() && (was.is_none() || row.link != **l)) {
            match crate::engine::large::link_references(tx, source, l)? {
                Ok(refs) => {
                    earlier = Some((row.count, row.kept));
                    (row.link, row.refs) = (*l, Ok(refs));
                }
                Err(b) if was.is_none() => row.refs = Err(b),
                Err(_) => {}
            }
        }
        let side = if kept { &mut row.kept } else { &mut row.count };
        *side = u64::try_from(*side as i64 + n).map_err(|_| Error::Corrupt("large value count below zero"))?;
        let refs = row.refs.clone().unwrap_or_default();
        put_link(tx, &lk, (row.count + row.kept > 0).then_some(&row), was)?;
        Ok(Some((refs, earlier)))
    })?;
    let Some((refs, earlier)) = moved else { return Ok((Vec::new(), 0)) };
    let Some((count, held)) = earlier else { return Ok((refs, 0)) };
    if kept {
        count_earlier(tx, source, ak, &refs, count, 0)?;
        Ok((refs, held))
    } else {
        count_earlier(tx, source, ak, &refs, 0, held)?;
        Ok((refs, count))
    }
}

/// A large value's row turned whole with references `refs`: they count for the reads made of it
/// before, `count` by the state or held fires, `kept` by held history.
fn count_earlier(tx: &mut Tx<'_>, source: &Tid, ak: &Ak, refs: &[Value], count: u64, kept: u64) -> Result<()> {
    if kept > 0 {
        kept::credit(tx, source, ak, refs, kept)?;
    }
    if count == 0 {
        return Ok(());
    }
    let mut d = Delta::default();
    d.count_all(refs, count as i64);
    note(tx, source, ak, d)
}

/// The `LINKS` rows of `(source, ak)` by content hash.
pub(super) fn stored_links(tx: &mut Tx<'_>, source: &Tid, ak: &Ak) -> Result<BTreeMap<[u8; 32], LinkRow>> {
    let links = tx.txn.index(LINKS)?;
    let pre = from_prefix(source, ak);
    let end = [pre.as_slice(), &[0xff; 33]].concat();
    let mut out = BTreeMap::new();
    scan_table(&mut tx.txn, links, &pre, Some(&end), |k, v| {
        let h = k.get(pre.len()..).and_then(|h| <[u8; 32]>::try_from(h).ok()).ok_or(Error::Corrupt("large value row"))?;
        out.insert(h, LinkRow::decode(&v)?);
        Ok(())
    })?;
    Ok(out)
}

/// Sets how many times `(source, ak)` reads each large value to `want` (by content hash);
/// the references each counts after.
fn set_links(tx: &mut Tx<'_>, source: &Tid, ak: &Ak, want: &BTreeMap<[u8; 32], (Link, i64)>) -> Result<BTreeMap<[u8; 32], Vec<Value>>> {
    let old = stored_links(tx, source, ak)?;
    for (h, r) in &old {
        if !want.contains_key(h) && r.count > 0 {
            move_link(tx, source, ak, h, None, -(r.count as i64), false)?;
        }
    }
    let mut out = BTreeMap::new();
    for (h, (l, n)) in want.iter().filter(|x| x.1.1 != 0) {
        let had = old.get(h).map_or(0, |r| r.count as i64);
        out.insert(*h, move_link(tx, source, ak, h, Some(l), n - had, false)?.0);
    }
    Ok(out)
}

/// Blobs `ids` were stored: each large value whose references waited for one is read again,
/// and once whole its references count for every read of it (spec/data-model.md §6: seen once
/// the node holds its chunks). A seek per blob stored.
pub(crate) fn fetched(tx: &mut Tx<'_>, ids: &[BlobId]) -> Result<()> {
    let waits = tx.txn.index(WAITS)?;
    let mut due = Vec::new();
    for id in ids {
        let end = [id.0.as_slice(), &[0xff; 16]].concat();
        scan_table(&mut tx.txn, waits, &id.0, Some(&end), |k, _| {
            due.push(k);
            Ok(())
        })?;
    }
    for k in due {
        let lk = k.get(32..).ok_or(Error::Corrupt("large value wait"))?.to_vec();
        let mut r = records::Rd::new(&lk);
        let (source, ak) = (r.tid()?, r.ak()?);
        tx.in_class(ak.ephemeral(), |tx| {
            let links = tx.txn.index(LINKS)?;
            let Some(mut row) = tx.txn.table_get(links, &lk)?.map(|v| LinkRow::decode(&v)).transpose()? else { return Ok(()) };
            let Err(was) = row.refs else { return Ok(()) };
            row.refs = crate::engine::large::link_references(tx, &source, &row.link)?;
            put_link(tx, &lk, Some(&row), Some(was))?;
            let Ok(refs) = &row.refs else { return Ok(()) };
            count_earlier(tx, &source, &ak, refs, row.count, row.kept)
        })?;
    }
    Ok(())
}

/// `note` of the rows by target and by source.
fn note_rows(tx: &mut Tx<'_>, source: &Tid, ak: &Ak, d: Delta) -> Result<()> {
    if d.0.values().all(|n| *n == 0) {
        return Ok(());
    }
    // the rows that appeared or went, for backlinks listeners
    let mut moved = Vec::new();
    tx.in_class(ak.ephemeral(), |tx| {
        let (to, from) = (tx.txn.index(TO)?, tx.txn.index(FROM)?);
        let pre = from_prefix(source, ak);
        for ((target, kind), n) in d.0.into_iter().filter(|x| x.1 != 0) {
            drop(osis_base::costs::span("refs: row written"));
            let fk = [pre.as_slice(), target.as_bytes(), &[kind.id()]].concat();
            let tk = to_key(&target, source, ak, kind);
            let old = tx.txn.table_get(from, &fk)?.map(|v| count_of(&v)).transpose()?.unwrap_or(0);
            let new = u64::try_from(old as i64 + n).map_err(|_| Error::Corrupt("reference count below zero"))?;
            if new == 0 {
                // the data it came from went: no local copy of the row stays
                tx.txn.table_remove(from, &fk, Shred::Yes)?;
                tx.txn.table_remove(to, &tk, Shred::Yes)?;
                moved.push((target, ak.clone()));
                // a need of the target went (a strong, or an account's `keys.0`): judged once the
                // pass ends (`retention::needed`)
                if kind == RefKind::Strong || ak.as_str() == "keys.0" {
                    tx.core.note_lost(target);
                }
                if kind == RefKind::Strong {
                    tx.core.ix.closure.note_row(*source, target);
                }
            } else {
                tx.txn.table_put(from, &fk, new.to_be_bytes().to_vec(), Shred::No)?;
                if old == 0 {
                    tx.txn.table_put(to, &tk, Vec::new(), Shred::No)?;
                    moved.push((target, ak.clone()));
                    // the node closure follows a strong appearing or going (`sync::units`)
                    if kind == RefKind::Strong {
                        tx.core.ix.closure.note_row(*source, target);
                    }
                }
            }
        }
        Ok(())
    })?;
    if tx.core.refs_watched && !moved.is_empty() {
        moved.dedup();
        tx.core.events.queue(Event::References(std::sync::Arc::new(moved)));
    }
    Ok(())
}

/// The stored counts of `(source, ak)` by target and kind.
pub(crate) fn stored(tx: &mut Tx<'_>, source: &Tid, ak: &Ak) -> Result<BTreeMap<(Tid, RefKind), u64>> {
    let from = tx.txn.index(FROM)?;
    let pre = from_prefix(source, ak);
    let end = [pre.as_slice(), &[0xff; 17]].concat();
    let mut out = BTreeMap::new();
    scan_table(&mut tx.txn, from, &pre, Some(&end), |k, v| {
        let bad = || Error::Corrupt("reference row");
        let (kind, t) = k.get(pre.len()..).and_then(|b| b.split_last()).ok_or_else(bad)?;
        let t = <[u8; osis_base::format::TID_LEN]>::try_from(t).map_err(|_| bad())?;
        out.insert((Tid::from_bytes(t), RefKind::from_id(u64::from(*kind)).ok_or_else(bad)?), count_of(&v)?);
        Ok(())
    })?;
    Ok(out)
}
/// Sets the rows of `(source, ak)` to what the whole state `f` holds (`None`: no state).
pub(crate) fn resync(tx: &mut Tx<'_>, source: &Tid, ak: &Ak, f: Option<&Fragment>) -> Result<()> {
    if !indexed(ak) {
        return Ok(());
    }
    let mut d = Delta::of(f);
    let held = set_links(tx, source, ak, &d.1)?;
    d.count_links(&held);
    let old = stored(tx, source, ak)?;
    d.sub(&old);
    note(tx, source, ak, d)
}

/// Removes every row of `(source, ak)` (its state is dropped).
pub(crate) fn clear(tx: &mut Tx<'_>, source: &Tid, ak: &Ak) -> Result<()> {
    resync(tx, source, ak, None)
}

/// The rows naming `target`.
pub(crate) fn to(tx: &mut Tx<'_>, target: &Tid) -> Result<Vec<Reference>> {
    let (to, from) = (tx.txn.index(TO)?, tx.txn.index(FROM)?);
    let pre = target.as_bytes().to_vec();
    let end = [pre.as_slice(), &[0xff; 16]].concat();
    let mut keys = Vec::new();
    scan_table(&mut tx.txn, to, &pre, Some(&end), |k, _| {
        keys.push(k);
        Ok(())
    })?;
    let mut out = Vec::new();
    for k in keys {
        let bad = || Error::Corrupt("reference row");
        let (source, ak, kind) = parse_to(k.get(pre.len()..).ok_or_else(bad)?)?;
        let fk = [from_prefix(&source, &ak).as_slice(), target.as_bytes(), &[kind.id()]].concat();
        let count = tx.txn.table_get(from, &fk)?.map(|v| count_of(&v)).transpose()?.ok_or_else(bad)?;
        out.push(Reference { target: *target, source, ak, kind, count });
    }
    Ok(out)
}

/// Up to `n` rows naming `target`, on `on` alone where given, after `after` (exclusive; `None`:
/// from the first), in (AK, source, kind) order: `n` rows read.
pub(crate) fn to_page(tx: &mut Tx<'_>, target: &Tid, on: Option<&Ak>, after: Option<(&Tid, &Ak, RefKind)>, n: usize) -> Result<Vec<(Tid, Ak, RefKind)>> {
    let to = tx.txn.index(TO)?;
    let pre = target.as_bytes().to_vec();
    let first = to_prefix(target, on);
    let start = match after {
        // the least key past it
        Some((s, ak, kind)) => [to_key(target, s, ak, kind).as_slice(), &[0]].concat().max(first.clone()),
        None => first.clone(),
    };
    // past every key of the prefix: an AK's rows end before its 0 turns 1, a target's before 0xff
    let end = match on {
        Some(ak) => [pre.as_slice(), ak.as_str().as_bytes(), &[1]].concat(),
        None => [pre.as_slice(), &[0xff; 16]].concat(),
    };
    let mut out = Vec::new();
    for (k, _) in tx.txn.table_range(to, &start, Some(&end), n)? {
        drop(osis_base::costs::span("refs: row read"));
        out.push(parse_to(k.get(pre.len()..).ok_or(Error::Corrupt("reference row"))?)?);
    }
    Ok(out)
}

/// Whether `source`'s value on `ak` references `target` by `kind`: one row probed.
pub(crate) fn has(tx: &mut Tx<'_>, target: &Tid, source: &Tid, ak: &Ak, kind: RefKind) -> Result<bool> {
    let to = tx.txn.index(TO)?;
    drop(osis_base::costs::span("refs: row read"));
    Ok(tx.txn.table_get(to, &to_key(target, source, ak, kind))?.is_some())
}

/// Whether `source` holds a strong to `target`, in any aspect: one probe per aspect holding a
/// reference to `target` (aspect names are static), never its other referrers.
pub(crate) fn strong_from(tx: &mut Tx<'_>, source: &Tid, target: &Tid) -> Result<bool> {
    let to = tx.txn.index(TO)?;
    let pre = target.as_bytes().to_vec();
    let end = [pre.as_slice(), &[0xff; 16]].concat();
    let mut start = pre.clone();
    loop {
        // the next aspect's first row
        let Some((k, _)) = tx.txn.table_range(to, &start, Some(&end), 1)?.into_iter().next() else { return Ok(false) };
        let (_, ak, _) = parse_to(k.get(pre.len()..).ok_or(Error::Corrupt("reference row"))?)?;
        if tx.txn.table_get(to, &to_key(target, source, &ak, RefKind::Strong))?.is_some() {
            return Ok(true);
        }
        start = [pre.as_slice(), ak.as_str().as_bytes(), &[1]].concat();
    }
}

/// The rows of `source`, every aspect.
pub(crate) fn from(tx: &mut Tx<'_>, source: &Tid) -> Result<Vec<Reference>> {
    let from = tx.txn.index(FROM)?;
    let pre = source.as_bytes().to_vec();
    let end = [pre.as_slice(), &[0xff; 16]].concat();
    let mut out = Vec::new();
    scan_table(&mut tx.txn, from, &pre, Some(&end), |k, v| {
        let mut r = records::Rd::new(&k);
        let (source, ak, target) = (r.tid()?, r.ak()?, r.tid()?);
        let kind = RefKind::from_id(u64::from(r.u8()?)).ok_or(Error::Corrupt("reference row"))?;
        r.end()?;
        out.push(Reference { target, source, ak, kind, count: count_of(&v)? });
        Ok(())
    })?;
    Ok(out)
}

/// Fills the index from every state (after `index::write_all` dropped it): each state read
/// once, the cache left as it was.
pub(crate) fn write_all(tx: &mut Tx<'_>) -> Result<()> {
    let mut aspects = Vec::new();
    tx.scan(records::ASPECTS, |k, _| {
        let mut r = records::Rd::new(k);
        aspects.push((r.tid()?, r.ak()?));
        Ok(())
    })?;
    // a signal has no aspect record: its held fires are found by the commits naming it
    let signals: Vec<(Tid, Ak)> = tx.core.ix.by_aspect.keys().filter(|(_, ak)| ak.signal() && indexed(ak)).cloned().collect();
    for (t, ak) in signals {
        resync_fires(tx, &t, &ak)?;
    }
    for (t, ak) in aspects.into_iter().filter(|(_, ak)| indexed(ak)) {
        let k = (t, ak.clone());
        let cached = tx.core.states.contains_key(&k);
        tx.load(&t, &ak)?;
        let f = tx.cached(&t, &ak).cloned();
        if cached {
            tx.evict_pages(&t, &ak);
        } else {
            tx.core.states.remove(&k);
            tx.core.pages.remove(&k);
        }
        resync(tx, &t, &ak, f.as_ref())?;
    }
    Ok(())
}

/// Debug: the rows of `(source, ak)` are what its whole state `f` holds.
#[cfg(debug_assertions)]
pub(crate) fn check(tx: &mut Tx<'_>, source: &Tid, ak: &Ak, f: Option<&Fragment>) -> Result<()> {
    if !indexed(ak) {
        return Ok(());
    }
    let mut all = Delta::of(f);
    check_links(tx, source, ak, &mut all)?;
    let want: BTreeMap<(Tid, RefKind), u64> = all.0.into_iter().filter(|x| x.1 != 0).map(|(t, n)| (t, n as u64)).collect();
    let got = stored(tx, source, ak)?;
    debug_assert_eq!(got, want, "reference rows of {source:?} {ak:?} differ from its state");
    Ok(())
}

/// Debug: the rows of signal `(tid, ak)` are what its held valid fires hold.
#[cfg(debug_assertions)]
pub(crate) fn check_fires(tx: &mut Tx<'_>, tid: &Tid, ak: &Ak) -> Result<()> {
    if !indexed(ak) {
        return Ok(());
    }
    let mut all = Delta::default();
    for (_, d) in fires(tx, tid, ak)? {
        for (k, n) in d.0 {
            *all.0.entry(k).or_default() += n;
        }
        for (h, (l, n)) in d.1 {
            all.1.entry(h).or_insert((l, 0)).1 += n;
        }
    }
    check_links(tx, tid, ak, &mut all)?;
    let want: BTreeMap<(Tid, RefKind), u64> = all.0.into_iter().filter(|x| x.1 != 0).map(|(t, n)| (t, n as u64)).collect();
    let got = stored(tx, tid, ak)?;
    debug_assert_eq!(got, want, "reference rows of signal {tid:?} {ak:?} differ from its held fires");
    Ok(())
}

/// Debug: the large-value rows of `(source, ak)` count the reads of `all` (which then counts
/// their references), each one's references what a read gives now, or a wait for a blob not held.
#[cfg(debug_assertions)]
fn check_links(tx: &mut Tx<'_>, source: &Tid, ak: &Ak, all: &mut Delta) -> Result<()> {
    let rows: BTreeMap<_, _> = stored_links(tx, source, ak)?.into_iter().filter(|x| x.1.count > 0).collect();
    let counts: BTreeMap<[u8; 32], u64> = all.1.iter().filter(|x| x.1.1 != 0).map(|(h, (_, n))| (*h, *n as u64)).collect();
    debug_assert_eq!(rows.iter().map(|(h, r)| (*h, r.count)).collect::<BTreeMap<_, _>>(), counts, "large-value rows of {source:?} {ak:?} differ from its reads");
    let waits = tx.txn.index(WAITS)?;
    let mut held = BTreeMap::new();
    for (h, r) in rows {
        let now = crate::engine::large::link_references(tx, source, &r.link)?;
        match &r.refs {
            Ok(refs) => debug_assert_eq!(now.as_ref().ok(), Some(refs), "large value of {source:?} {ak:?}: its references"),
            Err(b) => {
                debug_assert!(now.is_err(), "large value of {source:?} {ak:?}: whole, its references uncounted");
                debug_assert!(tx.txn.table_get(waits, &wait_key(b, &link_key(source, ak, &h)))?.is_some(), "large value of {source:?} {ak:?}: no wait");
            }
        }
        held.insert(h, r.refs.unwrap_or_default());
    }
    all.count_links(&held);
    Ok(())
}
