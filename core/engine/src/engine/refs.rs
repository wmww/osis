//! The reference index (notes/engine-refs.md): per (target, source thing, AK, kind) how many
//! times the source's held state on that aspect holds a reference of that kind to the target
//! (spec/data-model.md §8 Known references). Local and rebuildable (`write_all`), in two store
//! index tables, kept in the transaction that changes a state: a join counts the references at its
//! reach before and after (`Delta::reach`), a whole write (a rebuild: validity, expiry, purge,
//! destruction) the whole state against the stored rows (`resync`), a dropped aspect clears them.
//! An ephemeral aspect's rows are memory rows, as its state is. A row appearing or going is told
//! as `Event::References` once someone listens (`Engine::watch_references`).

use super::{Tx, records, scan_table};
use crate::error::{Error, Result};
use crate::events::Event;
use osis_base::{Ak, CommitId, RefKind, Tid, Value};
use osis_crdt::Fragment;
use osis_store::Shred;
use std::collections::BTreeMap;

/// Rows by target: target ‖ source ‖ AK ‖ 0 ‖ kind, empty.
pub(crate) const TO: &[u8] = b"node/refs to";
/// Rows by source: source ‖ AK length (u16) ‖ AK ‖ target ‖ kind, the count (u64).
pub(crate) const FROM: &[u8] = b"node/refs from";

/// Whether `ak` is indexed: every aspect with a state, and every durable signal by its held
/// valid fires (an ephemeral signal's fires are held by none).
pub fn indexed(ak: &Ak) -> bool {
    !(ak.signal() && ak.ephemeral())
}

/// What the held valid fires of signal `(tid, ak)` hold: each fire read (a rebuild's cost, as a
/// state aspect's rebuild reads its held bodies).
fn fires(tx: &mut Tx<'_>, tid: &Tid, ak: &Ak) -> Result<Delta> {
    let mut d = Delta::default();
    let held: Vec<CommitId> = tx.core.ix.by_aspect.get(&(*tid, ak.clone())).into_iter().flatten().map(|x| x.1).collect();
    for c in held {
        let Some(ai) = tx.core.ix.commits.get(&c).and_then(|m| m.aspect(tid, ak).filter(|ai| m.holds(*ai) && m.valid_at(*ai))) else { continue };
        crate::apply::each_held_piece(tx, &c, ai, &mut |_, f| {
            d.add(&f, 1);
            Ok(())
        })?;
    }
    Ok(d)
}

/// Sets the rows of signal `(tid, ak)` to what its held valid fires hold (`apply::rebuild`: a
/// fire dropped, forgotten or judged again).
pub(crate) fn resync_fires(tx: &mut Tx<'_>, tid: &Tid, ak: &Ak) -> Result<()> {
    if !indexed(ak) {
        return Ok(());
    }
    let mut d = fires(tx, tid, ak)?;
    d.sub(&stored(tx, tid, ak)?);
    note(tx, tid, ak, d)
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

impl Reference {
    /// Of the live ephemeral class (an ephemeral aspect), else live durable.
    pub fn ephemeral(&self) -> bool {
        self.ak.ephemeral()
    }
}

/// Count changes by target and kind.
#[derive(Default, Debug, PartialEq, Eq)]
pub(crate) struct Delta(BTreeMap<(Tid, RefKind), i64>);

impl Delta {
    /// Adds `sign` for every reference in the values `f` holds (`Fragment::each_value`).
    pub(crate) fn add(&mut self, f: &Fragment, sign: i64) {
        f.each_value(&mut |v| {
            drop(osis_base::costs::span("refs: value read"));
            references(v, &mut |k, t| *self.0.entry((t, k)).or_default() += sign);
        });
    }
    /// The references at the reach of `delta` in `st` (`Fragment::reach`: all a join of it can
    /// change), counted `sign` times.
    pub(crate) fn reach(st: &Fragment, delta: &Fragment, sign: i64) -> Delta {
        let mut d = Delta::default();
        d.add(&st.reach(delta), sign);
        d
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

/// Calls `f` on every reference at any depth of `v`, with its kind: map keys, set elements, enum
/// payloads, unknown tags' content; not inside a ticket (its tids are no references), a link (a
/// chunked value) or a string.
pub(crate) fn references(v: &Value, f: &mut dyn FnMut(RefKind, Tid)) {
    match v {
        Value::Strong(_) | Value::Weak(_) | Value::Ticket(_) => {
            if let Some((k, t)) = RefKind::of(v) {
                f(k, t);
            }
        }
        Value::Enum(_, Some(p)) => references(p, f),
        Value::Map(m) => m.iter().for_each(|(k, x)| {
            references(k, f);
            references(x, f);
        }),
        Value::List(x) => x.iter().for_each(|x| references(x, f)),
        Value::Set(x) => x.iter().for_each(|x| references(x, f)),
        Value::Unknown(u) => {
            if let Ok(x) = u.content().to_value() {
                references(&x, f);
            }
        }
        _ => {}
    }
}

fn from_prefix(source: &Tid, ak: &Ak) -> Vec<u8> {
    records::aspect_key(&[], source, ak)
}

fn to_key(target: &Tid, source: &Tid, ak: &Ak, kind: RefKind) -> Vec<u8> {
    [target.as_bytes().as_slice(), source.as_bytes(), ak.as_str().as_bytes(), &[0, kind.id()]].concat()
}

/// A `TO` key's source, AK and kind, past the target.
fn parse_to(rest: &[u8]) -> Result<(Tid, Ak, RefKind)> {
    let bad = || Error::Corrupt("reference row");
    let (s, a) = rest.split_at_checked(osis_base::format::TID_LEN).ok_or_else(bad)?;
    let source = Tid::from_bytes(s.try_into().map_err(|_| bad())?);
    let [a @ .., 0, k] = a else { return Err(bad()) };
    let ak = std::str::from_utf8(a).ok().and_then(|a| Ak::new(a).ok()).ok_or_else(bad)?;
    Ok((source, ak, RefKind::from_id(u64::from(*k)).ok_or_else(bad)?))
}

fn count_of(v: &[u8]) -> Result<u64> {
    Ok(u64::from_be_bytes(v.try_into().map_err(|_| Error::Corrupt("reference count"))?))
}

/// Applies the count changes `d` to the rows of `(source, ak)`.
pub(crate) fn note(tx: &mut Tx<'_>, source: &Tid, ak: &Ak, d: Delta) -> Result<()> {
    if !indexed(ak) {
        return Ok(());
    }
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
                moved.push(target);
                if kind == RefKind::Strong {
                    tx.core.ix.closure.note_row(*source, target);
                }
            } else {
                tx.txn.table_put(from, &fk, new.to_be_bytes().to_vec(), Shred::No)?;
                if old == 0 {
                    tx.txn.table_put(to, &tk, Vec::new(), Shred::No)?;
                    moved.push(target);
                    // the node closure follows a strong appearing or going (`sync::units`), and
                    // a ticket appearing for what a strong reaches
                    match kind {
                        RefKind::Strong => tx.core.ix.closure.note_row(*source, target),
                        RefKind::Ticket => tx.core.ix.closure.note_ticket(target),
                        RefKind::Weak => {}
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
    d.sub(&stored(tx, source, ak)?);
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

/// Up to `n` rows naming `target` after `after` (exclusive; `None`: from the first), in (source,
/// AK, kind) order: `n` rows read.
pub(crate) fn to_page(tx: &mut Tx<'_>, target: &Tid, after: Option<(&Tid, &Ak, RefKind)>, n: usize) -> Result<Vec<(Tid, Ak, RefKind)>> {
    let to = tx.txn.index(TO)?;
    let pre = target.as_bytes().to_vec();
    let start = match after {
        // the least key past it
        Some((s, ak, kind)) => [to_key(target, s, ak, kind).as_slice(), &[0]].concat(),
        None => pre.clone(),
    };
    let end = [pre.as_slice(), &[0xff; 16]].concat();
    let mut out = Vec::new();
    for (k, _) in tx.txn.table_range(to, &start, Some(&end), n)? {
        drop(osis_base::costs::span("refs: row read"));
        out.push(parse_to(k.get(pre.len()..).ok_or(Error::Corrupt("reference row"))?)?);
    }
    Ok(out)
}

/// Whether `source` holds a strong to `target`, in any aspect: O(its rows naming it).
pub(crate) fn strong_from(tx: &mut Tx<'_>, source: &Tid, target: &Tid) -> Result<bool> {
    let to = tx.txn.index(TO)?;
    let pre = [target.as_bytes().as_slice(), source.as_bytes()].concat();
    let end = [pre.as_slice(), &[0xff]].concat();
    let mut found = false;
    scan_table(&mut tx.txn, to, &pre, Some(&end), |k, _| {
        found |= k.last() == Some(&RefKind::Strong.id());
        Ok(())
    })?;
    Ok(found)
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
    let want: BTreeMap<(Tid, RefKind), u64> = Delta::of(f).0.into_iter().filter(|x| x.1 != 0).map(|(t, n)| (t, n as u64)).collect();
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
    let want: BTreeMap<(Tid, RefKind), u64> = fires(tx, tid, ak)?.0.into_iter().filter(|x| x.1 != 0).map(|(t, n)| (t, n as u64)).collect();
    let got = stored(tx, tid, ak)?;
    debug_assert_eq!(got, want, "reference rows of signal {tid:?} {ak:?} differ from its held fires");
    Ok(())
}
