//! The reference index (issues/thing-lifetimes.md, Index and backlinks; notes/engine-refs.md): per
//! (target, source thing, AK) how many times the target's tid occurs in the held values of the
//! source's state on that aspect. Local and rebuildable (`write_all`), in two store index tables,
//! kept in the transaction that changes a state: a join counts the tids at its reach before and
//! after (`Delta::reach`), a whole write (a rebuild: validity, expiry, purge, ending) the whole
//! state against the stored rows (`resync`), a dropped aspect clears them. An ephemeral aspect's
//! rows are memory rows, as its state is. A row appearing or going is told as
//! `Event::References` once someone listens (`Engine::watch_references`). spec: none (local;
//! notes/engine-refs.md).

use super::{Tx, records, scan_table};
use crate::error::{Error, Result};
use crate::events::Event;
use osis_base::{Ak, Tid, Value};
use osis_crdt::Fragment;
use osis_store::Shred;
use std::collections::BTreeMap;

/// Rows by target: target ‖ source ‖ AK, empty.
pub(crate) const TO: &[u8] = b"node/refs to";
/// Rows by source: source ‖ AK length (u16) ‖ AK ‖ target, the count (u64).
pub(crate) const FROM: &[u8] = b"node/refs from";
/// The list of a thing's retainers: indexed like any aspect, its rows say who lists a target
/// (they are not references for lifetime).
pub const RETAINERS: &str = "retainers^.0";

/// Whether the values of `ak` are indexed: every aspect with a state but `created.0` and the
/// role-class aspects (they say who has authority over a thing, not what it points to).
pub fn indexed(ak: &Ak) -> bool {
    !ak.signal() && ak.as_str() != "created.0" && !osis_schema::core_types::is_role_class(ak.as_str())
}

/// One row: `source` holds `target`'s tid `count` times in its values on `ak`.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Reference {
    pub target: Tid,
    pub source: Tid,
    pub ak: Ak,
    pub count: u64,
}

impl Reference {
    /// Of the live ephemeral class (an ephemeral aspect), else live durable.
    pub fn ephemeral(&self) -> bool {
        self.ak.ephemeral()
    }
    /// A `retainers^.0` row: `source` lists `target` as a retainer (not a reference).
    pub fn lists(&self) -> bool {
        self.ak.as_str() == RETAINERS
    }
}

/// Count changes by target.
#[derive(Default, Debug, PartialEq, Eq)]
pub(crate) struct Delta(BTreeMap<Tid, i64>);

impl Delta {
    /// Adds `sign` for every tid in the values `f` holds (`Fragment::each_value`).
    pub(crate) fn add(&mut self, f: &Fragment, sign: i64) {
        f.each_value(&mut |v| {
            drop(crate::costs::span("refs: value read"));
            tids(v, &mut |t| *self.0.entry(t).or_default() += sign);
        });
    }
    /// The tids at the reach of `delta` in `st` (`Fragment::reach`: all a join of it can
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
    fn sub(&mut self, o: &BTreeMap<Tid, u64>) {
        for (t, n) in o {
            *self.0.entry(*t).or_default() -= *n as i64;
        }
    }
}

/// Calls `f` on every tid at any depth of `v`: map keys, set elements, unknown tags' content;
/// not inside a link (a chunked value) or a string.
fn tids(v: &Value, f: &mut dyn FnMut(Tid)) {
    match v {
        Value::Tid(t) => f(*t),
        Value::Enum(_, Some(p)) => tids(p, f),
        Value::Map(m) => m.iter().for_each(|(k, x)| {
            tids(k, f);
            tids(x, f);
        }),
        Value::List(x) => x.iter().for_each(|x| tids(x, f)),
        Value::Set(x) => x.iter().for_each(|x| tids(x, f)),
        Value::Unknown(u) => {
            if let Ok(x) = u.content().to_value() {
                tids(&x, f);
            }
        }
        _ => {}
    }
}

fn from_prefix(source: &Tid, ak: &Ak) -> Vec<u8> {
    records::aspect_key(&[], source, ak)
}

fn count_of(v: &[u8]) -> Result<u64> {
    Ok(u64::from_be_bytes(v.try_into().map_err(|_| Error::Corrupt("reference count"))?))
}

/// Applies the count changes `d` to the rows of `(source, ak)`.
pub(crate) fn note(tx: &mut Tx<'_>, source: &Tid, ak: &Ak, d: Delta) -> Result<()> {
    if !indexed(ak) {
        return Ok(());
    }
    // the thing whose list changed is judged (also a list set empty or removed, no row moving)
    if ak.as_str() == RETAINERS {
        crate::retention::lifetimes::queue(tx, source)?;
    }
    if d.0.values().all(|n| *n == 0) {
        return Ok(());
    }
    // the rows that appeared or went, for backlinks listeners
    let mut moved = Vec::new();
    tx.in_class(ak.ephemeral(), |tx| {
        let (to, from) = (tx.txn.index(TO)?, tx.txn.index(FROM)?);
        let pre = from_prefix(source, ak);
        for (target, n) in d.0.into_iter().filter(|x| x.1 != 0) {
            drop(crate::costs::span("refs: row written"));
            let fk = [pre.as_slice(), target.as_bytes()].concat();
            let tk = [target.as_bytes().as_slice(), source.as_bytes(), ak.as_str().as_bytes()].concat();
            let old = tx.txn.table_get(from, &fk)?.map(|v| count_of(&v)).transpose()?.unwrap_or(0);
            let new = u64::try_from(old as i64 + n).map_err(|_| Error::Corrupt("reference count below zero"))?;
            if new == 0 {
                // the data it came from went: no local copy of the row stays
                tx.txn.table_remove(from, &fk, Shred::Yes)?;
                tx.txn.table_remove(to, &tk, Shred::Yes)?;
                moved.push(target);
            } else {
                tx.txn.table_put(from, &fk, new.to_be_bytes().to_vec(), Shred::No)?;
                if old == 0 {
                    tx.txn.table_put(to, &tk, Vec::new(), Shred::No)?;
                    moved.push(target);
                }
            }
        }
        Ok(())
    })?;
    // a thing a durable reference to which appeared or went is judged
    if !ak.ephemeral() && ak.as_str() != RETAINERS {
        for t in &moved {
            crate::retention::lifetimes::queue(tx, t)?;
        }
    }
    // an ended thing whose evidence a list or reference kept: its keep is judged again
    if crate::retention::end::needs_from(ak) {
        for t in &moved {
            if tx.core.ended(t) {
                tx.core.ended_due.insert(*t);
            }
        }
    }
    if tx.core.refs_watched && !moved.is_empty() {
        tx.core.events.queue(Event::References(std::sync::Arc::new(moved)));
    }
    Ok(())
}

/// The stored counts of `(source, ak)` by target.
pub(crate) fn stored(tx: &mut Tx<'_>, source: &Tid, ak: &Ak) -> Result<BTreeMap<Tid, u64>> {
    let from = tx.txn.index(FROM)?;
    let pre = from_prefix(source, ak);
    let end = [pre.as_slice(), &[0xff; 16]].concat();
    let mut out = BTreeMap::new();
    scan_table(&mut tx.txn, from, &pre, Some(&end), |k, v| {
        let t = k.get(pre.len()..).and_then(|b| <[u8; osis_base::format::TID_LEN]>::try_from(b).ok()).ok_or(Error::Corrupt("reference row"))?;
        out.insert(Tid::from_bytes(t), count_of(&v)?);
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
        let rest = k.get(pre.len()..).ok_or_else(bad)?;
        let (s, a) = rest.split_at_checked(osis_base::format::TID_LEN).ok_or_else(bad)?;
        let source = Tid::from_bytes(s.try_into().map_err(|_| bad())?);
        let ak = std::str::from_utf8(a).ok().and_then(|a| Ak::new(a).ok()).ok_or_else(bad)?;
        let fk = [from_prefix(&source, &ak).as_slice(), target.as_bytes()].concat();
        let count = tx.txn.table_get(from, &fk)?.map(|v| count_of(&v)).transpose()?.ok_or_else(bad)?;
        out.push(Reference { target: *target, source, ak, count });
    }
    Ok(out)
}

/// The things whose `retainers^.0` lists `target` (its durable rows of that AK).
pub(crate) fn listers(tx: &mut Tx<'_>, target: &Tid) -> Result<Vec<Tid>> {
    let to = tx.txn.index(TO)?;
    let pre = target.as_bytes().to_vec();
    let end = [pre.as_slice(), &[0xff; 16]].concat();
    let mut out = Vec::new();
    scan_table(&mut tx.txn, to, &pre, Some(&end), |k, _| {
        let rest = k.get(pre.len()..).ok_or(Error::Corrupt("reference row"))?;
        let (s, a) = rest.split_at_checked(osis_base::format::TID_LEN).ok_or(Error::Corrupt("reference row"))?;
        if a == RETAINERS.as_bytes() {
            out.push(Tid::from_bytes(s.try_into().map_err(|_| Error::Corrupt("reference row"))?));
        }
        Ok(())
    })?;
    Ok(out)
}

/// Whether `source` references `target` for lifetime: a durable row other than `retainers^.0`
/// (issues/thing-lifetimes.md, What a reference is).
pub(crate) fn references(tx: &mut Tx<'_>, source: &Tid, target: &Tid) -> Result<bool> {
    let to = tx.txn.index(TO)?;
    let pre = [target.as_bytes().as_slice(), source.as_bytes()].concat();
    let end = [pre.as_slice(), &[0xff]].concat();
    let mut any = false;
    for (k, _) in tx.txn.table_range(to, &pre, Some(&end), usize::MAX)? {
        drop(crate::costs::span("refs: row read"));
        let a = k.get(pre.len()..).ok_or(Error::Corrupt("reference row"))?;
        let ak = std::str::from_utf8(a).ok().and_then(|a| Ak::new(a).ok()).ok_or(Error::Corrupt("reference row"))?;
        if !ak.ephemeral() && ak.as_str() != RETAINERS {
            any = true;
            break;
        }
    }
    Ok(any)
}

/// Whether `source`'s aspect `ak` references `target` in a live durable value (a durable row).
pub(crate) fn references_in(tx: &mut Tx<'_>, source: &Tid, ak: &Ak, target: &Tid) -> Result<bool> {
    if ak.ephemeral() || !indexed(ak) {
        return Ok(false);
    }
    let to = tx.txn.index(TO)?;
    let k = [target.as_bytes().as_slice(), source.as_bytes(), ak.as_str().as_bytes()].concat();
    Ok(tx.txn.table_get(to, &k)?.is_some())
}

/// Up to `n` rows naming `target` after `after` (a source and AK, exclusive; `None`: from the
/// first), in (source, AK) order: the sources and AKs, `n` rows read.
pub(crate) fn to_page(tx: &mut Tx<'_>, target: &Tid, after: Option<(&Tid, &Ak)>, n: usize) -> Result<Vec<(Tid, Ak)>> {
    let to = tx.txn.index(TO)?;
    let pre = target.as_bytes().to_vec();
    let start = match after {
        Some((s, ak)) => [pre.as_slice(), s.as_bytes(), ak.as_str().as_bytes(), &[0]].concat(),
        None => pre.clone(),
    };
    let end = [pre.as_slice(), &[0xff; 16]].concat();
    let mut out = Vec::new();
    for (k, _) in tx.txn.table_range(to, &start, Some(&end), n)? {
        drop(crate::costs::span("refs: row read"));
        let bad = || Error::Corrupt("reference row");
        let rest = k.get(pre.len()..).ok_or_else(bad)?;
        let (s, a) = rest.split_at_checked(osis_base::format::TID_LEN).ok_or_else(bad)?;
        let source = Tid::from_bytes(s.try_into().map_err(|_| bad())?);
        let ak = std::str::from_utf8(a).ok().and_then(|a| Ak::new(a).ok()).ok_or_else(bad)?;
        out.push((source, ak));
    }
    Ok(out)
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
        out.push(Reference { target, source, ak, count: count_of(&v)? });
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
    let want: BTreeMap<Tid, u64> = Delta::of(f).0.into_iter().filter(|x| x.1 != 0).map(|(t, n)| (t, n as u64)).collect();
    let got = stored(tx, source, ak)?;
    debug_assert_eq!(got, want, "reference rows of {source:?} {ak:?} differ from its state");
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use osis_base::{CanonicalBytes, Unknown};

    // issues/thing-lifetimes.md (What a reference is: found without a schema): a tid at any depth,
    // map keys, set elements, enum payloads and unknown tags' content included; not in a string
    #[test]
    fn tids_at_any_depth() {
        let (a, b) = (Tid::from_bytes([1; 15]), Tid::from_bytes([2; 15]));
        let unknown = Unknown::new(70_000, CanonicalBytes::from_value(&Value::List(vec![Value::Tid(b)]))).unwrap();
        let v = Value::List(vec![
            Value::Map([(Value::Tid(a), Value::Set([Value::Tid(b)].into_iter().collect()))].into_iter().collect()),
            Value::Enum(3, Some(Box::new(Value::Tid(a)))),
            Value::Unknown(Box::new(unknown)),
            Value::Str(a.to_uri()),
        ]);
        let mut got: BTreeMap<Tid, u32> = BTreeMap::new();
        tids(&v, &mut |t| *got.entry(t).or_default() += 1);
        assert_eq!(got, [(a, 2), (b, 2)].into());
    }
}
