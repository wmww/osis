//! Strongs in history (spec/data-model.md §8 What counts; notes/engine-refs.md History holds):
//! on a thing whose newest held valid setting has `history_holds_targets`, each strong in a held
//! valid body of a counted aspect of it (`counted`) is an edge of the node closure and a need, as
//! a current value's strong, until the body goes (covered, expired, purged, invalid, forgotten,
//! released). Local and rebuildable, in three store index tables:
//! - `PARTS`: source ‖ AK ‖ 0 ‖ commit ‖ part (u32): the strongs that held body holds, by target
//!   with counts (`encode`); the source alone: its marker, its rows are kept.
//! - `FROM`: source ‖ target ‖ AK, the count over its parts (u64); `TO`: target ‖ source ‖ AK.
//!
//! Kept by `settle` (at each closure settle, `units::settle`) over the parts whose hold, validity
//! or body moved (`Core::kept_due`, noted where the meta or a leftover is written): O(those
//! bodies). A thing whose setting turns it on or off (`Core::kept_things_due`) has every body
//! read once, or its rows dropped.

use super::super::{Tx, scan_table};
use crate::engine::Core;
use crate::error::{Error, Result};
use osis_base::{Ak, CommitId, RefKind, Tid};
use osis_store::Shred;
use std::collections::BTreeMap;

pub(crate) const PARTS: &[u8] = b"node/refs kept parts";
pub(crate) const FROM: &[u8] = b"node/refs kept from";
pub(crate) const TO: &[u8] = b"node/refs kept to";

const TID: usize = osis_base::format::TID_LEN;

/// Whether held bodies of `ak` can hold their strongs' targets: a durable aspect the setting
/// governs (no fixed retention), not a signal (a held fire's references are the reference
/// index's, `refs::note`).
pub(crate) fn counted(ak: &Ak) -> bool {
    !ak.ephemeral() && !ak.signal() && osis_commit::retention::fixed_purge_by(ak.as_str()).is_none() && !osis_commit::retention::role_kept(ak.as_str())
}

/// Whether `tid`'s newest held valid setting says its history holds its strongs' targets.
pub(crate) fn holds_history(core: &Core, tid: &Tid) -> bool {
    core.ix.retention.get(tid).is_some_and(|s| !s.is_empty()) && crate::apply::validity::setting_now(core, tid).is_some_and(|s| s.history_holds_targets)
}

fn part_key(source: &Tid, ak: &Ak, c: &CommitId, ai: usize) -> Vec<u8> {
    [source.as_bytes().as_slice(), ak.as_str().as_bytes(), &[0], &c.0, &(ai as u32).to_be_bytes()].concat()
}

fn encode(m: &BTreeMap<Tid, u64>) -> Vec<u8> {
    m.iter().flat_map(|(t, n)| [t.as_bytes().as_slice(), &n.to_be_bytes()].concat()).collect()
}

fn decode(v: &[u8]) -> Result<BTreeMap<Tid, u64>> {
    let bad = || Error::Corrupt("kept strongs row");
    if !v.len().is_multiple_of(TID + 8) {
        return Err(bad());
    }
    v.chunks(TID + 8).map(|c| {
        let (t, n) = c.split_at(TID);
        Ok((Tid::from_bytes(t.try_into().map_err(|_| bad())?), u64::from_be_bytes(n.try_into().map_err(|_| bad())?)))
    }).collect()
}

/// The strongs held body `ai` of `c` holds while held and valid, by target.
fn held_strongs(tx: &mut Tx<'_>, source: &Tid, ak: &Ak, c: &CommitId, ai: usize) -> Result<BTreeMap<Tid, u64>> {
    let mut out = BTreeMap::new();
    let Some(m) = tx.core.ix.commits.get(c) else { return Ok(out) };
    if !m.holds(ai) || !m.valid_at(ai) || m.view.aspects.get(ai).is_none_or(|a| a.tid != *source || a.ak != *ak) {
        return Ok(out);
    }
    crate::apply::each_held_piece(tx, c, ai, &mut |_, f| {
        f.each_value(&mut |v| {
            super::references(v, &mut |k, t, _| {
                if k == RefKind::Strong {
                    *out.entry(t).or_default() += 1;
                }
            })
        });
        Ok(())
    })?;
    Ok(out)
}

/// Whether `source`'s rows are kept (its marker).
fn marked(tx: &mut Tx<'_>, source: &Tid) -> Result<bool> {
    let p = tx.txn.index(PARTS)?;
    Ok(tx.txn.table_get(p, source.as_bytes())?.is_some())
}

/// Adds `n` (signed) to the count of `source`'s strongs to `target` on `ak`, telling the node
/// closure of a row appearing or going and noting a lost need.
fn bump(tx: &mut Tx<'_>, source: &Tid, target: &Tid, ak: &Ak, n: i64) -> Result<()> {
    if n == 0 {
        return Ok(());
    }
    let (from, to) = (tx.txn.index(FROM)?, tx.txn.index(TO)?);
    let fk = [source.as_bytes().as_slice(), target.as_bytes(), ak.as_str().as_bytes()].concat();
    let tk = [target.as_bytes().as_slice(), source.as_bytes(), ak.as_str().as_bytes()].concat();
    let old = tx.txn.table_get(from, &fk)?.map(|v| v.try_into().map(u64::from_be_bytes).map_err(|_| Error::Corrupt("kept strongs count"))).transpose()?.unwrap_or(0);
    let new = u64::try_from(old as i64 + n).map_err(|_| Error::Corrupt("kept strongs count below zero"))?;
    if new == 0 {
        tx.txn.table_remove(from, &fk, Shred::Yes)?;
        tx.txn.table_remove(to, &tk, Shred::Yes)?;
        tx.core.note_lost(*target);
        tx.core.ix.closure.note_row(*source, *target);
    } else {
        tx.txn.table_put(from, &fk, new.to_be_bytes().to_vec(), Shred::No)?;
        if old == 0 {
            tx.txn.table_put(to, &tk, Vec::new(), Shred::No)?;
            tx.core.ix.closure.note_row(*source, *target);
        }
    }
    Ok(())
}

/// Brings the rows of every due part and thing to what is held (module doc).
pub(crate) fn settle(tx: &mut Tx<'_>) -> Result<()> {
    for t in std::mem::take(&mut tx.core.kept_things_due) {
        let (now, was) = (holds_history(tx.core, &t), marked(tx, &t)?);
        if now == was {
            continue;
        }
        let p = tx.txn.index(PARTS)?;
        if now {
            tx.txn.table_put(p, t.as_bytes(), Vec::new(), Shred::No)?;
            let on: Vec<(Ak, CommitId)> = tx.core.aspects_of(&t).filter(|((_, a), _)| counted(a)).flat_map(|((_, a), s)| s.iter().map(move |x| (a.clone(), x.1))).collect();
            for (ak, c) in on {
                if let Some(ai) = tx.core.ix.commits.get(&c).and_then(|m| m.aspect(&t, &ak)) {
                    tx.core.kept_due.insert((t, ak, c, ai));
                }
            }
            continue;
        }
        // off: every row of it goes
        tx.txn.table_remove(p, t.as_bytes(), Shred::Yes)?;
        let end = [t.as_bytes().as_slice(), &[0xff; 16]].concat();
        let mut keys = Vec::new();
        scan_table(&mut tx.txn, p, t.as_bytes(), Some(&end), |k, _| {
            keys.push(k);
            Ok(())
        })?;
        for k in keys {
            tx.txn.table_remove(p, &k, Shred::Yes)?;
        }
        let from = tx.txn.index(FROM)?;
        let mut rows = Vec::new();
        scan_table(&mut tx.txn, from, t.as_bytes(), Some(&end), |k, v| {
            rows.push((k, v));
            Ok(())
        })?;
        for (k, v) in rows {
            let (target, ak) = parse(&k)?;
            let n = u64::from_be_bytes(v.try_into().map_err(|_| Error::Corrupt("kept strongs count"))?);
            bump(tx, &t, &target, &ak, -(n as i64))?;
        }
    }
    let due = std::mem::take(&mut tx.core.kept_due);
    let mut on: BTreeMap<Tid, bool> = BTreeMap::new();
    for (t, ak, c, ai) in due {
        let marked = match on.get(&t) {
            Some(x) => *x,
            None => {
                let x = marked(tx, &t)?;
                on.insert(t, x);
                x
            }
        };
        if !marked {
            continue;
        }
        let want = held_strongs(tx, &t, &ak, &c, ai)?;
        let p = tx.txn.index(PARTS)?;
        let key = part_key(&t, &ak, &c, ai);
        let have = tx.txn.table_get(p, &key)?.map(|v| decode(&v)).transpose()?.unwrap_or_default();
        if want == have {
            continue;
        }
        if want.is_empty() {
            tx.txn.table_remove(p, &key, Shred::Yes)?;
        } else {
            tx.txn.table_put(p, &key, encode(&want), Shred::No)?;
        }
        let mut d: BTreeMap<Tid, i64> = want.iter().map(|(t, n)| (*t, *n as i64)).collect();
        for (x, n) in &have {
            *d.entry(*x).or_default() -= *n as i64;
        }
        for (target, n) in d {
            bump(tx, &t, &target, &ak, n)?;
        }
    }
    Ok(())
}

/// A `FROM` (or `TO`) key's second tid and AK.
fn parse(k: &[u8]) -> Result<(Tid, Ak)> {
    let bad = || Error::Corrupt("kept strongs row");
    let t = k.get(TID..2 * TID).ok_or_else(bad)?;
    let a = k.get(2 * TID..).ok_or_else(bad)?;
    let ak = std::str::from_utf8(a).ok().and_then(|a| Ak::new(a).ok()).ok_or_else(bad)?;
    Ok((Tid::from_bytes(t.try_into().map_err(|_| bad())?), ak))
}

/// The targets of `source`'s strongs in its held history, with the AK holding each.
pub(crate) fn from(tx: &mut Tx<'_>, source: &Tid) -> Result<Vec<(Tid, Ak)>> {
    let from = tx.txn.index(FROM)?;
    let end = [source.as_bytes().as_slice(), &[0xff; 16]].concat();
    let mut out = Vec::new();
    scan_table(&mut tx.txn, from, source.as_bytes(), Some(&end), |k, _| {
        out.push(parse(&k)?);
        Ok(())
    })?;
    Ok(out)
}

/// The things whose held history holds a strong to `target`, with the AK holding it.
pub(crate) fn to(tx: &mut Tx<'_>, target: &Tid) -> Result<Vec<(Tid, Ak)>> {
    let to = tx.txn.index(TO)?;
    let end = [target.as_bytes().as_slice(), &[0xff; 16]].concat();
    let mut out = Vec::new();
    scan_table(&mut tx.txn, to, target.as_bytes(), Some(&end), |k, _| {
        out.push(parse(&k)?);
        Ok(())
    })?;
    Ok(out)
}

/// Whether `source`'s held history holds a strong to `target`: one seek.
pub(crate) fn strong_from(tx: &mut Tx<'_>, source: &Tid, target: &Tid) -> Result<bool> {
    let from = tx.txn.index(FROM)?;
    let pre = [source.as_bytes().as_slice(), target.as_bytes()].concat();
    let end = [pre.as_slice(), &[0xff]].concat();
    Ok(!tx.txn.table_range(from, &pre, Some(&end), 1)?.is_empty())
}

/// Fills the rows afresh (after `index::write_all` dropped them).
pub(crate) fn write_all(tx: &mut Tx<'_>) -> Result<()> {
    for name in [PARTS, FROM, TO] {
        tx.txn.index(name)?;
    }
    let things: Vec<Tid> = tx.core.ix.retention.keys().copied().collect();
    tx.core.kept_things_due.extend(things);
    settle(tx)
}

/// Debug: the rows of `(source, ak)` are what its held valid bodies hold, kept iff its setting
/// says so.
#[cfg(debug_assertions)]
pub(crate) fn check(tx: &mut Tx<'_>, source: &Tid, ak: &Ak) -> Result<()> {
    let on = marked(tx, source)?;
    debug_assert_eq!(on, holds_history(tx.core, source), "kept strongs marker of {source:?} differs from its setting");
    let p = tx.txn.index(PARTS)?;
    let pre = [source.as_bytes().as_slice(), ak.as_str().as_bytes(), &[0]].concat();
    let end = [pre.as_slice(), &[0xff; 40]].concat();
    let mut got = BTreeMap::new();
    scan_table(&mut tx.txn, p, &pre, Some(&end), |k, v| {
        got.insert(k, decode(&v)?);
        Ok(())
    })?;
    let mut want = BTreeMap::new();
    if on && counted(ak) {
        let on: Vec<CommitId> = tx.core.ix.by_aspect.get(&(*source, ak.clone())).into_iter().flatten().map(|x| x.1).collect();
        for c in on {
            let Some(ai) = tx.core.ix.commits.get(&c).and_then(|m| m.aspect(source, ak)) else { continue };
            let s = held_strongs(tx, source, ak, &c, ai)?;
            if !s.is_empty() {
                want.insert(part_key(source, ak, &c, ai), s);
            }
        }
    }
    debug_assert_eq!(got, want, "kept strongs rows of {source:?} {ak:?} differ from its held bodies");
    let mut sum: BTreeMap<Tid, u64> = BTreeMap::new();
    for (t, n) in want.values().flatten() {
        *sum.entry(*t).or_default() += n;
    }
    let from = tx.txn.index(FROM)?;
    let end = [source.as_bytes().as_slice(), &[0xff; 16]].concat();
    let mut rows = BTreeMap::new();
    scan_table(&mut tx.txn, from, source.as_bytes(), Some(&end), |k, v| {
        let (t, a) = parse(&k)?;
        if a == *ak {
            rows.insert(t, u64::from_be_bytes(v.try_into().map_err(|_| Error::Corrupt("kept strongs count"))?));
        }
        Ok(())
    })?;
    debug_assert_eq!(rows, sum, "kept strongs counts of {source:?} {ak:?} differ from its parts");
    Ok(())
}
