//! References in history (spec/data-model.md §8 Held history; notes/engine-refs.md History
//! holds): on a thing whose newest held valid setting has `history_holds_targets`, each reference
//! in a held valid body of a counted aspect of it (`counted`), a held fire included, counts as a
//! current value's does until the body goes (covered, expired, purged, invalid, forgotten,
//! released): a strong an edge of the node closure and a need, a weak its target's stub. Local and
//! rebuildable, in three store index tables:
//! - `PARTS`: source ‖ AK ‖ 0 ‖ commit ‖ part (u32): the references that held body holds, by
//!   target and kind with counts, and the large values it holds, by content hash with counts
//!   (`Part`); the source alone: its marker, its rows are kept. A large value counts as its
//!   references, read once per aspect into its row of the reference index (`refs::move_link`, the
//!   row's `kept` count), counted once its chunks are held (`credit`).
//! - `FROM`: source ‖ target ‖ kind ‖ AK, the count over its parts and their large values (u64);
//!   `TO`: target ‖ source ‖ kind ‖ AK.
//!
//! Kept by `settle` (at each closure settle, `units::settle`) over the parts whose hold, validity
//! or body moved (`Core::kept_due`, noted where the meta or a leftover is written): O(those
//! bodies). A thing whose setting turns it on or off (`Core::kept_things_due`) has every body
//! read once, or its rows dropped.

use super::super::{Tx, scan_table};
use crate::engine::Core;
use crate::error::{Error, Result};
use osis_base::{Ak, CommitId, Link, RefKind, Tid, Value};
use osis_store::Shred;
use std::collections::BTreeMap;

pub(crate) const PARTS: &[u8] = b"node/refs kept parts";
pub(crate) const FROM: &[u8] = b"node/refs kept from";
pub(crate) const TO: &[u8] = b"node/refs kept to";

const TID: usize = osis_base::format::TID_LEN;

/// Whether held bodies of `ak` can hold their references' targets: a durable aspect the setting
/// governs (no fixed retention), a signal's fires as any other body.
pub(crate) fn counted(ak: &Ak) -> bool {
    !ak.ephemeral() && osis_commit::retention::fixed_purge_by(ak.as_str()).is_none()
}

/// Whether `tid`'s newest held valid setting says its history holds its references' targets.
pub(crate) fn holds_history(core: &Core, tid: &Tid) -> bool {
    core.ix.retention.get(tid).is_some_and(|s| !s.is_empty()) && crate::apply::validity::setting_now(core, tid).is_some_and(|s| s.history_holds_targets)
}

fn part_key(source: &Tid, ak: &Ak, c: &CommitId, ai: usize) -> Vec<u8> {
    [source.as_bytes().as_slice(), ak.as_str().as_bytes(), &[0], &c.0, &(ai as u32).to_be_bytes()].concat()
}

/// What a held body holds: its references by target and kind and its large values by content
/// hash, with counts. A `PARTS` row: the number of references (u32), each target ‖ kind ‖ count
/// (u64), each hash ‖ count (u64).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct Part {
    refs: BTreeMap<(Tid, RefKind), u64>,
    links: BTreeMap<[u8; 32], u64>,
}

impl Part {
    fn is_empty(&self) -> bool {
        self.refs.is_empty() && self.links.is_empty()
    }
    fn encode(&self) -> Vec<u8> {
        let n = (self.refs.len() as u32).to_be_bytes();
        let refs = self.refs.iter().flat_map(|((t, k), n)| [t.as_bytes().as_slice(), &[k.id()], &n.to_be_bytes()].concat());
        let links = self.links.iter().flat_map(|(h, n)| [h.as_slice(), &n.to_be_bytes()].concat());
        n.into_iter().chain(refs).chain(links).collect()
    }
    fn decode(v: &[u8]) -> Result<Part> {
        let bad = || Error::Corrupt("kept references row");
        let (n, rest) = v.split_first_chunk::<4>().ok_or_else(bad)?;
        let (s, l) = rest.split_at_checked(u32::from_be_bytes(*n) as usize * (TID + 9)).ok_or_else(bad)?;
        if !l.len().is_multiple_of(40) {
            return Err(bad());
        }
        let refs = s.chunks(TID + 9).map(|c| {
            let (t, rest) = c.split_at(TID);
            let (k, n) = rest.split_at(1);
            let kind = k.first().and_then(|k| RefKind::from_id(u64::from(*k))).ok_or_else(bad)?;
            Ok(((Tid::from_bytes(t.try_into().map_err(|_| bad())?), kind), u64::from_be_bytes(n.try_into().map_err(|_| bad())?)))
        }).collect::<Result<_>>()?;
        let links = l.chunks(40).map(|c| {
            let (h, n) = c.split_at(32);
            Ok((h.try_into().map_err(|_| bad())?, u64::from_be_bytes(n.try_into().map_err(|_| bad())?)))
        }).collect::<Result<_>>()?;
        Ok(Part { refs, links })
    }
}

/// What held body `ai` of `c` holds while held and valid (as written), with a link to each large
/// value it holds.
fn held_part(tx: &mut Tx<'_>, source: &Tid, ak: &Ak, c: &CommitId, ai: usize) -> Result<(Part, BTreeMap<[u8; 32], Link>)> {
    let (mut out, mut links) = (Part::default(), BTreeMap::new());
    let Some(m) = tx.core.ix.commits.get(c) else { return Ok((out, links)) };
    if !m.holds(ai) || !m.valid_at(ai) || m.view.aspects.get(ai).is_none_or(|a| a.tid != *source || a.ak != *ak) {
        return Ok((out, links));
    }
    crate::apply::each_held_piece(tx, c, ai, &mut |_, f| {
        f.each_value(&mut |v| {
            v.each_reference_or_link(&mut |r| match r {
                Value::Link(l) => {
                    *out.links.entry(l.hash).or_default() += 1;
                    links.insert(l.hash, **l);
                }
                r => {
                    if let Some((k, t)) = RefKind::of(r) {
                        *out.refs.entry((t, k)).or_default() += 1;
                    }
                }
            })
        });
        Ok(())
    })?;
    Ok((out, links))
}

/// The references among `refs` (a large value's), by target and kind, each `n` times.
fn refs_of(refs: &[Value], n: i64, out: &mut BTreeMap<(Tid, RefKind), i64>) {
    for r in refs {
        if let Some((k, t)) = RefKind::of(r) {
            *out.entry((t, k)).or_default() += n;
        }
    }
}

/// A large value `source`'s held history holds `n` times became whole with references `refs`
/// (`refs::count_earlier`): they count.
pub(super) fn credit(tx: &mut Tx<'_>, source: &Tid, ak: &Ak, refs: &[Value], n: u64) -> Result<()> {
    let mut d = BTreeMap::new();
    refs_of(refs, n as i64, &mut d);
    for ((target, k), n) in d {
        bump(tx, source, &target, k, ak, n)?;
    }
    Ok(())
}

/// Whether `source`'s rows are kept (its marker).
fn marked(tx: &mut Tx<'_>, source: &Tid) -> Result<bool> {
    let p = tx.txn.index(PARTS)?;
    Ok(tx.txn.table_get(p, source.as_bytes())?.is_some())
}

/// Adds `n` (signed) to the count of `source`'s `kind` references to `target` on `ak`, telling
/// the node closure of a row appearing or going and noting a lost need.
fn bump(tx: &mut Tx<'_>, source: &Tid, target: &Tid, kind: RefKind, ak: &Ak, n: i64) -> Result<()> {
    if n == 0 {
        return Ok(());
    }
    let (from, to) = (tx.txn.index(FROM)?, tx.txn.index(TO)?);
    let fk = [source.as_bytes().as_slice(), target.as_bytes(), &[kind.id()], ak.as_str().as_bytes()].concat();
    let tk = [target.as_bytes().as_slice(), source.as_bytes(), &[kind.id()], ak.as_str().as_bytes()].concat();
    let old = tx.txn.table_get(from, &fk)?.map(|v| v.try_into().map(u64::from_be_bytes).map_err(|_| Error::Corrupt("kept references count"))).transpose()?.unwrap_or(0);
    let new = u64::try_from(old as i64 + n).map_err(|_| Error::Corrupt("kept references count below zero"))?;
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
        // off: every row of it goes, its large values' reads with them
        tx.txn.table_remove(p, t.as_bytes(), Shred::Yes)?;
        let end = [t.as_bytes().as_slice(), &[0xff; 16]].concat();
        let mut parts = Vec::new();
        scan_table(&mut tx.txn, p, t.as_bytes(), Some(&end), |k, v| {
            parts.push((k, Part::decode(&v)?));
            Ok(())
        })?;
        for (k, part) in parts {
            tx.txn.table_remove(p, &k, Shred::Yes)?;
            let ak = part_ak(&k)?;
            for (h, n) in part.links {
                super::move_link(tx, &t, &ak, &h, None, -(n as i64), true)?;
            }
        }
        let from = tx.txn.index(FROM)?;
        let mut rows = Vec::new();
        scan_table(&mut tx.txn, from, t.as_bytes(), Some(&end), |k, v| {
            rows.push((k, v));
            Ok(())
        })?;
        for (k, v) in rows {
            let (target, kind, ak) = parse(&k)?;
            let n = u64::from_be_bytes(v.try_into().map_err(|_| Error::Corrupt("kept references count"))?);
            bump(tx, &t, &target, kind, &ak, -(n as i64))?;
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
        let (want, links) = held_part(tx, &t, &ak, &c, ai)?;
        let p = tx.txn.index(PARTS)?;
        let key = part_key(&t, &ak, &c, ai);
        let have = tx.txn.table_get(p, &key)?.map(|v| Part::decode(&v)).transpose()?.unwrap_or_default();
        if want == have {
            continue;
        }
        if want.is_empty() {
            tx.txn.table_remove(p, &key, Shred::Yes)?;
        } else {
            tx.txn.table_put(p, &key, want.encode(), Shred::No)?;
        }
        let mut d: BTreeMap<(Tid, RefKind), i64> = want.refs.iter().map(|(t, n)| (*t, *n as i64)).collect();
        for (x, n) in &have.refs {
            *d.entry(*x).or_default() -= *n as i64;
        }
        // each large value counts as its references, from its row (read on its first read)
        let mut moved: BTreeMap<[u8; 32], i64> = want.links.iter().map(|(h, n)| (*h, *n as i64)).collect();
        for (h, n) in &have.links {
            *moved.entry(*h).or_default() -= *n as i64;
        }
        for (h, n) in moved.into_iter().filter(|x| x.1 != 0) {
            let (refs, earlier) = super::move_link(tx, &t, &ak, &h, links.get(&h), n, true)?;
            refs_of(&refs, n + earlier as i64, &mut d);
        }
        for ((target, kind), n) in d {
            bump(tx, &t, &target, kind, &ak, n)?;
        }
    }
    Ok(())
}

/// A `PARTS` key's AK (past the source, before its 0).
fn part_ak(k: &[u8]) -> Result<Ak> {
    let bad = || Error::Corrupt("kept references row");
    let a = k.get(TID..).ok_or_else(bad)?;
    let a = a.get(..a.iter().position(|b| *b == 0).ok_or_else(bad)?).ok_or_else(bad)?;
    std::str::from_utf8(a).ok().and_then(|a| Ak::new(a).ok()).ok_or_else(bad)
}

/// A `FROM` (or `TO`) key's second tid, kind and AK.
fn parse(k: &[u8]) -> Result<(Tid, RefKind, Ak)> {
    let bad = || Error::Corrupt("kept references row");
    let t = k.get(TID..2 * TID).ok_or_else(bad)?;
    let kind = k.get(2 * TID).and_then(|x| RefKind::from_id(u64::from(*x))).ok_or_else(bad)?;
    let a = k.get(2 * TID + 1..).ok_or_else(bad)?;
    let ak = std::str::from_utf8(a).ok().and_then(|a| Ak::new(a).ok()).ok_or_else(bad)?;
    Ok((Tid::from_bytes(t.try_into().map_err(|_| bad())?), kind, ak))
}

/// The targets of `source`'s references in its held history, each with its kind and the AK
/// holding it.
pub(crate) fn from(tx: &mut Tx<'_>, source: &Tid) -> Result<Vec<(Tid, RefKind, Ak)>> {
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
        let (s, kind, ak) = parse(&k)?;
        if kind == RefKind::Strong {
            out.push((s, ak));
        }
        Ok(())
    })?;
    Ok(out)
}

/// Whether `source`'s held history holds a `kind` reference to `target`: one seek.
pub(crate) fn holds_from(tx: &mut Tx<'_>, source: &Tid, target: &Tid, kind: RefKind) -> Result<bool> {
    let from = tx.txn.index(FROM)?;
    let pre = [source.as_bytes().as_slice(), target.as_bytes(), &[kind.id()]].concat();
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
    debug_assert_eq!(on, holds_history(tx.core, source), "kept references marker of {source:?} differs from its setting");
    let p = tx.txn.index(PARTS)?;
    let pre = [source.as_bytes().as_slice(), ak.as_str().as_bytes(), &[0]].concat();
    let end = [pre.as_slice(), &[0xff; 40]].concat();
    let mut got = BTreeMap::new();
    scan_table(&mut tx.txn, p, &pre, Some(&end), |k, v| {
        got.insert(k, Part::decode(&v)?);
        Ok(())
    })?;
    let mut want = BTreeMap::new();
    if on && counted(ak) {
        let on: Vec<CommitId> = tx.core.ix.by_aspect.get(&(*source, ak.clone())).into_iter().flatten().map(|x| x.1).collect();
        for c in on {
            let Some(ai) = tx.core.ix.commits.get(&c).and_then(|m| m.aspect(source, ak)) else { continue };
            let (s, _) = held_part(tx, source, ak, &c, ai)?;
            if !s.is_empty() {
                want.insert(part_key(source, ak, &c, ai), s);
            }
        }
    }
    debug_assert_eq!(got, want, "kept references rows of {source:?} {ak:?} differ from its held bodies");
    // the large values' rows count their reads here, and their references count once whole
    let mut sum: BTreeMap<(Tid, RefKind), i64> = BTreeMap::new();
    let mut reads: BTreeMap<[u8; 32], u64> = BTreeMap::new();
    for part in want.values() {
        for (t, n) in &part.refs {
            *sum.entry(*t).or_default() += *n as i64;
        }
        for (h, n) in &part.links {
            *reads.entry(*h).or_default() += n;
        }
    }
    let rows = super::stored_links(tx, source, ak)?;
    let kept: BTreeMap<[u8; 32], u64> = rows.iter().filter(|x| x.1.kept > 0).map(|(h, r)| (*h, r.kept)).collect();
    debug_assert_eq!(kept, reads, "large-value rows of {source:?} {ak:?} differ from its held bodies' reads");
    for (h, n) in &reads {
        if let Some(Ok(refs)) = rows.get(h).map(|r| &r.refs) {
            refs_of(refs, *n as i64, &mut sum);
        }
    }
    let sum: BTreeMap<(Tid, RefKind), u64> = sum.into_iter().map(|(t, n)| (t, n as u64)).collect();
    let from = tx.txn.index(FROM)?;
    let end = [source.as_bytes().as_slice(), &[0xff; 16]].concat();
    let mut rows = BTreeMap::new();
    scan_table(&mut tx.txn, from, source.as_bytes(), Some(&end), |k, v| {
        let (t, kind, a) = parse(&k)?;
        if a == *ak {
            rows.insert((t, kind), u64::from_be_bytes(v.try_into().map_err(|_| Error::Corrupt("kept references count"))?));
        }
        Ok(())
    })?;
    debug_assert_eq!(rows, sum, "kept references counts of {source:?} {ak:?} differ from its parts");
    Ok(())
}
