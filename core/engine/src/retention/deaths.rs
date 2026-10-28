//! Deaths of writes (spec/crdt.md §4.8) for bodies with a relative keep bound (spec/commits.md
//! §5). A valid writer delta sorting after every held commit of its aspect takes its join's
//! deaths (`note_deaths`); any other marks the aspect (`Core::deaths_due`), and `settle_due`
//! replays it once per batch: over the late deltas' window when that judges every body they can
//! change (`window`), else over every held body (`replay_all`). A dropped body's writes stay,
//! value-less, as its residue (`records::DROPPED`) while a held bounded body sorts at or before
//! it, so a replay still meets a superseder whose body is gone.

use super::{body_class, bounded, check_at_most, held_part};
use crate::engine::records::{self, Rd};
use crate::engine::{Core, Tx};
use crate::error::Result;
use osis_commit::{Decoded, Header};
use osis_base::{Ak, CommitId, Tid, Ts};
use osis_crdt::{Changes, Death, Fragment, Stamp};
use osis_store::Shred;
use std::collections::{BTreeMap, BTreeSet, HashMap};

/// What the replay of an aspect's deaths must judge (`Core::deaths_due`; persisted as the
/// aspect's mark only, which an open reads as `Full`).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Due {
    /// Every held body: a validity flip, a snapshot or import, an open.
    Full,
    /// A valid writer delta joined out of `(ts, ID)` order.
    Late(Ts, CommitId),
    /// A held bounded body carrying a write a late delta's join killed (the delta's own too).
    Killed(CommitId),
    /// A `ts` a late delta's join dated a death at.
    Hint(Ts),
    /// A body whose keep-at-most check waited for the replay.
    Recheck(CommitId, usize),
}

/// The persisted index of the held bounded bodies' last deaths (a rebuildable store index:
/// `engine::index::write_all` rebuilds it from the death records): per row aspect key + last
/// death + `ts` (8 bytes each, big endian) + commit ID, no value; written with the death
/// records it follows, so a window finds the bodies dying after a late `ts` without reading
/// every record or holding them in memory.
const LAST_DEATHS: &[u8] = b"node/last deaths";

fn last_key(tid: &Tid, ak: &Ak, last: Ts, ts: Ts, c: &CommitId) -> Vec<u8> {
    let mut k = records::aspect_key(&[], tid, ak);
    k.extend_from_slice(&last.to_u64().to_be_bytes());
    k.extend_from_slice(&ts.to_u64().to_be_bytes());
    k.extend_from_slice(&c.0);
    k
}

/// Moves `c`'s row on `(tid, ak)` from last death `old` to `new` (`None`: no row).
fn put_last(tx: &mut Tx<'_>, tid: &Tid, ak: &Ak, c: &CommitId, old: Option<Ts>, new: Option<Ts>) -> Result<()> {
    if old == new {
        return Ok(());
    }
    let Some(ts) = tx.core.ix.commits.get(c).map(|m| m.header.ts) else { return Ok(()) };
    let t = tx.txn.index(LAST_DEATHS)?;
    if let Some(l) = old {
        tx.txn.table_remove(t, &last_key(tid, ak, l, ts, c), Shred::No)?;
    }
    if let Some(l) = new {
        tx.txn.table_put(t, &last_key(tid, ak, l, ts, c), Vec::new(), Shred::No)?;
    }
    Ok(())
}

/// Before part `ai` of `c` on `(tid, ak)` drops with its death record: removes its row,
/// shredded as the record is.
pub(crate) fn drop_last(tx: &mut Tx<'_>, tid: &Tid, ak: &Ak, c: &CommitId, ai: usize) -> Result<()> {
    let (Some(l), Some(ts)) = (death_of(tx, tid, ak, c, ai)?.map(|d| d.last), tx.core.ix.commits.get(c).map(|m| m.header.ts)) else { return Ok(()) };
    let t = tx.txn.index(LAST_DEATHS)?;
    tx.txn.table_remove(t, &last_key(tid, ak, l, ts, c), Shred::Yes)?;
    Ok(())
}

/// The rows of `(tid, ak)` with a last death at or after `from`, as `(last, ts, ID)`; `None`
/// when one does not parse.
pub(super) fn rows_from(tx: &mut Tx<'_>, tid: &Tid, ak: &Ak, from: Ts) -> Result<Option<Vec<(Ts, Ts, CommitId)>>> {
    let p = records::aspect_key(&[], tid, ak);
    let t = tx.txn.index(LAST_DEATHS)?;
    let end = [&p[..], &[0xff; 49]].concat();
    let start = [&p[..], &from.to_u64().to_be_bytes()].concat();
    let mut keys = Vec::new();
    crate::engine::scan_table(&mut tx.txn, t, &start, Some(&end), |k, _| {
        keys.push(k);
        Ok(())
    })?;
    let mut out = Vec::with_capacity(keys.len());
    for k in keys {
        let Some(r) = k.get(p.len()..).filter(|r| r.len() == 48) else { return Ok(None) };
        let mut r = Rd::new(r);
        let (Some(last), Some(ts)) = (Ts::from_u64(r.u64()?), Ts::from_u64(r.u64()?)) else { return Ok(None) };
        out.push((last, ts, CommitId(r.arr()?)));
    }
    Ok(Some(out))
}

/// The rows of `(tid, ak)` from its held bounded bodies' death records.
fn fresh_rows(tx: &mut Tx<'_>, tid: &Tid, ak: &Ak) -> Result<Vec<(Ts, Ts, CommitId)>> {
    let held: Vec<(Ts, CommitId)> = tx.core.ix.by_aspect.get(&(*tid, ak.clone())).into_iter().flatten().copied().collect();
    let mut out = Vec::new();
    for (ts, c) in held {
        let Some(ai) = bounded_part(tx.core, &c, tid, ak) else { continue };
        if let Some(d) = death_of(tx, tid, ak, &c, ai)? {
            out.push((d.last, ts, c));
        }
    }
    out.sort();
    Ok(out)
}

/// Removes every row of `(tid, ak)`.
fn clear_rows(tx: &mut Tx<'_>, tid: &Tid, ak: &Ak, shred: Shred) -> Result<()> {
    let p = records::aspect_key(&[], tid, ak);
    let t = tx.txn.index(LAST_DEATHS)?;
    let end = [&p[..], &[0xff; 49]].concat();
    crate::engine::clear_table(&mut tx.txn, t, &p, &end, shred)
}

/// Rewrites the rows of `(tid, ak)` from its death records (one did not parse).
fn rebuild_rows(tx: &mut Tx<'_>, tid: &Tid, ak: &Ak) -> Result<()> {
    clear_rows(tx, tid, ak, Shred::No)?;
    let t = tx.txn.index(LAST_DEATHS)?;
    for (last, ts, c) in fresh_rows(tx, tid, ak)? {
        tx.txn.table_put(t, &last_key(tid, ak, last, ts, &c), Vec::new(), Shred::No)?;
    }
    Ok(())
}

/// Writes every aspect's rows from the death records (`engine::index::write_all`, after the
/// index tables were dropped). Cost: one record per held bounded body.
pub(crate) fn write_last_deaths_all(tx: &mut Tx<'_>) -> Result<()> {
    let aspects: Vec<(Tid, Ak)> = tx.core.ix.by_aspect.keys().cloned().collect();
    for (tid, ak) in aspects {
        rebuild_rows(tx, &tid, &ak)?;
    }
    Ok(())
}

/// The bodies of `(tid, ak)` with a last death at or after `from`, as `(last, ts, ID)`; rows
/// that do not parse rebuild the aspect's rows first.
fn dying_after(tx: &mut Tx<'_>, tid: &Tid, ak: &Ak, from: Ts) -> Result<Vec<(Ts, Ts, CommitId)>> {
    if let Some(v) = rows_from(tx, tid, ak, from)? {
        return Ok(v);
    }
    rebuild_rows(tx, tid, ak)?;
    rows_from(tx, tid, ak, from)?.ok_or(crate::error::Error::Corrupt("last deaths"))
}

impl crate::Engine {
    /// Aspects whose last-death rows differ from their death records (tests).
    #[doc(hidden)]
    pub fn last_deaths_stale(&mut self) -> Result<Vec<(Tid, Ak)>> {
        self.run(|tx| {
            let aspects: Vec<(Tid, Ak)> = tx.core.ix.by_aspect.keys().cloned().collect();
            let mut out = Vec::new();
            for (tid, ak) in aspects {
                if rows_from(tx, &tid, &ak, Ts::default())? != Some(fresh_rows(tx, &tid, &ak)?) {
                    out.push((tid, ak));
                }
            }
            Ok(out)
        })
    }

    /// Damages the last-death rows (tests): garbles every row of `(tid, ak)` (a key that does
    /// not parse in its place).
    #[doc(hidden)]
    pub fn damage_last_deaths(&mut self, tid: &Tid, ak: &Ak) -> Result<usize> {
        let (tid, ak) = (*tid, ak.clone());
        self.run(|tx| {
            let rows = rows_from(tx, &tid, &ak, Ts::default())?.unwrap_or_default();
            clear_rows(tx, &tid, &ak, Shred::No)?;
            let t = tx.txn.index(LAST_DEATHS)?;
            for (last, ts, c) in &rows {
                let mut k = last_key(&tid, &ak, *last, *ts, c);
                k.truncate(k.len() - 3);
                tx.txn.table_put(t, &k, Vec::new(), Shred::No)?;
            }
            Ok(rows.len())
        })
    }
}

/// Below this many bodies before the last late delta, a window reads their records instead of
/// the last-death rows (which also hold every body after it).
const LASTS_MIN: usize = 64;

const LO: CommitId = CommitId([0; 32]);
const HI: CommitId = CommitId([0xff; 32]);

/// The aspect index of `(tid, ak)` in `c` if that part is held and has a relative bound.
fn bounded_part(core: &Core, c: &CommitId, tid: &Tid, ak: &Ak) -> Option<usize> {
    held_part(core, c, tid, ak).filter(|ai| core.ix.commits.get(c).and_then(|m| m.header.aspects.get(*ai)).is_some_and(bounded))
}

/// Whether `c` carries copies of others' writes (a snapshot or import).
fn copies(core: &Core, c: &CommitId) -> bool {
    core.ix.commits.get(c).is_none_or(|m| !m.header.kind.has_own_writes())
}

/// The first held body of `(tid, ak)` with a relative bound by `(ts, ID)`, cached
/// (`Core::first_bounded`, kept by `index_commit` and `keep_residue`).
pub(crate) fn first_bounded(core: &mut Core, tid: &Tid, ak: &Ak) -> Option<(Ts, CommitId)> {
    let k = (*tid, ak.clone());
    if let Some(f) = core.ix.first_bounded.get(&k) {
        return *f;
    }
    let f = core.ix.by_aspect.get(&k).into_iter().flatten().find(|(_, c)| bounded_part(core, c, tid, ak).is_some()).copied();
    core.ix.first_bounded.insert(k, f);
    f
}

/// The first held bounded body of `(tid, ak)` after `after`.
fn next_bounded(core: &Core, tid: &Tid, ak: &Ak, after: (Ts, CommitId)) -> Option<(Ts, CommitId)> {
    use std::ops::Bound::{Excluded, Unbounded};
    core.ix.by_aspect.get(&(*tid, ak.clone()))?.range((Excluded(after), Unbounded)).find(|(_, c)| bounded_part(core, c, tid, ak).is_some()).copied()
}

/// A commit just indexed (`apply::index_commit`): the first held bounded body of its aspects.
pub(crate) fn note_indexed(core: &mut Core, id: &CommitId, h: &crate::engine::View) {
    for a in h.aspects.iter().filter(|a| a.bounded) {
        let k = (a.tid, a.ak.clone());
        let Some(&old) = core.ix.first_bounded.get(&k) else { continue };
        if old.is_some_and(|f| f <= (h.ts, *id)) {
            continue;
        }
        core.ix.first_bounded.insert(k.clone(), Some((h.ts, *id)));
        // every commit dropped between the new first and the old one has no residue (none was
        // kept or left before a held bounded body sorting at or before it)
        if let (Some(old), Some(&bare)) = (old, core.ix.first_bare.get(&k)) {
            let mut low = bare;
            // the commit itself is not in `commits` yet
            for (ts, c) in core.ix.by_aspect.get(&k).into_iter().flat_map(|s| s.range((h.ts, *id)..old)).filter(|x| x.1 != *id) {
                if held_part(core, c, &a.tid, &a.ak).is_none() {
                    let t = if copies(core, c) { Ts::default() } else { *ts };
                    low = Some(low.map_or(t, |l| l.min(t)));
                }
            }
            core.ix.first_bare.insert(k, low);
        } else {
            core.ix.first_bare.remove(&k);
        }
    }
}

/// The lowest stamp of a write of `(tid, ak)` the state plays (last, in a replay) that a commit
/// dropped without a residue at or after the first held bounded body gives: the first such
/// node-form commit's `ts`, or the lowest `Ts` for a snapshot or import (copies of any stamp);
/// cached (`Core::first_bare`). A drop leaves a residue when a held bounded body sorts at or
/// before it, so such a commit comes from a held bounded body arriving older than the drop
/// (`note_indexed`), or from a part dropped with no body to keep. Cost when not cached: the
/// aspect's commits from the first held bounded body (in memory), a residue read per dropped
/// one up to the first without one.
fn first_bare(tx: &mut Tx<'_>, tid: &Tid, ak: &Ak) -> Result<Option<Ts>> {
    let k = (*tid, ak.clone());
    if let Some(b) = tx.core.ix.first_bare.get(&k) {
        return Ok(*b);
    }
    let _s = crate::costs::span("deaths: first bare");
    let Some(first) = first_bounded(tx.core, tid, ak) else { return Ok(None) };
    let core = &*tx.core;
    let dropped: Vec<(Ts, CommitId)> = core.ix.by_aspect.get(&k).into_iter().flat_map(|s| s.range(first..)).filter(|(_, c)| held_part(core, c, tid, ak).is_none()).copied().collect();
    let mut out = None;
    for (ts, c) in dropped {
        // after the first node-form one only a snapshot or import can give a lower stamp
        if (out.is_none() || copies(tx.core, &c)) && !plays_own(tx, tid, ak, &c)? {
            if copies(tx.core, &c) {
                out = Some(Ts::default());
                break;
            }
            out = out.or(Some(ts));
        }
    }
    tx.core.ix.first_bare.insert(k, out);
    Ok(out)
}

/// Before part `ai` of `c` drops (`drop_part`): keeps its deltas' writes (`bodies`) value-less
/// as its residue when a held bounded body of the aspect sorts at or before it (they may date
/// that body's writes, spec/crdt.md §4.8; a write dies only at a greater stamp), then drops the
/// residues no held bounded body sorts at or before any more. Residues carry no app data
/// (spec/crdt.md §4.7); a snapshot's or import's keeps only copies of writes whose own commit
/// is neither held nor a residue. Cost: O(one body) (a snapshot's: plus the aspect's residue
/// keys), plus once per dropped commit the step past it.
pub(crate) fn keep_residue(tx: &mut Tx<'_>, c: &CommitId, ai: usize, bodies: &[Fragment]) -> Result<()> {
    let Some(m) = tx.core.ix.commits.get(c) else { return Ok(()) };
    let Some(a) = m.header.aspects.get(ai) else { return Ok(()) };
    let (tid, ak, ts) = (a.tid, a.ak.clone(), m.header.ts);
    let me = (ts, *c);
    let first = first_bounded(tx.core, &tid, &ak);
    let next = if first == Some(me) { next_bounded(tx.core, &tid, &ak, me) } else { first };
    if !next.is_some_and(|n| n.0 <= ts) && !bodies.is_empty() && uncovered_copies_after(tx.core, &tid, &ak, me, ai) {
        // no residue: a held bounded snapshot or import after it that did not see it may carry
        // a copy it superseded (stamped below it, its own commit not playing it), which a
        // replay without it dates at a later superseder, after that snapshot (strays seed
        // 32432): replay once it is gone
        mark_deaths_due(tx, &tid, &ak)?;
    }
    if next.is_some_and(|n| n.0 <= ts) && bodies.is_empty() {
        // nothing to keep: a stray for `first_bare`
        if let Some(&b) = tx.core.ix.first_bare.get(&(tid, ak.clone())) {
            let t = if copies(tx.core, c) { Ts::default() } else { ts };
            tx.core.ix.first_bare.insert((tid, ak.clone()), Some(b.map_or(t, |b| b.min(t))));
        }
    }
    if next.is_some_and(|n| n.0 <= ts)
        && let Some((b, rest)) = bodies.split_first()
    {
        let mut f = b.clone();
        for x in rest {
            f.join_into(x.clone(), None, &mut Changes::new());
        }
        if copies(tx.core, c) {
            // copies a replay plays at their own commit (held, or a residue) are not kept: a
            // snapshot's residue would hold the aspect's whole state
            let kept = residue_ids(tx, &tid, &ak)?;
            let core = &*tx.core;
            f.remove_writes(&|d| core.commit_of(&tid, &ak, d).is_some_and(|x| x != *c && (held_part(core, &x, &tid, &ak).is_some() || kept.contains(&x))));
        }
        f.strip(&|_| true);
        // a snapshot's or import's left empty is kept too: none means its copies play with the
        // state, last (`strays_from`)
        tx.txn.put_local(&records::dropped_key(&tid, &ak, ts, c), &crate::engine::state::encode(&f)?, Shred::No)?;
    }
    if first == Some(me) {
        let gone: Vec<(Ts, CommitId)> = tx.core.ix.by_aspect.get(&(tid, ak.clone())).into_iter().flat_map(|s| s.range(me..)).take_while(|x| next.is_none_or(|n| x.0 < n.0)).copied().collect();
        for (t, x) in gone {
            tx.txn.remove_local(&records::dropped_key(&tid, &ak, t, &x), Shred::Yes)?;
        }
        // a known first bare commit before the new first is no longer one
        if tx.core.ix.first_bare.get(&(tid, ak.clone())).is_some_and(|b| b.is_some_and(|b| next.is_none_or(|n| b < n.0))) {
            tx.core.ix.first_bare.remove(&(tid, ak.clone()));
        }
        tx.core.ix.first_bounded.insert((tid, ak), next);
    }
    Ok(())
}

/// Whether a held bounded snapshot or import of `(tid, ak)` sorts after `me` (part `ai`) without
/// covering it: one whose frontier lacks `me`'s writes (a node-form commit; any other kind, or an
/// import, counts as not covered).
fn uncovered_copies_after(core: &Core, tid: &Tid, ak: &Ak, me: (Ts, CommitId), ai: usize) -> bool {
    let Some(m) = core.ix.commits.get(&me.1) else { return false };
    let hi = m.header.aspects.get(ai).map(|a| a.hi);
    let node = m.header.form == osis_commit::Form::Node && m.header.kind.has_own_writes();
    let author = m.header.author;
    copies_lacking(core, tid, ak, me, &|fr| node && fr.0.get(&author).is_some_and(|f| hi.is_some_and(|hi| f.saturating_add(1) >= hi)))
}

/// Whether a held bounded snapshot or import of `(tid, ak)` other than `from`'s commit sorts at
/// or after `from` without being `covered` (by its frontier; an import never is).
fn copies_lacking(core: &Core, tid: &Tid, ak: &Ak, from: (Ts, CommitId), covered: &dyn Fn(&osis_crdt::Frontiers) -> bool) -> bool {
    let k = (*tid, ak.clone());
    core.ix.copies.get(&k).into_iter().flat_map(|x| x.range(from..)).filter(|x| x.1 != from.1 && bounded_part(core, &x.1, tid, ak).is_some()).any(|(_, s)| {
        let fr = core.ix.snapshots.get(&k).and_then(|v| v.iter().find(|x| x.1 == *s)).map(|x| &x.2);
        !fr.is_some_and(covered)
    })
}

/// Drops every residue of `(tid, ak)` (the aspect is forgotten).
pub(crate) fn drop_residues(tx: &mut Tx<'_>, tid: &Tid, ak: &Ak) -> Result<()> {
    let p = records::aspect_key(records::DROPPED, tid, ak);
    let mut keys = Vec::new();
    tx.scan(&p, |k, _| {
        keys.push([&p[..], k].concat());
        Ok(())
    })?;
    for k in keys {
        tx.txn.remove_local(&k, Shred::Yes)?;
    }
    tx.core.ix.first_bounded.remove(&(*tid, ak.clone()));
    tx.core.ix.first_bare.remove(&(*tid, ak.clone()));
    clear_rows(tx, tid, ak, Shred::Yes)
}

/// The commits of `(tid, ak)` with a residue.
fn residue_ids(tx: &mut Tx<'_>, tid: &Tid, ak: &Ak) -> Result<BTreeSet<CommitId>> {
    let mut out = BTreeSet::new();
    tx.scan(&records::aspect_key(records::DROPPED, tid, ak), |k, _| {
        let mut r = Rd::new(k);
        r.u64()?;
        out.insert(CommitId(r.arr()?));
        Ok(())
    })?;
    Ok(out)
}

fn residues(tx: &mut Tx<'_>, tid: &Tid, ak: &Ak) -> Result<BTreeMap<CommitId, Fragment>> {
    let mut raw = Vec::new();
    tx.scan(&records::aspect_key(records::DROPPED, tid, ak), |k, v| {
        let mut r = Rd::new(k);
        r.u64()?;
        raw.push((CommitId(r.arr()?), v));
        Ok(())
    })?;
    raw.into_iter().map(|(c, v)| Ok((c, crate::engine::state::decode(&v)?))).collect()
}

/// The held bodies with a relative bound carrying write `dot` of `(tid, ak)` when it died at
/// `at`: its own commit's, and every compaction snapshot taken before `at` whose frontier holds
/// it (a snapshot carries every write live at its time up to its frontier, spec/crdt.md §8).
/// Commit-form writes are found in their own commit only (snapshots keep no frontier for them).
/// Dropped bodies are not.
fn carriers(core: &Core, tid: &Tid, ak: &Ak, dot: &osis_crdt::Dot, at: Ts) -> Vec<(CommitId, usize)> {
    let mut out = Vec::new();
    if let Some(c) = core.commit_of(tid, ak, dot)
        && let Some(ai) = bounded_part(core, &c, tid, ak)
    {
        out.push((c, ai));
    }
    if let osis_crdt::SourceKind::Node(n) = dot.owner().src.kind() {
        for (ts, s, fr) in core.ix.snapshots.get(&(*tid, ak.clone())).into_iter().flatten() {
            // an invalid snapshot carries nothing (spec/permissions.md §5.2)
            if *ts < at
                && fr.0.get(n).is_some_and(|f| *f >= dot.owner().ctr)
                && !crate::apply::validity::invalid_snapshot(core, s, tid, ak)
                && let Some(ai) = bounded_part(core, s, tid, ak)
            {
                out.push((*s, ai));
            }
        }
    }
    out
}

/// Records the deaths a join of a delta in `(ts, ID)` order reported (`replays` false): per
/// body, first and last so far, on every held body with a relative bound carrying the write;
/// drops bodies past keep at most (spec/commits.md §5).
pub(crate) fn note_deaths(tx: &mut Tx<'_>, tid: &Tid, ak: &Ak, deaths: &[Death]) -> Result<()> {
    // a write a replay plays only with the state (its own commit dropped without a residue, or
    // never held) may have dated a held body that arrived after the drop (stamped at or after
    // `first_bare`), or a copy it superseded in a held bounded snapshot or import after it that
    // did not see it (strays seed 67421); once dead in the state a replay dates those at a later
    // superseder: replay
    if !deaths.is_empty() && first_bounded(tx.core, tid, ak).is_some() {
        let b = first_bare(tx, tid, ak)?;
        let unseen = |core: &Core, s: &osis_crdt::Stamp| {
            let d = s.dot.owner();
            let seen = |fr: &osis_crdt::Frontiers| matches!(d.src.kind(), osis_crdt::SourceKind::Node(n) if fr.0.get(n).is_some_and(|f| *f >= d.ctr));
            copies_lacking(core, tid, ak, (s.ts, LO), &seen)
        };
        for d in deaths {
            if !(b.is_some_and(|b| d.stamp.ts >= b) || unseen(tx.core, &d.stamp)) {
                continue;
            }
            let own = match tx.core.commit_of(tid, ak, &d.stamp.dot) {
                Some(x) => plays_own(tx, tid, ak, &x)?,
                None => false,
            };
            if !own {
                return mark_deaths_due(tx, tid, ak);
            }
        }
    }
    let mut bodies = BTreeSet::new();
    for d in deaths {
        for (c, ai) in carriers(tx.core, tid, ak, &d.stamp.dot, d.at) {
            let Some(h) = tx.core.ix.commits.get(&c).map(|m| m.header.clone()) else { continue };
            let (body, _) = body_class(tx.core, &h, &c, ai);
            let old = tx.txn.death(tid, ak, &body)?;
            let n = osis_store::Deaths { first: old.map_or(d.at, |o| o.first.min(d.at)), last: old.map_or(d.at, |o| o.last.max(d.at)) };
            if old != Some(n) {
                tx.txn.set_death(tid, ak, &body, Some(n))?;
                put_last(tx, tid, ak, &c, old.map(|o| o.last), Some(n.last))?;
            }
            // node-sync judges the bodies a write killed again (bounds, liveness)
            tx.core.mark_changed(c);
            bodies.insert((c, ai));
        }
    }
    for (c, ai) in bodies {
        check_at_most(tx, &c, ai)?;
    }
    Ok(())
}

/// Whether a valid delta of `c` (header `h`) on `(tid, ak)` needs the aspect's deaths replayed
/// instead of taken from its join. A join reports deaths against the state, which gives each
/// write its earliest superseder (spec/crdt.md §4.8) only for a delta with a `ts` above every
/// other held commit of the aspect and carrying no copies of others' writes; and only bodies with a
/// relative bound keep deaths.
pub(crate) fn replays(core: &mut Core, c: &CommitId, h: &Header, tid: &Tid, ak: &Ak) -> bool {
    let Some(held) = core.ix.by_aspect.get(&(*tid, ak.clone())) else { return false };
    // a stamp orders a `ts` tie by dot, not commit ID: ties replay
    let late = !h.kind.has_own_writes() || held.iter().rev().find(|x| x.1 != *c).is_some_and(|x| x.0 >= h.ts);
    late && first_bounded(core, tid, ak).is_some()
}

/// Adds `item` to the replay waiting on `(tid, ak)` (marked in the store: an open replays it
/// whole). The replay runs once, at the end of the transaction or, within a node-sync step,
/// before its deaths are next read (`Engine::settle_deaths`): a step of late deltas costs one
/// replay per aspect. Until then its death records may be off either way (a validity flip can
/// remove a superseder), so its keep-at-most bounds wait (`check_at_most`).
pub(crate) fn mark(tx: &mut Tx<'_>, tid: &Tid, ak: &Ak, item: Due) -> Result<()> {
    let k = (*tid, ak.clone());
    if !tx.core.ix.deaths_due.contains_key(&k) {
        tx.txn.put_local(&records::aspect_key(records::DEATHS_DUE, tid, ak), &[], Shred::No)?;
    }
    tx.core.ix.deaths_due.insert(k, item);
    Ok(())
}

/// Marks `(tid, ak)` for a replay of every held body if one has a relative bound (others'
/// writes un-merged under an invalid commit's creations).
pub(crate) fn mark_if_bounded(tx: &mut Tx<'_>, tid: &Tid, ak: &Ak) -> Result<()> {
    if first_bounded(tx.core, tid, ak).is_some() {
        mark_deaths_due(tx, tid, ak)?;
    }
    Ok(())
}

/// Marks `(tid, ak)` for a replay of every held body.
pub(crate) fn mark_deaths_due(tx: &mut Tx<'_>, tid: &Tid, ak: &Ak) -> Result<()> {
    mark(tx, tid, ak, Due::Full)
}

/// Marks `(tid, ak)` after valid delta `c` (header `h`) joined out of order (`replays`) and
/// reported `deaths` against the state: the replay judges what it can change (`window`).
pub(crate) fn mark_late(tx: &mut Tx<'_>, c: &CommitId, h: &Header, tid: &Tid, ak: &Ak, deaths: &[Death]) -> Result<()> {
    if !h.kind.has_own_writes() {
        return mark_deaths_due(tx, tid, ak);
    }
    mark(tx, tid, ak, Due::Late(h.ts, *c))?;
    let killed: BTreeSet<CommitId> = deaths.iter().flat_map(|d| carriers(tx.core, tid, ak, &d.stamp.dot, d.at)).map(|x| x.0).collect();
    for x in killed {
        mark(tx, tid, ak, Due::Killed(x))?;
    }
    if let Some(at) = deaths.iter().map(|d| d.at).max() {
        mark(tx, tid, ak, Due::Hint(at))?;
    }
    Ok(())
}

/// `Engine::settle_deaths` in `tx`.
pub(crate) fn settle_due(tx: &mut Tx<'_>) -> Result<()> {
    // one aspect at a time: settling one may add rechecks to another still marked
    while let Some((k, items)) = tx.core.ix.deaths_due.iter().next().map(|(k, s)| (k.clone(), s.iter().cloned().collect::<Vec<_>>())) {
        let (tid, ak) = k.clone();
        // unmarked first: `check_at_most` skips marked aspects
        for i in &items {
            tx.core.ix.deaths_due.remove(&k, i);
        }
        tx.txn.remove_local(&records::aspect_key(records::DEATHS_DUE, &tid, &ak), Shred::No)?;
        let judged = if items.contains(&Due::Full) {
            None
        } else {
            let _s = crate::costs::span("deaths: window");
            window(tx, &tid, &ak, &items)?
        };
        let Some(judged) = judged else {
            let _s = crate::costs::span("deaths: whole replay");
            rejudge_deaths(tx, &tid, &ak)?;
            continue;
        };
        #[cfg(debug_assertions)]
        if items.iter().any(|i| matches!(i, Due::Late(..))) {
            check_window(tx, &tid, &ak)?;
        }
        let recheck = items.iter().filter_map(|i| match i {
            Due::Recheck(c, ai) => Some((*c, *ai)),
            _ => None,
        });
        let bodies: BTreeSet<(CommitId, usize)> = judged.into_iter().chain(recheck).collect();
        for (c, ai) in bodies {
            if tx.core.ix.commits.get(&c).and_then(|m| m.header.aspects.get(ai)).is_some_and(|a| a.retention.at_most.rel.is_some()) {
                check_at_most(tx, &c, ai)?;
            }
        }
    }
    Ok(())
}

pub(crate) fn load_deaths_due(tx: &mut Tx<'_>) -> Result<()> {
    let mut v = Vec::new();
    tx.scan(records::DEATHS_DUE, |k, _| {
        let mut r = Rd::new(k);
        v.push((r.tid()?, r.ak()?));
        Ok(())
    })?;
    for k in v {
        tx.core.ix.deaths_due.insert(k, Due::Full);
    }
    Ok(())
}

/// Deaths of `(tid, ak)` from scratch (`replay_all`), then its keep-at-most bounds again: after
/// a validity flip, a snapshot or import, an open, or late deltas `window` cannot judge.
pub(crate) fn rejudge_deaths(tx: &mut Tx<'_>, tid: &Tid, ak: &Ak) -> Result<()> {
    if first_bounded(tx.core, tid, ak).is_some() {
        replay_all(tx, tid, ak)?;
    }
    recheck_at_most(tx, tid, ak)
}

/// Joins `f` into `st`, collecting its deaths. A snapshot's (`copies`) copy of a write already
/// dead in the replay is not dated again (two snapshots carrying a write whose own commit is
/// not held: the later one would date it at a later winner): a death whose stamp died before
/// and that the snapshot holds a write of (`holds_stamp`; not merely a record keyed by its dot,
/// such as an entry it removed: a write sharing a dead write's stamp then dies here for the
/// first time, order seed 7855).
fn join(st: &mut Fragment, f: Fragment, copies: bool, deaths: &mut Vec<Death>, dead: &mut BTreeSet<Stamp>) {
    let mut ch = Changes::new();
    let g = copies.then(|| f.clone());
    st.join_into(f, None, &mut ch);
    for d in ch.into_deaths() {
        if let Some(g) = &g
            && dead.contains(&d.stamp)
            && g.holds_stamp(&d.stamp)
        {
            continue;
        }
        dead.insert(d.stamp.clone());
        deaths.push(d);
    }
}

/// Each write dies at the earliest `ts` among the applied commits superseding it (spec/crdt.md
/// §4.8): the held bodies and residues are joined in `(ts, ID)` order (valid writes only; a
/// snapshot's or import's copies of writes whose own commit is held or has a residue removed, so
/// they play at their own commit), then the state (live writes of dropped bodies without a
/// residue); a write dies at the first join superseding it. Every held body with a relative
/// bound gets the first and last of its writes' deaths. A function of the held bodies, the
/// residues and the state. Cost: the aspect's held bodies, residues and whole state.
fn replay_all(tx: &mut Tx<'_>, tid: &Tid, ak: &Ak) -> Result<()> {
    let got = replayed(tx, tid, ak)?;
    let held: Vec<CommitId> = tx.core.ix.by_aspect.get(&(*tid, ak.clone())).into_iter().flatten().map(|x| x.1).collect();
    for c in &held {
        let Some(ai) = bounded_part(tx.core, c, tid, ak) else { continue };
        set_deaths(tx, tid, ak, c, ai, got.get(&(*c, ai)).copied())?;
    }
    Ok(())
}

/// `replay_all`'s deaths per held bounded body.
fn replayed(tx: &mut Tx<'_>, tid: &Tid, ak: &Ak) -> Result<BTreeMap<(CommitId, usize), (Ts, Ts)>> {
    let held: Vec<CommitId> = tx.core.ix.by_aspect.get(&(*tid, ak.clone())).into_iter().flatten().map(|x| x.1).collect();
    let invalid = crate::apply::invalid_of(tx.core, tid, ak);
    let res = residues(tx, tid, ak)?;
    let mut st = Fragment::default();
    let mut deaths = Vec::new();
    let mut dead = BTreeSet::new();
    for c in &held {
        if crate::apply::validity::invalid_snapshot(tx.core, c, tid, ak) {
            continue;
        }
        let parts: Vec<Fragment> = match held_part(tx.core, c, tid, ak) {
            Some(ai) => {
                let _s = crate::costs::span("deaths: read bodies");
                crate::apply::held_parts(tx, c, ai)?.into_iter().map(Decoded::into_fragment).collect()
            }
            None => res.get(c).cloned().into_iter().collect(),
        };
        let _s = crate::costs::span("deaths: join");
        let cp = copies(tx.core, c);
        for mut f in parts {
            let core = &*tx.core;
            f.remove_dots(&|d| invalid.iter().any(|o| o.owns(d)));
            if cp {
                f.remove_writes(&|d| core.commit_of(tid, ak, d).is_some_and(|x| x != *c && (held_part(core, &x, tid, ak).is_some() || res.contains_key(&x))));
            }
            join(&mut st, f, cp, &mut deaths, &mut dead);
        }
    }
    {
        let _s = crate::costs::span("deaths: state");
        tx.load(tid, ak)?;
        if let Some(Some(cur)) = tx.core.states.get(&(*tid, ak.clone())).cloned() {
            join(&mut st, cur, false, &mut deaths, &mut dead);
        }
    }
    let mut got: BTreeMap<(CommitId, usize), (Ts, Ts)> = BTreeMap::new();
    for d in &deaths {
        for k in carriers(tx.core, tid, ak, &d.stamp.dot, d.at) {
            let e = got.entry(k).or_insert((d.at, d.at));
            *e = (e.0.min(d.at), e.1.max(d.at));
        }
    }
    Ok(got)
}

fn set_deaths(tx: &mut Tx<'_>, tid: &Tid, ak: &Ak, c: &CommitId, ai: usize, d: Option<(Ts, Ts)>) -> Result<()> {
    let Some(h) = tx.core.ix.commits.get(c).map(|m| m.header.clone()) else { return Ok(()) };
    let (body, _) = body_class(tx.core, &h, c, ai);
    let d = d.map(|(first, last)| osis_store::Deaths { first, last });
    let old = tx.txn.death(tid, ak, &body)?;
    if old == d {
        return Ok(());
    }
    // node-sync judges again only the bodies whose deaths moved
    if tx.core.changed.is_some() {
        tx.core.mark_changed(*c);
    }
    tx.txn.set_death(tid, ak, &body, d)?;
    put_last(tx, tid, ak, c, old.map(|x| x.last), d.map(|x| x.last))
}

fn death_of(tx: &mut Tx<'_>, tid: &Tid, ak: &Ak, c: &CommitId, ai: usize) -> Result<Option<osis_store::Deaths>> {
    let Some(h) = tx.core.ix.commits.get(c).map(|m| m.header.clone()) else { return Ok(None) };
    let (body, _) = body_class(tx.core, &h, c, ai);
    Ok(tx.txn.death(tid, ak, &body)?)
}

/// Deaths of the bodies the late writer deltas in `items` can change, from a replay of the
/// aspect's bodies (held, or a residue) from the first of those bodies to the latest death they
/// can have, then the snapshots and imports after it, then the state if a dropped body there
/// has no residue (as `replay_all`); the bodies judged, or `None` when that window cannot judge
/// them (a snapshot or import among them, or at or after its start with a death after the first
/// late `ts`).
///
/// Exact (the records before the batch being exact): a write dies only at a greater stamp, so a
/// late delta L changes only bodies sorting at or before it, and only their writes that died
/// after its `ts` (their last death is later) or were live (its join killed them: `Killed`);
/// its own writes die at or before the winner its join met (`Hint`); and their writes a replay
/// dated at a write it plays after its stamp (`strays_from`), which L may now claim first (a
/// held snapshot between that stamp and L may then gain a death: `None`; and when the winner
/// L's join met may be such a write, a replay meets it later, so the window runs to the last
/// body). A snapshot or import sorting after L carries older writes: L may date one of them earlier, before the snapshot,
/// which then loses that death; one with no death after L's `ts` has none to lose. Every write
/// of a body in the window dies at the same superseder as in a replay of every body, since
/// nothing before the window's start supersedes it. Cost: the bodies from the first judged one
/// to the latest death among them, the snapshots and imports after it, the state where a
/// dropped body has no residue, plus the held records before the last late delta (under 64)
/// or the last-death rows from the first late `ts` (or the lowest stray stamp), plus
/// `strays_from`'s.
fn window(tx: &mut Tx<'_>, tid: &Tid, ak: &Ak, items: &[Due]) -> Result<Option<Vec<(CommitId, usize)>>> {
    let late: Vec<(Ts, CommitId)> = items.iter().filter_map(|i| if let Due::Late(t, c) = i { Some((*t, *c)) } else { None }).collect();
    let (Some(t_min), Some(t_max)) = (late.iter().map(|x| x.0).min(), late.iter().map(|x| x.0).max()) else { return Ok(Some(Vec::new())) };
    if first_bounded(tx.core, tid, ak).is_none() {
        return Ok(Some(Vec::new()));
    }
    if unkilled_drops(tx.core, tid, ak, t_min) {
        return Ok(None);
    }
    let k = (*tid, ak.clone());
    let mut u = t_max;
    let mut judge: BTreeMap<(Ts, CommitId), usize> = BTreeMap::new();
    // bodies at or before a late delta with a death after the first one
    let before: Vec<(Ts, CommitId)> = tx.core.ix.by_aspect.get(&k).into_iter().flat_map(|s| s.range(..=(t_max, HI))).take(LASTS_MIN).copied().collect();
    // a copy playing after its stamp may have dated a death before `t_min` that a late delta
    // now claims first: bodies dying from the lowest such stamp are judged too
    let stray = strays_from(tx, tid, ak, t_min, t_max)?;
    let lo = stray.map_or(t_min, |s| s.min(t_min));
    // a stray dated a write before a held snapshot that carries it, and a late delta after it
    // may now: the snapshot gains that death, from no record or one before `lo`
    if let Some(s) = stray.filter(|s| *s <= t_max)
        && tx.core.ix.copies.get(&k).into_iter().flat_map(|x| x.range((s, LO)..=(t_max, HI))).any(|(_, c)| bounded_part(tx.core, c, tid, ak).is_some())
    {
        return Ok(None);
    }
    if lo < t_min {
        drop(crate::costs::span(if lo == Ts::default() { "deaths: window strays, every body" } else { "deaths: window strays" }));
    }
    let dying: Vec<(Ts, Ts, CommitId)> = if before.len() < LASTS_MIN {
        // few bodies before: their records, without loading the index
        let mut v = Vec::new();
        for (ts, c) in before {
            if let Some(ai) = bounded_part(tx.core, &c, tid, ak)
                && let Some(d) = death_of(tx, tid, ak, &c, ai)?
            {
                v.push((d.last, ts, c));
            }
        }
        v
    } else {
        dying_after(tx, tid, ak, lo)?
    };
    let dying = dying.into_iter().filter(|x| (x.0 > t_min || (lo < t_min && x.0 >= lo)) && x.1 <= t_max);
    for (last, ts, c) in dying {
        let Some(ai) = bounded_part(tx.core, &c, tid, ak) else { continue };
        judge.insert((ts, c), ai);
        u = u.max(last);
    }
    // bodies whose live writes a late delta killed, and the late deltas
    let named: BTreeSet<CommitId> = items.iter().filter_map(|i| if let Due::Killed(c) | Due::Late(_, c) = i { Some(*c) } else { None }).collect();
    for c in named {
        let Some(ai) = bounded_part(tx.core, &c, tid, ak) else { continue };
        let Some(ts) = tx.core.ix.commits.get(&c).map(|m| m.header.ts) else { continue };
        if let Some(d) = death_of(tx, tid, ak, &c, ai)? {
            u = u.max(d.last);
        }
        judge.insert((ts, c), ai);
    }
    let hint = items.iter().filter_map(|i| if let Due::Hint(t) = i { Some(*t) } else { None }).max();
    if let Some(h) = hint {
        u = u.max(h);
    }
    // the winner a late delta's join met may be a stray, which a replay meets later (after
    // other superseders, or with the state): its own writes may die past the hint, so the
    // window plays every body after its start
    if stray.is_some_and(|s| hint.is_some_and(|h| s <= h))
        && let Some(&(last, _)) = tx.core.ix.by_aspect.get(&k).and_then(|x| x.last())
    {
        u = u.max(last);
    }
    let Some(&(t_start, _)) = judge.keys().next() else { return Ok(Some(Vec::new())) };
    // A snapshot's or import's record spans every write it carries, from before the window too:
    // one judged, or one at or after the window's start with a death after the first late
    // `ts` (a late delta may date a write it carries earlier, before it), replays whole. One
    // dying by then keeps its record (only those it carries live a late delta can kill, and
    // those name it `Killed`); its copies play at its position (`replay_all`).
    if judge.keys().any(|(_, c)| copies(tx.core, c)) {
        return Ok(None);
    }
    let after: Vec<(Ts, CommitId)> = tx.core.ix.copies.get(&k).into_iter().flat_map(|s| s.range((t_start, LO)..)).copied().collect();
    for (_, s) in &after {
        if let Some(ai) = bounded_part(tx.core, s, tid, ak)
            && death_of(tx, tid, ak, s, ai)?.is_some_and(|d| d.last > t_min)
        {
            return Ok(None);
        }
    }
    // the bodies through `u`, then the snapshots and imports after it: a copy's own commit may
    // be one never held, with a stamp in the window
    let mut fold: Vec<(Ts, CommitId)> = tx.core.ix.by_aspect.get(&k).into_iter().flat_map(|s| s.range((t_start, LO)..=(u, HI))).copied().collect();
    fold.extend(after.iter().filter(|x| x.0 > u));
    let snaps: Vec<(Ts, CommitId)> = fold.iter().filter(|x| copies(tx.core, &x.1)).copied().collect();
    let play = playing_copies(tx, tid, ak, t_start, &snaps)?;
    let invalid = crate::apply::invalid_of(tx.core, tid, ak);
    let mut st = Fragment::default();
    let mut deaths = Vec::new();
    let mut dead = BTreeSet::new();
    // whether a copy's own commit plays it (held, or a residue), per commit
    let mut plays: HashMap<CommitId, bool> = HashMap::new();
    let mut gone = false;
    for (ts, c) in &fold {
        if crate::apply::validity::invalid_snapshot(tx.core, c, tid, ak) {
            continue;
        }
        let cp = copies(tx.core, c);
        if cp && !play.contains(c) {
            drop(crate::costs::span("deaths: window skips copies"));
            #[cfg(debug_assertions)]
            plays_nothing(tx, tid, ak, c, t_start, &invalid)?;
            continue;
        }
        if cp {
            drop(crate::costs::span("deaths: window over copies"));
        }
        let parts: Vec<Fragment> = match held_part(tx.core, c, tid, ak) {
            Some(ai) => crate::apply::held_parts(tx, c, ai)?.into_iter().map(Decoded::into_fragment).collect(),
            None => match tx.txn.get_local(&records::dropped_key(tid, ak, *ts, c))? {
                Some(b) => vec![crate::engine::state::decode(&b)?],
                None => {
                    // its live writes are in the state
                    gone = true;
                    Vec::new()
                }
            },
        };
        for mut f in parts {
            if cp {
                let own = std::cell::RefCell::new(BTreeSet::new());
                let core = &*tx.core;
                f.holds_dots(&|d| {
                    if let Some(x) = core.commit_of(tid, ak, d).filter(|x| x != c) {
                        own.borrow_mut().insert(x);
                    }
                    false
                });
                for x in own.into_inner() {
                    if let std::collections::hash_map::Entry::Vacant(e) = plays.entry(x) {
                        let p = held_part(tx.core, &x, tid, ak).is_some() || tx.core.ix.commits.get(&x).map(|m| m.header.ts).map(|t| tx.txn.get_local(&records::dropped_key(tid, ak, t, &x))).transpose()?.flatten().is_some();
                        e.insert(p);
                    }
                }
            }
            let core = &*tx.core;
            f.remove_dots(&|d| invalid.iter().any(|o| o.owns(d)));
            if cp {
                f.remove_writes(&|d| core.commit_of(tid, ak, d).is_some_and(|x| x != *c && plays.get(&x).copied().unwrap_or(false)));
            }
            join(&mut st, f, cp, &mut deaths, &mut dead);
        }
    }
    if gone {
        let _s = crate::costs::span("deaths: window with the state");
        // as `replay_all`: the live writes of dropped bodies without a residue
        tx.load(tid, ak)?;
        if let Some(Some(cur)) = tx.core.states.get(&k).cloned() {
            join(&mut st, cur, false, &mut deaths, &mut dead);
        }
    }
    let judged: BTreeSet<(CommitId, usize)> = judge.iter().map(|((_, c), ai)| (*c, *ai)).collect();
    let mut got: BTreeMap<(CommitId, usize), (Ts, Ts)> = BTreeMap::new();
    for d in &deaths {
        for k in carriers(tx.core, tid, ak, &d.stamp.dot, d.at) {
            if judged.contains(&k) {
                let e = got.entry(k).or_insert((d.at, d.at));
                *e = (e.0.min(d.at), e.1.max(d.at));
            }
        }
    }
    for (c, ai) in &judged {
        set_deaths(tx, tid, ak, c, *ai, got.get(&(*c, *ai)).copied())?;
    }
    Ok(Some(judged.into_iter().collect()))
}

/// Whether a dropped body of `(tid, ak)` sorts between `t_min` and an invalid commit or a
/// snapshot carrying invalid writes after it. A dropped body's write is gone from the state; an
/// invalid one un-merged is too, so a dead body's residue whose killer turned invalid is live in
/// a replay (it supersedes a late delta's writes) but absent from the state the late delta's join
/// met: no hint bounds where it dies (walks seeds 40558, 40797). Cost: the aspect's invalid parts
/// and carried groups, then its commits from `t_min` to the last of them (in memory).
fn unkilled_drops(core: &Core, tid: &Tid, ak: &Ak, t_min: Ts) -> bool {
    let k = (*tid, ak.clone());
    let ts_of = |c: &CommitId| core.ix.commits.get(c).map(|m| m.header.ts);
    let invalid = core.ix.invalid.get(&k).into_iter().flatten().filter(|c| {
        core.ix.commits.get(c).is_some_and(|m| m.header.aspects.iter().position(|a| a.tid == *tid && a.ak == *ak).is_some_and(|ai| !m.valid.get(ai).copied().unwrap_or(false)))
    });
    let carried = core.ix.carried.get(&k).into_iter().flatten().filter(|g| !g.invalid.is_empty()).map(|g| &g.snap);
    let Some(last) = invalid.chain(carried).filter_map(ts_of).filter(|t| *t >= t_min).max() else { return false };
    core.ix.by_aspect.get(&k).into_iter().flat_map(|s| s.range((t_min, LO)..=(last, HI))).any(|(_, c)| held_part(core, c, tid, ak).is_none())
}

/// Debug builds, after a window (also one that judged nothing): every held bounded body of
/// `(tid, ak)` dated as a whole replay dates it, and the last-death rows are the records'.
#[cfg(debug_assertions)]
fn check_window(tx: &mut Tx<'_>, tid: &Tid, ak: &Ak) -> Result<()> {
    let want = replayed(tx, tid, ak)?;
    let held: Vec<CommitId> = tx.core.ix.by_aspect.get(&(*tid, ak.clone())).into_iter().flatten().map(|x| x.1).collect();
    for c in held {
        let Some(ai) = bounded_part(tx.core, &c, tid, ak) else { continue };
        let have = death_of(tx, tid, ak, &c, ai)?.map(|d| (d.first, d.last));
        debug_assert!(have == want.get(&(c, ai)).copied(), "window deaths of {c:?} on {tid:?} {ak:?}: {have:?}, a whole replay {:?}", want.get(&(c, ai)));
    }
    let fresh = fresh_rows(tx, tid, ak)?;
    debug_assert!(rows_from(tx, tid, ak, Ts::default())? == Some(fresh), "last deaths of {tid:?} {ak:?} differ from the records");
    Ok(())
}

/// The lowest stamp of a write of `(tid, ak)` that a replay plays after a late delta at
/// `t_min` although it sorts before it: a copy in a snapshot or import sorting after `t_min`
/// whose own commit does not play it (never held: `Core::carried`; a commit-form source not
/// playing its own, `Core::authors`; a node-form commit dropped without a residue), or a live
/// write of a commit dropped without a residue (the state plays last). A whole replay dates a
/// write such a one superseded at the late delta when that also supersedes it and plays first,
/// so a body whose last death is from that stamp may change though it died before `t_min`
/// (walks seed 7204), and a held snapshot between the stamp and the late delta may gain the
/// death (`None` from the window; the retention.rs differential, seed 1018). `None` also when no
/// held bounded body sorts at or before `t_max`. A dropped snapshot after `t_min` gives its residue's stamps; an import
/// after it, or a snapshot or import dropped without a residue from the first held bounded body
/// (its copies play with the state), the lowest `Ts` (`first_bare`). `None`: no such write.
/// Cost: `first_bare`'s (cached), and with a snapshot or import after `t_min`: those, a residue
/// read per dropped one, the carried groups and the thing's commit-form sources (a residue read
/// per one of the aspect not held).
fn strays_from(tx: &mut Tx<'_>, tid: &Tid, ak: &Ak, t_min: Ts, t_max: Ts) -> Result<Option<Ts>> {
    let k = (*tid, ak.clone());
    // only a held bounded body sorting before a late delta can change
    if first_bounded(tx.core, tid, ak).is_none_or(|f| f.0 > t_max) {
        return Ok(None);
    }
    let mut lo: Option<Ts> = None;
    let mut low = |t: Ts| lo = Some(lo.map_or(t, |l| l.min(t)));
    // commits dropped without a residue from the first held bounded body (none before it
    // supersedes a write of one): their live writes, or copies, play with the state, last
    if let Some(b) = first_bare(tx, tid, ak)? {
        low(b);
    }
    let snaps: Vec<(Ts, CommitId)> = tx.core.ix.copies.get(&k).into_iter().flat_map(|s| s.range((t_min, LO)..)).copied().collect();
    if snaps.is_empty() {
        return Ok(lo);
    }
    for (ts, s) in &snaps {
        if held_part(tx.core, s, tid, ak).is_some() {
            if tx.core.ix.commits.get(s).is_none_or(|m| !crate::apply::is_kind_snapshot(m.header.kind)) {
                return Ok(Some(Ts::default()));
            }
            continue;
        }
        // dropped: its residue's copies (those whose own commit played them were left out),
        // or with none, the state's
        let Some(b) = tx.txn.get_local(&records::dropped_key(tid, ak, *ts, s))? else { return Ok(Some(Ts::default())) };
        for (_, t) in crate::engine::state::decode(&b)?.writes() {
            match t {
                Some(t) => low(t),
                None => return Ok(Some(Ts::default())),
            }
        }
    }
    if let Some(v) = tx.core.ix.carried.get(&k) {
        for g in v.iter().filter(|g| snaps.iter().any(|x| x.1 == g.snap)) {
            low(g.ts);
        }
    }
    let srcs: Vec<(CommitId, Ts)> = tx.core.ix.authors.range((*tid, LO)..=(*tid, HI)).map(|(k, v)| (k.1, v.1)).collect();
    for (x, ts) in srcs {
        let own = match tx.core.ix.commits.get(&x) {
            None => false,
            Some(m) if m.header.aspects.iter().any(|a| a.tid == *tid && a.ak == *ak) => plays_own(tx, tid, ak, &x)?,
            Some(m) => m.header.aspects.iter().any(|a| a.tid == *tid),
        };
        if !own {
            low(ts);
        }
    }
    Ok(lo)
}

/// Whether `c`'s own position plays its writes on `(tid, ak)`: held, or a residue.
fn plays_own(tx: &mut Tx<'_>, tid: &Tid, ak: &Ak, c: &CommitId) -> Result<bool> {
    if held_part(tx.core, c, tid, ak).is_some() {
        return Ok(true);
    }
    let Some(ts) = tx.core.ix.commits.get(c).map(|m| m.header.ts) else { return Ok(false) };
    Ok(tx.txn.get_local(&records::dropped_key(tid, ak, ts, c))?.is_some())
}

/// The snapshots and imports among `snaps` of `(tid, ak)` whose copies a window starting at
/// `t_start` must play: imports, dropped snapshots (a residue, or none: the state), and the
/// held snapshots that may carry a copy stamped at or after `t_start` whose own commit does
/// not play it (neither held nor a residue). The window
/// removes the copies their own commit plays, and a copy stamped before `t_start` supersedes no
/// write of a body sorting at or after it, the only writes the window dates (a write dies only
/// at a greater stamp, spec/crdt.md §4.8), so playing such a snapshot dates none of them. Such
/// a copy is a write of: a commit never held (`Core::carried`, per snapshot and `ts`); a
/// node-form commit of the aspect at or after `t_start`, dropped without a residue (no later
/// than the snapshot: carried writes are stamped no later than it, spec/crdt.md §8); or a
/// commit-form source of the thing at or after `t_start` (`Core::authors`, a `ts` no lower
/// than its writes') that is not the thing's own commit on another aspect. Cost: the commits of
/// the aspect from `t_start` to the last of `snaps` (in memory; a residue read per dropped one,
/// up to the first without one), the thing's commit-form sources and the carried groups.
fn playing_copies(tx: &mut Tx<'_>, tid: &Tid, ak: &Ak, t_start: Ts, snaps: &[(Ts, CommitId)]) -> Result<BTreeSet<CommitId>> {
    // a dropped snapshot has no carried groups left (`forget_snapshot`): its residue, or the
    // state where it has none, may hold copies of writes never held here
    let mut out: BTreeSet<CommitId> =
        snaps.iter().filter(|x| held_part(tx.core, &x.1, tid, ak).is_none() || tx.core.ix.commits.get(&x.1).is_none_or(|m| !crate::apply::is_kind_snapshot(m.header.kind))).map(|x| x.1).collect();
    let Some(last) = snaps.iter().map(|x| x.0).max() else { return Ok(out) };
    // commit-form sources
    let srcs: Vec<CommitId> = tx.core.ix.authors.range((*tid, LO)..=(*tid, HI)).filter(|(_, v)| v.1 >= t_start).map(|(k, _)| k.1).collect();
    for x in srcs {
        let own = match tx.core.ix.commits.get(&x) {
            None => false,
            Some(m) if m.header.aspects.iter().any(|a| a.tid == *tid && a.ak == *ak) => plays_own(tx, tid, ak, &x)?,
            // the thing's own commit on other aspects: none of its writes is on this one
            Some(m) => m.header.aspects.iter().any(|a| a.tid == *tid),
        };
        if !own {
            out.extend(snaps.iter().map(|x| x.1));
            return Ok(out);
        }
    }
    // the first node-form commit from `t_start` dropped without a residue
    let k = (*tid, ak.clone());
    let range: Vec<(Ts, CommitId)> = tx.core.ix.by_aspect.get(&k).into_iter().flat_map(|s| s.range((t_start, LO)..=(last, HI))).copied().collect();
    let mut bare = None;
    for (ts, c) in range {
        if tx.core.ix.commits.get(&c).is_some_and(|m| m.header.kind.has_own_writes()) && !plays_own(tx, tid, ak, &c)? {
            bare = Some(ts);
            break;
        }
    }
    let carried = tx.core.ix.carried.get(&k);
    for (ts, s) in snaps {
        if bare.is_some_and(|b| b <= *ts) || carried.is_some_and(|v| v.iter().any(|g| g.snap == *s && g.ts >= t_start)) {
            out.insert(*s);
        }
    }
    Ok(out)
}

/// Debug check of a snapshot a window skips (`playing_copies`): with the copies their own commit
/// plays and the invalid writes removed, it holds no write stamped at or after `t_start` but the
/// element creations of those commits, which stay as anchors.
#[cfg(debug_assertions)]
fn plays_nothing(tx: &mut Tx<'_>, tid: &Tid, ak: &Ak, c: &CommitId, t_start: Ts, invalid: &[crate::engine::Owned]) -> Result<()> {
    let Some(ai) = held_part(tx.core, c, tid, ak) else { return Ok(()) };
    for mut f in crate::apply::held_parts(tx, c, ai)?.into_iter().map(Decoded::into_fragment) {
        let mut own = BTreeMap::new();
        for (d, _) in f.writes() {
            if let Some(x) = tx.core.commit_of(tid, ak, &d).filter(|x| x != c)
                && !own.contains_key(&x)
            {
                let p = plays_own(tx, tid, ak, &x)?;
                own.insert(x, p);
            }
        }
        let core = &*tx.core;
        f.remove_dots(&|d| invalid.iter().any(|o| o.owns(d)));
        f.remove_writes(&|d| core.commit_of(tid, ak, d).is_some_and(|x| x != *c && own.get(&x).copied().unwrap_or(false)));
        // a played element creation stays as an anchor (sequences): not a copy
        let late: Vec<_> = f.writes().into_iter().filter(|(d, ts)| ts.is_some_and(|t| t >= t_start) && !core.commit_of(tid, ak, d).is_some_and(|x| own.get(&x).copied().unwrap_or(false))).collect();
        debug_assert!(late.is_empty(), "window skipped {c:?} on {tid:?} {ak:?}, which plays {late:?}");
    }
    Ok(())
}

/// Judges the keep-at-most bounds of the held bodies of `(tid, ak)` under a relative bound
/// again: their deaths or live writes may have changed (spec/commits.md §5).
fn recheck_at_most(tx: &mut Tx<'_>, tid: &Tid, ak: &Ak) -> Result<()> {
    let held: Vec<CommitId> = tx.core.ix.by_aspect.get(&(*tid, ak.clone())).into_iter().flatten().map(|x| x.1).collect();
    for c in held {
        let Some(ai) = held_part(tx.core, &c, tid, ak) else { continue };
        if tx.core.ix.commits.get(&c).and_then(|m| m.header.aspects.get(ai)).is_none_or(|a| a.retention.at_most.rel.is_none()) {
            continue;
        }
        check_at_most(tx, &c, ai)?;
    }
    Ok(())
}
