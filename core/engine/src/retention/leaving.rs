//! When bodies leave history, as events (spec/commits.md §5 The setting; notes/engine-retention.md
//! Leaving history). Bodies of one aspect of a thing leave in the order they were replaced, so each such
//! aspect keeps the bodies in replaced order, a cursor (every place at or before it is out of
//! history) and one timer, at the leaving of the first place past the cursor
//! (`Indexes::leave_from`, `leave_due`). The places: a signal's fires by `ts` (`by_aspect`: a fire
//! is replaced when written); a value aspect's rows (`Indexes::leaving`), one per held valid
//! part replaced on a dated aspect (`history::Kept::dated`), no earlier than its replaced-at (a purged part
//! at its request's `ts`), kept for parts out of history too (a late setting may bring them
//! back). A window passing walks the places that leave; a setting change those that leave or come
//! back; each once, reading no body and walking none that stays.
//!
//! Rows only time events, never a read: listing, keep bounds and undo judge history from the held
//! set when asked (`bounds`). A row is a schedule never earlier than its part's replaced-at, set
//! where that may move (`date_due`, at a transaction's end, `Dating`): a kill from the killing
//! writes' stamps, no body read, on the dying writes' own commits and every snapshot of the aspect
//! (one carrying none of them gets a row it leaves with nothing to tell); a rebuild and an aspect turning dated from the held set; a part's
//! own change (dropped, stripped, its validity). A late row tells listeners and marks node-sync
//! late, never before the body leaves.
//!
//! What leaving does: a value part is told to commit listeners (`listing`) and marked for
//! node-sync (`Core::mark_changed`: its keep bound passed); a fire's body drops. A purge
//! request's header keeps its commit's parts to its purge floor (spec/commits.md §5 Purge), a time
//! no setting moves, as an expiry: a per-part `T_KEPT` timer, armed at the floor when a value part
//! arrives (`on_parts`), and for a fire the walk reaches before it (as a purged fire's tombstone,
//! `edits::settle`).

use super::{T_KEPT, history};
use crate::engine::records::{self, Rd, Wr};
use crate::engine::{Core, Tx};
use crate::error::{Error, Result};
use osis_base::{Ak, CommitId, Tid, Ts};
use osis_commit::FOREVER;
use osis_store::Shred;
use std::collections::{BTreeMap, BTreeSet};
use std::ops::Bound::{Excluded, Unbounded};

/// A place among an aspect's bodies in replaced order: replaced-at, commit.
pub(crate) type Place = (Ts, CommitId);

/// An aspect's cursor (`Indexes::leave_from`): when its timer is due (`u64::MAX`: none), and the
/// last place known out of history (`None`: none).
pub(crate) type From = (u64, Option<Place>);

fn row_key(tid: &Tid, ak: &Ak, p: &Place) -> Vec<u8> {
    [records::aspect_key(records::LEAVING, tid, ak).as_slice(), &p.0.to_u64().to_be_bytes(), &p.1.0].concat()
}

/// When a body of `k` replaced at `ts` leaves history (wall ms; 0: never in it).
fn leaves(k: &history::Kept, ts: Ts) -> u64 {
    k.leaves_at(Some(ts.wall_ms().0))
}

/// Writes local row `key` (`val`; `None`: removed) in `(tid, ak)`'s class.
fn put(tx: &mut Tx<'_>, tid: &Tid, ak: &Ak, key: &[u8], val: Option<&[u8]>) -> Result<()> {
    let memory = tx.txn.is_memory_aspect(tid, ak);
    tx.in_class(memory, |tx| {
        match val {
            Some(v) => tx.txn.put_local(key, v, Shred::No)?,
            None => drop(tx.txn.remove_local(key, Shred::No)?),
        }
        Ok(())
    })
}

fn put_row(tx: &mut Tx<'_>, tid: &Tid, ak: &Ak, p: Place) -> Result<()> {
    tx.core.ix.leaving.insert((*tid, ak.clone()), p);
    tx.core.ix.dated.insert((p.1, *tid, ak.clone()), p.0);
    put(tx, tid, ak, &row_key(tid, ak, &p), Some(&[]))
}

fn remove_row(tx: &mut Tx<'_>, tid: &Tid, ak: &Ak, p: Place) -> Result<()> {
    tx.core.ix.leaving.remove(&(*tid, ak.clone()), &p);
    tx.core.ix.dated.remove(&(p.1, *tid, ak.clone()));
    put(tx, tid, ak, &row_key(tid, ak, &p), None)
}

/// Sets `(tid, ak)`'s cursor (`None`: the aspect has none: nothing of it leaves in order).
fn set_from(tx: &mut Tx<'_>, tid: &Tid, ak: &Ak, f: Option<From>) -> Result<()> {
    let k = (*tid, ak.clone());
    let old = tx.core.ix.leave_from.get(&k).copied();
    if old == f {
        return Ok(());
    }
    if let Some((due, _)) = old
        && due != u64::MAX
    {
        tx.core.ix.leave_due.remove(&due, &k);
    }
    let key = records::aspect_key(records::LEAVE_FROM, tid, ak);
    match f {
        Some((due, out)) => {
            tx.core.ix.leave_from.insert(k.clone(), (due, out));
            if due != u64::MAX {
                tx.core.ix.leave_due.insert(due, k);
                tx.core.timer_floor = tx.core.timer_floor.min(due);
            }
            let mut w = Wr::new().u64(due).u8(u8::from(out.is_some()));
            if let Some(p) = out {
                w = w.u64(p.0.to_u64()).raw(&p.1.0);
            }
            put(tx, tid, ak, &key, Some(&w.take()))
        }
        None => {
            tx.core.ix.leave_from.remove(&k);
            put(tx, tid, ak, &key, None)
        }
    }
}

/// The places of `(tid, ak)` in replaced order (`range`), a signal's fires or a value aspect's rows.
fn places<'a>(core: &'a Core, tid: &Tid, ak: &Ak) -> Option<&'a BTreeSet<Place>> {
    let k = (*tid, ak.clone());
    if ak.signal() { core.ix.by_aspect.get(&k) } else { core.ix.leaving.get(&k) }
}

/// The first place of `(tid, ak)` past `out`.
fn first_after(core: &Core, tid: &Tid, ak: &Ak, out: Option<Place>) -> Option<Place> {
    let s = places(core, tid, ak)?;
    match out {
        Some(p) => s.range((Excluded(p), Unbounded)).next().copied(),
        None => s.iter().next().copied(),
    }
}

/// Arms `(tid, ak)`'s timer at the leaving of its first place past the cursor (none when it never
/// leaves): O(log places).
fn rearm(tx: &mut Tx<'_>, tid: &Tid, ak: &Ak, k: &history::Kept) -> Result<()> {
    let Some((_, out)) = tx.core.ix.leave_from.get(&(*tid, ak.clone())).copied() else { return Ok(()) };
    let due = first_after(tx.core, tid, ak, out).map(|p| leaves(k, p.0)).filter(|t| *t < FOREVER).unwrap_or(u64::MAX);
    set_from(tx, tid, ak, Some((due, out)))
}

/// Tells that part `(tid, ak)` of `c` left or came back into history: listeners, and node-sync
/// (its keep bound moved past the clock).
fn moved(tx: &mut Tx<'_>, tid: &Tid, ak: &Ak, c: &CommitId) {
    tx.core.mark_changed(*c);
    if crate::engine::listing::listened(tx.core, tid, ak) {
        tx.core.commits_named(*tid, ak.clone(), *c);
    }
}

/// Place `p` of `(tid, ak)` left history at `now` (its timeline's bound passed): a value part is
/// told, a held fire's body drops; a fire its commit's purge floor keeps gets a timer at the floor.
fn left(tx: &mut Tx<'_>, tid: &Tid, ak: &Ak, p: Place, now: u64) -> Result<()> {
    drop(crate::costs::span("leaving: place left"));
    let c = p.1;
    let Some(m) = tx.core.ix.commits.get(&c) else { return Ok(()) };
    let Some(ai) = m.aspect(tid, ak) else { return Ok(()) };
    let h = m.header.clone();
    let held = m.holds(ai);
    #[cfg(debug_assertions)]
    let whole = held && !m.bare(ai) && m.valid_at(ai);
    let floor = osis_commit::retention::purge_keep_until(&h).filter(|t| *t > now);
    if !ak.signal() {
        // never early: a row's part is out of history by a fresh judgment when its row leaves, or
        // not replaced (a snapshot's row set by a kill of writes it does not carry, a text creation
        // revived: a tick that tells nothing new; the death that replaces it sets the row again).
        // A row may be late: an earlier superseder of a dead write arriving moves no row
        #[cfg(debug_assertions)]
        if whole && tx.core.recheck_at((tx.core.tx_store, tx.core.generation, tx.core.memory_generation), format!("leaving {tid:?} {ak:?}")) {
            let fresh = crate::costs::paused(|| super::bounds::fresh_replaced_at(tx, &h, &c, ai))?;
            let k = history::of(tx.core, tid, ak);
            assert!(fresh.is_none_or(|f| leaves(&k, f) <= now), "{c:?} on {tid:?} {ak:?} left at row {p:?} while in history (replaced at {fresh:?})");
        }
        // one its purge floor keeps listed is told again then, by its floor's timer (`on_parts`)
        moved(tx, tid, ak, &c);
        return Ok(());
    }
    if !held {
        return Ok(());
    }
    match floor {
        Some(t) => tx.put_timer(t, &c, ai, T_KEPT),
        None => {
            super::drop_part(tx, &c, ai)?;
            crate::engine::edits::time_passed(tx, &c, ai);
            Ok(())
        }
    }
}

/// Walks `(tid, ak)` from its cursor while places leave by `now` (each `left`), moving the cursor
/// past them; then rearms. O(places that leave).
fn walk(tx: &mut Tx<'_>, tid: &Tid, ak: &Ak, k: &history::Kept, now: u64) -> Result<()> {
    let Some((_, mut out)) = tx.core.ix.leave_from.get(&(*tid, ak.clone())).copied() else { return Ok(()) };
    while let Some(p) = first_after(tx.core, tid, ak, out) {
        if leaves(k, p.0) > now {
            break;
        }
        out = Some(p);
        left(tx, tid, ak, p, now)?;
    }
    let due = tx.core.ix.leave_from.get(&(*tid, ak.clone())).map_or(u64::MAX, |f| f.0);
    set_from(tx, tid, ak, Some((due, out)))?;
    rearm(tx, tid, ak, k)
}

/// `(tid, ak)`'s timer is due: its places leaving by now leave (`walk`).
pub(crate) fn passed(tx: &mut Tx<'_>, tid: &Tid, ak: &Ak) -> Result<()> {
    let k = history::of(tx.core, tid, ak);
    let now = tx.now().0;
    walk(tx, tid, ak, &k, now)
}

/// The aspects whose timers are due by `now`, and when the first of the others is (`u64::MAX`:
/// none).
pub(crate) fn due(core: &Core, now: u64) -> (Vec<(Tid, Ak)>, u64) {
    let due = core.ix.leave_due.range(..=now).flat_map(|(_, s)| s.iter().cloned()).collect();
    let next = core.ix.leave_due.range((Excluded(now), Unbounded)).next().map_or(u64::MAX, |x| *x.0);
    (due, next)
}

/// A fire `p` of signal `(tid, ak)` held, kept past `now` by its timeline: its place joins the
/// walk (before the cursor, the cursor moves back to it).
pub(crate) fn fire_held(tx: &mut Tx<'_>, tid: &Tid, ak: &Ak, p: Place) -> Result<()> {
    let k = history::of(tx.core, tid, ak);
    let now = tx.now().0;
    if leaves(&k, p.0) <= now {
        return Ok(());
    }
    // with no cursor yet every earlier fire is out (each held one kept would have made one)
    let f = match tx.core.ix.leave_from.get(&(*tid, ak.clone())).copied() {
        Some(f) => f,
        None => (u64::MAX, places(tx.core, tid, ak).and_then(|s| s.range(..p).next_back().copied())),
    };
    let out = before(tx.core, tid, ak, f.1, p);
    set_from(tx, tid, ak, Some((f.0, out)))?;
    rearm(tx, tid, ak, &k)
}

/// Cursor `out` with place `p` (in history) past it: the place before `p` when `p` is at or
/// before `out`.
fn before(core: &Core, tid: &Tid, ak: &Ak, out: Option<Place>, p: Place) -> Option<Place> {
    if out.is_none_or(|o| o < p) {
        return out;
    }
    places(core, tid, ak).and_then(|s| s.range(..p).next_back().copied())
}

/// The settings of `tid` changed (`retention::settings_changed`): for aspect `ak`, the places
/// that leave by the new timeline leave, and on a value aspect those it brings back come back
/// (a late setting; walked back from the cursor while in history); the timer rearms. An aspect
/// turning dated has every held part dated (`date_due`, a rare path: O(the aspect's history));
/// one turning undated loses its rows (those in history told, as they leave).
pub(crate) fn settings_changed(tx: &mut Tx<'_>, tid: &Tid, ak: &Ak) -> Result<()> {
    let k = history::of(tx.core, tid, ak);
    let now = tx.now().0;
    let key = (*tid, ak.clone());
    let from = tx.core.ix.leave_from.get(&key).copied();
    if ak.signal() {
        return if from.is_some() { walk(tx, tid, ak, &k, now) } else { Ok(()) };
    }
    match (from, k.dated()) {
        (None, false) => Ok(()),
        (None, true) => {
            let on: Vec<CommitId> = tx.core.ix.by_aspect.get(&key).into_iter().flatten().map(|x| x.1).collect();
            tx.core.to_date.extend(on.into_iter().map(|c| (*tid, ak.clone(), c, Dating::Full(true))));
            set_from(tx, tid, ak, Some((u64::MAX, None)))
        }
        (Some((_, out)), false) => {
            let rows: Vec<Place> = tx.core.ix.leaving.get(&key).into_iter().flatten().copied().collect();
            for p in rows {
                if out.is_none_or(|o| p > o) {
                    moved(tx, tid, ak, &p.1);
                }
                remove_row(tx, tid, ak, p)?;
            }
            set_from(tx, tid, ak, None)
        }
        (Some((due, mut out)), true) => {
            // back from the cursor while in history by the new timeline
            while let Some(p) = out {
                if leaves(&k, p.0) <= now {
                    break;
                }
                drop(crate::costs::span("leaving: place back"));
                moved(tx, tid, ak, &p.1);
                out = tx.core.ix.leaving.get(&key).and_then(|s| s.range(..p).next_back().copied());
            }
            set_from(tx, tid, ak, Some((due, out)))?;
            walk(tx, tid, ak, &k, now)
        }
    }
}

/// How a part's row is set at a transaction's end (`date_due`), weakest first (a part asked for
/// more than once takes the strongest).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Dating {
    /// Its meta changed: its row goes if it is no longer held whole and valid (a purged part's
    /// is its request's `ts`), else stays.
    Kept,
    /// A write of it (or, a snapshot's, maybe of it) died under writes stamped up to this
    /// (`Killed::at`): its row is set no earlier, never moved earlier, no body read.
    Killed(Ts),
    /// Dated from the held set (`bounds::dated_replaced_at`: the aspect's held bodies read once
    /// while they do not change): a rebuild, and every held part of an aspect turning dated (`true`: a row
    /// landing in history is told).
    Full(bool),
}

/// The row of value part `(tid, ak)` of `c` by `how` (`old`: its row now): a held valid part with
/// values by `how`, a purged one at its request's `ts`; `None`: no row (not held, invalid, live
/// when dated whole).
fn row_at(tx: &mut Tx<'_>, c: &CommitId, tid: &Tid, ak: &Ak, how: Dating, old: Option<Ts>) -> Result<Option<Ts>> {
    let Some(m) = tx.core.ix.commits.get(c) else { return Ok(None) };
    let Some(ai) = m.aspect(tid, ak) else { return Ok(None) };
    if !m.valid_at(ai) {
        return Ok(None);
    }
    let h = m.header.clone();
    if m.holds(ai) && !m.bare(ai) {
        return match how {
            Dating::Kept => Ok(old),
            Dating::Killed(t) => Ok(old.max(Some(t))),
            Dating::Full(_) => super::bounds::dated_replaced_at(tx, &h, c, ai),
        };
    }
    let by = super::purged_by(tx, &h, c, ai)?;
    Ok(by.and_then(|b| tx.core.ix.commits.get(&b)).map(|m| m.view.ts))
}

/// At a transaction's end: the rows of the parts whose date may have moved (`Core::to_date`: a
/// kill sets the rows of the dying writes' own commits and the aspect's snapshots no earlier than
/// the killing writes, reading no body; a rebuild and an aspect turning dated date whole, the aspect's held bodies read once for
/// all, `Core::held_writes`), and of every part with a row or stripped whose meta changed. So
/// a row is a schedule that is never early: the date it holds is the part's replaced-at or later
/// (an earlier superseder arriving, or the killing writes stamped after the first superseder,
/// leave it late). A row that moves is marked for node-sync, and told where it crosses the clock;
/// the cursor moves back past a row that lands in history before it; each aspect touched rearms.
pub(crate) fn date_due(tx: &mut Tx<'_>) -> Result<()> {
    let mut items: BTreeMap<(Tid, Ak, CommitId), Dating> = BTreeMap::new();
    for (t, a, c, how) in std::mem::take(&mut tx.core.to_date) {
        let e = items.entry((t, a, c)).or_insert(how);
        *e = (*e).max(how);
    }
    let state = |m: &crate::engine::Meta, ai: usize| (m.valid_at(ai), m.dropped.contains_key(&ai), m.stripped.contains(&ai), m.missing.contains(&ai));
    for (id, old) in tx.core.ix.commits.before() {
        let Some(old) = old else { continue };
        let new = tx.core.ix.commits.get(id);
        for (ai, a) in old.view.aspects.iter().enumerate() {
            if a.ak.signal() || new.is_some_and(|n| state(old, ai) == state(n, ai)) {
                continue;
            }
            let k = (*id, a.tid, a.ak.clone());
            if tx.core.ix.dated.contains_key(&k) || new.is_some_and(|n| n.stripped.contains(&ai)) {
                items.entry((a.tid, a.ak.clone(), *id)).or_insert(Dating::Kept);
            }
        }
    }
    if items.is_empty() {
        return Ok(());
    }
    let now = tx.now().0;
    let mut kept: BTreeMap<(Tid, Ak), history::Kept> = BTreeMap::new();
    for ((tid, ak, c), how) in items {
        if ak.signal() {
            continue;
        }
        let k = kept.entry((tid, ak.clone())).or_insert_with(|| history::of(tx.core, &tid, &ak)).clone();
        let old = tx.core.ix.dated.get(&(c, tid, ak.clone())).copied();
        let new = if k.dated() { row_at(tx, &c, &tid, &ak, how, old)? } else { None };
        if old == new {
            continue;
        }
        drop(crate::costs::span("leaving: row dated"));
        // a part replaced or dropped is told by its own change (`listing_moved`,
        // `commit_changes`); a row dated anew, where it crosses the clock
        let was = old.is_some_and(|o| leaves(&k, o) > now);
        let crossed = (old.is_some() || how == Dating::Full(true)) && was != new.is_some_and(|n| leaves(&k, n) > now);
        if let Some(t) = old {
            remove_row(tx, &tid, &ak, (t, c))?;
        }
        if let Some(t) = new {
            put_row(tx, &tid, &ak, (t, c))?;
            let f = tx.core.ix.leave_from.get(&(tid, ak.clone())).copied().unwrap_or((u64::MAX, None));
            let out = if leaves(&k, t) > now { before(tx.core, &tid, &ak, f.1, (t, c)) } else { f.1 };
            set_from(tx, &tid, &ak, Some((f.0, out)))?;
        }
        tx.core.mark_changed(c);
        if crossed && crate::engine::listing::listened(tx.core, &tid, &ak) {
            tx.core.commits_named(tid, ak.clone(), c);
        }
    }
    for ((tid, ak), k) in kept {
        rearm(tx, &tid, &ak, &k)?;
    }
    Ok(())
}

/// Reads the rows and cursors at open (`apply::load`); a row of a commit no longer held there
/// (its records changed outside the indexes) goes.
pub(crate) fn load(tx: &mut Tx<'_>) -> Result<()> {
    let mut rows = Vec::new();
    tx.scan(records::LEAVING, |k, _| {
        let mut r = Rd::new(k);
        let (tid, ak) = (r.tid()?, r.ak()?);
        let ts = Ts::from_u64(r.u64()?).ok_or(Error::Corrupt("leaving row"))?;
        let c = CommitId(r.arr()?);
        r.end()?;
        rows.push((tid, ak, (ts, c)));
        Ok(())
    })?;
    for (tid, ak, p) in rows {
        if tx.core.ix.commits.get(&p.1).is_some_and(|m| m.aspect(&tid, &ak).is_some()) {
            tx.core.ix.leaving.insert((tid, ak.clone()), p);
            tx.core.ix.dated.insert((p.1, tid, ak), p.0);
        } else {
            put(tx, &tid, &ak, &row_key(&tid, &ak, &p), None)?;
        }
    }
    let mut froms = Vec::new();
    tx.scan(records::LEAVE_FROM, |k, v| {
        let mut r = Rd::new(k);
        let (tid, ak) = (r.tid()?, r.ak()?);
        let mut r = Rd::new(&v);
        let due = r.u64()?;
        let out = if r.u8()? == 1 { Some((Ts::from_u64(r.u64()?).ok_or(Error::Corrupt("leaving cursor"))?, CommitId(r.arr()?))) } else { None };
        r.end()?;
        froms.push(((tid, ak), (due, out)));
        Ok(())
    })?;
    for (k, f) in froms {
        if f.0 != u64::MAX {
            tx.core.ix.leave_due.insert(f.0, k.clone());
        }
        tx.core.ix.leave_from.insert(k, f);
    }
    tx.core.timer_floor = 0;
    Ok(())
}

/// Things `things` forgotten (`forget`): their cursors, rows and settings moves go.
pub(crate) fn forget_things(tx: &mut Tx<'_>, things: &BTreeSet<Tid>) -> Result<()> {
    tx.core.settings_moved.retain(|t, _| !things.contains(t));
    let keys: Vec<(Tid, Ak)> = tx.core.ix.leave_from.keys().filter(|(t, _)| things.contains(t)).cloned().collect();
    for (tid, ak) in keys {
        let rows: Vec<Place> = tx.core.ix.leaving.get(&(tid, ak.clone())).into_iter().flatten().copied().collect();
        for p in rows {
            remove_row(tx, &tid, &ak, p)?;
        }
        set_from(tx, &tid, &ak, None)?;
    }
    Ok(())
}
