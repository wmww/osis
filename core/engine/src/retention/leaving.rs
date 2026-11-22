//! When bodies leave history, as events (spec/commits.md §5 The setting; notes/engine-retention-history.md
//! Leaving history). Bodies of one aspect of a thing leave in the order they were replaced, so each such
//! aspect keeps the bodies in replaced order, a cursor (every place at or before it is out of
//! history) and one timer, at the leaving of the first place past the cursor
//! (`Indexes::leave_from`, `leave_due`). The places: a signal's fires by `ts` (`by_aspect`: a fire
//! is replaced when written); a value aspect's rows (`Indexes::leaving`), one per held valid
//! part replaced on a dated aspect (`history::Kept::dated`), at its replaced-at (a purged part
//! at its own `ts`), kept for parts out of history too (a late setting may bring them
//! back). A window passing walks the places that leave; a setting change those that leave or come
//! back; each once, reading no body and walking none that stays.
//!
//! A row is its part's replaced-at, exact (`bounds::index_date`): every reader of a dated part's
//! date reads its row (`bounds::dated_replaced_at`), and `date_due` dates again, at a
//! transaction's end, each part whose date the transaction may have moved.
//!
//! What leaving does: a value part is told to commit listeners (`listing`) and marked for
//! sync (its keep bound passed); a fire's body drops. A purge
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

/// When a body of `k` replaced at `ts` leaves history (wall ms): the first time at or after its
/// replacement at which the current setting does not keep it (spec/commits.md §5 The setting), so
/// places leave in replaced order whatever the clock. `leaves_at` reads one replaced under no
/// history as out at once (0), also when replaced ahead of the clock; here it leaves at its
/// replacement, which only tells it late, never early. A body under the setting's floor (out when
/// replaced) is scheduled as one above it, so told late, never early: the order stays one cursor.
fn leaves(k: &history::Kept, ts: Ts) -> u64 {
    let r = ts.wall_ms().0;
    k.leaves_at(Some(r), Ts::MAX).max(r)
}

/// Writes local row `key` (`val`; `None`: removed) in `ak`'s class.
fn put(tx: &mut Tx<'_>, ak: &Ak, key: &[u8], val: Option<&[u8]>) -> Result<()> {
    let memory = ak.ephemeral();
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
    put(tx, ak, &row_key(tid, ak, &p), Some(&[]))
}

fn remove_row(tx: &mut Tx<'_>, tid: &Tid, ak: &Ak, p: Place) -> Result<()> {
    tx.core.ix.leaving.remove(&(*tid, ak.clone()), &p);
    tx.core.ix.dated.remove(&(p.1, *tid, ak.clone()));
    put(tx, ak, &row_key(tid, ak, &p), None)
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
            put(tx, ak, &key, Some(&w.take()))
        }
        None => {
            tx.core.ix.leave_from.remove(&k);
            put(tx, ak, &key, None)
        }
    }
}

/// The places of `(tid, ak)` in replaced order (`range`), a signal's fires or a value aspect's rows.
fn places<'a>(core: &'a Core, tid: &Tid, ak: &Ak) -> Option<&'a BTreeSet<Place>> {
    let k = (*tid, ak.clone());
    if ak.signal() { core.ix.by_aspect.get(&k) } else { core.ix.leaving.get(&k) }
}

/// Whether value part `(tid, ak)` of `c` is out of history: its row at or before the cursor.
pub(crate) fn out_of_history(core: &Core, c: &CommitId, tid: &Tid, ak: &Ak) -> bool {
    let Some(ts) = core.ix.dated.get(&(*c, *tid, ak.clone())) else { return false };
    core.ix.leave_from.get(&(*tid, ak.clone())).and_then(|f| f.1).is_some_and(|last| (*ts, *c) <= last)
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
    if crate::engine::listing::listened(tx.core, tid, ak) {
        tx.core.commits_named(*tid, ak.clone(), *c);
    }
}

/// Place `p` of `(tid, ak)` left history at `now` (its setting's bound passed): a value part is
/// told, a held fire's body drops; a fire its commit's purge floor keeps gets a timer at the floor.
fn left(tx: &mut Tx<'_>, tid: &Tid, ak: &Ak, p: Place, now: u64) -> Result<()> {
    drop(osis_base::costs::span("leaving: place left"));
    let c = p.1;
    let Some(m) = tx.core.ix.commits.get(&c) else { return Ok(()) };
    let Some(ai) = m.aspect(tid, ak) else { return Ok(()) };
    let h = m.header.clone();
    let held = m.holds(ai);
    let floor = osis_commit::retention::purge_keep_until(&h).filter(|t| *t > now);
    if !ak.signal() {
        // one its purge floor keeps listed is told again then, by its floor's timer (`on_parts`)
        moved(tx, tid, ak, &c);
        // out of history it counts for the compaction trigger, as when applied
        if held {
            let memory = tx.is_memory_commit(&c);
            tx.in_class(memory, |tx| match tx.get_commit(&c)? {
                Some(blob) => crate::retention::compact::Trigger::counts(tx, &c, tid, ak, &blob, ai),
                None => Ok(()),
            })?;
        }
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

/// Signal `(tid, ak)` lost a fire: with none left held its cursor goes (every fire held later is
/// placed afresh, `fire_held`), so a signal leaves no row once its fires are gone.
pub(crate) fn unplaced(tx: &mut Tx<'_>, tid: &Tid, ak: &Ak) -> Result<()> {
    if !ak.signal() || places(tx.core, tid, ak).is_some_and(|s| !s.is_empty()) {
        return Ok(());
    }
    set_from(tx, tid, ak, None)
}

/// The aspects whose timers are due by `now`, and when the first of the others is (`u64::MAX`:
/// none).
pub(crate) fn due(core: &Core, now: u64) -> (Vec<(Tid, Ak)>, u64) {
    let due = core.ix.leave_due.range(..=now).flat_map(|(_, s)| s.iter().cloned()).collect();
    let next = core.ix.leave_due.range((Excluded(now), Unbounded)).next().map_or(u64::MAX, |x| *x.0);
    (due, next)
}

/// A fire `p` of signal `(tid, ak)` held, kept past `now` by its setting: its place joins the
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
/// that leave by the new setting leave, and on a value aspect those it brings back come back
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
            tx.core.to_date.push((*tid, ak.clone(), true));
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
            // back from the cursor while in history by the new setting
            while let Some(p) = out {
                if leaves(&k, p.0) <= now {
                    break;
                }
                drop(osis_base::costs::span("leaving: place back"));
                moved(tx, tid, ak, &p.1);
                out = tx.core.ix.leaving.get(&key).and_then(|s| s.range(..p).next_back().copied());
            }
            set_from(tx, tid, ak, Some((due, out)))?;
            walk(tx, tid, ak, &k, now)
        }
    }
}

/// A part's date (`bounds::index_date`, or `held_date` unchecked).
type DateOf = fn(&mut Tx<'_>, &osis_commit::Header, &CommitId, usize) -> Result<Option<Ts>>;

/// The row of value part `(tid, ak)` of `c`: a held valid part with values at its replaced-at
/// (`date`), a purged one at its own `ts`; `None`: no row (not held, invalid, live).
fn row_at(tx: &mut Tx<'_>, c: &CommitId, tid: &Tid, ak: &Ak, date: DateOf) -> Result<Option<Ts>> {
    let Some(m) = tx.core.ix.commits.get(c) else { return Ok(None) };
    let Some(ai) = m.aspect(tid, ak) else { return Ok(None) };
    if !m.valid_at(ai) {
        return Ok(None);
    }
    let h = m.header.clone();
    if m.holds(ai) && !m.bare(ai) {
        return date(tx, &h, c, ai);
    }
    Ok(super::purged_by(tx, &h, c, ai)?.map(|_| h.ts))
}

/// What of a part the aspect's held writes note (`bounds::HeldWrites`): held, valid, bare.
pub(crate) type Noted = (bool, bool, bool);

/// `Noted` of part `ai` of `m`.
fn noted(m: &crate::engine::Meta, ai: usize) -> Noted {
    (m.holds(ai), m.valid_at(ai), m.bare(ai))
}

/// Whether a dated aspect's rows may lag its held set in the running transaction: a commit with
/// a part on it changed, or it was rebuilt, since the rows were last dated (`date_due`).
pub(crate) fn dating_due(core: &Core, tid: &Tid, ak: &Ak) -> bool {
    core.to_date.iter().any(|(t, a, _)| t == tid && a == ak)
        || core.ix.commits.before().into_iter().any(|(c, old)| core.ix.commits.get(c).into_iter().chain(old).any(|m| m.aspect(tid, ak).is_some()))
}

/// At a transaction's end: each dated aspect's rows follow its held set, so a row is its part's
/// replaced-at (`bounds::index_date`), exact. On an aspect the transaction only added noted
/// bodies to (applied, a late part come, turned valid), the parts dated again are the changed
/// ones and those whose writes the new bodies' writes may date anew (`bounds::moved_by_joins`):
/// O(what they supersede), whatever the aspect's history. Where a noted body left or changed
/// (dropped, stripped, turned invalid), the aspect was rebuilt (`Core::to_date`) or turned dated
/// (`true`, also on a dated aspect with no cursor yet: a row landing in history is told), every
/// part is dated again: O(the aspect's
/// history), as the rebuild. A row that moves is marked for node-sync, and told where it crosses
/// the clock; the cursor moves back past a row that lands in history before it; each aspect
/// touched rearms. A transaction's end dates twice: a later pass compares each part with what an
/// earlier one dated (`Core::dated_as`). Debug builds check every row of each aspect dated
/// incrementally (`rows_exact`).
pub(crate) fn date_due(tx: &mut Tx<'_>) -> Result<()> {
    // per aspect: whole (telling rows landing in history), or the changed and joined commits
    let mut whole: BTreeMap<(Tid, Ak), bool> = BTreeMap::new();
    for (t, a, tell) in std::mem::take(&mut tx.core.to_date) {
        *whole.entry((t, a)).or_default() |= tell;
    }
    let mut changed: BTreeMap<(Tid, Ak), (BTreeSet<CommitId>, Vec<CommitId>)> = BTreeMap::new();
    // what an earlier pass of this transaction dated, else the meta before it
    let seen: BTreeMap<(CommitId, usize), Noted> = tx.core.dated_as.iter().map(|(c, ai, n)| ((*c, *ai), *n)).collect();
    let mut now_as = Vec::new();
    for (id, old) in tx.core.ix.commits.before() {
        let new = tx.core.ix.commits.get(id);
        let Some(view) = new.or(old).map(|m| m.view.clone()) else { continue };
        for (ai, a) in view.aspects.iter().enumerate() {
            if a.ak.signal() {
                continue;
            }
            let k = (a.tid, a.ak.clone());
            let was = match seen.get(&(*id, ai)) {
                Some(n) => Some(*n),
                None => old.map(|m| noted(m, ai)),
            };
            let is = new.map(|m| noted(m, ai));
            if let Some(n) = is {
                now_as.push((*id, ai, n));
            }
            if was == is {
                continue;
            }
            let e = changed.entry(k.clone()).or_default();
            e.0.insert(*id);
            // a noted body left or changed: writes may have left the held set
            if was.is_some_and(|w| w.0 && w.1) {
                whole.entry(k).or_default();
            } else if is.is_some_and(|w| w.0 && w.1) {
                e.1.push(*id);
            }
        }
    }
    tx.core.dated_as.extend(now_as);
    let keys: BTreeSet<(Tid, Ak)> = whole.keys().chain(changed.keys()).cloned().collect();
    let now = tx.now().0;
    for (tid, ak) in keys {
        let k = history::of(tx.core, &tid, &ak);
        let key = (tid, ak.clone());
        // kept by a setting with no cursor: turned dated in this transaction (before
        // `settings_changed` gave it one), its rows not kept so far
        let fresh = k.keeps() && !tx.core.ix.leave_from.contains_key(&key);
        let tell = if fresh { Some(true) } else { whole.get(&key).copied() };
        let on: BTreeSet<CommitId> = if !k.dated() {
            tx.core.ix.leaving.get(&key).into_iter().flatten().map(|p| p.1).collect()
        } else if tell.is_some() {
            let mut on: BTreeSet<CommitId> = tx.core.ix.by_aspect.get(&key).into_iter().flatten().map(|x| x.1).collect();
            on.extend(tx.core.ix.leaving.get(&key).into_iter().flatten().map(|p| p.1));
            on
        } else {
            let (ch, joined) = changed.remove(&key).unwrap_or_default();
            let mut on = super::bounds::moved_by_joins(tx, &tid, &ak, &joined)?;
            on.extend(ch);
            on
        };
        for c in on {
            let old = tx.core.ix.dated.get(&(c, tid, ak.clone())).copied();
            let new = if k.dated() { row_at(tx, &c, &tid, &ak, super::bounds::index_date)? } else { None };
            if old == new {
                continue;
            }
            drop(osis_base::costs::span("leaving: row dated"));
            // a part replaced or dropped is told by its own change (`listing_moved`,
            // `commit_changes`); a row dated anew, where it crosses the clock
            let was = old.is_some_and(|o| leaves(&k, o) > now);
            let crossed = (old.is_some() || tell == Some(true)) && was != new.is_some_and(|n| leaves(&k, n) > now);
            if let Some(t) = old {
                remove_row(tx, &tid, &ak, (t, c))?;
            }
            if let Some(t) = new {
                put_row(tx, &tid, &ak, (t, c))?;
                let f = tx.core.ix.leave_from.get(&key).copied().unwrap_or((u64::MAX, None));
                let out = if leaves(&k, t) > now { before(tx.core, &tid, &ak, f.1, (t, c)) } else { f.1 };
                set_from(tx, &tid, &ak, Some((f.0, out)))?;
            }
            if crossed && crate::engine::listing::listened(tx.core, &tid, &ak) {
                tx.core.commits_named(tid, ak.clone(), c);
            }
        }
        if fresh && !tx.core.ix.leave_from.contains_key(&key) {
            set_from(tx, &tid, &ak, Some((u64::MAX, None)))?;
        }
        // dated whole, every part was just dated (checked against the state, `index_date`)
        #[cfg(debug_assertions)]
        if k.dated() && tell.is_none() {
            super::bounds::unseen(tx, |tx| rows_exact(tx, &tid, &ak))?;
        }
        rearm(tx, &tid, &ak, &k)?;
    }
    Ok(())
}

/// Every held part of dated `(tid, ak)` has its row at `row_at`, and no other row is left: an
/// incremental dating missed nothing. Each part's date is checked against the state where it
/// is dated, not here.
#[cfg(debug_assertions)]
fn rows_exact(tx: &mut Tx<'_>, tid: &Tid, ak: &Ak) -> Result<()> {
    let key = (*tid, ak.clone());
    let mut on: BTreeSet<CommitId> = tx.core.ix.by_aspect.get(&key).into_iter().flatten().map(|x| x.1).collect();
    on.extend(tx.core.ix.leaving.get(&key).into_iter().flatten().map(|p| p.1));
    for c in on {
        let want = row_at(tx, &c, tid, ak, super::bounds::held_date)?;
        assert_eq!(tx.core.ix.dated.get(&(c, *tid, ak.clone())).copied(), want, "{c:?} on {tid:?} {ak:?}: its row vs its date from the held set");
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
            put(tx, &ak, &row_key(&tid, &ak, &p), None)?;
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

/// Forgets the leaving rows of the aspects `keys` (those without a cursor are skipped); a part
/// still held there is dated again at the transaction's end (`date_due`).
pub(crate) fn forget_aspects(tx: &mut Tx<'_>, keys: impl IntoIterator<Item = (Tid, Ak)>) -> Result<()> {
    for (tid, ak) in keys {
        if !tx.core.ix.leave_from.contains_key(&(tid, ak.clone())) {
            continue;
        }
        let rows: Vec<Place> = tx.core.ix.leaving.get(&(tid, ak.clone())).into_iter().flatten().copied().collect();
        for p in rows {
            remove_row(tx, &tid, &ak, p)?;
        }
        set_from(tx, &tid, &ak, None)?;
        tx.core.to_date.push((tid, ak, false));
    }
    Ok(())
}
