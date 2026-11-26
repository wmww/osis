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
//! A row is its part's replaced-at, exact (`bounds::held_date`): every reader of a dated part's
//! date reads its row (`bounds::dated_replaced_at`), and `date_due` dates again, at a
//! transaction's end, each part whose date the transaction may have moved.
//!
//! What leaving does: a value part is told to commit listeners (`listing`) and marked for
//! sync (its keep bound passed); a fire's body drops. A purge
//! request's header keeps its commit's parts to its purge floor (spec/commits.md §5 Purge), a time
//! no setting moves, as an expiry: a per-part `T_KEPT` timer, armed at the floor when a value part
//! arrives (`on_parts`), and for a fire the walk reaches before it (as a purged fire's listing end,
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
    #[cfg(debug_assertions)]
    tx.core.unchecked_rows.insert((*tid, ak.clone()));
    tx.core.ix.leaving.insert((*tid, ak.clone()), p);
    tx.core.ix.dated.insert((p.1, *tid, ak.clone()), p.0);
    put(tx, ak, &row_key(tid, ak, &p), Some(&[]))
}

fn remove_row(tx: &mut Tx<'_>, tid: &Tid, ak: &Ak, p: Place) -> Result<()> {
    #[cfg(debug_assertions)]
    tx.core.unchecked_rows.insert((*tid, ak.clone()));
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
    #[cfg(debug_assertions)]
    tx.core.unchecked_rows.insert((*tid, ak.clone()));
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
            tx.core.to_date.push(*tid, ak.clone(), true);
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

/// The row of value part `(tid, ak)` of `c`: a held valid part, its own writes live, at its replaced-at
/// (`bounds::held_date`), a purged one at its own `ts`; `None`: no row (not held, invalid, live).
fn row_at(tx: &mut Tx<'_>, c: &CommitId, tid: &Tid, ak: &Ak) -> Result<Option<Ts>> {
    let Some(m) = tx.core.ix.commits.get(c) else { return Ok(None) };
    let Some(ai) = m.aspect(tid, ak) else { return Ok(None) };
    if !m.valid_at(ai) {
        return Ok(None);
    }
    let h = m.header.clone();
    if m.holds(ai) && !m.own_gone(ai) {
        return super::bounds::held_date(tx, c, tid, ak);
    }
    Ok(super::purged_by(tx, &h, c, ai)?.map(|_| h.ts))
}

/// What of a part its aspect's rows follow: held, valid, and its form (`bounds::Form`: as a
/// leftover, bare).
type Noted = (bool, bool, super::bounds::Form);

/// `Noted` of part `ai` of `m`.
fn noted(m: &crate::engine::Meta, ai: usize) -> Noted {
    (m.holds(ai), m.valid_at(ai), (m.stripped(ai), m.own_gone(ai)))
}

/// Whether a dated aspect's rows may lag its held set in the running transaction: a commit with
/// a part on it changed (`Commits::changed_on`), or it was rebuilt (`ToDate::has`), since the
/// rows were last dated (`date_due`). Two lookups, whatever the transaction changed.
pub(crate) fn dating_due(core: &Core, tid: &Tid, ak: &Ak) -> bool {
    core.to_date.has(tid, ak) || core.ix.commits.changed_on(tid, ak)
}

/// Dated aspects whose every part's replaced-at the running transaction may have moved (a
/// rebuild; `true`: turned dated, a row landing in history told), dated whole at its end
/// (`date_due`): a list cut back to a mark's length by a rollback, and its aspects counted, so
/// `has` is one lookup.
#[derive(Clone, Default)]
pub(crate) struct ToDate {
    list: Vec<(Tid, Ak, bool)>,
    on: BTreeMap<(Tid, Ak), usize>,
    /// How many were pushed in the running transaction, those a pass took included, and on
    /// which aspects (one a rollback cut stays: a superset).
    pushes: usize,
    pushed: BTreeSet<(Tid, Ak)>,
}

impl ToDate {
    pub(crate) fn push(&mut self, tid: Tid, ak: Ak, tell: bool) {
        *self.on.entry((tid, ak.clone())).or_default() += 1;
        self.pushed.insert((tid, ak.clone()));
        self.list.push((tid, ak, tell));
        self.pushes += 1;
    }
    pub(crate) fn len(&self) -> usize {
        self.list.len()
    }
    /// Cuts the list back to its first `n` (a rollback to a mark).
    pub(crate) fn truncate(&mut self, n: usize) {
        for (t, a, _) in self.list.drain(n.min(self.list.len())..) {
            let k = (t, a);
            if let Some(c) = self.on.get_mut(&k) {
                *c -= 1;
                if *c == 0 {
                    self.on.remove(&k);
                }
            }
        }
    }
    /// The list, emptied.
    pub(crate) fn take(&mut self) -> Vec<(Tid, Ak, bool)> {
        self.on.clear();
        std::mem::take(&mut self.list)
    }
    pub(crate) fn clear(&mut self) {
        self.take();
        self.pushes = 0;
        self.pushed.clear();
    }
    /// Whether `(tid, ak)` was pushed since the transaction began, taken or not.
    pub(crate) fn pushed(&self, tid: &Tid, ak: &Ak) -> bool {
        self.pushed.contains(&(*tid, ak.clone()))
    }
    /// How many were pushed since the transaction began (`clear`), taken or not.
    pub(crate) fn pushes(&self) -> usize {
        self.pushes
    }
    /// Whether `(tid, ak)` is listed. Debug builds check it against the list.
    pub(crate) fn has(&self, tid: &Tid, ak: &Ak) -> bool {
        let has = self.on.contains_key(&(*tid, ak.clone()));
        debug_assert_eq!(has, self.list.iter().any(|(t, a, _)| t == tid && a == ak), "to_date's count of {tid:?} {ak:?}");
        has
    }
}

/// At a transaction's end: each dated aspect's rows follow its held set, so a row is its part's
/// replaced-at (`bounds::held_date`), exact. Every changed aspect's held writes, dated or not,
/// are brought up to date with the commits the transaction changed (`bounds::settle_index`: each body joined or left
/// costs its own writes and those whose death it moves), and the parts rowed again are the
/// changed ones and those whose date that moved (`Core::dates_moved`): O(what the change
/// supersedes), whatever the aspect's history. Where the aspect was rebuilt (`Core::to_date`: a
/// validity flip, an un-merge) or turned dated (`true`, also on a dated aspect with no cursor
/// yet: a row landing in history is told), every part is rowed again: O(the aspect's parts) row
/// reads, no body read but to build held writes it has none of. A row that moves is marked for
/// node-sync, and told where it crosses the clock; the cursor moves back past a row that lands
/// in history before it; each aspect touched rearms. A transaction's end dates twice: the held
/// writes say which bodies they hold, so a later pass follows what changed since the earlier.
/// Debug builds check each row written against the state (`bounds::whole_date`).
pub(crate) fn date_due(tx: &mut Tx<'_>) -> Result<()> {
    // per aspect: whole (telling rows landing in history), or the changed commits
    let mut whole: BTreeMap<(Tid, Ak), bool> = BTreeMap::new();
    for (t, a, tell) in tx.core.to_date.take() {
        *whole.entry((t, a)).or_default() |= tell;
    }
    let mut changed: BTreeMap<(Tid, Ak), BTreeSet<CommitId>> = BTreeMap::new();
    for (id, old) in tx.core.ix.commits.before() {
        let new = tx.core.ix.commits.get(id);
        let Some(view) = new.or(old).map(|m| m.view.clone()) else { continue };
        for (ai, a) in view.aspects.iter().enumerate() {
            if a.ak.signal() {
                continue;
            }
            #[cfg(debug_assertions)]
            tx.core.unchecked_rows.insert((a.tid, a.ak.clone()));
            if old.map(|m| noted(m, ai)) != new.map(|m| noted(m, ai)) {
                changed.entry((a.tid, a.ak.clone())).or_default().insert(*id);
            }
        }
    }
    // a signal's fires are placed by their own `ts`, never dated
    for (t, a, c) in tx.core.bodies_rewritten.iter().chain(&tx.core.dates_moved).filter(|x| !x.1.signal()) {
        changed.entry((*t, a.clone())).or_default().insert(*c);
    }
    let keys: BTreeSet<(Tid, Ak)> = whole.keys().chain(changed.keys()).cloned().collect();
    let now = tx.now().0;
    for (tid, ak) in keys {
        let k = history::of(tx.core, &tid, &ak);
        let key = (tid, ak.clone());
        // kept by a setting with no cursor: turned dated in this transaction (before
        // `settings_changed` gave it one), its rows not kept so far
        let fresh = k.keeps() && !tx.core.ix.leave_from.contains_key(&key);
        let tell = if fresh { Some(true) } else { whole.get(&key).copied() };
        let every = |core: &Core| -> BTreeSet<CommitId> {
            let mut on: BTreeSet<CommitId> = core.ix.by_aspect.get(&key).into_iter().flatten().map(|x| x.1).collect();
            on.extend(core.ix.leaving.get(&key).into_iter().flatten().map(|p| p.1));
            on
        };
        super::bounds::settle_index(tx, &tid, &ak)?;
        let on: BTreeSet<CommitId> = if !k.dated() {
            tx.core.ix.leaving.get(&key).into_iter().flatten().map(|p| p.1).collect()
        } else if tell.is_some() {
            every(tx.core)
        } else {
            let mut on = changed.remove(&key).unwrap_or_default();
            on.extend(tx.core.dates_moved.iter().filter(|x| x.0 == tid && x.1 == ak).map(|x| x.2));
            on
        };
        for c in on {
            let old = tx.core.ix.dated.get(&(c, tid, ak.clone())).copied();
            let new = if k.dated() { row_at(tx, &c, &tid, &ak)? } else { None };
            if old == new {
                continue;
            }
            drop(osis_base::costs::span("leaving: row dated"));
            #[cfg(debug_assertions)]
            if k.dated() {
                check_row(tx, &c, &tid, &ak, new)?;
            }
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
        rearm(tx, &tid, &ak, &k)?;
    }
    Ok(())
}

/// Debug builds: row `new` of held valid part `(tid, ak)` of `c`, dated from the held writes, is
/// its date by the state's deaths (`bounds::whole_date`: the part joined into a copy of the
/// state at its positions). A test hook wrote states no body gives (`Core::unchecked_tx`): no
/// check reads them.
#[cfg(debug_assertions)]
fn check_row(tx: &mut Tx<'_>, c: &CommitId, tid: &Tid, ak: &Ak, new: Option<Ts>) -> Result<()> {
    let Some(m) = tx.core.ix.commits.get(c) else { return Ok(()) };
    let Some(ai) = m.aspect(tid, ak) else { return Ok(()) };
    if tx.core.unchecked_tx || !(m.valid_at(ai) && m.holds(ai) && !m.own_gone(ai)) {
        return Ok(());
    }
    let h = m.header.clone();
    let whole = super::bounds::unseen(tx, |tx| super::bounds::whole_date(tx, &h, c, ai))?;
    assert_eq!(new, whole, "{c:?} on {tid:?} {ak:?}: dated from the held writes vs the state's deaths");
    Ok(())
}

/// Debug builds: the held writes of `(tid, ak)` are those of its held bodies
/// (`bounds::index_exact`), every held part has its row at `row_at` (none where the aspect is
/// not dated), and no other row is left.
#[cfg(debug_assertions)]
fn rows_exact_on(tx: &mut Tx<'_>, key: &(Tid, Ak), when: &str) -> Result<()> {
    let (tid, ak) = (&key.0, &key.1);
    let dated = history::of(tx.core, tid, ak).dated();
    // dates from the held bodies joined from nothing, not from the rows kept
    let fresh = super::bounds::index_exact(tx, tid, ak, when)?;
    let fresh = dated.then_some(fresh);
    let mut on: BTreeSet<CommitId> = tx.core.ix.by_aspect.get(key).into_iter().flatten().map(|x| x.1).collect();
    on.extend(tx.core.ix.leaving.get(key).into_iter().flatten().map(|p| p.1));
    for c in on {
        let want = match (&fresh, tx.core.ix.commits.get(&c).and_then(|m| Some((m, m.aspect(tid, ak)?)))) {
            (Some(f), Some((m, ai))) if m.valid_at(ai) && m.holds(ai) && !m.own_gone(ai) => f.date(&c),
            (Some(_), Some((m, ai))) if m.valid_at(ai) => {
                let h = m.header.clone();
                super::purged_by(tx, &h, &c, ai)?.map(|_| h.ts)
            }
            _ => None,
        };
        assert_eq!(tx.core.ix.dated.get(&(c, *tid, ak.clone())).copied(), want, "{when}: {c:?} on {tid:?} {ak:?}: its row vs its date from the held set");
    }
    Ok(())
}

/// Debug builds, at the end of the engine's history (with the index check, `Engine::check_index`,
/// never per transaction): every held part of each aspect of `keys` (`Core::unchecked_rows`:
/// those whose rows a transaction wrote or should have written since the last check) has its row
/// at `row_at`, and no other row is left, so no dating missed a part whose date moved. Each row
/// written is checked against the state where it is dated (`check_row`), not here.
#[cfg(debug_assertions)]
pub(crate) fn rows_exact(tx: &mut Tx<'_>, keys: &BTreeSet<(Tid, Ak)>) -> Result<()> {
    super::bounds::unseen(tx, |tx| keys.iter().filter(|k| !k.1.signal()).try_for_each(|key| rows_exact_on(tx, key, "end of history")))
}

/// Reads the rows and cursors at open (`apply::load`); a row of a commit no longer held there
/// (its records changed outside the indexes) goes.
pub(crate) fn load(tx: &mut Tx<'_>) -> Result<()> {
    let rows = tx.scan_rows(records::LEAVING, |k, _| {
        let mut r = Rd::new(k);
        let (tid, ak) = (r.tid()?, r.ak()?);
        let ts = Ts::from_u64(r.u64()?).ok_or(Error::Corrupt("leaving row"))?;
        let c = CommitId(r.arr()?);
        r.end()?;
        Ok((tid, ak, (ts, c)))
    })?;
    for (tid, ak, p) in rows {
        if tx.core.ix.commits.get(&p.1).is_some_and(|m| m.aspect(&tid, &ak).is_some()) {
            tx.core.ix.leaving.insert((tid, ak.clone()), p);
            tx.core.ix.dated.insert((p.1, tid, ak), p.0);
        } else {
            put(tx, &ak, &row_key(&tid, &ak, &p), None)?;
        }
    }
    let froms = tx.scan_rows(records::LEAVE_FROM, |k, v| {
        let mut r = Rd::new(k);
        let (tid, ak) = (r.tid()?, r.ak()?);
        let mut r = Rd::new(&v);
        let due = r.u64()?;
        let out = if r.u8()? == 1 { Some((Ts::from_u64(r.u64()?).ok_or(Error::Corrupt("leaving cursor"))?, CommitId(r.arr()?))) } else { None };
        r.end()?;
        Ok(((tid, ak), (due, out)))
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

/// Forgets the held writes and leaving rows of the aspects `keys` (rows of those without a
/// cursor are skipped); a part still held there is dated again at the transaction's end
/// (`date_due`).
pub(crate) fn forget_aspects(tx: &mut Tx<'_>, keys: impl IntoIterator<Item = (Tid, Ak)>) -> Result<()> {
    for (tid, ak) in keys {
        if !ak.signal() {
            super::bounds::drop_index(tx, &tid, &ak)?;
        }
        if !tx.core.ix.leave_from.contains_key(&(tid, ak.clone())) {
            continue;
        }
        #[cfg(debug_assertions)]
        tx.core.unchecked_rows.insert((tid, ak.clone()));
        let rows: Vec<Place> = tx.core.ix.leaving.get(&(tid, ak.clone())).into_iter().flatten().copied().collect();
        for p in rows {
            remove_row(tx, &tid, &ak, p)?;
        }
        set_from(tx, &tid, &ak, None)?;
        tx.core.to_date.push(tid, ak, false);
    }
    Ok(())
}
