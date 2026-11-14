//! A held body's keep-at-least bound and whether it holds a live write (spec/commits.md §5).

use super::{aspect_index, bounded, gone_of, held_part, known_part, writes_of};
#[cfg(test)]
use super::oracle;
use crate::engine::{Core, Engine, Tx};
use crate::error::{Error, Result};
use osis_base::{Ak, CommitId, Tid, Ts};
use osis_commit::Header;
use osis_crdt::{ByWrite, Fragment, Winners, Won};
use std::collections::BTreeSet;
use std::sync::Arc;

/// `Engine::delta_live` in `tx` (`Core::live_bodies`).
pub(crate) fn delta_live(tx: &mut Tx<'_>, c: &CommitId, tid: &Tid, ak: &Ak) -> Result<bool> {
    let key = (*c, *tid, ak.clone());
    osis_base::memo::Memo::get_in(tx, |tx| &tx.core.live_bodies, &key, |tx| delta_live_read(tx, &key))
}

/// `delta_live` read anew: an unknown commit counts live (its apply may change nothing here).
fn delta_live_read(tx: &mut Tx<'_>, (c, tid, ak): &(CommitId, Tid, Ak)) -> Result<bool> {
    let Some(ai) = aspect_index(tx.core, c, tid, ak) else { return Ok(true) };
    let r = live(tx, c, ai)?;
    #[cfg(test)]
    assert_eq!(r, oracle::live(tx, c, ai)?, "live streamed vs whole");
    Ok(r)
}

/// Before which wall ms delta `a` of `h` leaves only by purge
/// request or expiry (spec/commits.md §5 Keep bounds; 0: no floor): the later of when it leaves
/// history (`history::Kept::leaves_at`, replaced at wall ms `replaced`; `None`: not replaced) and
/// the purge-request floor.
pub(crate) fn kept_until(core: &Core, h: &Header, a: &osis_commit::AspectEntry, replaced: Option<u64>) -> u64 {
    super::history::of(core, &a.tid, &a.ak).leaves_at(replaced).max(osis_commit::retention::purge_keep_until(h).unwrap_or(0))
}

/// Whether `s` is a snapshot whose part on `(tid, ak)` this node holds whole (received, not
/// dropped or held as its leftover) and judges valid: one that may stand for the aspect's
/// history (spec/commits.md §5 Purge).
pub(crate) fn valid_snapshot_held(core: &Core, s: &CommitId, tid: &Tid, ak: &Ak) -> bool {
    let Some(m) = core.ix.commits.get(s) else { return false };
    m.view.kind.is_compaction() && m.aspect(tid, ak).is_some_and(|ai| !m.body_gone(ai) && !m.missing(ai) && m.valid_at(ai))
}

/// `Engine::part_keeps` of part `(tid, ak)` of `c` in `tx`: before which wall ms it leaves only
/// by purge or expiry, a replacement dated ahead of the clock included (`at_clock`): from then
/// any node may drop it as covered (spec/commits.md §5 Keep bounds).
pub(crate) fn part_keep(tx: &mut Tx<'_>, c: &CommitId, tid: &Tid, ak: &Ak) -> Result<u64> {
    let (ai, h) = known_part(tx.core, c, tid, ak)?;
    tx.core.replaced_reads += 1;
    let b = part_bounds(tx, &h, c, ai)?;
    Ok(at_clock(tx.core, b))
}

/// What history and the purge floor keep of part `(tid, ak)` of `c` (its own aspect's setting at
/// its own replacement, without `at_clock`): what a listing shows of it (spec/commits.md §7
/// Listed parts).
pub(crate) fn body_history_keep(tx: &mut Tx<'_>, c: &CommitId, tid: &Tid, ak: &Ak) -> Result<u64> {
    let (ai, h) = known_part(tx.core, c, tid, ak)?;
    tx.core.replaced_reads += 1;
    let r = part_replaced_at(tx, &h, c, ai)?.map(|t| t.wall_ms().0);
    Ok(h.aspects.get(ai).map_or(0, |a| kept_until(tx.core, &h, a, r)))
}

/// Whether part `ai` of `c` is in kept history by its thing's setting alone at wall ms `now`
/// (spec/commits.md §7 Undo): replaced, while in history (`Kept::leaves_at`); live, while kept
/// while live (`live_keep`). Neither the purge floor nor the clock counts, nor whether the body
/// is still held: what undo may take back is the setting's alone.
pub(crate) fn setting_keeps(tx: &mut Tx<'_>, c: &CommitId, ai: usize, now: u64) -> Result<bool> {
    let h = tx.core.ix.commits.get(c).ok_or(Error::UnknownCommit(*c))?.header.clone();
    let Some(a) = h.aspects.get(ai) else { return Ok(false) };
    let until = match part_replaced_at(tx, &h, c, ai)? {
        Some(r) => super::history::of(tx.core, &a.tid, &a.ak).leaves_at(Some(r.wall_ms().0)),
        None => live_keep(tx.core, c, ai, a),
    };
    Ok(until > now)
}

/// The keep bound of part `ai` of `c` but for the clock: its own aspect's timeline at its own
/// replacement (`part_replaced_at`, spec/commits.md §5 Dated only where history is kept), and
/// that replacement (wall ms, 0: none) for `at_clock`. A part's date and keep read only its
/// aspect's writes and setting, so no other part of its commit keeps it (a purge-on-replace part
/// goes under its cover whatever its commit's kept parts keep), a covered drop on one aspect
/// moves no other part's bound, and a part on an aspect no setting keeps has none. A part not
/// replaced is kept while live where its aspect's setting says so (`live_keep`).
fn part_bounds(tx: &mut Tx<'_>, h: &Header, c: &CommitId, ai: usize) -> Result<(u64, u64)> {
    let Some(a) = h.aspects.get(ai) else { return Ok((0, 0)) };
    let r = part_replaced_at(tx, h, c, ai)?.map(|t| t.wall_ms().0);
    let k = kept_until(tx.core, h, a, r);
    let k = if r.is_none() { k.max(live_keep(tx.core, c, ai, a)) } else { k };
    Ok((k, r.unwrap_or(0)))
}

/// Until when part `ai` of `c` (`a`), not dated as replaced, is kept while live (spec/commits.md
/// §5 Kept while live): its aspect's `history::Kept::live_until` for a held valid delta with
/// values, not a snapshot's or a signal's; 0 for any other. On an aspect some setting keeps
/// history (`bounded`), a part `part_replaced_at` dates nothing of is live; on any other
/// `live_until` is 0 but for fixed retention, whose parts are dated (role) or never out.
pub(crate) fn live_keep(core: &Core, c: &CommitId, ai: usize, a: &osis_commit::AspectEntry) -> u64 {
    let Some(m) = core.ix.commits.get(c) else { return 0 };
    if m.view.kind.is_compaction() || a.ak.signal() || !m.holds(ai) || m.bare(ai) || !m.valid_at(ai) {
        return 0;
    }
    super::history::of(core, &a.tid, &a.ak).live_until()
}

/// A keep bound and replacement (`part_bounds`) at the node's clock: a body replaced after the
/// clock is kept until the clock reaches it (spec/commits.md §5 Keep bounds: a body leaves history
/// no earlier than replaced). Only a dated part has a replacement (`part_replaced_at`): where no
/// setting keeps history for its aspect nothing is dated and it adds no bound.
fn at_clock(core: &Core, (k, last): (u64, u64)) -> u64 {
    if last > core.now().0 { k.max(last) } else { k }
}

/// `part_bounds` of every part of `c`, by aspect index (`Engine::part_keeps`). A memo
/// (`Core::part_bounds`): the clock is read after it, so a bound holds while what it read does.
fn commit_bounds(tx: &mut Tx<'_>, c: &CommitId) -> Result<Arc<Vec<(u64, u64)>>> {
    let h = tx.core.ix.commits.get(c).ok_or(Error::UnknownCommit(*c))?.header.clone();
    tx.core.replaced_reads += 1;
    let mut out = Vec::with_capacity(h.aspects.len());
    for ai in 0..h.aspects.len() {
        out.push(part_bounds(tx, &h, c, ai)?);
    }
    Ok(Arc::new(out))
}

/// The writes that win in part `f` (`Fragment::winners`): one walk, counted
/// (`Core::death_walks`).
pub(super) fn winners_of(tx: &mut Tx<'_>, f: &Fragment) -> Winners {
    tx.core.death_walks += 1;
    f.winners()
}

/// When part `ai` of held commit `c` was replaced, for a relative keep at least (spec/commits.md
/// §5 Bodies and deaths): a function of the held set, judged when asked, never stored, and never
/// of how a part is paged (`deaths` judges it whole). Only its own writes date it, and only
/// where some setting keeps history for its aspect (`bounded`; elsewhere no history is at stake,
/// so a covered body drops at once whatever other aspects keep): a part on another aspect, kept
/// or not, neither dates it nor is dated by it (Fathom: a setting governs its aspect's data). A
/// signal's part is replaced at its own `ts`. Otherwise `dated_replaced_at`.
fn part_replaced_at(tx: &mut Tx<'_>, h: &Header, c: &CommitId, ai: usize) -> Result<Option<Ts>> {
    let Some(a) = h.aspects.get(ai) else { return Ok(None) };
    // a signal's body is replaced when written (spec/commits.md §5 Signals)
    if a.ak.signal() {
        return Ok(Some(h.ts));
    }
    if !bounded(tx.core, &a.tid, &a.ak) {
        return Ok(None);
    }
    dated_replaced_at(tx, h, c, ai)
}

/// When part `ai` of `c` was replaced, whatever its aspect's bounds (also what purge on replace
/// asks, `replace::under_purge`). A write of the held valid part is dead when it wins in the part
/// and not once the part joins the state (spec/crdt.md §4.8, `Fragment::winners`); it died at the
/// earliest `ts` among the held valid writes superseding it alone, read from any held body other
/// than `c` holding one (`HeldWrites::holds`: its own commit, or a snapshot carrying it), by the
/// write's own `ts` wherever it is read (a valid snapshot's copy of a write whose own delta is
/// held invalid counts as the write itself, spec/crdt.md §4.8 When). The part is replaced at the
/// latest of its writes' deaths, a snapshot's leaving out those a held valid snapshot stamped
/// later holds as winners (`HeldWrites::carried`: that one keeps their history); `None`: no such
/// write is dead, so it is past a relative bound. So a cover dropping a body redates nothing in
/// history: no date is read from which body holds a write, the cover carries the body's live
/// writes with their stamps, and any write it alone dated was replaced no later than it
/// (notes/engine-retention-dating.md Invariant). A node holding more bodies
/// dates no later. Invalid parts and bare leftovers (no values to keep) are not judged. A memo
/// (`Core::replaced_dates`): judged again only when what it read moved (the aspect's held
/// bodies, their validity and the state), the aspect's held bodies read once for every
/// judgment until then (`held_writes`).
pub(super) fn dated_replaced_at(tx: &mut Tx<'_>, h: &Header, c: &CommitId, ai: usize) -> Result<Option<Ts>> {
    let Some(a) = h.aspects.get(ai) else { return Ok(None) };
    if a.ak.signal() {
        return Ok(Some(h.ts));
    }
    osis_base::memo::Memo::get_in(tx, |tx| &tx.core.replaced_dates, &(*c, ai), |tx| judge_replaced_at(tx, h, c, ai))
}

/// `dated_replaced_at` judged anew.
fn judge_replaced_at(tx: &mut Tx<'_>, h: &Header, c: &CommitId, ai: usize) -> Result<Option<Ts>> {
    let Some(a) = h.aspects.get(ai) else { return Ok(None) };
    let (tid, ak) = (a.tid, a.ak.clone());
    if held_part(tx.core, c, &tid, &ak) != Some(ai) || tx.core.ix.commits.get(c).is_none_or(|m| m.bare(ai) || !m.valid_at(ai)) {
        return Ok(None);
    }
    let mut dead = deaths(tx, c, ai, &tid, &ak)?;
    #[cfg(test)]
    assert_eq!(dead, oracle::deaths(tx, c, ai, &tid, &ak)?, "deaths at the part's positions vs the whole state");
    if dead.is_empty() {
        return Ok(None);
    }
    let held = held_writes(tx, &tid, &ak)?;
    if h.kind.is_compaction() {
        dead.retain(|w| !held.carried.get(w).is_some_and(|v| v.iter().any(|(t, x)| *t > h.ts && x != c)));
    }
    // the state is the join of the held bodies (un-merged, spec/crdt.md §4.6) and the part's own
    // writes supersede none of its winners, so another body holds each superseder, dated by its
    // own stamp whichever body holds it
    let date = |s: &osis_crdt::Stamp, v: &Vec<(Ts, CommitId)>| v.iter().any(|x| x.1 != *c).then_some(s.ts);
    let mut out: Option<Ts> = None;
    for w in &dead {
        let d = held.holds.first_superseding(w, date).ok_or(Error::Corrupt("a dead write no other held body supersedes"))?;
        out = out.max(Some(d));
    }
    Ok(out)
}

/// What `dated_replaced_at` reads of the held bodies of an aspect, by write (`osis_crdt::ByWrite`).
#[derive(Clone, Debug, Default, PartialEq)]
pub(crate) struct HeldWrites {
    /// The aspect's held commits read (`Indexes::by_aspect`) and those with a part invalid here
    /// (`Indexes::invalid`): each body's writes below are a function of the body and its
    /// validity alone, so a body joining adds its own (`amend_held_writes`).
    bodies: Vec<(Ts, CommitId)>,
    invalid: BTreeSet<CommitId>,
    /// The writes each held body holds, winning there or not (`Fragment::held_writes`), as the
    /// state joins it (an invalid delta's writes left out, a valid snapshot's body whole, an
    /// invalid snapshot's giving nothing): the two earliest such bodies by `(ts, ID)`, so one is not
    /// the body judged.
    holds: ByWrite<Vec<(Ts, CommitId)>>,
    /// The writes each held valid snapshot with values holds as winners: its `ts` and ID, in
    /// that order.
    carried: ByWrite<Vec<(Ts, CommitId)>>,
}

/// `HeldWrites` of `(tid, ak)`, through `Core::held_writes` (a memo): read anew, or, when the
/// aspect only gained bodies since, amended by theirs (`amend_held_writes`), so a join reads its
/// own body, not the aspect's.
pub(super) fn held_writes(tx: &mut Tx<'_>, tid: &Tid, ak: &Ak) -> Result<Arc<HeldWrites>> {
    osis_base::memo::Memo::get_amended_in(
        tx,
        |tx| &tx.core.held_writes,
        &(*tid, ak.clone()),
        |tx| read_held_writes(tx, tid, ak).map(Arc::new),
        |tx, old| Ok(amend_held_writes(tx, tid, ak, old)?.map(Arc::new)),
    )
}

/// The commits with a part of `(tid, ak)` invalid here, and its held commits: what
/// `amend_held_writes` compares, read inside `memo::accounted`.
fn aspect_bodies(core: &Core, tid: &Tid, ak: &Ak) -> (BTreeSet<CommitId>, Vec<(Ts, CommitId)>) {
    let k = (*tid, ak.clone());
    osis_base::memo::accounted(|| (core.ix.invalid.get(&k).cloned().unwrap_or_default(), core.ix.by_aspect.get(&k).into_iter().flatten().cloned().collect()))
}

/// `HeldWrites` of `(tid, ak)` read anew: every held body of the aspect, each part whole.
pub(super) fn read_held_writes(tx: &mut Tx<'_>, tid: &Tid, ak: &Ak) -> Result<HeldWrites> {
    let (invalid, on) = aspect_bodies(tx.core, tid, ak);
    let mut out = HeldWrites { bodies: on.clone(), invalid, ..HeldWrites::default() };
    for (ts, x) in on {
        note_body(tx, tid, ak, ts, x, &mut out)?;
    }
    Ok(out)
}

/// `old` brought up to date when the aspect's held commits only grew and none of `old`'s flipped
/// (`HeldWrites::invalid`, read at both): each new body's writes noted, what a fresh read gives.
/// `None` (read it anew) when a commit left the aspect or an old one's validity moved. The
/// aspect's commits and invalid parts are its accounted reads (`aspect_bodies`): any other move
/// of what `old` read (a held body's part dropped, a late part come, a rollback of records)
/// reads it anew.
fn amend_held_writes(tx: &mut Tx<'_>, tid: &Tid, ak: &Ak, old: &HeldWrites) -> Result<Option<HeldWrites>> {
    let (invalid, on) = aspect_bodies(tx.core, tid, ak);
    // both sorted: each of `old.bodies` still held, the rest new
    let mut was = old.bodies.iter().peekable();
    let mut new = Vec::new();
    for x in &on {
        match was.peek() {
            Some(w) if *w == x => {
                was.next();
            }
            Some(w) if *w < x => return Ok(None),
            _ => new.push(*x),
        }
    }
    if was.next().is_some() {
        return Ok(None);
    }
    // the old commits invalid now are those invalid then
    if !invalid.iter().filter(|c| !new.iter().any(|x| x.1 == **c)).eq(old.invalid.iter()) {
        return Ok(None);
    }
    let mut out = old.clone();
    out.bodies = on;
    out.invalid = invalid;
    for (ts, x) in new {
        note_body(tx, tid, ak, ts, x, &mut out)?;
    }
    Ok(Some(out))
}

/// Notes held body `(ts, x)` of `(tid, ak)` in `out` (`HeldWrites`), its part read whole; an
/// invalid part gives nothing (un-merge takes all an invalid delta's body carries, `apply::rebuilt`).
fn note_body(tx: &mut Tx<'_>, tid: &Tid, ak: &Ak, ts: Ts, x: CommitId, out: &mut HeldWrites) -> Result<()> {
    let Some(xai) = held_part(tx.core, &x, tid, ak) else { return Ok(()) };
    let Some(m) = tx.core.ix.commits.get(&x) else { return Ok(()) };
    if !m.valid_at(xai) {
        return Ok(());
    }
    let snap = m.header.kind.is_compaction();
    let carries = snap && !m.bare(xai);
    let Some(f) = crate::apply::held_fragment(tx, &x, xai)? else { return Ok(()) };
    drop(osis_base::costs::span("deaths: a body"));
    if carries {
        out.carried.note(&f.winners(), |_, v| {
            v.push((ts, x));
            v.sort();
        });
    }
    out.holds.note(&f.held_writes(), |_, v| {
        v.push((ts, x));
        v.sort();
        v.truncate(2);
    });
    Ok(())
}

/// The writes of held part `ai` of `c` the state supersedes (spec/crdt.md §4.8): the part's
/// winners that do not win once it joins, whole, a copy of the state at its positions
/// (`Tx::state_part_at`: O(part), whatever the state's size).
fn deaths(tx: &mut Tx<'_>, c: &CommitId, ai: usize, tid: &Tid, ak: &Ak) -> Result<BTreeSet<Won>> {
    let Some(f) = crate::apply::held_fragment(tx, c, ai)? else { return Ok(BTreeSet::new()) };
    let Some(mut st) = tx.state_part_at(tid, ak, &f)? else { return Ok(BTreeSet::new()) };
    let mine = winners_of(tx, &f);
    st.join(f);
    let joined = winners_of(tx, &st);
    Ok(mine.minus(&joined))
}

/// The aspect index of `(tid, ak)` in `c` if that part is held with values (a bare leftover has
/// no values to keep: `Meta::bare`), for an aspect with a relative bound (`bounded`).
fn bounded_part(core: &Core, c: &CommitId, tid: &Tid, ak: &Ak) -> Option<usize> {
    held_part(core, c, tid, ak).filter(|ai| core.ix.commits.get(c).is_some_and(|m| !m.bare(*ai)))
}

/// The writes joins on an aspect superseded (spec/crdt.md §4.8), for `mark_killed`: by dot, or
/// `all` when a join is not judged write by write (a reset joined by pages); `at`, the latest
/// stamp among the writes winning where one died: no earlier than any of their deaths (each dead
/// write's superseder wins there, or is beaten by a later winner), so a date never early.
#[derive(Debug, Default)]
pub(crate) struct Killed {
    pub dots: BTreeSet<osis_crdt::Dot>,
    pub all: bool,
    pub at: Option<Ts>,
}

impl Killed {
    /// Notes the writes the join of `d` into `st` superseded: `before`, the winners of `st` at
    /// `d`'s reach and of `d` (`Killed::before`), against `st` after the join.
    pub(crate) fn note(&mut self, before: &Winners, st: &Fragment, d: &Fragment) {
        let after = st.reach(d).winners();
        let dead = before.minus(&after);
        if !dead.is_empty() {
            self.at = self.at.max(after.iter().map(|w| w.stamp.ts).max());
            self.dots.extend(dead.into_iter().map(|w| w.stamp.dot));
        }
    }
    /// What `note` compares with: the winners `st ⊔ d` may supersede.
    pub(crate) fn before(st: &Fragment, d: &Fragment) -> Winners {
        let mut w = st.reach(d).winners();
        w.extend(d.winners());
        w
    }
}

/// A join on `(tid, ak)` superseded `dead`: the held bodies with a relative bound it may have
/// replaced (the dying writes' own commits, and the aspect's snapshots, which may carry them) are
/// judged again by node-sync (`Core::changed`), and the history row of each is set no earlier
/// than `Killed::at` (`Core::to_date`, `Dating::Killed`: no body read; a snapshot whether or not it
/// carries a dying write, as telling which would read it); with `Killed::all`, every one dated
/// whole (`mark_bounded`).
/// On any aspect the dying writes' own commits are marked and become cover candidates: a body
/// kept while live may not be now (`live_keep`); with `Killed::all`, every held body of the
/// aspect (a reset joined by pages: rare).
pub(crate) fn mark_killed(tx: &mut Tx<'_>, tid: &Tid, ak: &Ak, dead: &Killed) {
    if dead.all {
        return mark_bounded(tx, tid, ak);
    }
    if dead.dots.is_empty() {
        return;
    }
    let core = &*tx.core;
    let owners: BTreeSet<CommitId> = dead.dots.iter().filter_map(|d| core.commit_of(tid, ak, d)).collect();
    let mut on = owners.clone();
    on.extend(core.ix.snapshots.get(&(*tid, ak.clone())).into_iter().flatten().map(|x| x.1));
    crate::engine::listing::note_killed(tx, tid, ak, &on);
    for c in &owners {
        tx.core.mark_changed(*c);
    }
    let held: Vec<CommitId> = owners.iter().copied().filter(|c| super::held_part(tx.core, c, tid, ak).is_some()).collect();
    tx.core.cover_candidates.entry((*tid, ak.clone())).or_default().extend(held);
    if !bounded(tx.core, tid, ak) {
        return;
    }
    for c in on {
        if bounded_part(tx.core, &c, tid, ak).is_some() {
            tx.core.mark_changed(c);
            if let Some(t) = dead.at {
                tx.core.to_date.push((*tid, ak.clone(), c, super::leaving::Dating::Killed(t)));
            }
        }
    }
}

/// The state of `(tid, ak)` was rebuilt (a validity flip, an un-merge, a drop): every held body
/// with a relative bound is judged again by node-sync and its history row dated again, as when it
/// was replaced may have moved, and
/// every held body is a cover candidate again (a write of it may have died; the rebuild read
/// them all already).
pub(crate) fn mark_bounded(tx: &mut Tx<'_>, tid: &Tid, ak: &Ak) {
    let on: Vec<CommitId> = tx.core.ix.by_aspect.get(&(*tid, ak.clone())).into_iter().flatten().map(|x| x.1).collect();
    let k = (*tid, ak.clone());
    let delta = |c: &CommitId| tx.core.ix.commits.get(c).is_some_and(|m| !m.header.kind.is_compaction() && !m.view.memory) && super::held_part(tx.core, c, tid, ak).is_some();
    let fresh: Vec<CommitId> = on.iter().copied().filter(|c| delta(c)).collect();
    if !fresh.is_empty() {
        tx.core.cover_candidates.entry(k).or_default().extend(fresh);
    }
    if !bounded(tx.core, tid, ak) {
        return;
    }
    for c in on {
        if bounded_part(tx.core, &c, tid, ak).is_some() {
            tx.core.mark_changed(c);
            tx.core.to_date.push((*tid, ak.clone(), c, super::leaving::Dating::Full(false)));
        }
    }
}

/// `Engine::delta_live` of delta `ai` of `c`, judged against the state in
/// `tx`: a function of the commits applied (the join's), so alike at nodes that applied the
/// same ones.
pub(super) fn live(tx: &mut Tx<'_>, c: &CommitId, ai: usize) -> Result<bool> {
    let Some(h) = tx.core.ix.commits.get(c).map(|m| m.header.clone()) else { return Ok(true) };
    if h.kind.is_compaction() {
        return snapshot_live(tx, &h, c, ai);
    }
    let Some(a) = h.aspects.get(ai) else { return Ok(false) };
    let own = writes_of(&h, c, ai);
    let owns = |st: &Fragment| st.holds_owned_write(&|src, lo, hi| own.iter().any(|o| o.owns_range(src, lo, hi)));
    // per piece of the delta, the state at its positions (O(piece), whatever the state's size;
    // all of it when none is held)
    let mut live = false;
    let held = crate::apply::each_held_piece(tx, c, ai, &mut |tx, f| {
        if !live {
            live = tx.state_part_at(&a.tid, &a.ak, &f)?.as_ref().is_some_and(owns);
        }
        Ok(())
    })?;
    if held.is_none() {
        live = tx.state(&a.tid, &a.ak)?.is_some_and(owns);
    }
    Ok(live)
}

/// Whether a compaction snapshot carries a write still live in this node's state (`delta_live`;
/// live writes as for deltas, `Fragment::live_writes`: no element or entry tombstone): held, a
/// write it carries (by dot) is there, judged a piece of it at a time against the state's part
/// it meets. Not held (dropped or never received), which writes it carried are not known here: it
/// is live while the state holds a write stamped at or before its `ts` (the header's `ts` bounds
/// what it carried) or one without a `ts` (a sequence record whose creation is gone): an
/// over-approximation, so its delete at hosts waits for a carrier (spec/sync-compaction.md §1).
pub(super) fn snapshot_live(tx: &mut Tx<'_>, h: &Header, c: &CommitId, ai: usize) -> Result<bool> {
    let Some(a) = h.aspects.get(ai) else { return Ok(false) };
    // by dot: records without a `ts` count too
    let valid = crate::apply::copies::snapshot_valid(tx.core, c, &a.tid, &a.ak);
    let mut live = false;
    let held = crate::apply::each_held_piece(tx, c, ai, &mut |tx, f| {
        let carried: BTreeSet<osis_crdt::Dot> = f.live_writes().into_iter().map(|(d, _)| d).collect();
        if !live && !carried.is_empty() {
            // a valid snapshot is joined in the state, so a dot it shares with the state sits
            // at a position it holds; an invalid one's may sit elsewhere (one delta stamp
            // covers many positions)
            let st = if valid { tx.state_part_at(&a.tid, &a.ak, &f)? } else { tx.state_at(&a.tid, &a.ak, &f)? };
            live = st.is_some_and(|st| st.live_writes().into_iter().any(|(d, _)| carried.contains(&d)));
        }
        Ok(())
    })?;
    if live || held.is_some() {
        return Ok(live);
    }
    let Some(st) = tx.state(&a.tid, &a.ak)? else { return Ok(false) };
    Ok(st.live_writes().iter().any(|(_, t)| t.is_none_or(|t| t <= h.ts)))
}

impl Engine {
    /// Keep-at-least bound (wall ms, 0: none) of each part of known commit `c`, by aspect index
    /// (`part_keep`): a commit's judgment costs O(parts) death reads.
    pub fn part_keeps(&mut self, c: &CommitId) -> Result<Vec<u64>> {
        let b = osis_base::memo::Memo::get_in(self, |e| &e.core.part_bounds, c, |e| e.run(|tx| commit_bounds(tx, c)))?;
        Ok(b.iter().map(|x| at_clock(&self.core, *x)).collect())
    }

    /// Whether aspect `a` of `h` is a permanent delta (`history::permanent`).
    pub fn permanent(&self, h: &Header, a: &osis_commit::AspectEntry) -> bool {
        super::history::permanent(&self.core, h, a, self.now().0)
    }

    /// Whether a header of `h` may be a lasting header on `t` (spec/commits.md §5): it carries a
    /// purge request, or a permanent delta on `t` unless `t` was destroyed by release alone (no header of
    /// it lasts).
    pub fn may_last_on(&self, h: &Header, t: &osis_base::Tid) -> bool {
        let now = self.now().0;
        !h.purge.is_empty() || h.aspects.iter().any(|a| a.tid == *t && super::history::permanent(&self.core, h, a, now)) && !super::destroy::released(&self.core, t, now)
    }

    /// From when any node may drop held part `(tid, ak)` of `c` under a held valid writer's
    /// cover or its author's own whole replaces (spec/commits.md §5 Out of history, spec/sync.md
    /// §7): its keep-at-least bound on this node's clock (`part_keep`; a local drop changes only
    /// this node's reads, which follow its clock; deleting it at hosts waits `MAX_DRIFT` more,
    /// `Dropped::hosts_from`). Out of history nothing promises to keep it, so the cover's writer
    /// need not hold the purge right.
    pub fn drop_from(&mut self, c: &CommitId, tid: &Tid, ak: &Ak) -> Result<u64> {
        let (c, tid, ak) = (*c, *tid, ak.clone());
        self.read(|tx| part_keep(tx, &c, &tid, &ak))
    }

    /// Whether held part `(tid, ak)` of `c` is replaced: a write of it is dead (spec/commits.md
    /// §5 Bodies and deaths; `false` when not held whole and valid).
    pub fn replaced(&mut self, c: &CommitId, tid: &Tid, ak: &Ak) -> Result<bool> {
        let (c, tid, ak) = (*c, *tid, ak.clone());
        self.read(|tx| {
            let Some(ai) = held_part(tx.core, &c, &tid, &ak) else { return Ok(false) };
            if tx.core.ix.commits.get(&c).is_none_or(|m| m.bare(ai)) {
                return Ok(false);
            }
            super::replace::replaced(tx, &c, ai, &tid, &ak)
        })
    }

    /// Body `(tid, ak)` of `c` is kept for good (its `drop_from` is past `FOREVER`: while live,
    /// spec/commits.md §5 Kept while live): it leaves the aspect's cover candidates
    /// (`Core::cover_judged_on`) until a write of it dies, its aspect is rebuilt or its thing's
    /// setting changes.
    pub fn settle_kept(&mut self, c: &CommitId, tid: &Tid, ak: &Ak) {
        if let Some(s) = self.core.cover_candidates.get_mut(&(*tid, ak.clone())) {
            s.remove(c);
        }
    }

    /// When part `ak` of `c` was replaced, for a relative keep at least (`part_replaced_at`;
    /// `None`: no relative bound on its aspect, or no write of it dead).
    pub fn replaced_at(&mut self, c: &CommitId, tid: &Tid, ak: &Ak) -> Result<Option<Ts>> {
        let (c, tid, ak) = (*c, *tid, ak.clone());
        self.read(|tx| {
            let (ai, h) = known_part(tx.core, &c, &tid, &ak)?;
            tx.core.replaced_reads += 1;
            part_replaced_at(tx, &h, &c, ai)
        })
    }

    /// Whether a write of `c`'s delta on `(tid, ak)` is still in this node's state (a dot it owns
    /// survives there; unknown counts as live): what only a blob of `c` can carry (spec/sync.md
    /// §6, §7). A delta without one needs no carrier before it leaves a label (spec/sync-compaction.md §1);
    /// one with one goes only after its carrier (spec/commits.md §5). Writes the state does not
    /// hold count dead: superseded, purged or expired ones, and those of deltas invalid here or
    /// undone (stripped from the state; live again once a validity flip or a redo puts them
    /// back). Any write counts: resets (a tombstone's, for its remover) and value-less writes
    /// too. A memo (`Core::live_bodies`): a hit runs no transaction.
    pub fn delta_live(&mut self, c: &CommitId, tid: &Tid, ak: &Ak) -> Result<bool> {
        let key = (*c, *tid, ak.clone());
        osis_base::memo::Memo::get_in(self, |e| &e.core.live_bodies, &key, |e| e.run(|tx| delta_live_read(tx, &key)))
    }

    /// Whether delta `ai` of `c` holds writes of its own and is held value-less for all of them: a
    /// purge took them, so it has no live write to carry (spec/commits.md §5).
    pub fn part_valueless(&self, h: &Header, c: &CommitId, ai: usize) -> bool {
        !gone_of(&self.core, h, c, ai).is_empty()
    }

    /// The lowest `ts` among the writes the held body of aspect `ak` of `c` carries (`None`: not
    /// held, or none stamped). Tests: the order harness bounds which invalid writes may have
    /// killed a snapshot's carried write.
    #[doc(hidden)]
    pub fn body_min_ts(&mut self, c: &CommitId, tid: &Tid, ak: &Ak) -> Result<Option<Ts>> {
        let (c, tid, ak) = (*c, *tid, ak.clone());
        self.read(|tx| {
            let Some(ai) = aspect_index(tx.core, &c, &tid, &ak) else { return Ok(None) };
            let mut min = None;
            crate::apply::each_held_piece(tx, &c, ai, &mut |_, f| {
                min = f.writes().into_iter().filter_map(|(_, t)| t).chain(min).min();
                Ok(())
            })?;
            Ok(min)
        })
    }

    /// Whether `c` is known with an aspect `(tid, ak)` whose body is neither dropped nor held as
    /// its leftover (`Meta::body_gone`): true for a missing part too (`Engine::aspect_dump` shows
    /// which).
    pub fn body_not_dropped(&self, c: &CommitId, tid: &Tid, ak: &Ak) -> bool {
        let Some(m) = self.core.ix.commits.get(c) else { return false };
        m.aspect(tid, ak).is_some_and(|ai| !m.body_gone(ai))
    }

    /// Whether this node keeps held part `(tid, ak)` of `c` under cover `s` though `s` covers it
    /// (`retention::own_kept_under`, spec/sync-compaction.md §1 own bodies).
    pub fn own_kept_under(&mut self, s: &CommitId, c: &CommitId, tid: &Tid, ak: &Ak) -> Result<bool> {
        let (s, c, tid, ak) = (*s, *c, *tid, ak.clone());
        self.read(|tx| super::own_kept_under(tx, &s, &c, &tid, &ak))
    }

    /// Whether `c`'s part on `(tid, ak)` drops as covered (compaction, spec/commits.md §5;
    /// `retention::drops_as_covered`).
    pub fn droppable_if_covered(&self, c: &CommitId, tid: &Tid, ak: &Ak) -> bool {
        let Some(m) = self.core.ix.commits.get(c) else { return false };
        m.aspect(tid, ak).is_some_and(|ai| super::drops_as_covered(m, ai, self.now().0))
    }

    /// The snapshots that covered `c`'s part on `(tid, ak)` when it dropped, and those that
    /// covered such a coverer dropped in turn (`Dropped::covered_by`).
    pub fn coverers_of(&self, c: &CommitId, tid: &Tid, ak: &Ak) -> Vec<CommitId> {
        let Some(ai) = self.core.ix.commits.get(c).and_then(|m| m.aspect(tid, ak)) else { return Vec::new() };
        super::coverers(&self.core, c, ai)
    }
}
