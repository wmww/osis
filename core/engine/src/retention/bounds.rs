//! A held body's keep-at-least bound and whether it holds a live write (spec/commits.md §5).

use super::{aspect_index, body_class, body_classes, bounded, gone_of, held_part, known_part, writes_of};
#[cfg(test)]
use super::oracle;
use crate::engine::{Core, Engine, Tx};
use crate::error::{Error, Result};
use osis_base::{Ak, CommitId, Tid, Ts};
use osis_commit::Header;
use osis_crdt::{ByWrite, Fragment, Winners, Won};
use std::collections::BTreeSet;
use std::sync::Arc;

/// `Engine::body_live` in `tx`: any delta of the body's class live (`delta_live`).
pub(crate) fn body_live(tx: &mut Tx<'_>, c: &CommitId, tid: &Tid, ak: &Ak) -> Result<bool> {
    // an unknown commit counts live (its apply may change nothing here)
    let Some(ai) = aspect_index(tx.core, c, tid, ak) else { return Ok(true) };
    let Some(h) = tx.core.ix.commits.get(c).map(|m| m.header.clone()) else { return Ok(true) };
    for x in body_class(tx.core, &h, ai) {
        let Some(a) = h.aspects.get(x) else { continue };
        if delta_live(tx, c, &a.tid, &a.ak)? {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Whether something reads part `(tid, ak)` of `c` on its own, so no cover drops it (spec/commits.md
/// §5 Covered): a cover drops a part when it carries every live write of it and nothing reads the
/// part alone. A held durable delta none of whose writes is dead is read alone (a purge by name,
/// a fallen purge bringing it back, listings); one with a dead write (`replace::replaced`), a
/// compaction snapshot (its writes are copies) and an in-memory part (no purge, host copy or
/// listing of its own) are not. Judged per part, as a cover drops one part (`drop_part_for`); the
/// other parts of its body class are judged by their own aspects. A delta found read alone leaves
/// `Core::cover_candidates`. Cost: the part read once against the state's part it meets.
pub(crate) fn read_alone(tx: &mut Tx<'_>, c: &CommitId, tid: &Tid, ak: &Ak) -> Result<bool> {
    let Some(ai) = held_part(tx.core, c, tid, ak) else { return Ok(false) };
    let Some(m) = tx.core.ix.commits.get(c) else { return Ok(false) };
    if m.header.kind.is_compaction() || m.view.memory || ak.signal() || m.bare(ai) {
        return Ok(false);
    }
    if super::replace::replaced(tx, c, ai, tid, ak)? {
        return Ok(false);
    }
    if let Some(s) = tx.core.cover_candidates.get_mut(&(*tid, ak.clone())) {
        s.remove(c);
    }
    Ok(true)
}

/// `Engine::delta_live` in `tx`, through `Core::live_bodies` (per delta: what forgets it is a
/// change of that aspect's state alone).
pub(crate) fn delta_live(tx: &mut Tx<'_>, c: &CommitId, tid: &Tid, ak: &Ak) -> Result<bool> {
    let key = (*c, *tid, ak.clone());
    if let Some(v) = tx.core.live_bodies.get(&key.0).and_then(|m| m.get(&(key.1, key.2.clone()))) {
        return Ok(*v);
    }
    // an unknown commit counts live, uncached (its apply may change nothing here)
    let Some(ai) = aspect_index(tx.core, c, tid, ak) else { return Ok(true) };
    let r = live(tx, c, ai)?;
    #[cfg(test)]
    assert_eq!(r, oracle::live(tx, c, ai)?, "live streamed vs whole");
    tx.core.live_bodies.entry(key.0).or_default().insert((key.1, key.2), r);
    Ok(r)
}

/// Before which wall ms a body of `h` holding deltas of aspect `a`'s class leaves only by purge
/// request or expiry (spec/commits.md §5 Keep bounds; 0: no floor): the later of when it leaves
/// history (`history::Kept::leaves_at`, replaced at wall ms `replaced`; `None`: not replaced) and
/// the purge-request floor.
pub(crate) fn kept_until(core: &Core, h: &Header, a: &osis_commit::AspectEntry, replaced: Option<u64>) -> u64 {
    super::history::of(core, &a.tid, &a.ak).leaves_at(replaced).max(osis_commit::retention::purge_keep_until(h).unwrap_or(0))
}

/// `Engine::body_keep` in `tx`: before which wall ms the body leaves only by purge or expiry, a
/// replacement dated ahead of the clock included (`clock_keep`): from then any node may drop it
/// as covered (spec/commits.md §5 Keep bounds).
pub(crate) fn body_keep(tx: &mut Tx<'_>, c: &CommitId, tid: &Tid, ak: &Ak) -> Result<u64> {
    let (ai, h) = known_part(tx.core, c, tid, ak)?;
    let holders = body_class(tx.core, &h, ai);
    class_keep(tx, &h, c, &holders)
}

/// What history and the purge floor keep of part `(tid, ak)` of `c` (its own aspect's setting at
/// its own replacement, without `clock_keep`): what a listing shows of it (spec/commits.md §7
/// Listed parts).
pub(crate) fn body_history_keep(tx: &mut Tx<'_>, c: &CommitId, tid: &Tid, ak: &Ak) -> Result<u64> {
    let (ai, h) = known_part(tx.core, c, tid, ak)?;
    tx.core.replaced_reads += 1;
    let r = part_replaced_at(tx, &h, c, ai)?.map(|t| t.wall_ms().0);
    Ok(h.aspects.get(ai).map_or(0, |a| kept_until(tx.core, &h, a, r)))
}

/// A body replaced at wall ms `replaced` after the node's clock is kept until the clock reaches it
/// (spec/commits.md §5 Keep bounds: a body leaves history no earlier than replaced). Only a dated
/// part has a `replaced` (`part_replaced_at`): where no setting keeps history for its aspect nothing is
/// dated and it adds no bound.
fn clock_keep(core: &Core, replaced: Option<u64>) -> u64 {
    replaced.filter(|r| *r > core.now().0).unwrap_or(0)
}

/// The keep bound of the body class `holders` of `c` (its parts go together, `body_class`): the
/// latest of its parts' own, each its own aspect's timeline at its own replacement
/// (`part_replaced_at`) and `clock_keep` (spec/commits.md §5 Dated only where history is kept).
/// A part's date and keep read only its aspect's writes and setting, so a covered drop on one
/// aspect moves no other part's bound, and a part on an aspect no setting keeps adds none.
fn class_keep(tx: &mut Tx<'_>, h: &Header, c: &CommitId, holders: &[usize]) -> Result<u64> {
    tx.core.replaced_reads += 1;
    let mut k = 0;
    for x in holders {
        let Some(a) = h.aspects.get(*x) else { continue };
        let r = part_replaced_at(tx, h, c, *x)?.map(|t| t.wall_ms().0);
        k = k.max(kept_until(tx.core, h, a, r)).max(clock_keep(tx.core, r));
    }
    Ok(k)
}

/// `Engine::body_keeps` in `tx`: each body's parts judged once.
fn body_keeps(tx: &mut Tx<'_>, c: &CommitId) -> Result<Vec<u64>> {
    let h = tx.core.ix.commits.get(c).ok_or(Error::UnknownCommit(*c))?.header.clone();
    let mut out = vec![0; h.aspects.len()];
    for holders in body_classes(tx.core, &h) {
        let k = class_keep(tx, &h, c, &holders)?;
        for x in holders {
            if let Some(o) = out.get_mut(x) {
                *o = k;
            }
        }
    }
    Ok(out)
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
/// (notes/engine-retention.md Replaced, the covered-drop invariant). A node holding more bodies
/// dates no later. Invalid parts and bare leftovers (no values to keep) are not judged. A memo
/// (`Core::replaced_dates`): judged again only when what it read moved (the aspect's held
/// bodies, their validity and the state), the aspect's held bodies read once for every
/// judgment until then (`held_writes`).
pub(super) fn dated_replaced_at(tx: &mut Tx<'_>, h: &Header, c: &CommitId, ai: usize) -> Result<Option<Ts>> {
    let Some(a) = h.aspects.get(ai) else { return Ok(None) };
    if a.ak.signal() {
        return Ok(Some(h.ts));
    }
    crate::engine::memo::Memo::get_in(tx, |tx| &tx.core.replaced_dates, &(*c, ai), |tx| judge_replaced_at(tx, h, c, ai, false))
}

/// Debug builds: `dated_replaced_at` judged anew, no memo read (the aspect's held bodies too).
#[cfg(debug_assertions)]
pub(super) fn fresh_replaced_at(tx: &mut Tx<'_>, h: &Header, c: &CommitId, ai: usize) -> Result<Option<Ts>> {
    if h.aspects.get(ai).is_some_and(|a| a.ak.signal()) {
        return Ok(Some(h.ts));
    }
    crate::engine::memo::unrecorded(|| judge_replaced_at(tx, h, c, ai, true))
}

/// `dated_replaced_at` judged anew (`fresh`: the held bodies read anew too).
fn judge_replaced_at(tx: &mut Tx<'_>, h: &Header, c: &CommitId, ai: usize, fresh: bool) -> Result<Option<Ts>> {
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
    let held = if fresh { Arc::new(read_held_writes(tx, &tid, &ak)?) } else { held_writes(tx, &tid, &ak)? };
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
#[derive(Debug, Default, PartialEq)]
pub(crate) struct HeldWrites {
    /// The writes each held body holds, winning there or not (`Fragment::held_writes`), as the
    /// state joins it (an invalid delta's writes left out, from a valid snapshot only what it
    /// holds under such a dot without a write of its own there, `Unmerge::unvouched`; an invalid
    /// snapshot's body gives nothing): the two earliest such bodies by `(ts, ID)`, so one is not
    /// the body judged.
    holds: ByWrite<Vec<(Ts, CommitId)>>,
    /// The writes each held valid snapshot with values holds as winners: its `ts` and ID.
    carried: ByWrite<Vec<(Ts, CommitId)>>,
}

/// `HeldWrites` of `(tid, ak)`, through `Core::held_writes` (a memo).
fn held_writes(tx: &mut Tx<'_>, tid: &Tid, ak: &Ak) -> Result<Arc<HeldWrites>> {
    crate::engine::memo::Memo::get_in(tx, |tx| &tx.core.held_writes, &(*tid, ak.clone()), |tx| read_held_writes(tx, tid, ak).map(Arc::new))
}

/// `HeldWrites` of `(tid, ak)` read anew: every held body of the aspect, each part whole.
fn read_held_writes(tx: &mut Tx<'_>, tid: &Tid, ak: &Ak) -> Result<HeldWrites> {
    let un = crate::apply::Unmerge::of(tx, tid, ak)?;
    let on: Vec<(Ts, CommitId)> = tx.core.ix.by_aspect.get(&(*tid, ak.clone())).into_iter().flatten().cloned().collect();
    let mut out = HeldWrites::default();
    for (ts, x) in on {
        let Some(xai) = held_part(tx.core, &x, tid, ak) else { continue };
        if crate::apply::copies::invalid_snapshot(tx.core, &x, tid, ak) {
            continue;
        }
        let Some(m) = tx.core.ix.commits.get(&x) else { continue };
        let snap = m.header.kind.is_compaction();
        let carries = snap && !m.bare(xai) && m.valid_at(xai);
        let Some(mut f) = crate::apply::held_fragment(tx, &x, xai)? else { continue };
        drop(crate::costs::span("deaths: a body"));
        if carries {
            out.carried.note(&f.winners(), |_, v| v.push((ts, x)));
        }
        f.remove_writes(&|d| if snap { un.unvouched(d) } else { un.bad(d) });
        out.holds.note(&f.held_writes(), |_, v| {
            v.push((ts, x));
            v.sort();
            v.truncate(2);
        });
    }
    Ok(out)
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
/// read on its own may not be now (`read_alone`); with `Killed::all`, every held body of the
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

/// From when any node may drop held body `(tid, ak)` of `c` under a held valid writer's cover
/// (spec/commits.md §5 Out of history, spec/sync.md §7): its keep-at-least bound on this node's
/// clock (a local drop changes only this node's reads, which follow its clock; deleting it at
/// hosts waits `MAX_DRIFT` more, `Dropped::hosts_from`). Out of history nothing promises to keep
/// it, so the cover's writer need not hold the purge right.
pub(crate) fn drop_from(tx: &mut Tx<'_>, c: &CommitId, tid: &Tid, ak: &Ak) -> Result<u64> {
    body_keep(tx, c, tid, ak)
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

/// Whether a compaction snapshot carries a write still live in this node's state (`body_live`;
/// live writes as for deltas, `Fragment::live_writes`: no element or entry tombstone): held, a
/// write it carries (by dot) is there, judged a piece of it at a time against the state's part
/// it meets. Not held (dropped or never received), which writes it carried are not known here: it
/// is live while the state holds a write stamped at or before its `ts` (the header's `ts` bounds
/// what it carried) or one without a `ts` (a sequence record whose creation is gone): an
/// over-approximation, so its delete at hosts waits for a carrier (spec/sync.md §7).
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
    /// Keep-at-least bound (wall ms, 0: none) of the body holding each part of known commit `c`,
    /// by aspect index: judged once per body, so a commit's judgment costs O(parts) death reads.
    pub fn body_keeps(&mut self, c: &CommitId) -> Result<Vec<u64>> {
        let c = *c;
        self.run(|tx| body_keeps(tx, &c))
    }

    /// What `body_keeps` gives for each part of `h` were no body of it replaced: equal to it
    /// when no bound is dated by a replacement.
    pub fn keeps_unreplaced(&self, h: &Header) -> Vec<u64> {
        let mut out = vec![0; h.aspects.len()];
        for holders in body_classes(&self.core, h) {
            let k = holders.iter().filter_map(|x| h.aspects.get(*x)).map(|a| kept_until(&self.core, h, a, None)).max().unwrap_or(0);
            for x in holders {
                if let Some(o) = out.get_mut(x) {
                    *o = k;
                }
            }
        }
        out
    }

    /// Whether aspect `a` of `h` is a permanent delta (`history::permanent`).
    pub fn permanent(&self, h: &Header, a: &osis_commit::AspectEntry) -> bool {
        super::history::permanent(&self.core, h, a, self.now().0)
    }

    /// Whether a header of `h` may be a lasting header on `t` (spec/commits.md §5): it carries a
    /// purge request, or a permanent delta on `t` unless `t` ended by release alone (no header of
    /// it lasts).
    pub fn may_last_on(&self, h: &Header, t: &osis_base::Tid) -> bool {
        let now = self.now().0;
        !h.purge.is_empty() || h.aspects.iter().any(|a| a.tid == *t && super::history::permanent(&self.core, h, a, now)) && !super::end::released(&self.core, t, now)
    }

    /// From when any node may drop held body `(tid, ak)` of `c` as covered (`drop_from`), under a
    /// snapshot or its author's own whole replaces.
    pub fn drop_from(&mut self, c: &CommitId, tid: &Tid, ak: &Ak) -> Result<u64> {
        let (c, tid, ak) = (*c, *tid, ak.clone());
        self.run(|tx| drop_from(tx, &c, &tid, &ak))
    }

    /// Whether something reads the body holding `(tid, ak)` of `c` on its own, so no cover drops
    /// it (`read_alone`).
    pub fn read_alone(&mut self, c: &CommitId, tid: &Tid, ak: &Ak) -> Result<bool> {
        let (c, tid, ak) = (*c, *tid, ak.clone());
        self.run(|tx| read_alone(tx, &c, &tid, &ak))
    }

    /// When part `ak` of `c` was replaced, for a relative keep at least (`part_replaced_at`;
    /// `None`: no relative bound on its aspect, or no write of it dead).
    pub fn replaced_at(&mut self, c: &CommitId, tid: &Tid, ak: &Ak) -> Result<Option<Ts>> {
        let (c, tid, ak) = (*c, *tid, ak.clone());
        self.run(|tx| {
            let (ai, h) = known_part(tx.core, &c, &tid, &ak)?;
            tx.core.replaced_reads += 1;
            part_replaced_at(tx, &h, &c, ai)
        })
    }

    /// Whether a write of the body holding aspect `ak` of `c` is still in this node's state (a
    /// dot its deltas own survives there; unknown counts as live). A
    /// body without one needs no carrier before it leaves a label (spec/sync.md §7); one with one
    /// goes only after its carrier (spec/commits.md §5). Writes the state does not hold count
    /// dead: superseded, purged or expired ones, and those of deltas invalid here or undone (they
    /// are stripped from the state; they count live again once a validity flip or a redo puts
    /// them back). Any write counts: resets (a tombstone's, for its remover) and value-less writes too. Any
    /// delta of the body's class live (`delta_live`).
    pub fn body_live(&mut self, c: &CommitId, tid: &Tid, ak: &Ak) -> Result<bool> {
        let (c, tid, ak) = (*c, *tid, ak.clone());
        self.run(|tx| body_live(tx, &c, &tid, &ak))
    }

    /// Whether a write of `c`'s delta on `(tid, ak)` itself is still in this node's state, as
    /// `body_live` asks of the body: what only a blob of `c` can carry (spec/sync.md §6, §7).
    /// Kept until the aspect's state changes (`Core::live_bodies`).
    pub fn delta_live(&mut self, c: &CommitId, tid: &Tid, ak: &Ak) -> Result<bool> {
        if let Some(v) = self.core.live_bodies.get(c).and_then(|m| m.get(&(*tid, ak.clone()))) {
            return Ok(*v);
        }
        let (c, tid, ak) = (*c, *tid, ak.clone());
        self.run(|tx| delta_live(tx, &c, &tid, &ak))
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
        self.run(|tx| {
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

    /// Whether `s` is a snapshot whose part on `(tid, ak)` this node holds whole (received, not
    /// dropped or held as its leftover) and judges valid: one that may stand for the aspect's
    /// history (spec/commits.md §5 Purge).
    pub fn holds_valid_snapshot(&self, s: &CommitId, tid: &Tid, ak: &Ak) -> bool {
        let Some(m) = self.core.ix.commits.get(s) else { return false };
        m.view.kind.is_compaction() && m.aspect(tid, ak).is_some_and(|ai| !m.body_gone(ai) && !m.missing.contains(&ai) && m.valid_at(ai))
    }

    /// Whether `c`'s part on `(tid, ak)` is held and drops as covered (compaction, spec/commits.md
    /// §5): a body not dropped, or a leftover past its expiry (`expired_leftover`).
    pub fn droppable_if_covered(&self, c: &CommitId, tid: &Tid, ak: &Ak) -> bool {
        let Some(m) = self.core.ix.commits.get(c) else { return false };
        m.aspect(tid, ak).is_some_and(|ai| !m.body_gone(ai) || (!m.dropped.contains_key(&ai) && super::expired_leftover(m, ai, self.now().0)))
    }

    /// The snapshots that covered `c`'s part on `(tid, ak)` when it dropped, and those that
    /// covered such a coverer dropped in turn (`Dropped::covered_by`).
    pub fn coverers_of(&self, c: &CommitId, tid: &Tid, ak: &Ak) -> Vec<CommitId> {
        let Some(ai) = self.core.ix.commits.get(c).and_then(|m| m.aspect(tid, ak)) else { return Vec::new() };
        super::coverers(&self.core, c, ai)
    }
}
