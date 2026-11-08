//! A held body's keep-at-least bound and whether it holds a live write (spec/commits.md §5).

use super::{aspect_index, body_class, body_classes, bounded, gone_of, held_part, known_part, writes_of};
#[cfg(test)]
use super::oracle;
use crate::engine::{Core, Engine, Tx};
use crate::error::{Error, Result};
use osis_base::{Ak, CommitId, Tid, Ts};
use osis_commit::Header;
use osis_crdt::{Fragment, Stamp, Winners, Won};
use osis_perm::At;
use std::collections::{BTreeMap, BTreeSet};

/// `Engine::body_live` in `tx`, through `Core::live_bodies`.
pub(super) fn body_live(tx: &mut Tx<'_>, c: &CommitId, tid: &Tid, ak: &Ak) -> Result<bool> {
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

/// `Engine::body_keep` in `tx`: before which wall ms the body leaves only by purge or expiry.
pub(crate) fn body_keep(tx: &mut Tx<'_>, c: &CommitId, tid: &Tid, ak: &Ak) -> Result<u64> {
    let (ai, h) = known_part(tx.core, c, tid, ak)?;
    let a = h.aspects.get(ai).ok_or(Error::UnknownCommit(*c))?;
    let holders = body_class(tx.core, &h, ai);
    let r = replaced_at(tx, &h, c, &holders)?;
    Ok(osis_commit::retention::body_keep(&h, a, r.map(|t| t.wall_ms().0)))
}

/// `Engine::body_keeps` in `tx`: each body's replacement judged once.
fn body_keeps(tx: &mut Tx<'_>, c: &CommitId) -> Result<Vec<u64>> {
    let h = tx.core.ix.commits.get(c).ok_or(Error::UnknownCommit(*c))?.header.clone();
    let mut out = vec![0; h.aspects.len()];
    for holders in body_classes(tx.core, &h) {
        let Some(a) = holders.first().and_then(|x| h.aspects.get(*x)) else { continue };
        let r = replaced_at(tx, &h, c, &holders)?;
        let k = osis_commit::retention::body_keep(&h, a, r.map(|t| t.wall_ms().0));
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

/// When the body of `c` holding aspects `holders` (one class, `body_class`) was replaced, for a
/// relative keep at least (spec/commits.md §5): a function of the held set, judged when asked,
/// never stored, and never of how a part is paged (`deaths` judges it whole). A write of a held
/// valid part is dead when it wins in the part and not once the part joins the state
/// (spec/crdt.md §4.8, `Fragment::winners`); it died at the
/// `ts` of the earliest held valid body holding a write that supersedes it (`first_deaths`): its
/// superseder's own commit, or a later snapshot carrying it (never earlier than the death). A
/// delta's body is replaced at the earliest of its writes' deaths, a snapshot's at the latest
/// among those no held valid snapshot stamped later carries (`carried`: that one keeps their
/// history, so this one is needed only for writes that died before it); `None`: no such write
/// is dead, so it is past a relative bound. A node holding more bodies dates no later.
/// Bodies with no relative bound, invalid parts and bare leftovers (no values to keep) are not
/// judged (`Core::replaced_reads` counts the judgments).
pub(super) fn replaced_at(tx: &mut Tx<'_>, h: &Header, c: &CommitId, holders: &[usize]) -> Result<Option<Ts>> {
    // a signal's body is replaced when written (spec/commits.md §5 Signals; `body_class` keeps it
    // apart from other deltas)
    if holders.first().and_then(|ai| h.aspects.get(*ai)).is_some_and(|a| a.ak.signal()) {
        return Ok(Some(h.ts));
    }
    if !holders.first().and_then(|ai| h.aspects.get(*ai)).is_some_and(bounded) {
        return Ok(None);
    }
    tx.core.replaced_reads += 1;
    let snap = h.kind.is_compaction();
    let mut out: Option<Ts> = None;
    for ai in holders {
        let Some(a) = h.aspects.get(*ai) else { continue };
        let (tid, ak) = (a.tid, a.ak.clone());
        if held_part(tx.core, c, &tid, &ak) != Some(*ai) || tx.core.ix.commits.get(c).is_none_or(|m| m.bare(*ai) || !m.valid_at(*ai)) {
            continue;
        }
        let mut dead = deaths(tx, c, *ai, &tid, &ak)?;
        #[cfg(test)]
        assert_eq!(dead.keys().cloned().collect::<BTreeSet<_>>(), oracle::deaths(tx, c, *ai, &tid, &ak)?, "deaths at the part's positions vs the whole state");
        if snap && !dead.is_empty() {
            let gone = carried(tx, h.ts, a, c, &dead)?;
            dead.retain(|w, _| !gone.contains(w));
        }
        if dead.is_empty() {
            continue;
        }
        let first = first_deaths(tx, c, *ai, &tid, &ak, &dead, snap)?;
        // a superseder no body of the walk holds dates as the state holds it (`deaths`)
        let each = dead.iter().map(|(w, up)| first.get(w).copied().unwrap_or(*up));
        let part = if snap { each.max() } else { each.min() };
        out = match (out, part) {
            (Some(o), Some(p)) => Some(if snap { o.max(p) } else { o.min(p) }),
            (o, p) => o.or(p),
        };
    }
    Ok(out)
}

/// The writes of held part `ai` of `c` the state supersedes (spec/crdt.md §4.8): the part's
/// winners that do not win once it joins, whole, a copy of the state at its positions
/// (`Tx::state_part_at`: O(part), whatever the state's size). Each with the date of its
/// superseder as the state holds it (`date`); a superseder not found among the join's winners
/// (none for honest clocks) dates at the latest write the join holds, no earlier than any.
fn deaths(tx: &mut Tx<'_>, c: &CommitId, ai: usize, tid: &Tid, ak: &Ak) -> Result<BTreeMap<Won, Ts>> {
    let Some(f) = crate::apply::held_fragment(tx, c, ai)? else { return Ok(BTreeMap::new()) };
    let Some(mut st) = tx.state_part_at(tid, ak, &f)? else { return Ok(BTreeMap::new()) };
    let mine = winners_of(tx, &f);
    st.join(f);
    let joined = winners_of(tx, &st);
    let latest = joined.iter().map(|w| w.stamp.ts).max().unwrap_or_default();
    let mut out = BTreeMap::new();
    for w in mine.minus(&joined) {
        let at = match joined.superseder(&w) {
            Some(k) => date(tx, tid, ak, &k)?,
            None => latest,
        };
        out.insert(w, at);
    }
    Ok(out)
}

/// The writes of `dead` (the dead writes of snapshot `c`, stamped `ts`, part `a`) a held valid
/// snapshot stamped later, keeping history at least as long, holds as winners (spec/commits.md
/// §5): that one keeps their history, each write judged by position, exactly. The later
/// snapshots are read in `ts` order until every write is carried.
fn carried(tx: &mut Tx<'_>, ts: Ts, a: &osis_commit::AspectEntry, c: &CommitId, dead: &BTreeMap<Won, Ts>) -> Result<BTreeSet<Won>> {
    let (tid, ak) = (&a.tid, &a.ak);
    let keeps = |x: &osis_commit::AspectEntry| osis_commit::retention::KeepRule::of_aspect(x).after.unwrap_or(0);
    let after = keeps(a);
    let mut later: Vec<(Ts, CommitId, usize)> = tx.core.ix.snapshots.get(&(*tid, ak.clone())).into_iter().flatten().filter(|x| x.0 > ts && x.1 != *c && !crate::apply::copies::invalid_snapshot(tx.core, &x.1, tid, ak)).filter_map(|x| held_part(tx.core, &x.1, tid, ak).map(|ai| (x.0, x.1, ai))).filter(|x| tx.core.ix.commits.get(&x.1).is_some_and(|m| !m.bare(x.2) && m.valid_at(x.2) && m.header.aspects.get(x.2).is_some_and(|l| keeps(l) >= after))).collect();
    later.sort();
    let mut left: BTreeSet<Won> = dead.keys().cloned().collect();
    for (_, l, lai) in later {
        let Some(f) = crate::apply::held_fragment(tx, &l, lai)? else { continue };
        let w = winners_of(tx, &f);
        left.retain(|x| !w.contains(x));
        if left.is_empty() {
            break;
        }
    }
    Ok(dead.keys().filter(|w| !left.contains(*w)).cloned().collect())
}

/// When the writes of `dead` died: the first held valid body of the aspect other than `c`
/// stamped no earlier than the earliest of them, in `(ts, ID)` order (invalid deltas' writes
/// left out, from a valid snapshot only what it holds under such a dot without a write of its
/// own there, `Unmerge::unvouched`), holding a write that supersedes one. Supersession is judged
/// against the write alone (spec/crdt.md §4.8): a piece of a body kills a write of the part when
/// it is a winner of the part's piece the body piece can reach (`Fragment::reach`) and not of
/// the two joined. A body holding the superseder is its own commit or a later snapshot carrying
/// it, dated at the snapshot (never earlier than the death). A delta stops at the first death
/// (only the earliest counts); a snapshot when every write has died. A write no body of the
/// walk kills is left out. Cost: the aspect's bodies from the part's earliest dead write to its
/// last death, each piece against the part's piece it reaches.
fn first_deaths(tx: &mut Tx<'_>, c: &CommitId, ai: usize, tid: &Tid, ak: &Ak, dead: &BTreeMap<Won, Ts>, snap: bool) -> Result<BTreeMap<Won, Ts>> {
    let un = crate::apply::Unmerge::of(tx, tid, ak)?;
    let strip = |f: &mut Fragment, snap: bool| f.remove_writes(&|d| if snap { un.unvouched(d) } else { un.bad(d) });
    let mut own = Fragment::default();
    crate::apply::each_held_piece(tx, c, ai, &mut |_, mut f| {
        strip(&mut f, snap);
        own.join(f);
        Ok(())
    })?;
    tx.core.death_walks += 1;
    let from = dead.keys().map(|w| w.stamp.ts).min().unwrap_or_default();
    let mut bodies: Vec<(Ts, CommitId, usize, bool)> = Vec::new();
    for (ts, x) in tx.core.ix.by_aspect.get(&(*tid, ak.clone())).into_iter().flatten().filter(|x| x.1 != *c && x.0 >= from).cloned().collect::<Vec<_>>() {
        let Some(xai) = held_part(tx.core, &x, tid, ak) else { continue };
        if crate::apply::copies::invalid_snapshot(tx.core, &x, tid, ak) {
            continue;
        }
        bodies.push((ts, x, xai, tx.core.ix.commits.get(&x).is_some_and(|m| m.header.kind.is_compaction())));
    }
    let mut left: BTreeSet<&Won> = dead.keys().collect();
    let mut out = BTreeMap::new();
    for (ts, x, xai, xsnap) in bodies {
        drop(crate::costs::span("deaths: a body"));
        crate::apply::each_held_piece(tx, &x, xai, &mut |_, mut f| {
            strip(&mut f, xsnap);
            let mut region = own.reach(&f);
            let before = region.winners();
            if !left.iter().any(|w| before.contains(w)) {
                return Ok(());
            }
            region.join(f);
            let after = region.winners();
            left.retain(|w| {
                let dies = before.contains(w) && !after.contains(w);
                if dies {
                    out.insert((*w).clone(), ts);
                }
                !dies
            });
            Ok(())
        })?;
        if left.is_empty() || !snap && !out.is_empty() {
            break;
        }
    }
    Ok(out)
}

/// The date of a death by the write stamped `k` on `(tid, ak)` as the state shows it: `k`'s
/// `ts`, or when its own delta is invalid here (the state holds it as a valid snapshot's copy,
/// which supersedes from the snapshot on, spec/crdt.md §4.8) the earliest held valid snapshot's
/// `ts` holding it, if later.
fn date(tx: &mut Tx<'_>, tid: &Tid, ak: &Ak, k: &Stamp) -> Result<Ts> {
    if !crate::apply::invalid_of(tx.core, tid, ak).iter().any(|o| o.owns(k.dot.origin())) {
        return Ok(k.ts);
    }
    let mut snaps: Vec<(Ts, CommitId, usize)> = tx.core.ix.snapshots.get(&(*tid, ak.clone())).into_iter().flatten().filter(|x| x.0 > k.ts && !crate::apply::copies::invalid_snapshot(tx.core, &x.1, tid, ak)).filter_map(|x| held_part(tx.core, &x.1, tid, ak).map(|ai| (x.0, x.1, ai))).collect();
    snaps.sort();
    for (ts, s, ai) in snaps {
        let mut holds = false;
        crate::apply::each_held_piece(tx, &s, ai, &mut |_, f| {
            holds |= f.holds_stamp(k);
            Ok(())
        })?;
        if holds {
            return Ok(ts);
        }
    }
    Ok(k.ts)
}

/// The aspect index of `(tid, ak)` in `c` if that part is held with values and has a relative
/// bound (a bare leftover has no values to keep: `Meta::bare`).
fn bounded_part(core: &Core, c: &CommitId, tid: &Tid, ak: &Ak) -> Option<usize> {
    held_part(core, c, tid, ak).filter(|ai| core.ix.commits.get(c).is_some_and(|m| !m.bare(*ai) && m.header.aspects.get(*ai).is_some_and(bounded)))
}

/// Whether a held body of `(tid, ak)` has a relative bound (debug builds: checked against a walk
/// of the aspect's bodies).
pub(crate) fn any_bounded(core: &Core, tid: &Tid, ak: &Ak) -> bool {
    let k = (*tid, ak.clone());
    let any = core.ix.bounded_held.contains_key(&k);
    debug_assert_eq!(any, core.ix.by_aspect.get(&k).into_iter().flatten().any(|(_, c)| bounded_part(core, c, tid, ak).is_some()), "bounded_held of {tid:?} {ak:?}");
    any
}

/// The writes joins on an aspect superseded (spec/crdt.md §4.8), for `mark_killed`: by dot, or
/// `all` when a join is not judged write by write (a reset joined by pages).
#[derive(Debug, Default)]
pub(crate) struct Killed {
    pub dots: BTreeSet<osis_crdt::Dot>,
    pub all: bool,
}

impl Killed {
    /// Notes the writes the join of `d` into `st` superseded: `before`, the winners of `st` at
    /// `d`'s reach and of `d` (`Killed::before`), against `st` after the join.
    pub(crate) fn note(&mut self, before: &Winners, st: &Fragment, d: &Fragment) {
        self.dots.extend(before.minus(&st.reach(d).winners()).into_iter().map(|w| w.stamp.dot));
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
/// judged again by node-sync (`Core::changed`); with `Killed::all`, every one (`mark_bounded`).
pub(crate) fn mark_killed(tx: &mut Tx<'_>, tid: &Tid, ak: &Ak, dead: &Killed) {
    if dead.all {
        return mark_bounded(tx, tid, ak);
    }
    if dead.dots.is_empty() || !any_bounded(tx.core, tid, ak) {
        return;
    }
    let core = &*tx.core;
    let mut on: BTreeSet<CommitId> = dead.dots.iter().filter_map(|d| core.commit_of(tid, ak, d)).collect();
    on.extend(core.ix.snapshots.get(&(*tid, ak.clone())).into_iter().flatten().map(|x| x.1));
    for c in on {
        if bounded_part(tx.core, &c, tid, ak).is_some() {
            tx.core.mark_changed(c);
        }
    }
}

/// The state of `(tid, ak)` was rebuilt (a validity flip, an un-merge, a drop): every held body
/// with a relative bound is judged again by node-sync, as when it was replaced may have moved.
pub(crate) fn mark_bounded(tx: &mut Tx<'_>, tid: &Tid, ak: &Ak) {
    if !any_bounded(tx.core, tid, ak) {
        return;
    }
    let on: Vec<CommitId> = tx.core.ix.by_aspect.get(&(*tid, ak.clone())).into_iter().flatten().map(|x| x.1).collect();
    for c in on {
        if bounded_part(tx.core, &c, tid, ak).is_some() {
            tx.core.mark_changed(c);
        }
    }
}

/// From when this node's compaction may drop held body `(tid, ak)` of `c` as covered
/// (spec/commits.md §5, spec/sync.md §7): `MAX_DRIFT` past its keep-at-least
/// bound (a node whose clock lags by up to that still holds it must-hold and would place it
/// again); `None` when this node may not purge it now (node-sync's `drop_covered`).
pub(crate) fn drop_from(tx: &mut Tx<'_>, c: &CommitId, tid: &Tid, ak: &Ak) -> Result<Option<u64>> {
    let (ai, h) = known_part(tx.core, c, tid, ak)?;
    let by = h.aspects.get(ai).map_or(osis_base::PurgeBy::Nobody, |a| a.retention.by);
    let me = tx.core.id.tid();
    let at = At::now(Ts::make(tx.now(), 0).unwrap_or_default());
    if !tx.core.timelines.get(tid).is_some_and(|tl| tl.may_purge(&me, tid, by, &h.actor, at)) {
        return Ok(None);
    }
    Ok(Some(body_keep(tx, c, tid, ak)?.saturating_add(osis_base::format::MAX_DRIFT_MS)))
}

/// `Engine::body_live` of the body holding aspect `ai` of `c`, judged against the state in
/// `tx`: a function of the commits applied (the join's), so alike at nodes that applied the
/// same ones.
pub(super) fn live(tx: &mut Tx<'_>, c: &CommitId, ai: usize) -> Result<bool> {
    let Some(h) = tx.core.ix.commits.get(c).map(|m| m.header.clone()) else { return Ok(true) };
    let holders = body_class(tx.core, &h, ai);
    if h.kind.is_compaction() {
        return snapshot_live(tx, &h, c, &holders);
    }
    for x in holders {
        let Some(a) = h.aspects.get(x) else { continue };
        let own = writes_of(&h, c, x);
        let owns = |st: &Fragment| st.holds_owned_write(&|src, lo, hi| own.iter().any(|o| o.owns_range(src, lo, hi)));
        // per piece of each delta of the body, the state's part it meets (all of it when none
        // is held)
        let mut live = false;
        let held = crate::apply::each_held_piece(tx, c, x, &mut |tx, f| {
            if !live {
                live = tx.state_at(&a.tid, &a.ak, &f)?.as_ref().is_some_and(owns);
            }
            Ok(())
        })?;
        if held.is_none() {
            live = tx.state(&a.tid, &a.ak)?.is_some_and(owns);
        }
        if live {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Whether a compaction snapshot carries a write still live in this node's state (`body_live`;
/// live writes as for deltas, `Fragment::live_writes`: no element or entry tombstone): held, a
/// write it carries (by dot) is there, judged a piece of it at a time against the state's part
/// it meets. Not held (dropped or never received), which writes it carried are not known here: it
/// is live while the state holds a write stamped at or before its `ts` (the header's `ts` bounds
/// what it carried) or one without a `ts` (a sequence record whose creation is gone): an
/// over-approximation, so its delete at hosts waits for a carrier (spec/sync.md §7).
pub(super) fn snapshot_live(tx: &mut Tx<'_>, h: &Header, c: &CommitId, holders: &[usize]) -> Result<bool> {
    for x in holders {
        let Some(a) = h.aspects.get(*x) else { continue };
        // by dot: records without a `ts` count too
        let mut live = false;
        let held = crate::apply::each_held_piece(tx, c, *x, &mut |tx, f| {
            let carried: BTreeSet<osis_crdt::Dot> = f.live_writes().into_iter().map(|(d, _)| d).collect();
            if !live && !carried.is_empty() {
                live = tx.state_at(&a.tid, &a.ak, &f)?.is_some_and(|st| st.live_writes().into_iter().any(|(d, _)| carried.contains(&d)));
            }
            Ok(())
        })?;
        if live {
            return Ok(true);
        }
        if held.is_some() {
            continue;
        }
        let Some(st) = tx.state(&a.tid, &a.ak)? else { continue };
        if st.live_writes().iter().any(|(_, t)| t.is_none_or(|t| t <= h.ts)) {
            return Ok(true);
        }
    }
    Ok(false)
}

impl Engine {
    /// Keep-at-least bound (wall ms, 0: none) of the body holding each part of known commit `c`,
    /// by aspect index: judged once per body, so a commit's judgment costs O(parts) death reads.
    pub fn body_keeps(&mut self, c: &CommitId) -> Result<Vec<u64>> {
        let c = *c;
        self.run(|tx| body_keeps(tx, &c))
    }

    /// From when this node's compaction may drop held body `(tid, ak)` of `c` as covered
    /// (`drop_from`); `None`: never, it may not purge it.
    pub fn drop_from(&mut self, c: &CommitId, tid: &Tid, ak: &Ak) -> Result<Option<u64>> {
        let (c, tid, ak) = (*c, *tid, ak.clone());
        self.run(|tx| drop_from(tx, &c, &tid, &ak))
    }

    /// When the body holding aspect `ak` of `c` was replaced, for a relative keep at least
    /// (`replaced_at`; `None`: no relative bound, or no write of it dead).
    pub fn replaced_at(&mut self, c: &CommitId, tid: &Tid, ak: &Ak) -> Result<Option<Ts>> {
        let (c, tid, ak) = (*c, *tid, ak.clone());
        self.run(|tx| {
            let (ai, h) = known_part(tx.core, &c, &tid, &ak)?;
            let holders = body_class(tx.core, &h, ai);
            replaced_at(tx, &h, &c, &holders)
        })
    }

    /// Whether a write of the body holding aspect `ak` of `c` is still in this node's state (a
    /// dot its deltas own survives there; unknown counts as live). A
    /// body without one needs no carrier before it leaves a label (spec/sync.md §7); one with one
    /// goes only after its carrier (spec/commits.md §5). Writes the state does not hold count
    /// dead: superseded, purged or expired ones, and those of deltas invalid here or undone (they
    /// are stripped from the state; they count live again once a validity flip or a redo puts
    /// them back). Any write counts: resets (a tombstone's, for its remover) and value-less writes too. Kept per body
    /// until its aspect's state changes (`Core::live_bodies`).
    pub fn body_live(&mut self, c: &CommitId, tid: &Tid, ak: &Ak) -> Result<bool> {
        if let Some(v) = self.core.live_bodies.get(c).and_then(|m| m.get(&(*tid, ak.clone()))) {
            return Ok(*v);
        }
        let (c, tid, ak) = (*c, *tid, ak.clone());
        self.run(|tx| body_live(tx, &c, &tid, &ak))
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
