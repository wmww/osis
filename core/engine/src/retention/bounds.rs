//! A held body's keep-at-least bound and whether it holds a live write (spec/commits.md §5).

use super::{aspect_index, body_class, body_classes, bounded, gone_of, held_part, known_part, writes_of};
#[cfg(test)]
use super::oracle;
use crate::engine::{Core, Engine, Tx};
use crate::error::{Error, Result};
use osis_base::{Ak, CommitId, Tid, Ts};
use osis_commit::Header;
use osis_crdt::{Changes, Death, Fragment, Stamp};
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

/// The superseder of `d`.
fn killer(d: &Death) -> Stamp {
    Stamp { ts: d.at, dot: d.by.clone() }
}

/// Whether death `d` is of a write `f` holds: `f` holds a write of its stamp but not its
/// superseder's (a stamp names several writes: a map entry's creation outlives its value write;
/// a body holding any write of the superseder's stamp holds the superseder).
pub(super) fn dies_in(f: &Fragment, d: &Death) -> bool {
    f.holds_stamp(&d.stamp) && !f.holds_stamp(&killer(d))
}

/// When the body of `c` holding aspects `holders` (one class, `body_class`) was replaced, for a
/// relative keep at least (spec/commits.md §5): a function of the held set, judged when asked,
/// never stored. A write of a held valid part is dead when joining the part into the state
/// reports it superseded (spec/crdt.md §4.8: pruned, beaten, its element deleted); it died at the
/// first held valid body, in `(ts, ID)` order, whose writes supersede it (`first_deaths`), dated
/// at that body's `ts` (a snapshot carrying an older superseder dates later, never earlier). A
/// delta's body is replaced at the earliest of its writes' deaths, a snapshot's at the latest (it
/// keeps the history of every write it carries, each for D after that write died); `None`: no
/// write of it is dead, so it is past a relative bound. Bodies with no relative bound, invalid
/// parts and bare leftovers (no values to keep) are not judged (`Core::replaced_reads` counts
/// the judgments).
pub(super) fn replaced_at(tx: &mut Tx<'_>, h: &Header, c: &CommitId, holders: &[usize]) -> Result<Option<Ts>> {
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
        let dead = dead_writes(tx, c, *ai, &tid, &ak)?;
        #[cfg(test)]
        assert_eq!(dead, oracle::dead_writes(tx, c, *ai, &tid, &ak)?, "dead writes streamed vs whole");
        if dead.is_empty() {
            continue;
        }
        let first = first_deaths(tx, c, *ai, &tid, &ak, &dead, snap)?;
        let each = dead.iter().map(|(s, (_, up))| first.get(s).map_or(*up, |t| (*t).min(*up)));
        let part = if snap { each.max() } else { each.min() };
        out = match (out, part) {
            (Some(o), Some(p)) => Some(if snap { o.max(p) } else { o.min(p) }),
            (o, p) => o.or(p),
        };
    }
    Ok(out)
}

/// The writes of held part `ai` of `c` the state supersedes, by stamp (a stamp names several
/// writes: a map entry's creation and its value, a struct's fields): how many, and the latest
/// date of the superseders the state holds (`date`: an upper bound of their deaths). Each piece
/// of the part joins into a copy of the state's part it meets.
pub(super) fn dead_writes(tx: &mut Tx<'_>, c: &CommitId, ai: usize, tid: &Tid, ak: &Ak) -> Result<BTreeMap<Stamp, (usize, Ts)>> {
    let mut found = Vec::new();
    crate::apply::each_held_piece(tx, c, ai, &mut |tx, f| {
        let Some(mut st) = tx.state_at(tid, ak, &f)? else { return Ok(()) };
        let mut ch = Changes::new();
        st.join_into(f.clone(), None, &mut ch);
        found.extend(ch.into_deaths().into_iter().filter(|d| dies_in(&f, d)));
        Ok(())
    })?;
    let mut out: BTreeMap<Stamp, (usize, Ts)> = BTreeMap::new();
    for d in &found {
        let at = date(tx, tid, ak, d)?;
        let e = out.entry(d.stamp.clone()).or_insert((0, at));
        e.0 += 1;
        e.1 = e.1.max(at);
    }
    Ok(out)
}

/// When each stamp of `dead` (`dead_writes`) had all its counted writes superseded: part `ai` of
/// `c` joined whole, then every other held valid body of the aspect stamped no earlier than the
/// earliest dead write, in `(ts, ID)` order (invalid deltas' writes left out, from a valid
/// snapshot only what it holds under such a dot without a write of its own there,
/// `Unmerge::unvouched`), each death counted against its stamp at the joining body's `ts`.
/// Stops past the latest date a stamp still waits for (the state's superseders, `dead`), and
/// for a delta at its first death. Cost: the aspect's bodies in that window.
fn first_deaths(tx: &mut Tx<'_>, c: &CommitId, ai: usize, tid: &Tid, ak: &Ak, dead: &BTreeMap<Stamp, (usize, Ts)>, snap: bool) -> Result<BTreeMap<Stamp, Ts>> {
    let un = crate::apply::Unmerge::of(tx, tid, ak)?;
    let strip = |f: &mut Fragment, snap: bool| f.remove_writes(&|d| if snap { un.unvouched(d) } else { un.bad(d) });
    let mut scratch = Fragment::default();
    crate::apply::each_held_piece(tx, c, ai, &mut |_, mut f| {
        strip(&mut f, snap);
        scratch.join(f);
        Ok(())
    })?;
    let from = dead.keys().map(|s| s.ts).min().unwrap_or_default();
    let bound = if snap { dead.values().map(|x| x.1).max() } else { dead.values().map(|x| x.1).min() }.unwrap_or_default();
    let bodies: Vec<(Ts, CommitId)> = tx.core.ix.by_aspect.get(&(*tid, ak.clone())).into_iter().flatten().filter(|x| x.1 != *c && x.0 >= from && x.0 <= bound).cloned().collect();
    let mut seen: BTreeMap<Stamp, usize> = BTreeMap::new();
    let mut out: BTreeMap<Stamp, Ts> = BTreeMap::new();
    for (ts, x) in bodies {
        if out.len() == dead.len() || (!snap && !out.is_empty()) {
            break;
        }
        let Some(xai) = held_part(tx.core, &x, tid, ak) else { continue };
        if crate::apply::copies::invalid_snapshot(tx.core, &x, tid, ak) {
            continue;
        }
        let xsnap = tx.core.ix.commits.get(&x).is_some_and(|m| m.header.kind.is_compaction());
        let mut deaths = Vec::new();
        crate::apply::each_held_piece(tx, &x, xai, &mut |_, mut f| {
            strip(&mut f, xsnap);
            let mut ch = Changes::new();
            scratch.join_into(f, None, &mut ch);
            deaths.extend(ch.into_deaths());
            Ok(())
        })?;
        for d in deaths {
            let Some((n, _)) = dead.get(&d.stamp) else { continue };
            let k = seen.entry(d.stamp.clone()).or_default();
            *k += 1;
            if *k >= *n {
                out.entry(d.stamp).or_insert(ts);
            }
        }
    }
    Ok(out)
}

/// The date of death `d` on `(tid, ak)` as the state shows it: its superseder's `ts`, or when the
/// superseder's own delta is invalid here (the state holds it as a valid snapshot's copy, which
/// supersedes from the snapshot on, spec/crdt.md §4.8) the earliest held valid snapshot's `ts`
/// holding it, if later.
pub(super) fn date(tx: &mut Tx<'_>, tid: &Tid, ak: &Ak, d: &Death) -> Result<Ts> {
    if !crate::apply::invalid_of(tx.core, tid, ak).iter().any(|o| o.owns(d.by.origin())) {
        return Ok(d.at);
    }
    let k = killer(d);
    let mut snaps: Vec<(Ts, CommitId, usize)> = tx.core.ix.snapshots.get(&(*tid, ak.clone())).into_iter().flatten().filter(|x| x.0 > d.at && !crate::apply::copies::invalid_snapshot(tx.core, &x.1, tid, ak)).filter_map(|x| held_part(tx.core, &x.1, tid, ak).map(|ai| (x.0, x.1, ai))).collect();
    snaps.sort();
    for (ts, s, ai) in snaps {
        let mut holds = false;
        crate::apply::each_held_piece(tx, &s, ai, &mut |_, f| {
            holds |= f.holds_stamp(&k);
            Ok(())
        })?;
        if holds {
            return Ok(ts);
        }
    }
    Ok(d.at)
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

/// A join on `(tid, ak)` reported `deaths`: the held bodies with a relative bound they may have
/// replaced (the dying writes' own commits, and the aspect's snapshots, which may carry them) are
/// judged again by node-sync (`Core::changed`).
pub(crate) fn mark_killed(tx: &mut Tx<'_>, tid: &Tid, ak: &Ak, deaths: &[Death]) {
    if deaths.is_empty() || !any_bounded(tx.core, tid, ak) {
        return;
    }
    let core = &*tx.core;
    let mut on: BTreeSet<CommitId> = deaths.iter().filter_map(|d| core.commit_of(tid, ak, &d.stamp.dot)).collect();
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
/// what it carried) or one without a `ts` (a bare anchor it may carry): an over-approximation, so
/// its delete at hosts waits for a carrier (spec/sync.md §7).
pub(super) fn snapshot_live(tx: &mut Tx<'_>, h: &Header, c: &CommitId, holders: &[usize]) -> Result<bool> {
    for x in holders {
        let Some(a) = h.aspects.get(*x) else { continue };
        // by dot: bare anchors and other writes without a `ts` count too
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
