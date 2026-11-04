//! A held body's keep bounds and whether it holds a live write (spec/commits.md §5).

use super::{aspect_index, body_class, deaths_of, gone_of, known_part, writes_of};
#[cfg(test)]
use super::oracle;
use crate::engine::{Engine, Tx};
use crate::error::{Error, Result};
use osis_base::{Ak, CommitId, Tid, Ts};
use osis_commit::Header;
use osis_crdt::Fragment;
use osis_perm::At;
use std::collections::{BTreeMap, BTreeSet};

/// `Engine::body_live` in `tx`, through `Core::live_bodies`.
fn body_live(tx: &mut Tx<'_>, c: &CommitId, tid: &Tid, ak: &Ak) -> Result<bool> {
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

/// `Engine::body_keep` in `tx`, deaths settled.
pub(crate) fn body_keep(tx: &mut Tx<'_>, c: &CommitId, tid: &Tid, ak: &Ak) -> Result<osis_commit::retention::Keep> {
    let (ai, h) = known_part(tx.core, c, tid, ak)?;
    let r = h.aspects.get(ai).ok_or(Error::UnknownCommit(*c))?.retention;
    let d = deaths_of(tx, &h, c, ai)?;
    let live = r.at_most.rel.is_some() && d.is_some() && body_live(tx, c, tid, ak)?;
    Ok(osis_commit::retention::body_keep(&h, &r, d.map(|d| d.0.wall_ms().0), d.map(|d| d.1.wall_ms().0), live))
}

/// From when this node's compaction may drop held body `(tid, ak)` of `c` as covered
/// (spec/commits.md §5, spec/sync.md §7), deaths settled: `MAX_DRIFT` past its keep-at-least
/// bound (a node whose clock lags by up to that still holds it must-hold and would place it
/// again); `None` when this node may not purge it now. One predicate for compaction
/// (node-sync's `drop_covered`) and a demotion's frontier (`receipt::droppable_here`), so the
/// two never disagree.
pub(crate) fn drop_from(tx: &mut Tx<'_>, c: &CommitId, tid: &Tid, ak: &Ak) -> Result<Option<u64>> {
    let (ai, h) = known_part(tx.core, c, tid, ak)?;
    let by = h.aspects.get(ai).map_or(osis_base::PurgeBy::Nobody, |a| a.retention.by);
    let me = tx.core.id.tid();
    let at = At::now(Ts::make(tx.now(), 0).unwrap_or_default());
    if !tx.core.timelines.get(tid).is_some_and(|tl| tl.may_purge(&me, tid, by, &h.purge_actor(), at)) {
        return Ok(None);
    }
    Ok(Some(body_keep(tx, c, tid, ak)?.at_least.saturating_add(osis_base::format::MAX_DRIFT_MS)))
}

/// `Engine::body_live` of the body holding aspect `ai` of `c`, judged against the state in
/// `tx`: a function of the commits applied (the join's), so alike at nodes that applied the
/// same ones.
pub(super) fn live(tx: &mut Tx<'_>, c: &CommitId, ai: usize) -> Result<bool> {
    let Some(h) = tx.core.ix.commits.get(c).map(|m| m.header.clone()) else { return Ok(true) };
    let (_, holders) = body_class(tx.core, &h, c, ai);
    if h.kind.is_compaction() {
        return snapshot_live(tx, &h, c, &holders);
    }
    for x in holders {
        let Some(a) = h.aspects.get(x) else { continue };
        // an import's writes are under its origins' dots (`writes_of`)
        let own = writes_of(tx.core, &h, c, x);
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
        if held.is_empty() {
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
/// it meets. Dropped, which writes it carried went with the body
/// (spec/commits.md §5), so whether it
/// was live then is kept (`Dropped::live`): dropped dead it stays dead (undo and redo write
/// new dots; a write a validity flip brings back comes from a held body,
/// which carries it at hosts itself); dropped live, it is
/// live while the state holds a write stamped at or before its `ts` (the header's `ts` bounds
/// what it carried) or one without a `ts` (a bare anchor it may carry): an
/// over-approximation, so its delete at hosts waits for a carrier (spec/sync.md §7).
/// Never held: a write stamped at or before its `ts`.
pub(super) fn snapshot_live(tx: &mut Tx<'_>, h: &Header, c: &CommitId, holders: &[usize]) -> Result<bool> {
    // per dropped aspect, whether it was live then
    let dropped: BTreeMap<usize, bool> = tx.core.ix.commits.get(c).map(|m| m.dropped.iter().map(|(ai, d)| (*ai, d.live)).collect()).unwrap_or_default();
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
        if !held.is_empty() || dropped.get(x) == Some(&false) {
            continue;
        }
        let Some(st) = tx.state(&a.tid, &a.ak)? else { continue };
        let tsless = dropped.contains_key(x);
        if st.live_writes().iter().any(|(_, t)| t.map_or(tsless, |t| t <= h.ts)) {
            return Ok(true);
        }
    }
    Ok(false)
}

impl Engine {
    /// Keep bounds of a held body (wall ms): (keep at least, keep at most).
    pub fn body_keep(&mut self, c: &CommitId, tid: &Tid, ak: &Ak) -> Result<osis_commit::retention::Keep> {
        self.settle_deaths()?;
        let (c, tid, ak) = (*c, *tid, ak.clone());
        self.run(|tx| body_keep(tx, &c, &tid, &ak))
    }

    /// From when this node's compaction may drop held body `(tid, ak)` of `c` as covered
    /// (`drop_from`); `None`: never, it may not purge it.
    pub fn drop_from(&mut self, c: &CommitId, tid: &Tid, ak: &Ak) -> Result<Option<u64>> {
        self.settle_deaths()?;
        let (c, tid, ak) = (*c, *tid, ak.clone());
        self.run(|tx| drop_from(tx, &c, &tid, &ak))
    }

    /// First and last death so far of the writes of the body holding aspect `ak` of `c`.
    pub fn deaths(&mut self, c: &CommitId, tid: &Tid, ak: &Ak) -> Result<Option<(Ts, Ts)>> {
        self.settle_deaths()?;
        let (c, tid, ak) = (*c, *tid, ak.clone());
        self.run(|tx| {
            let (ai, h) = known_part(tx.core, &c, &tid, &ak)?;
            deaths_of(tx, &h, &c, ai)
        })
    }

    /// Whether a write of the body holding aspect `ak` of `c` is still in this node's state (a
    /// dot its deltas own, an import's origins' dots, survives there; unknown counts as live). A
    /// body without one needs no carrier before it leaves a label (spec/sync.md §7); one with one
    /// gets `AT_MOST_GRACE` (spec/commits.md §5). Writes the state does not hold count
    /// dead: superseded, purged or expired ones, and those of deltas invalid here or undone (they
    /// are stripped from the state; they count live again once a validity flip or a redo puts
    /// them back). Any write counts: resets, tombstones and value-less writes too. Kept per body
    /// until its aspect's state changes (`Core::live_bodies`).
    pub fn body_live(&mut self, c: &CommitId, tid: &Tid, ak: &Ak) -> Result<bool> {
        if let Some(v) = self.core.live_bodies.get(c).and_then(|m| m.get(&(*tid, ak.clone()))) {
            return Ok(*v);
        }
        let (c, tid, ak) = (*c, *tid, ak.clone());
        self.run(|tx| body_live(tx, &c, &tid, &ak))
    }

    /// Whether delta `ai` of `c` holds writes of its own and is held value-less for all of them: a
    /// purge took them, so it has no live write to carry (spec/commits.md §5). An import with a
    /// purged origin and another standing is not: its other writes count (`body_live`). Limit, with
    /// that other origin dead too: the residue reads live and its blob waits for a carrier. Only a
    /// hand-made import lists several origins, and only the thing's creator can write one.
    pub fn part_valueless(&self, h: &Header, c: &CommitId, ai: usize) -> bool {
        let own = writes_of(&self.core, h, c, ai);
        !own.is_empty() && gone_of(&self.core, h, c, ai).len() == own.len()
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

    /// Whether `c` is known with an aspect `(tid, ak)` whose body is not dropped: true for a
    /// missing part too (`Engine::aspect_dump` shows which).
    pub fn body_not_dropped(&self, c: &CommitId, tid: &Tid, ak: &Ak) -> bool {
        let Some(m) = self.core.ix.commits.get(c) else { return false };
        m.aspect(tid, ak).is_some_and(|ai| !m.dropped.contains_key(&ai))
    }
}
