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

/// Whether death `d` is of a write of a fragment holding `held` (`Fragment::stamps`): it holds a
/// write of its stamp but not its superseder's (a stamp names several writes: a map entry's
/// creation outlives its value write; a body holding any write of the superseder's stamp holds
/// the superseder). Indexed once per fragment: a reset kills every write of a part, and a walk
/// of the part per death was quadratic.
pub(super) fn dies_in(held: &osis_crdt::Stamps, d: &Death) -> bool {
    held.holds(&d.stamp) && !held.holds(&killer(d))
}

/// When the body of `c` holding aspects `holders` (one class, `body_class`) was replaced, for a
/// relative keep at least (spec/commits.md §5): a function of the held set, judged when asked,
/// never stored, and never of how a part is paged (`deaths` joins it whole). A write of a held
/// valid part is dead when joining the part into the state reports it superseded (spec/crdt.md
/// §4.8: pruned, beaten, its element deleted); it died at the
/// `ts` of the earliest held valid body holding a write that supersedes it (`first_deaths`): its
/// superseder's own commit, or a later snapshot carrying it (never earlier than the death). A
/// delta's body is replaced at the earliest of its writes' deaths, a snapshot's at the latest
/// among those no held valid snapshot stamped later carries (`carried`: that one keeps their
/// history, so this one is needed only for writes that died before it); `None`: no such write
/// is dead, so it is past a relative bound. A node holding more bodies dates no later.
/// Bodies with no relative bound, invalid parts and bare leftovers (no values to keep) are not
/// judged (`Core::replaced_reads` counts the judgments).
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
        let found = deaths(tx, c, *ai, &tid, &ak)?;
        let mut dead = tally(tx, &tid, &ak, &found)?;
        if snap && !dead.is_empty() {
            let gone = carried(tx, h.ts, a, c, &found)?;
            dead.retain(|s, _| !gone.contains(s));
        }
        if dead.is_empty() {
            continue;
        }
        let first = first_deaths(tx, c, *ai, &tid, &ak, &dead, &counts(&found), snap)?;
        // a superseder no body of the walk holds dates as the state holds it (`date`)
        let each = dead.iter().map(|(s, up)| first.get(s).copied().unwrap_or(*up));
        let part = if snap { each.max() } else { each.min() };
        out = match (out, part) {
            (Some(o), Some(p)) => Some(if snap { o.max(p) } else { o.min(p) }),
            (o, p) => o.or(p),
        };
    }
    Ok(out)
}

/// The deaths of the writes of held part `ai` of `c` the state supersedes: the part joins whole,
/// in one join, into a copy of the state at its positions (`Tx::state_part_at`): O(part),
/// whatever the state's size. Never piece by piece: a page piece repeats the entry creations on
/// its path (`osis_crdt::Piece::Page`), so per-piece joins report those writes once per page and
/// what the reports count would depend on how the part is paged.
fn deaths(tx: &mut Tx<'_>, c: &CommitId, ai: usize, tid: &Tid, ak: &Ak) -> Result<Vec<Death>> {
    let Some(f) = crate::apply::held_fragment(tx, c, ai)? else { return Ok(Vec::new()) };
    let Some(mut st) = tx.state_part_at(tid, ak, &f)? else { return Ok(Vec::new()) };
    let held = f.stamps();
    let mut ch = Changes::new();
    st.join_into(f, None, &mut ch);
    Ok(ch.into_deaths().into_iter().filter(|d| dies_in(&held, d)).collect())
}

/// The stamps of `deaths` (the part's dead writes), each with the latest date of the superseders
/// the state holds (`date`): a set, all a delta's dating needs.
fn tally(tx: &mut Tx<'_>, tid: &Tid, ak: &Ak, found: &[Death]) -> Result<BTreeMap<Stamp, Ts>> {
    let mut out: BTreeMap<Stamp, Ts> = BTreeMap::new();
    for d in found {
        let at = date(tx, tid, ak, d)?;
        let e = out.entry(d.stamp.clone()).or_insert(at);
        *e = (*e).max(at);
    }
    Ok(out)
}

/// How many of `deaths` one join reported per stamp. A stamp names several writes (a map
/// entry's creation and its value, a struct's fields, every value one write op set), and a
/// snapshot's dating is per write (when the last of them died, whether a later snapshot carries
/// them all), so a set of stamps would date it early; with no position in a death, the
/// reports of one whole join stand in for the writes (issues/death-write-identity.md).
fn counts(found: &[Death]) -> BTreeMap<Stamp, usize> {
    let mut out: BTreeMap<Stamp, usize> = BTreeMap::new();
    for d in found {
        *out.entry(d.stamp.clone()).or_default() += 1;
    }
    out
}

/// A death as `carried` compares it: the same write dies alike in every body holding it.
type DeathKey = (Stamp, Ts, osis_crdt::Dot, bool);

fn death_key(d: &Death) -> DeathKey {
    (d.stamp.clone(), d.at, d.by.clone(), d.element)
}

/// The stamps of `found` (the deaths of snapshot `c`, stamped `ts`, part `a`) whose every dead
/// write a held valid snapshot stamped later, keeping history at least as long, carries
/// (spec/commits.md §5): that one keeps their history.
/// A later snapshot's copy of a dead write dies alike when it joins the state, so it carries
/// the write when its own `deaths` hold the same death; a stamp is judged whole (one of its
/// writes carried and another not keeps it). The later snapshots are read in `ts` order until
/// every stamp is carried.
fn carried(tx: &mut Tx<'_>, ts: Ts, a: &osis_commit::AspectEntry, c: &CommitId, found: &[Death]) -> Result<BTreeSet<Stamp>> {
    let (tid, ak) = (&a.tid, &a.ak);
    let keeps = |x: &osis_commit::AspectEntry| osis_commit::retention::KeepRule::of_aspect(x).after.unwrap_or(0);
    let after = keeps(a);
    let mut want: BTreeMap<DeathKey, usize> = BTreeMap::new();
    for d in found {
        *want.entry(death_key(d)).or_default() += 1;
    }
    let mut later: Vec<(Ts, CommitId, usize)> = tx.core.ix.snapshots.get(&(*tid, ak.clone())).into_iter().flatten().filter(|x| x.0 > ts && x.1 != *c && !crate::apply::copies::invalid_snapshot(tx.core, &x.1, tid, ak)).filter_map(|x| held_part(tx.core, &x.1, tid, ak).map(|ai| (x.0, x.1, ai))).filter(|x| tx.core.ix.commits.get(&x.1).is_some_and(|m| !m.bare(x.2) && m.valid_at(x.2) && m.header.aspects.get(x.2).is_some_and(|l| keeps(l) >= after))).collect();
    later.sort();
    // per death the most copies one later snapshot carries
    let mut have: BTreeMap<DeathKey, usize> = BTreeMap::new();
    for (_, l, lai) in later {
        let mut n: BTreeMap<DeathKey, usize> = BTreeMap::new();
        for d in deaths(tx, &l, lai, tid, ak)? {
            let k = death_key(&d);
            if want.contains_key(&k) {
                *n.entry(k).or_default() += 1;
            }
        }
        for (k, x) in n {
            let e = have.entry(k).or_default();
            *e = (*e).max(x);
        }
        if want.iter().all(|(k, x)| have.get(k).is_some_and(|h| h >= x)) {
            break;
        }
    }
    let mut kept: BTreeSet<Stamp> = BTreeSet::new();
    for (k, x) in &want {
        if have.get(k).is_none_or(|h| h < x) {
            kept.insert(k.0.clone());
        }
    }
    Ok(want.keys().map(|k| k.0.clone()).filter(|s| !kept.contains(s)).collect())
}

/// When the writes of `dead` (`tally`; `want`: `counts`) died, per stamp: every held valid body of the
/// aspect other than `c` stamped no earlier than the earliest dead write joins, in `(ts, ID)`
/// order (invalid deltas' writes left out, from a valid snapshot only what it holds under such a
/// dot without a write of its own there, `Unmerge::unvouched`), into a scratch fragment holding
/// part `ai` of `c` (supersession is judged against the write alone, spec/crdt.md §4.8, so the
/// first body whose join kills a write of the part is the earliest body holding its
/// superseder). A delta dates at the first such body. A snapshot needs every counted write of a
/// stamp dead (`snapshot_deaths`), counted as `counts` counts them, a whole join at a time. A stamp no held body supersedes (its superseder only in the
/// state) is left out. Cost: the aspect's bodies from the part's earliest dead write to its last
/// death, a snapshot's joined twice (to the end and again when a stamp no held body supersedes).
#[allow(clippy::too_many_arguments)]
fn first_deaths(tx: &mut Tx<'_>, c: &CommitId, ai: usize, tid: &Tid, ak: &Ak, dead: &BTreeMap<Stamp, Ts>, want: &BTreeMap<Stamp, usize>, snap: bool) -> Result<BTreeMap<Stamp, Ts>> {
    let un = crate::apply::Unmerge::of(tx, tid, ak)?;
    let strip = |f: &mut Fragment, snap: bool| f.remove_writes(&|d| if snap { un.unvouched(d) } else { un.bad(d) });
    let mut own = Fragment::default();
    crate::apply::each_held_piece(tx, c, ai, &mut |_, mut f| {
        strip(&mut f, snap);
        own.join(f);
        Ok(())
    })?;
    let held = own.stamps();
    let from = dead.keys().map(|s| s.ts).min().unwrap_or_default();
    let mut bodies: Vec<(Ts, CommitId, usize, bool)> = Vec::new();
    for (ts, x) in tx.core.ix.by_aspect.get(&(*tid, ak.clone())).into_iter().flatten().filter(|x| x.1 != *c && x.0 >= from).cloned().collect::<Vec<_>>() {
        let Some(xai) = held_part(tx.core, &x, tid, ak) else { continue };
        if crate::apply::copies::invalid_snapshot(tx.core, &x, tid, ak) {
            continue;
        }
        bodies.push((ts, x, xai, tx.core.ix.commits.get(&x).is_some_and(|m| m.header.kind.is_compaction())));
    }
    // joins body `b` into `into`, returning the stamps of `dead` whose writes of the part it
    // reported killed (a stamp names several writes: an entry's creation and its value)
    let join = |tx: &mut Tx<'_>, into: &mut Fragment, b: &Body| -> Result<BTreeMap<Stamp, usize>> {
        let (_, x, xai, xsnap) = *b;
        let mut k: BTreeMap<Stamp, usize> = BTreeMap::new();
        crate::apply::each_held_piece(tx, &x, xai, &mut |_, mut f| {
            strip(&mut f, xsnap);
            let mut ch = Changes::new();
            into.join_into(f, None, &mut ch);
            for d in ch.into_deaths().into_iter().filter(|d| dead.contains_key(&d.stamp) && dies_in(&held, d)) {
                *k.entry(d.stamp).or_default() += 1;
            }
            Ok(())
        })?;
        Ok(k)
    };
    let mut scratch = own.clone();
    if !snap {
        for b in &bodies {
            let k = join(tx, &mut scratch, b)?;
            if !k.is_empty() {
                // the first death of a write of the delta: its replacement
                return Ok(k.into_keys().map(|s| (s, b.0)).collect());
            }
        }
        return Ok(BTreeMap::new());
    }
    let want: BTreeMap<Stamp, usize> = dead.keys().map(|s| (s.clone(), want.get(s).copied().unwrap_or(0))).collect();
    snapshot_deaths(tx, &own, &held, &want, &bodies, &mut |tx, f, b| join(tx, f, b), &mut scratch)
}

/// A held valid body `first_deaths` joins: its `ts`, commit, part, whether a snapshot.
type Body = (Ts, CommitId, usize, bool);

/// Per stamp, the deaths of the part's writes a join reported.
type Kills = BTreeMap<Stamp, usize>;

/// `first_deaths` of a snapshot: per stamp of `dead` the `ts` of the first of `bodies` (joined by
/// `join`) by which as many writes are dead as `dead` holds (`counts`). A join reports a death
/// again (a later body's copy of the dead write, a record pair's cross death, spec/crdt.md §5.6;
/// a page piece's path), so reports only bound it from below; the counts are taken afresh, the
/// part joined whole into the bodies so far and its deaths counted as `counts` counts them, at
/// each body reporting a death once the
/// reports could have them all. A snapshot keeps every write's history, so only that latest
/// date counts (`replaced_at`): the walk stops at the first body by which every stamp is dead.
/// When some stamp no held body supersedes, the stamps dead by the end take the first body by
/// which they all are, found by a second walk.
#[allow(clippy::too_many_arguments)]
fn snapshot_deaths(tx: &mut Tx<'_>, own: &Fragment, held: &osis_crdt::Stamps, dead: &BTreeMap<Stamp, usize>, bodies: &[Body], join: &mut dyn FnMut(&mut Tx<'_>, &mut Fragment, &Body) -> Result<Kills>, scratch: &mut Fragment) -> Result<BTreeMap<Stamp, Ts>> {
    let afresh = |others: &Fragment| -> BTreeSet<Stamp> {
        let mut v = others.clone();
        let mut ch = Changes::new();
        v.join_into(own.clone(), None, &mut ch);
        let mut k: BTreeMap<Stamp, usize> = BTreeMap::new();
        for d in ch.into_deaths().into_iter().filter(|d| dies_in(held, d)) {
            *k.entry(d.stamp).or_default() += 1;
        }
        dead.iter().filter(|(s, want)| k.get(*s).is_some_and(|x| x >= *want)).map(|(s, _)| s.clone()).collect()
    };
    // whether the reports so far could hold every death of `s`
    let could = |sum: &Kills, s: &Stamp| sum.get(s).zip(dead.get(s)).is_some_and(|(x, d)| x >= d);
    let mut others = Fragment::default();
    let mut sum: Kills = BTreeMap::new();
    let mut reported: Vec<Kills> = Vec::with_capacity(bodies.len());
    for b in bodies {
        let k = join(tx, scratch, b)?;
        join(tx, &mut others, b)?;
        for (s, x) in &k {
            *sum.entry(s.clone()).or_default() += x;
        }
        let hit = !k.is_empty();
        reported.push(k);
        if hit && dead.keys().all(|s| could(&sum, s)) && afresh(&others).len() == dead.len() {
            return Ok(dead.keys().map(|s| (s.clone(), b.0)).collect());
        }
    }
    let all = afresh(&others);
    if all.is_empty() {
        return Ok(BTreeMap::new());
    }
    // the first body by whose reports every stamp dead by the end could be
    sum.clear();
    let mut start = bodies.len();
    for (i, k) in reported.iter().enumerate() {
        for (s, x) in k {
            *sum.entry(s.clone()).or_default() += x;
        }
        if all.iter().all(|s| could(&sum, s)) {
            start = i;
            break;
        }
    }
    others = Fragment::default();
    let mut last = Ts::default();
    for (i, (b, k)) in bodies.iter().zip(&reported).enumerate() {
        join(tx, &mut others, b)?;
        last = b.0;
        if i >= start && !k.is_empty() && afresh(&others).is_superset(&all) {
            break;
        }
    }
    Ok(all.into_iter().map(|s| (s, last)).collect())
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
