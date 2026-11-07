//! Deaths of writes (spec/crdt.md §4.8) for bodies with a relative keep bound (spec/commits.md
//! §5), dated per node: a write dies at the `ts` of the first superseder the node held, met in a
//! join (`note_deaths`: a join reports deaths against the state, in order or late) or, when the
//! aspect's deaths are dated again (`replay_all`, after a validity flip or an un-merge marked it,
//! `Core::deaths_due`), first in `(ts, ID)` order among the held bodies. That is a valid
//! superseder's `ts`, so never earlier than the earliest. A body carries a dying write when the
//! write is its own (`Core::commit_of`) or, for a snapshot, when its body holds a write of the
//! stamp and none of the superseder's (`dies_in`: holding any write of the superseder means its
//! author applied it); a death a snapshot's own join reports of a write it carries is its alone.
//! A snapshot arriving takes the deaths of the writes it carries that the state superseded
//! before it (`note_copies`). A write dies for a body no earlier than the body's `ts`. A write
//! invalid here, or one an un-merge took, has no superseder: no death. Only keep-for-D reads
//! deaths (a delta's first, a snapshot's last, `osis_commit::retention::body_keep`).

use super::{body_of, bounded, held_part};
use crate::engine::records::{self, Rd};
use crate::engine::{Core, Owned, Tx};
use crate::error::Result;
use osis_base::{Ak, CommitId, Tid, Ts};
use osis_crdt::{Changes, Death, Fragment, Stamp, Stamps};
use osis_store::Shred;
use std::collections::{BTreeMap, BTreeSet};

/// The aspect index of `(tid, ak)` in `c` if that part is held with values and has a relative bound
/// (a bare leftover has no values to keep, so no deaths: `Meta::bare`).
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

/// The superseder of `d`.
pub(super) fn killer(d: &Death) -> Stamp {
    Stamp { ts: d.at, dot: d.by.clone() }
}

/// Whether death `d` is of a write `f` carries: `f` holds a write of its stamp but not its
/// superseder (a stamp names several writes: a map entry's creation outlives its value write;
/// a body holding any write of the superseder's stamp was taken after it).
pub(super) fn dies_in(f: &Fragment, d: &Death) -> bool {
    f.holds_stamp(&d.stamp) && !f.holds_stamp(&killer(d))
}

/// Per aspect and transaction step, what crediting deaths reads of the held bodies: the stamps of
/// each snapshot part read (`holds`) and the deltas invalid here (`invalid`).
#[derive(Default)]
struct Parts {
    stamps: BTreeMap<CommitId, Vec<Stamps>>,
    invalid: Option<Vec<Owned>>,
}

impl Parts {
    /// Whether part `ai` of snapshot `c` holds a write stamped `s`. Cost: the part's stamps
    /// indexed once per step, a piece at a time (many deaths ask of one part), then a lookup.
    fn holds(&mut self, tx: &mut Tx<'_>, c: &CommitId, ai: usize, s: &Stamp) -> Result<bool> {
        if !self.stamps.contains_key(c) {
            let mut ix = Vec::new();
            crate::apply::each_held_piece(tx, c, ai, &mut |_, f| {
                ix.push(f.stamps());
                Ok(())
            })?;
            self.stamps.insert(*c, ix);
        }
        Ok(self.stamps.get(c).is_some_and(|v| v.iter().any(|x| x.holds(s))))
    }

    /// The date of `d`: the superseder's `ts`, or when the superseder's own delta is invalid here
    /// (the state holds it as a valid snapshot's copy, which supersedes from the snapshot on,
    /// spec/crdt.md §4.8) the earliest such snapshot's `ts` if later.
    fn date(&mut self, tx: &mut Tx<'_>, tid: &Tid, ak: &Ak, d: &Death) -> Result<Ts> {
        let invalid = self.invalid.get_or_insert_with(|| crate::apply::invalid_of(tx.core, tid, ak));
        if !invalid.iter().any(|o| o.owns(d.by.origin())) {
            return Ok(d.at);
        }
        let k = killer(d);
        let snaps: Vec<(Ts, CommitId, usize)> = tx.core.ix.snapshots.get(&(*tid, ak.clone())).into_iter().flatten().filter(|x| !crate::apply::copies::invalid_snapshot(tx.core, &x.1, tid, ak)).filter_map(|x| held_part(tx.core, &x.1, tid, ak).map(|ai| (x.0, x.1, ai))).collect();
        let mut at = None;
        for (ts, s, ai) in snaps {
            if ts > d.at && at.is_none_or(|a| ts < a) && self.holds(tx, &s, ai, &k)? {
                at = Some(ts);
            }
        }
        Ok(at.unwrap_or(d.at))
    }

    /// Whether part `ai` of snapshot `c` carries the write of death `d` (`dies_in`, by the
    /// index).
    fn carries(&mut self, tx: &mut Tx<'_>, c: &CommitId, ai: usize, d: &Death) -> Result<bool> {
        Ok(self.holds(tx, c, ai, &d.stamp)? && !self.holds(tx, c, ai, &killer(d))?)
    }

    /// The held bodies with a relative bound credited with death `d` of `(tid, ak)`, dated `at`,
    /// each with the date it dies for that body (no earlier than the body's `ts`). A death the
    /// join of a snapshot `me` reports of a write it carries (`carries`: a copy of a write dead
    /// already, or the first copy of one the state superseded) is the snapshot's alone; any
    /// other credits the write's own commit and every valid compaction snapshot carrying it,
    /// among `joined` when given (a replay: the snapshots joined so far). A snapshot stamped
    /// before the write cannot carry it (spec/crdt.md §2.2). Dropped bodies are not credited.
    fn credit(&mut self, tx: &mut Tx<'_>, tid: &Tid, ak: &Ak, d: &Death, me: Option<(CommitId, usize, Ts)>, joined: Option<&BTreeSet<CommitId>>) -> Result<Vec<(CommitId, usize, Ts)>> {
        let at = self.date(tx, tid, ak, d)?;
        if let Some((s, ai, ts)) = me
            && self.carries(tx, &s, ai, d)?
        {
            return Ok(vec![(s, ai, at.max(ts))]);
        }
        let core = &*tx.core;
        let mut out = Vec::new();
        if let Some(c) = core.commit_of(tid, ak, &d.stamp.dot)
            && let Some(ai) = bounded_part(core, &c, tid, ak)
            && let Some(m) = core.ix.commits.get(&c)
        {
            out.push((c, ai, at.max(m.header.ts)));
        }
        let snaps: Vec<(Ts, CommitId, usize)> = core
            .ix
            .snapshots
            .get(&(*tid, ak.clone()))
            .into_iter()
            .flatten()
            .filter(|x| x.0 >= d.stamp.ts && joined.is_none_or(|j| j.contains(&x.1)) && !crate::apply::copies::invalid_snapshot(core, &x.1, tid, ak))
            .filter_map(|x| bounded_part(core, &x.1, tid, ak).map(|ai| (x.0, x.1, ai)))
            .collect();
        for (ts, s, ai) in snaps {
            if self.carries(tx, &s, ai, d)? {
                out.push((s, ai, at.max(ts)));
            }
        }
        Ok(out)
    }
}

/// Records `at` on the body of part `ai` of `c`: first and last so far.
fn add_death(tx: &mut Tx<'_>, tid: &Tid, ak: &Ak, c: &CommitId, ai: usize, at: Ts) -> Result<()> {
    let Some(body) = body_of(tx.core, c, ai) else { return Ok(()) };
    let old = tx.txn.death(tid, ak, &body)?;
    let n = osis_store::Deaths { first: old.map_or(at, |o| o.first.min(at)), last: old.map_or(at, |o| o.last.max(at)) };
    if old != Some(n) {
        tx.txn.set_death(tid, ak, &body, Some(n))?;
    }
    // node-sync judges the bodies a write killed again (bounds, liveness)
    tx.core.mark_changed(*c);
    Ok(())
}

/// Records the deaths the join of commit `c`'s part reported, at the superseder's `ts` the join
/// met: per body, first and last so far, on every held body with a relative bound credited
/// (`Parts::credit`).
pub(crate) fn note_deaths(tx: &mut Tx<'_>, tid: &Tid, ak: &Ak, c: &CommitId, deaths: &[Death]) -> Result<()> {
    let mut parts = Parts::default();
    let me = tx.core.ix.commits.get(c).filter(|m| m.header.kind.is_compaction()).and_then(|m| bounded_part(tx.core, c, tid, ak).map(|ai| (*c, ai, m.header.ts)));
    for d in deaths {
        for (c, ai, at) in parts.credit(tx, tid, ak, d, me, None)? {
            add_death(tx, tid, ak, &c, ai, at)?;
        }
    }
    Ok(())
}

/// The deaths of the writes part `ai` of `c` carries that the state supersedes, each no earlier
/// than the commit's `ts`: the part a piece at a time, each joined into a copy of the state's
/// part it meets (`Tx::state_at`), its copies of writes whose own delta is held (left out of its
/// join) included.
fn body_deaths(tx: &mut Tx<'_>, c: &CommitId, ai: usize, tid: &Tid, ak: &Ak, ts: Ts) -> Result<BTreeSet<Ts>> {
    let mut parts = Parts::default();
    let mut found = Vec::new();
    crate::apply::each_held_piece(tx, c, ai, &mut |tx, f| {
        let Some(mut st) = tx.state_at(tid, ak, &f)? else { return Ok(()) };
        let mut ch = Changes::new();
        st.join_into(f.clone(), None, &mut ch);
        found.extend(ch.into_deaths().into_iter().filter(|d| dies_in(&f, d)));
        Ok(())
    })?;
    let mut out = BTreeSet::new();
    for d in &found {
        out.insert(parts.date(tx, tid, ak, d)?.max(ts));
    }
    Ok(out)
}

/// A valid snapshot `c` just joined on `(tid, ak)`: the writes it carries that the state already
/// superseded die for it (`body_deaths`). Cost: only for a bounded part, the snapshot's part a
/// piece at a time against the state's part it meets.
pub(crate) fn note_copies(tx: &mut Tx<'_>, c: &CommitId, tid: &Tid, ak: &Ak) -> Result<()> {
    let Some(ai) = bounded_part(tx.core, c, tid, ak) else { return Ok(()) };
    let Some(ts) = tx.core.ix.commits.get(c).map(|m| m.header.ts) else { return Ok(()) };
    let deaths = body_deaths(tx, c, ai, tid, ak, ts)?;
    #[cfg(test)]
    assert_eq!(deaths, super::oracle::body_deaths(tx, c, ai, tid, ak, ts)?, "body_deaths streamed vs whole");
    for at in deaths {
        add_death(tx, tid, ak, c, ai, at)?;
    }
    Ok(())
}

/// Marks `(tid, ak)` for a recompute of its deaths (marked in the store: an open recomputes
/// it). It runs once, at the end of the transaction or, within a node-sync step, before its
/// deaths are next read (`Engine::settle_deaths`). Until then its records may be off either way
/// (a validity flip can remove a superseder).
pub(crate) fn mark_deaths_due(tx: &mut Tx<'_>, tid: &Tid, ak: &Ak) -> Result<()> {
    let k = (*tid, ak.clone());
    if tx.core.ix.deaths_due.insert(k) {
        // a memory aspect's mark is memory (gone at restart, with the aspect)
        tx.put_aspect_local(records::DEATHS_DUE, tid, ak, &[])?;
    }
    Ok(())
}

/// Marks `(tid, ak)` if a held body has a relative bound (others' writes un-merged under an
/// invalid commit's creations).
pub(crate) fn mark_if_bounded(tx: &mut Tx<'_>, tid: &Tid, ak: &Ak) -> Result<()> {
    if any_bounded(tx.core, tid, ak) {
        mark_deaths_due(tx, tid, ak)?;
    }
    Ok(())
}

/// `Engine::settle_deaths` in `tx`.
pub(crate) fn settle_due(tx: &mut Tx<'_>) -> Result<()> {
    // one aspect at a time, unmarked first
    while let Some(k) = tx.core.ix.deaths_due.iter().next().cloned() {
        tx.core.ix.deaths_due.remove(&k);
        let (tid, ak) = k;
        tx.txn.remove_local(&records::aspect_key(records::DEATHS_DUE, &tid, &ak), Shred::No)?;
        let _s = crate::costs::span("deaths: recompute");
        rejudge_deaths(tx, &tid, &ak)?;
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
    tx.core.ix.deaths_due.extend(v);
    Ok(())
}

/// Deaths of `(tid, ak)` from scratch (`replay_all`): after a validity flip, an un-merge, a
/// rebuild.
pub(crate) fn rejudge_deaths(tx: &mut Tx<'_>, tid: &Tid, ak: &Ak) -> Result<()> {
    if !any_bounded(tx.core, tid, ak) {
        return Ok(());
    }
    replay_all(tx, tid, ak)
}

/// Each write dies at the first superseding write among the held bodies joined in `(ts, ID)`
/// order (valid writes only: the invalid deltas' own writes are left out, and from a valid
/// snapshot's body only what it holds under such a dot without a write of its own there,
/// `Unmerge::unvouched`; a leftover as any held body), then the state (live writes of bodies
/// dropped otherwise); each death credited as it is reported (`Parts::credit`: a snapshot's
/// own copies dying at its join credit it alone, so a copy of a write dead already dates no
/// other body again; the snapshots stamped after a superseder are not joined yet, so they are
/// judged at their own turn); every held body with a relative bound gets the first and last of
/// its deaths. A valid write nested in a record an invalid delta
/// created is un-merged from the state (spec/crdt.md §4.6) but dies like any other at a valid
/// superseder (§4.8, judged against the write alone: a reset on that record), whether the
/// record was un-merged before or after it joined (seed 52040). A superseder whose body was
/// dropped dates nothing unless its write is live: a write it superseded dies at a later one
/// here. Cost: the aspect's held bodies and whole state. Limit: a
/// snapshot's copy of a text element creation whose own delta is not held meets only the latest
/// delete the state shows (spec/crdt.md §5.7): dated there, later than at its own delta's play.
fn replay_all(tx: &mut Tx<'_>, tid: &Tid, ak: &Ak) -> Result<()> {
    let held: Vec<CommitId> = tx.core.ix.by_aspect.get(&(*tid, ak.clone())).into_iter().flatten().map(|x| x.1).collect();
    let un = crate::apply::Unmerge::of(tx, tid, ak)?;
    let mut st = Fragment::default();
    let mut parts = Parts::default();
    let mut joined = BTreeSet::new();
    let mut got: BTreeMap<(CommitId, usize), (Ts, Ts)> = BTreeMap::new();
    let take = |got: &mut BTreeMap<(CommitId, usize), (Ts, Ts)>, c: CommitId, ai: usize, at: Ts| {
        let e = got.entry((c, ai)).or_insert((at, at));
        *e = (e.0.min(at), e.1.max(at));
    };
    for c in &held {
        let Some(ai) = held_part(tx.core, c, tid, ak) else { continue };
        if crate::apply::copies::invalid_snapshot(tx.core, c, tid, ak) {
            continue;
        }
        let _s = crate::costs::span("deaths: join bodies");
        let (snap, ts) = tx.core.ix.commits.get(c).map(|m| (m.header.kind.is_compaction(), m.header.ts)).unwrap_or_default();
        let me = (snap && bounded_part(tx.core, c, tid, ak) == Some(ai)).then_some((*c, ai, ts));
        let mut deaths = Vec::new();
        crate::apply::each_held_piece(tx, c, ai, &mut |_, mut f| {
            // a valid snapshot's copies all play (spec/permissions.md §5.2)
            f.remove_writes(&|d| if snap { un.unvouched(d) } else { un.bad(d) });
            let mut ch = Changes::new();
            st.join_into(f, None, &mut ch);
            deaths.extend(ch.into_deaths());
            Ok(())
        })?;
        for d in &deaths {
            for (c, ai, at) in parts.credit(tx, tid, ak, d, me, Some(&joined))? {
                take(&mut got, c, ai, at);
            }
        }
        if snap {
            joined.insert(*c);
        }
    }
    {
        let _s = crate::costs::span("deaths: state");
        if let Some(cur) = tx.state(tid, ak)?.cloned() {
            let mut ch = Changes::new();
            st.join_into(cur, None, &mut ch);
            for d in ch.into_deaths() {
                for (c, ai, at) in parts.credit(tx, tid, ak, &d, None, None)? {
                    take(&mut got, c, ai, at);
                }
            }
        }
    }
    for c in &held {
        let Some(ai) = bounded_part(tx.core, c, tid, ak) else { continue };
        set_deaths(tx, tid, ak, c, ai, got.get(&(*c, ai)).copied())?;
    }
    Ok(())
}

fn set_deaths(tx: &mut Tx<'_>, tid: &Tid, ak: &Ak, c: &CommitId, ai: usize, d: Option<(Ts, Ts)>) -> Result<()> {
    let Some(body) = body_of(tx.core, c, ai) else { return Ok(()) };
    let d = d.map(|(first, last)| osis_store::Deaths { first, last });
    if tx.txn.death(tid, ak, &body)? == d {
        return Ok(());
    }
    // node-sync judges again only the bodies whose deaths moved
    if tx.core.changed.is_some() {
        tx.core.mark_changed(*c);
    }
    Ok(tx.txn.set_death(tid, ak, &body, d)?)
}
