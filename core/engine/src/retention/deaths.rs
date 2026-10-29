//! Deaths of writes (spec/crdt.md §4.8) for bodies with a relative keep bound (spec/commits.md
//! §5), dated per node: a write dies at the `ts` of the superseding write its join met here (a
//! join reports deaths against the state, `note_deaths`), whatever the arrival order. That is
//! the `ts` of an applied superseder, so never earlier than the earliest one. A snapshot arriving
//! takes the deaths of the writes it carries that the state superseded before it (`note_copies`).
//! A validity flip or an un-merge marks the aspect (`Core::deaths_due`): the transaction, or
//! within a node-sync step the next read of deaths, recomputes its deaths from the held bodies
//! and the state (`replay_all`).

use super::{body_class, bounded, check_at_most, held_part};
use crate::engine::records::{self, Rd};
use crate::engine::{Core, Tx};
use crate::error::Result;
use osis_base::{Ak, CommitId, Tid, Ts};
use osis_commit::Decoded;
use osis_crdt::{Changes, Death, Fragment, Stamp};
use osis_store::Shred;
use std::collections::{BTreeMap, BTreeSet};

/// The aspect index of `(tid, ak)` in `c` if that part is held and has a relative bound.
fn bounded_part(core: &Core, c: &CommitId, tid: &Tid, ak: &Ak) -> Option<usize> {
    held_part(core, c, tid, ak).filter(|ai| core.ix.commits.get(c).and_then(|m| m.header.aspects.get(*ai)).is_some_and(bounded))
}

/// Whether a held body of `(tid, ak)` has a relative bound. Cost: the aspect's commits (in
/// memory); only flips and un-merges ask.
fn any_bounded(core: &Core, tid: &Tid, ak: &Ak) -> bool {
    core.ix.by_aspect.get(&(*tid, ak.clone())).into_iter().flatten().any(|(_, c)| bounded_part(core, c, tid, ak).is_some())
}

/// The held bodies with a relative bound carrying write `dot` of `(tid, ak)` when it died at
/// `at`: its own commit's, and every compaction snapshot taken before `at` whose frontier holds
/// it (a snapshot carries every write live at its time up to its frontier, spec/crdt.md §8).
/// Commit-form writes are found in their own commit only (snapshots keep no frontier for them).
/// Dropped bodies are not.
fn carriers(core: &Core, tid: &Tid, ak: &Ak, dot: &osis_crdt::Dot, at: Ts) -> Vec<(CommitId, usize)> {
    let mut out = Vec::new();
    if let Some(c) = core.commit_of(tid, ak, dot)
        && let Some(ai) = bounded_part(core, &c, tid, ak)
    {
        out.push((c, ai));
    }
    if let osis_crdt::SourceKind::Node(n) = dot.owner().src.kind() {
        for (ts, s, fr, _) in core.ix.snapshots.get(&(*tid, ak.clone())).into_iter().flatten() {
            // an invalid snapshot carries nothing (spec/permissions.md §5.2)
            if *ts < at
                && fr.0.get(n).is_some_and(|f| *f >= dot.owner().ctr)
                && !crate::apply::validity::invalid_snapshot(core, s, tid, ak)
                && let Some(ai) = bounded_part(core, s, tid, ak)
            {
                out.push((*s, ai));
            }
        }
    }
    out
}

/// Records `at` on the body of part `ai` of `c`: first and last so far.
fn add_death(tx: &mut Tx<'_>, tid: &Tid, ak: &Ak, c: &CommitId, ai: usize, at: Ts) -> Result<()> {
    let Some(h) = tx.core.ix.commits.get(c).map(|m| m.header.clone()) else { return Ok(()) };
    let (body, _) = body_class(tx.core, &h, c, ai);
    let old = tx.txn.death(tid, ak, &body)?;
    let n = osis_store::Deaths { first: old.map_or(at, |o| o.first.min(at)), last: old.map_or(at, |o| o.last.max(at)) };
    if old != Some(n) {
        tx.txn.set_death(tid, ak, &body, Some(n))?;
    }
    // node-sync judges the bodies a write killed again (bounds, liveness)
    tx.core.mark_changed(*c);
    Ok(())
}

/// Records the deaths a join of a valid delta reported, at the superseder's `ts` the join met:
/// per body, first and last so far, on every held body with a relative bound carrying the
/// write; drops bodies past keep at most (spec/commits.md §5), in this transaction.
pub(crate) fn note_deaths(tx: &mut Tx<'_>, tid: &Tid, ak: &Ak, deaths: &[Death]) -> Result<()> {
    let mut bodies = BTreeSet::new();
    for d in deaths {
        for (c, ai) in carriers(tx.core, tid, ak, &d.stamp.dot, d.at) {
            add_death(tx, tid, ak, &c, ai, d.at)?;
            bodies.insert((c, ai));
        }
    }
    for (c, ai) in bodies {
        check_at_most(tx, &c, ai)?;
    }
    Ok(())
}

/// A valid snapshot `c` just joined on `(tid, ak)`: the writes it carries that the state already
/// superseded die for it at the superseder's `ts` when that is after the snapshot (as
/// `carriers`), its copies of writes whose own delta is held (left out of its join) included.
/// Cost: the snapshot's part and the aspect's state, only for a bounded part.
pub(crate) fn note_copies(tx: &mut Tx<'_>, c: &CommitId, tid: &Tid, ak: &Ak) -> Result<()> {
    let Some(ai) = bounded_part(tx.core, c, tid, ak) else { return Ok(()) };
    let Some(ts) = tx.core.ix.commits.get(c).map(|m| m.header.ts) else { return Ok(()) };
    tx.load(tid, ak)?;
    let Some(Some(st)) = tx.core.states.get(&(*tid, ak.clone())).cloned() else { return Ok(()) };
    let mut deaths = Vec::new();
    // a valid snapshot vouches for every write it carries (spec/permissions.md §5.2)
    for f in crate::apply::held_parts(tx, c, ai)?.into_iter().map(Decoded::into_fragment) {
        let mut st = st.clone();
        let mut ch = Changes::new();
        st.join_into(f.clone(), None, &mut ch);
        deaths.extend(ch.into_deaths().into_iter().filter(|d| d.at > ts && f.holds_stamp(&d.stamp)));
    }
    if deaths.is_empty() {
        return Ok(());
    }
    for d in &deaths {
        add_death(tx, tid, ak, c, ai, d.at)?;
    }
    check_at_most(tx, c, ai)
}

/// Marks `(tid, ak)` for a recompute of its deaths (marked in the store: an open recomputes
/// it). It runs once, at the end of the transaction or, within a node-sync step, before its
/// deaths are next read (`Engine::settle_deaths`). Until then its records may be off either way
/// (a validity flip can remove a superseder), so its keep-at-most bounds wait (`check_at_most`).
pub(crate) fn mark_deaths_due(tx: &mut Tx<'_>, tid: &Tid, ak: &Ak) -> Result<()> {
    let k = (*tid, ak.clone());
    if tx.core.ix.deaths_due.insert(k) {
        tx.txn.put_local(&records::aspect_key(records::DEATHS_DUE, tid, ak), &[], Shred::No)?;
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
    // one aspect at a time, unmarked first: `check_at_most` skips marked aspects
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

/// Deaths of `(tid, ak)` from scratch (`replay_all`), then its keep-at-most bounds again: after
/// a validity flip, an un-merge, a rebuild.
pub(crate) fn rejudge_deaths(tx: &mut Tx<'_>, tid: &Tid, ak: &Ak) -> Result<()> {
    if any_bounded(tx.core, tid, ak) {
        replay_all(tx, tid, ak)?;
    }
    recheck_at_most(tx, tid, ak)
}

/// Joins `f` into `st`, collecting its deaths. A snapshot's (`copies`) copy of a write already
/// dead in the replay is not dated again (two snapshots carrying a write whose own commit is
/// not held: the later one would date it at a later winner): a death whose stamp died before
/// and that the snapshot holds a write of (`holds_stamp`; not merely a record keyed by its dot,
/// such as an entry it removed: a write sharing a dead write's stamp then dies here for the
/// first time, order seed 7855).
fn join(st: &mut Fragment, f: Fragment, copies: bool, deaths: &mut Vec<Death>, dead: &mut BTreeSet<Stamp>) {
    let mut ch = Changes::new();
    let g = copies.then(|| f.clone());
    st.join_into(f, None, &mut ch);
    for d in ch.into_deaths() {
        if let Some(g) = &g
            && dead.contains(&d.stamp)
            && g.holds_stamp(&d.stamp)
        {
            continue;
        }
        dead.insert(d.stamp.clone());
        deaths.push(d);
    }
}

/// Each write dies at the first superseding write among the held bodies joined in `(ts, ID)`
/// order (valid writes only; a snapshot's or import's copies of writes whose own commit is held
/// removed, so they play at their own commit), then the state (live writes of dropped bodies);
/// every held body with a relative bound gets the first and last of its writes' deaths. A
/// superseder whose body was dropped dates nothing unless its write is live: a write it
/// superseded dies at a later one here. Cost: the aspect's held bodies and whole state.
fn replay_all(tx: &mut Tx<'_>, tid: &Tid, ak: &Ak) -> Result<()> {
    let held: Vec<CommitId> = tx.core.ix.by_aspect.get(&(*tid, ak.clone())).into_iter().flatten().map(|x| x.1).collect();
    let un = crate::apply::Unmerge::of(tx, tid, ak, &BTreeMap::new())?;
    let mut st = Fragment::default();
    let mut deaths = Vec::new();
    let mut dead = BTreeSet::new();
    for c in &held {
        let Some(ai) = held_part(tx.core, c, tid, ak) else { continue };
        if crate::apply::validity::invalid_snapshot(tx.core, c, tid, ak) {
            continue;
        }
        let parts: Vec<Fragment> = {
            let _s = crate::costs::span("deaths: read bodies");
            crate::apply::held_parts(tx, c, ai)?.into_iter().map(Decoded::into_fragment).collect()
        };
        let _s = crate::costs::span("deaths: join");
        let cp = tx.core.ix.commits.get(c).is_none_or(|m| !m.header.kind.has_own_writes());
        for mut f in parts {
            let core = &*tx.core;
            f.remove_dots(&|d| un.bad(d));
            if cp {
                f.remove_writes(&|d| core.commit_of(tid, ak, d).is_some_and(|x| x != *c && held_part(core, &x, tid, ak).is_some()));
            }
            join(&mut st, f, cp, &mut deaths, &mut dead);
        }
    }
    {
        let _s = crate::costs::span("deaths: state");
        tx.load(tid, ak)?;
        if let Some(Some(cur)) = tx.core.states.get(&(*tid, ak.clone())).cloned() {
            join(&mut st, cur, false, &mut deaths, &mut dead);
        }
    }
    let mut got: BTreeMap<(CommitId, usize), (Ts, Ts)> = BTreeMap::new();
    for d in &deaths {
        for k in carriers(tx.core, tid, ak, &d.stamp.dot, d.at) {
            let e = got.entry(k).or_insert((d.at, d.at));
            *e = (e.0.min(d.at), e.1.max(d.at));
        }
    }
    for c in &held {
        let Some(ai) = bounded_part(tx.core, c, tid, ak) else { continue };
        set_deaths(tx, tid, ak, c, ai, got.get(&(*c, ai)).copied())?;
    }
    Ok(())
}

fn set_deaths(tx: &mut Tx<'_>, tid: &Tid, ak: &Ak, c: &CommitId, ai: usize, d: Option<(Ts, Ts)>) -> Result<()> {
    let Some(h) = tx.core.ix.commits.get(c).map(|m| m.header.clone()) else { return Ok(()) };
    let (body, _) = body_class(tx.core, &h, c, ai);
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

/// Judges the keep-at-most bounds of the held bodies of `(tid, ak)` under a relative bound
/// again: their deaths or live writes may have changed (spec/commits.md §5).
fn recheck_at_most(tx: &mut Tx<'_>, tid: &Tid, ak: &Ak) -> Result<()> {
    let held: Vec<CommitId> = tx.core.ix.by_aspect.get(&(*tid, ak.clone())).into_iter().flatten().map(|x| x.1).collect();
    for c in held {
        let Some(ai) = held_part(tx.core, &c, tid, ak) else { continue };
        if tx.core.ix.commits.get(&c).and_then(|m| m.header.aspects.get(ai)).is_none_or(|a| a.retention.at_most.rel.is_none()) {
            continue;
        }
        check_at_most(tx, &c, ai)?;
    }
    Ok(())
}
