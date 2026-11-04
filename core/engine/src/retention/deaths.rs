//! Deaths of writes (spec/crdt.md §4.8) for bodies with a relative keep bound (spec/commits.md
//! §5), dated per node: a write dies at the `ts` of the superseding write its join met here (a
//! join reports deaths against the state, `note_deaths`), whatever the arrival order. That is
//! the `ts` of an applied superseder, so never earlier than the earliest one. A snapshot arriving
//! takes the deaths of the writes it carries that the state superseded before it (`note_copies`).
//! A validity flip or an un-merge marks the aspect (`Core::deaths_due`): the transaction, or
//! within a node-sync step the next read of deaths, recomputes its deaths from the held bodies
//! and the state (`replay_all`). A write invalid here, or one an un-merge took, has no superseder
//! to date it: under keep at most 0 after replaced it counts dead from its fall (`falls`,
//! `date_falls`).

use super::{body_of, bounded, check_at_most, held_part};
use crate::engine::records::{self, Rd};
use crate::engine::{Core, Tx};
use crate::error::Result;
use osis_base::{Ak, CommitId, Tid, Ts};
use osis_crdt::{Changes, Death, Fragment, Stamp, Stamps, TextDeletes};
use osis_store::Shred;
use std::collections::{BTreeMap, BTreeSet};

/// The aspect index of `(tid, ak)` in `c` if that part is held and has a relative bound.
fn bounded_part(core: &Core, c: &CommitId, tid: &Tid, ak: &Ak) -> Option<usize> {
    held_part(core, c, tid, ak).filter(|ai| core.ix.commits.get(c).and_then(|m| m.header.aspects.get(*ai)).is_some_and(bounded))
}

/// Whether a held body of `(tid, ak)` has a relative bound (debug builds: checked against a walk
/// of the aspect's bodies).
pub(crate) fn any_bounded(core: &Core, tid: &Tid, ak: &Ak) -> bool {
    let k = (*tid, ak.clone());
    let any = core.ix.bounded_held.contains_key(&k);
    debug_assert_eq!(any, core.ix.by_aspect.get(&k).into_iter().flatten().any(|(_, c)| bounded_part(core, c, tid, ak).is_some()), "bounded_held of {tid:?} {ak:?}");
    any
}

/// Whether a snapshot with frontier `fr` and `Absorbed` `abs` is known, from those alone, to
/// have been taken after its author applied the write of dot `o`: a session-form one under its
/// frontier, a commit-form one when `abs` lists its commit. A snapshot may carry writes past these
/// (a session write applied before an earlier counter): `Parts::holds` reads its body.
fn took(fr: &osis_crdt::Frontiers, abs: &[(CommitId, Tid)], o: &osis_crdt::Dot) -> bool {
    let o = o.owner();
    match o.src.kind() {
        osis_crdt::SourceKind::Session(_) => fr.of(&o.src) >= o.ctr,
        osis_crdt::SourceKind::Commit(c) => abs.iter().any(|(a, _)| a == c),
        osis_crdt::SourceKind::Derived(_) => false,
    }
}

/// The held commit of `(tid, ak)` whose own writes the dot `o` names (the session-form or
/// commit-form commit owning it), with its part's index.
fn own_commit(core: &Core, tid: &Tid, ak: &Ak, o: &osis_crdt::Dot) -> Option<(CommitId, usize)> {
    core.commit_of(tid, ak, o).and_then(|c| held_part(core, &c, tid, ak).map(|ai| (c, ai)))
}

/// The held bodies with a relative bound carrying the write of death `d` of `(tid, ak)`, dated
/// `at` (`d.at`, or later for a vouched copy, `replay_all`), each with the date it dies for that
/// body: its own commits' at `at`; every compaction snapshot taken before `d.at` that carries it
/// (a snapshot carries every write live at its time that its author had applied, spec/crdt.md
/// §8: `took`, else its body holds a write of the stamp) at `at`; a snapshot taken at or after
/// `d.at` whose author had not applied the superseder and whose body carries the dying write
/// (`Parts::carries`), at `at` or the snapshot's `ts` if later (spec/commits.md §5: a snapshot's
/// writes die for it no earlier than its `ts`). Dropped bodies are not. Cost: in memory, but for a snapshot newer than the write that `took` does not decide
/// (its body read, once per `parts`) and a superseder some later snapshot had not applied: the
/// superseder's body (else the state) joined into a copy of that snapshot's part (once per pair
/// per `parts`).
fn carriers(tx: &mut Tx<'_>, parts: &mut Parts, tid: &Tid, ak: &Ak, d: &Death, at: Ts) -> Result<Vec<(CommitId, usize, Ts)>> {
    let dot = &d.stamp.dot;
    let core = &*tx.core;
    let mut out: Vec<(CommitId, usize, Ts)> = own_commit(core, tid, ak, dot).into_iter().filter(|(c, ai)| bounded_part(core, c, tid, ak) == Some(*ai)).map(|(c, ai)| (c, ai, at)).collect();
    let snaps: Vec<(Ts, CommitId, usize, bool, bool)> = core
        .ix
        .snapshots
        .get(&(*tid, ak.clone()))
        .into_iter()
        .flatten()
        // an invalid snapshot carries nothing (spec/permissions.md §5.2)
        .filter(|(_, s, _, _)| !crate::apply::copies::invalid_snapshot(core, s, tid, ak))
        .filter_map(|(ts, s, fr, abs)| bounded_part(core, s, tid, ak).map(|ai| (*ts, *s, ai, took(fr, abs, dot), took(fr, abs, &d.by))))
        .collect();
    for (ts, s, ai, has, saw) in snaps {
        // a snapshot taken before the write cannot carry it
        if !has && (ts < d.stamp.ts || !parts.holds(tx, &s, ai, &d.stamp)?) {
            continue;
        }
        if ts < d.at {
            out.push((s, ai, at));
        } else if !saw && parts.carries(tx, tid, ak, &s, ai, d)? {
            out.push((s, ai, at.max(ts)));
        }
    }
    Ok(out)
}

/// The superseder of `d`.
pub(super) fn killer(d: &Death) -> Stamp {
    Stamp { ts: d.at, dot: d.by.clone() }
}

/// Whether death `d`, reported by joining `f` into a state, is of a write `f` carries: `f` holds
/// a write of its stamp but not its superseder (a stamp names several writes: a map entry's
/// creation outlives its value write, and a state's write superseded by one of `f` shares its
/// stamp with `f`'s creation of the entry).
pub(super) fn dies_in(f: &Fragment, d: &Death) -> bool {
    f.holds_stamp(&d.stamp) && !f.holds_stamp(&killer(d))
}

/// Per snapshot read by `carriers` and source of superseders (a held body, or the state), the
/// writes of its part that a superseder from there supersedes, as (dead stamp, superseder):
/// the source joined into a copy of the part (the state: the part into a copy of the state),
/// per transaction step; and the stamps of the snapshot parts read (`holds`).
#[derive(Default)]
struct Parts {
    killed: BTreeMap<(CommitId, Option<CommitId>), Killed>,
    stamps: BTreeMap<CommitId, Vec<Stamps>>,
}

/// Writes superseded, as (dead stamp, superseder).
type Killed = BTreeSet<(Stamp, Stamp)>;

impl Parts {
    /// Whether part `ai` of snapshot `c` holds a write stamped `s` (so its author had applied
    /// that write's commit, spec/crdt.md §8). Cost: the part's stamps indexed once per step, a
    /// piece at a time (many deaths ask of one part), then a lookup.
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

    /// Whether part `ai` of snapshot `c` carries the write `d` killed, a write of its stamp that
    /// its superseder supersedes. A stamp names several writes (an entry's creation and its
    /// value, a struct's fields): the part may carry one of them while another died, so the
    /// superseder itself is joined against the part: its own body if held; else each held valid snapshot carrying it (`took`, else
    /// its body holds the superseder's stamp; a kill by it there is a true death); else the
    /// state (the superseder then still wins there, or its write's later death is dated there
    /// instead: no held body carries it, so a recompute dates the write there too).
    fn carries(&mut self, tx: &mut Tx<'_>, tid: &Tid, ak: &Ak, c: &CommitId, ai: usize, d: &Death) -> Result<bool> {
        let want = (d.stamp.clone(), killer(d));
        let core = &*tx.core;
        let own = own_commit(core, tid, ak, &d.by);
        let srcs: Vec<(CommitId, usize)> = if let Some(o) = own {
            vec![o]
        } else {
            let cand: Vec<(CommitId, usize, bool)> = core
                .ix
                .snapshots
                .get(&(*tid, ak.clone()))
                .into_iter()
                .flatten()
                .filter(|(ts, s, _, _)| s != c && *ts >= d.at && !crate::apply::copies::invalid_snapshot(core, s, tid, ak))
                .filter_map(|(_, s, fr, abs)| held_part(core, s, tid, ak).map(|sai| (*s, sai, took(fr, abs, &d.by))))
                .collect();
            let mut v = Vec::new();
            for (s, sai, has) in cand {
                if has || self.holds(tx, &s, sai, &want.1)? {
                    v.push((s, sai));
                }
            }
            v
        };
        for src in srcs {
            if self.kills(tx, tid, ak, (c, ai), Some(src), &want)? {
                return Ok(true);
            }
        }
        if own.is_some() {
            return Ok(false);
        }
        self.kills(tx, tid, ak, (c, ai), None, &want)
    }

    /// Whether a source supersedes `want` (dead stamp, superseder) in part `ai` of `c`, a piece
    /// `f` of the part at a time: part `kai` of `k` joined into a copy of `f` (of each of its
    /// pieces the part at `f`'s positions, `Fragment::part_at`: all a join there meets), or for
    /// `None` `f` joined into a copy of the state's part it meets (`Tx::state_at`). Cached per
    /// (part, source). Cost: with a source, its part decoded once per piece of `c`'s (rare: a
    /// snapshot whose author had not seen a superseder, `carries`).
    fn kills(&mut self, tx: &mut Tx<'_>, tid: &Tid, ak: &Ak, (c, ai): (&CommitId, usize), src: Option<(CommitId, usize)>, want: &(Stamp, Stamp)) -> Result<bool> {
        let key = (*c, src.map(|x| x.0));
        if let Some(k) = self.killed.get(&key) {
            return Ok(k.contains(want));
        }
        let mut dead = BTreeSet::new();
        crate::apply::each_held_piece(tx, c, ai, &mut |tx, f| {
            let mut ch = Changes::new();
            if let Some((k, kai)) = src {
                let mut g = f.clone();
                crate::apply::each_held_piece(tx, &k, kai, &mut |_, x| {
                    g.join_into(x.part_at(&f), None, &mut ch);
                    Ok(())
                })?;
            } else if let Some(mut st) = tx.state_at(tid, ak, &f)? {
                st.join_into(f.clone(), None, &mut ch);
            }
            dead.extend(ch.into_deaths().into_iter().filter(|d| dies_in(&f, d)).map(|d| (d.stamp.clone(), killer(&d))));
            Ok(())
        })?;
        #[cfg(test)]
        assert_eq!(dead, super::oracle::kills(tx, tid, ak, (c, ai), src)?, "kills streamed vs whole");
        let hit = dead.contains(want);
        self.killed.insert(key, dead);
        Ok(hit)
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

/// Whether a superseder of `deaths` is a vouched copy, its own delta invalid here: the join gives
/// the invalid commit's `ts`, and which snapshot's `ts` dates it is `replay_all`'s to say.
fn by_vouched_copy(core: &Core, tid: &Tid, ak: &Ak, deaths: &[Death]) -> bool {
    if deaths.is_empty() {
        return false;
    }
    let invalid = crate::apply::invalid_of(core, tid, ak);
    !invalid.is_empty() && deaths.iter().any(|d| invalid.iter().any(|o| o.owns(d.by.owner())))
}

/// Records the deaths a join of a valid delta reported, at the superseder's `ts` the join met:
/// per body, first and last so far, on every held body with a relative bound carrying the
/// write; drops bodies past keep at most (spec/commits.md §5), in this transaction.
pub(crate) fn note_deaths(tx: &mut Tx<'_>, tid: &Tid, ak: &Ak, deaths: &[Death]) -> Result<()> {
    if by_vouched_copy(tx.core, tid, ak, deaths) {
        return mark_deaths_due(tx, tid, ak);
    }
    let mut bodies = BTreeSet::new();
    let mut parts = Parts::default();
    for d in deaths {
        for (c, ai, at) in carriers(tx, &mut parts, tid, ak, d, d.at)? {
            add_death(tx, tid, ak, &c, ai, at)?;
            bodies.insert((c, ai));
        }
    }
    for (c, ai) in bodies {
        check_at_most(tx, &c, ai)?;
    }
    Ok(())
}

/// A valid snapshot `c` just joined on `(tid, ak)`: the writes it carries that the state already
/// superseded die for it at the superseder's `ts`, or at the snapshot's when that is later and
/// its author had not seen the superseder (as `carriers`), its copies of writes whose own delta
/// is held (left out of its join) included.
/// Cost: only for a bounded part, the snapshot's part a piece at a time, each joined into a copy
/// of the state's part it meets (`Tx::state_at`).
pub(crate) fn note_copies(tx: &mut Tx<'_>, c: &CommitId, tid: &Tid, ak: &Ak) -> Result<()> {
    let Some(ai) = bounded_part(tx.core, c, tid, ak) else { return Ok(()) };
    let Some(ts) = tx.core.ix.commits.get(c).map(|m| m.header.ts) else { return Ok(()) };
    let (fr, abs) = tx.core.ix.snapshots.get(&(*tid, ak.clone())).into_iter().flatten().find(|x| x.1 == *c).map(|x| (x.2.clone(), x.3.clone())).unwrap_or_default();
    // the dates (a write a page's path repeats, such as the entry it lies under, dies once)
    let mut deaths = BTreeSet::new();
    let mut undated = false;
    // a valid snapshot vouches for every write it carries (spec/permissions.md §5.2)
    crate::apply::each_held_piece(tx, c, ai, &mut |tx, f| {
        let Some(mut st) = tx.state_at(tid, ak, &f)? else { return Ok(()) };
        let mut ch = Changes::new();
        st.join_into(f.clone(), None, &mut ch);
        undated |= ch.undated();
        let core = &*tx.core;
        let joined = ch.into_deaths();
        undated |= by_vouched_copy(core, tid, ak, &joined);
        deaths.extend(joined.into_iter().filter(|d| f.holds_stamp(&d.stamp) && (d.at > ts || !took(&fr, &abs, &d.by) && dies_in(&f, d))).map(|d| d.at.max(ts)));
        Ok(())
    })?;
    #[cfg(test)]
    {
        let a: Vec<Ts> = deaths.iter().copied().collect();
        let w = super::oracle::copies_deaths(tx, c, ai, tid, ak, ts, &|d| took(&fr, &abs, &d.by))?;
        assert_eq!(a, w, "note_copies streamed vs whole");
    }
    // a copy of a held creation or delete, an out-of-order flag or a vouched copy: dated from the
    // bodies alone
    if undated {
        mark_deaths_due(tx, tid, ak)?;
    }
    if deaths.is_empty() {
        return Ok(());
    }
    for at in deaths {
        add_death(tx, tid, ak, c, ai, at)?;
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
    if !any_bounded(tx.core, tid, ak) {
        return Ok(());
    }
    replay_all(tx, tid, ak)?;
    recheck_at_most(tx, tid, ak)
}

/// Joins `f` into `st`, collecting its deaths. A snapshot's (`copies`) copy of a write already
/// dead in the replay is not dated again (two snapshots carrying a write whose own commit is
/// not held: the later one would date it at a later winner): a death whose stamp died before
/// and that the snapshot holds a write of (`holds_stamp`; not merely a record keyed by its dot,
/// such as an entry it removed: a write sharing a dead write's stamp then dies here for the
/// first time, order seed 7855). A snapshot's copy of a text creation also meets the deletes
/// joined before it, which the state shows only the last of: unless it died before (seed
/// 8413009), it dies at the earliest one newer than it (`TextDeletes`), as its own delta, had it
/// played, would have (seed 7731022). That death adds to what the join reports, never hides one
/// (a reset's at the same `ts` dates a snapshot that had not applied it, seed 8413015). Each death
/// goes in with its date, `date` of it.
fn join(st: &mut Fragment, f: Fragment, copies: bool, deaths: &mut Vec<(Death, Ts)>, dead: &mut BTreeSet<Stamp>, dels: Option<&mut TextDeletes>, date: impl Fn(&Death) -> Ts) {
    let mut ch = Changes::new();
    let mut late = Vec::new();
    if let Some(dels) = dels {
        if copies {
            late = dels.deaths(&f);
            late.retain(|d| !dead.contains(&d.stamp));
        }
        dels.add(&f);
    }
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
        deaths.push((d.clone(), date(&d)));
    }
    deaths.extend(late.into_iter().map(|d| {
        let at = date(&d);
        (d, at)
    }));
}

/// Each write dies at the first superseding write among the held bodies joined in `(ts, ID)`
/// order (valid writes only; a snapshot's copies of writes whose own commit is held valid
/// removed, so they play at their own commit), a body dropped value-less (expired, purged) as its residue, then the state (live
/// writes of bodies dropped otherwise); every held body with a relative bound gets the first and
/// last of its writes' deaths. Only the invalid deltas' own writes are left out: a valid write
/// nested in a record they created is un-merged from the state (spec/crdt.md §4.6) but dies
/// like any other at a valid superseder (§4.8, judged against the write alone: a reset on that
/// record), whether the record was un-merged before or after it joined (seed 52040). A superseder whose body was dropped for its keep bounds dates
/// nothing unless its write is live: a write it superseded dies at a later one here.
///
/// A valid snapshot's copy of a write whose own delta is invalid supersedes from the snapshot on,
/// and dates there (spec/commits.md §5): its stamp's `ts` is an invalid commit's, which says
/// nothing of when a valid write superseded anything. The invariant, which needs no window or
/// cache: a date is never an invalid commit's `ts` (the state holds such a write only while a
/// valid snapshot vouches for it, and that snapshot's body plays first: a body after it dates at
/// its own `ts`, later), so a valid superseder
/// arriving later never shows a date earlier than the earliest valid one. Cost: the aspect's held
/// bodies, residues and whole state.
fn replay_all(tx: &mut Tx<'_>, tid: &Tid, ak: &Ak) -> Result<()> {
    let held: Vec<CommitId> = tx.core.ix.by_aspect.get(&(*tid, ak.clone())).into_iter().flatten().map(|x| x.1).collect();
    let un = crate::apply::Unmerge::of(tx, tid, ak)?;
    let mut st = Fragment::default();
    let mut deaths = Vec::new();
    let mut dead = BTreeSet::new();
    let mut dels = TextDeletes::default();
    for c in &held {
        let Some(ai) = held_part(tx.core, c, tid, ak) else {
            // a body dropped value-less (expired, purged) plays as its residue: its writes
            // supersede like any held (spec/crdt.md §4.7)
            if let Some(mut f) = residue_of(tx, c, tid, ak)? {
                f.remove_writes(&|d| un.bad(d));
                // a write a vouched copy killed dies no earlier than the body's `ts`, as below
                let ts = tx.core.ix.commits.get(c).map(|m| m.header.ts);
                join(&mut st, f, false, &mut deaths, &mut dead, Some(&mut dels), |d| if un.bad(d.by.owner()) { ts.map_or(d.at, |ts| d.at.max(ts)) } else { d.at });
            }
            continue;
        };
        if crate::apply::copies::invalid_snapshot(tx.core, c, tid, ak) {
            continue;
        }
        let _s = crate::costs::span("deaths: join bodies");
        let (kind, ts) = tx.core.ix.commits.get(c).map(|m| (m.header.kind, m.header.ts)).unzip();
        let snap = kind.is_some_and(|k| k.is_compaction());
        crate::apply::each_held_piece(tx, c, ai, &mut |tx, mut f| {
            let core = &*tx.core;
            // a valid snapshot's copies all play (spec/permissions.md §5.2)
            f.remove_writes(&|d| if snap { un.unvouched(d) } else { un.bad(d) });
            // (a valid snapshot's copy of an invalid delta's write plays at the snapshot: the
            // delta's own writes are un-merged, the copy is what the state holds)
            if snap {
                f.remove_writes(&|d| own_commit(core, tid, ak, d).is_some_and(|(x, ai)| x != *c && core.ix.commits.get(&x).is_some_and(|m| m.valid_at(ai))));
            }
            // (a body played after it meets the copy already joined: its own `ts`, no earlier
            // than the snapshot's)
            let date = |d: &Death| if un.bad(d.by.owner()) { ts.map_or(d.at, |ts| d.at.max(ts)) } else { d.at };
            join(&mut st, f, snap, &mut deaths, &mut dead, Some(&mut dels), date);
            Ok(())
        })?;
    }
    {
        let _s = crate::costs::span("deaths: state");
        if let Some(cur) = tx.state(tid, ak)?.cloned() {
            // joined last: no copy meets its deletes
            join(&mut st, cur, false, &mut deaths, &mut dead, None, |d| d.at);
        }
    }
    // a text creation dies once, at its earliest delete (spec/crdt.md §4.8; a delete over an
    // undelete reports it again)
    let mut elems: BTreeMap<Stamp, (Death, Ts)> = BTreeMap::new();
    deaths.retain(|(d, at)| {
        if d.element && elems.get(&d.stamp).is_none_or(|o| *at < o.1) {
            elems.insert(d.stamp.clone(), (d.clone(), *at));
        }
        !d.element
    });
    deaths.extend(elems.into_values());
    let mut got: BTreeMap<(CommitId, usize), (Ts, Ts)> = BTreeMap::new();
    let mut parts = Parts::default();
    for (d, date) in &deaths {
        for (c, ai, at) in carriers(tx, &mut parts, tid, ak, d, *date)? {
            let e = got.entry((c, ai)).or_insert((at, at));
            *e = (e.0.min(at), e.1.max(at));
        }
    }
    date_falls(tx, tid, ak, &held, &mut got)?;
    for c in &held {
        let Some(ai) = bounded_part(tx.core, c, tid, ak) else { continue };
        set_deaths(tx, tid, ak, c, ai, got.get(&(*c, ai)).copied())?;
    }
    Ok(())
}

/// Whether a fall dates a death on part `a` of a commit (spec/commits.md §5): it answers to keep
/// at most 0 after replaced, and no role commit goes this way. A body with no such bound keeps its
/// fallen writes.
pub(crate) fn falls(h: &osis_commit::Header, a: &osis_commit::AspectEntry) -> bool {
    a.retention.at_most.rel.is_some() && h.kind != osis_commit::Kind::Role
}

/// `(tid, ak, fall)` of part `ai` of `c` if it is held, invalid here and a fall dates it (`falls`).
fn fallen(core: &Core, c: &CommitId, ai: usize) -> Option<(Tid, Ak, Ts)> {
    let m = core.ix.commits.get(c).filter(|m| !m.view.memory && m.holds(ai) && !m.valid_at(ai))?;
    let a = m.header.aspects.get(ai).filter(|a| falls(&m.header, a))?;
    Some((a.tid, a.ak.clone(), crate::apply::validity::fell_at(core, &m.header, c, ai)))
}

/// Part `ai` of `c` arrived: if invalid here, its fall dated and its bound judged, this part alone,
/// so a forged write costs no walk of the aspect (no join reports it; a write it un-merged marks
/// the aspect by itself, `mark_if_bounded`).
pub(crate) fn date_arrival(tx: &mut Tx<'_>, c: &CommitId, ai: usize) -> Result<()> {
    let Some((tid, ak, at)) = fallen(tx.core, c, ai) else { return Ok(()) };
    add_death(tx, &tid, &ak, c, ai, at)?;
    check_at_most(tx, c, ai)
}

/// Part `ai` of `c` judged invalid again: its aspect's deaths recomputed only if the demotion that
/// took it is another now, so what moves no date (a forged role commit) costs no walk of the aspect.
pub(crate) fn fall_moved(tx: &mut Tx<'_>, c: &CommitId, ai: usize) -> Result<()> {
    let Some((tid, ak, at)) = fallen(tx.core, c, ai) else { return Ok(()) };
    let Some(body) = body_of(tx.core, c, ai) else { return Ok(()) };
    if tx.txn.death(&tid, &ak, &body)?.is_none_or(|d| d.first != at && d.last != at) {
        mark_deaths_due(tx, &tid, &ak)?;
    }
    Ok(())
}

/// Adds the falls of `(tid, ak)` to `got`: a held body under keep at most 0 after replaced counts dead
/// from its own fall if invalid here (`fell_at`), and if valid with no write in the state and no
/// death from the newest fall on the aspect, no earlier than its own `ts` (an un-merge took its
/// writes under a record an invalid delta created; which one is not kept, so the date may be late,
/// never early). Only a decided judgment counts: a commit waiting is not applied, and a demotion
/// waiting moves no timeline. A flip, an un-merge or a fall that moved dates them again
/// (`mark_deaths_due`, `fall_moved`). Cost: per held body with no death, on an aspect holding an
/// invalid part, its liveness.
fn date_falls(tx: &mut Tx<'_>, tid: &Tid, ak: &Ak, held: &[CommitId], got: &mut BTreeMap<(CommitId, usize), (Ts, Ts)>) -> Result<()> {
    let core = &*tx.core;
    let fell_at = |c: &CommitId, m: &crate::engine::Meta, ai: usize| crate::apply::validity::fell_at(core, &m.header, c, ai);
    let newest = core.ix.invalid.get(&(*tid, ak.clone())).into_iter().flatten().filter_map(|c| {
        let m = core.ix.commits.get(c)?;
        let ai = m.aspect(tid, ak).filter(|ai| !m.valid_at(*ai))?;
        Some(fell_at(c, m, ai))
    }).max();
    let Some(newest) = newest else { return Ok(()) };
    let mut dated = Vec::new();
    let mut taken = Vec::new();
    for c in held {
        let Some(ai) = bounded_part(core, c, tid, ak) else { continue };
        let Some(m) = core.ix.commits.get(c).filter(|m| !m.view.memory) else { continue };
        if !m.header.aspects.get(ai).is_some_and(|a| falls(&m.header, a)) {
            continue;
        }
        if !m.valid_at(ai) {
            dated.push(((*c, ai), fell_at(c, m, ai)));
        } else if m.header.kind.has_own_writes() && !got.contains_key(&(*c, ai)) {
            taken.push(((*c, ai), newest.max(m.header.ts)));
        }
    }
    for (k, at) in taken {
        if !super::live(tx, &k.0, k.1)? {
            dated.push((k, at));
        }
    }
    for (k, at) in dated {
        let e = got.entry(k).or_insert((at, at));
        *e = (e.0.min(at), e.1.max(at));
    }
    Ok(())
}

/// The value-less residue of `c`'s part on `(tid, ak)` (`retention::make_valueless`), if any.
fn residue_of(tx: &mut Tx<'_>, c: &CommitId, tid: &Tid, ak: &Ak) -> Result<Option<Fragment>> {
    let Some(ai) = tx.core.ix.commits.get(c).and_then(|m| m.aspect(tid, ak)).filter(|ai| super::valueless(tx.core, c, *ai)) else { return Ok(None) };
    let Some(v) = tx.txn.get_local(&records::residue_key(tid, ak, c, ai))? else { return Ok(None) };
    Ok(Some(crate::engine::state::decode(&v)?))
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

/// Judges the keep-at-most bounds of the held bodies of `(tid, ak)` under 0 after replaced
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
