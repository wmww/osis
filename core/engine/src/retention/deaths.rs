//! Deaths of writes (spec/crdt.md §4.8) for bodies with a relative keep bound (spec/commits.md
//! §5), dated per node: a write dies at the `ts` of the superseding write its join met here (a
//! join reports deaths against the state, `note_deaths`), whatever the arrival order. That is
//! the `ts` of an applied superseder, so never earlier than the earliest one. A snapshot arriving
//! takes the deaths of the writes it carries that the state superseded before it (`note_copies`).
//! A validity flip or an un-merge marks the aspect (`Core::deaths_due`): the transaction, or
//! within a node-sync step the next read of deaths, recomputes its deaths from the held bodies
//! and the state (`replay_all`).

use super::{body_of, bounded, check_at_most, held_part};
use crate::engine::records::{self, Rd};
use crate::engine::{Core, Tx};
use crate::error::Result;
use osis_base::{Ak, CommitId, Tid, Ts};
use osis_commit::Decoded;
use osis_crdt::{Changes, Death, Fragment, Stamp, Stamps};
use osis_store::Shred;
use std::collections::{BTreeMap, BTreeSet};

/// The aspect index of `(tid, ak)` in `c` if that part is held and has a relative bound.
fn bounded_part(core: &Core, c: &CommitId, tid: &Tid, ak: &Ak) -> Option<usize> {
    held_part(core, c, tid, ak).filter(|ai| core.ix.commits.get(c).and_then(|m| m.header.aspects.get(*ai)).is_some_and(bounded))
}

/// Whether a held body of `(tid, ak)` has a relative bound. Cost: the aspect's commits (in
/// memory); only flips and un-merges ask.
pub(crate) fn any_bounded(core: &Core, tid: &Tid, ak: &Ak) -> bool {
    core.ix.by_aspect.get(&(*tid, ak.clone())).into_iter().flatten().any(|(_, c)| bounded_part(core, c, tid, ak).is_some())
}

/// Whether a snapshot with frontier `fr` and `Absorbed` `abs` on `tid` is known, from those
/// alone, to have been taken after its author applied the write of dot `o`: a node-form one under
/// its frontier, a commit-form one when `abs` lists its commit or a held import of it. A snapshot
/// may carry writes past these (a node-form write applied before an earlier counter, an import
/// whose header this node does not hold): `Parts::holds` reads its body.
fn took(core: &Core, tid: &Tid, fr: &osis_crdt::Frontiers, abs: &[(CommitId, Tid)], o: &osis_crdt::Dot) -> bool {
    let o = o.owner();
    match o.src.kind() {
        osis_crdt::SourceKind::Node(n) => fr.0.get(n).is_some_and(|f| *f >= o.ctr),
        osis_crdt::SourceKind::Commit(c) => {
            let imports = core.ix.imports.get(&(*tid, *c));
            abs.iter().any(|(a, _)| a == c || imports.is_some_and(|i| i.contains(a)))
        }
        osis_crdt::SourceKind::Derived(_) => false,
    }
}

/// The held commits of `(tid, ak)` whose own writes the dot `o` names: the node-form or
/// commit-form commit owning it, and the held imports listing a commit-form dot's commit as
/// origin (spec/permissions.md §7), each with its part's index.
fn own_commits(core: &Core, tid: &Tid, ak: &Ak, o: &osis_crdt::Dot) -> Vec<(CommitId, usize)> {
    let imports: Vec<CommitId> = match o.owner().src.kind() {
        osis_crdt::SourceKind::Commit(c) => core.ix.imports.get(&(*tid, *c)).into_iter().flatten().copied().collect(),
        _ => Vec::new(),
    };
    core.commit_of(tid, ak, o).into_iter().chain(imports).filter_map(|c| held_part(core, &c, tid, ak).map(|ai| (c, ai))).collect()
}

/// The held bodies with a relative bound carrying the write of death `d` of `(tid, ak)`, each
/// with the date it dies for that body: its own commits' at `d.at`; every compaction snapshot
/// taken before `d.at` that carries it (a snapshot carries every write live at its time that
/// its author had applied, spec/crdt.md §8: `took`, else its body holds a write of the stamp)
/// at `d.at`; a snapshot taken at or after `d.at` whose author had not applied the superseder
/// and whose body carries the dying write (`Parts::carries`), at the snapshot's `ts`
/// (spec/commits.md §5: a snapshot's writes die for it no earlier than its `ts`). Dropped bodies
/// are not. Cost: in memory, but for a snapshot newer than the write that `took` does not decide
/// (its body read, once per `parts`) and a superseder some later snapshot had not applied: the
/// superseder's body (else the state) joined into a copy of that snapshot's part (once per pair
/// per `parts`).
fn carriers(tx: &mut Tx<'_>, parts: &mut Parts, tid: &Tid, ak: &Ak, d: &Death) -> Result<Vec<(CommitId, usize, Ts)>> {
    let (dot, at) = (&d.stamp.dot, d.at);
    let core = &*tx.core;
    let mut out: Vec<(CommitId, usize, Ts)> = own_commits(core, tid, ak, dot).into_iter().filter(|(c, ai)| bounded_part(core, c, tid, ak) == Some(*ai)).map(|(c, ai)| (c, ai, at)).collect();
    let snaps: Vec<(Ts, CommitId, usize, bool, bool)> = core
        .ix
        .snapshots
        .get(&(*tid, ak.clone()))
        .into_iter()
        .flatten()
        // an invalid snapshot carries nothing (spec/permissions.md §5.2)
        .filter(|(_, s, _, _)| !crate::apply::validity::invalid_snapshot(core, s, tid, ak))
        .filter_map(|(ts, s, fr, abs)| bounded_part(core, s, tid, ak).map(|ai| (*ts, *s, ai, took(core, tid, fr, abs, dot), took(core, tid, fr, abs, &d.by))))
        .collect();
    for (ts, s, ai, has, saw) in snaps {
        // a snapshot taken before the write cannot carry it
        if !has && (ts < d.stamp.ts || !parts.holds(tx, &s, ai, &d.stamp)?) {
            continue;
        }
        if ts < at {
            out.push((s, ai, at));
        } else if !saw && parts.carries(tx, tid, ak, &s, ai, d)? {
            out.push((s, ai, ts));
        }
    }
    Ok(out)
}

/// The superseder of `d`.
fn killer(d: &Death) -> Stamp {
    Stamp { ts: d.at, dot: d.by.clone() }
}

/// Whether death `d`, reported by joining `f` into a state, is of a write `f` carries: `f` holds
/// a write of its stamp but not its superseder (a stamp names several writes: a map entry's
/// creation outlives its value write, and a state's write superseded by one of `f` shares its
/// stamp with `f`'s creation of the entry).
fn dies_in(f: &Fragment, d: &Death) -> bool {
    f.holds_stamp(&d.stamp) && !f.holds_stamp(&killer(d))
}

/// Per snapshot read by `carriers` and source of superseders (a held body, or the state), the
/// writes of its part that a superseder from there supersedes, as (dead stamp, superseder):
/// the source joined into a copy of the part (the state: the part into a copy of the state),
/// per transaction step; and the snapshot parts read whole, with their stamps (`holds`).
#[derive(Default)]
struct Parts {
    killed: BTreeMap<(CommitId, Option<CommitId>), Killed>,
    read: BTreeMap<CommitId, Vec<Fragment>>,
    stamps: BTreeMap<CommitId, Vec<Stamps>>,
}

/// Writes superseded, as (dead stamp, superseder).
type Killed = BTreeSet<(Stamp, Stamp)>;

impl Parts {
    /// Part `ai` of `c`, decoded once per step.
    fn part(&mut self, tx: &mut Tx<'_>, c: &CommitId, ai: usize) -> Result<&[Fragment]> {
        if !self.read.contains_key(c) {
            let fs = crate::apply::held_parts(tx, c, ai)?.into_iter().map(Decoded::into_fragment).collect();
            self.read.insert(*c, fs);
        }
        Ok(self.read.get(c).map(Vec::as_slice).unwrap_or_default())
    }

    /// Whether part `ai` of snapshot `c` holds a write stamped `s` (so its author had applied
    /// that write's commit, spec/crdt.md §8). Cost: the part walked once per step (many deaths
    /// ask of one part), then a lookup.
    fn holds(&mut self, tx: &mut Tx<'_>, c: &CommitId, ai: usize, s: &Stamp) -> Result<bool> {
        if !self.stamps.contains_key(c) {
            let ix = self.part(tx, c, ai)?.iter().map(Fragment::stamps).collect();
            self.stamps.insert(*c, ix);
        }
        Ok(self.stamps.get(c).is_some_and(|v| v.iter().any(|x| x.holds(s))))
    }

    /// Whether part `ai` of snapshot `c` carries the write `d` killed, a write of its stamp that
    /// its superseder supersedes. A stamp names several writes (an entry's creation and its
    /// value, a struct's fields): the part may carry one of them while another died, so the
    /// superseder itself is joined against the part: its own bodies if held (its commit, the
    /// imports of a commit-form one); else each held valid snapshot carrying it (`took`, else
    /// its body holds the superseder's stamp; a kill by it there is a true death); else the
    /// state (the superseder then still wins there, or its write's later death is dated there
    /// instead: no held body carries it, so a recompute dates the write there too).
    fn carries(&mut self, tx: &mut Tx<'_>, tid: &Tid, ak: &Ak, c: &CommitId, ai: usize, d: &Death) -> Result<bool> {
        let want = (d.stamp.clone(), killer(d));
        let core = &*tx.core;
        let own = own_commits(core, tid, ak, &d.by);
        let srcs: Vec<(CommitId, usize)> = if !own.is_empty() {
            own.clone()
        } else {
            let cand: Vec<(CommitId, usize, bool)> = core
                .ix
                .snapshots
                .get(&(*tid, ak.clone()))
                .into_iter()
                .flatten()
                .filter(|(ts, s, _, _)| s != c && *ts >= d.at && !crate::apply::validity::invalid_snapshot(core, s, tid, ak))
                .filter_map(|(_, s, fr, abs)| held_part(core, s, tid, ak).map(|sai| (*s, sai, took(core, tid, fr, abs, &d.by))))
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
        if !own.is_empty() {
            return Ok(false);
        }
        self.kills(tx, tid, ak, (c, ai), None, &want)
    }

    /// Whether a source supersedes `want` (dead stamp, superseder) in part `ai` of `c`: part
    /// `kai` of `k` joined into a copy of the part, or for `None` the part joined into a copy of
    /// the state. Cached per (part, source).
    fn kills(&mut self, tx: &mut Tx<'_>, tid: &Tid, ak: &Ak, (c, ai): (&CommitId, usize), src: Option<(CommitId, usize)>, want: &(Stamp, Stamp)) -> Result<bool> {
        let key = (*c, src.map(|x| x.0));
        if let Some(k) = self.killed.get(&key) {
            return Ok(k.contains(want));
        }
        {
            let mut dead = BTreeSet::new();
            let fs = self.part(tx, c, ai)?.to_vec();
            let mut keep = |f: &Fragment, ch: Changes| dead.extend(ch.into_deaths().into_iter().filter(|d| dies_in(f, d)).map(|d| (d.stamp.clone(), killer(&d))));
            if let Some((k, kai)) = src {
                let ks: Vec<Fragment> = crate::apply::held_parts(tx, &k, kai)?.into_iter().map(Decoded::into_fragment).collect();
                for f in &fs {
                    let (mut g, mut ch) = (f.clone(), Changes::new());
                    for x in &ks {
                        g.join_into(x.clone(), None, &mut ch);
                    }
                    keep(f, ch);
                }
            } else {
                tx.load(tid, ak)?;
                if let Some(Some(st)) = tx.core.states.get(&(*tid, ak.clone())).cloned() {
                    for f in &fs {
                        let (mut st, mut ch) = (st.clone(), Changes::new());
                        st.join_into(f.clone(), None, &mut ch);
                        keep(f, ch);
                    }
                }
            }
            let hit = dead.contains(want);
            self.killed.insert(key, dead);
            Ok(hit)
        }
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

/// Records the deaths a join of a valid delta reported, at the superseder's `ts` the join met:
/// per body, first and last so far, on every held body with a relative bound carrying the
/// write; drops bodies past keep at most (spec/commits.md §5), in this transaction.
pub(crate) fn note_deaths(tx: &mut Tx<'_>, tid: &Tid, ak: &Ak, deaths: &[Death]) -> Result<()> {
    let mut bodies = BTreeSet::new();
    let mut parts = Parts::default();
    for d in deaths {
        for (c, ai, at) in carriers(tx, &mut parts, tid, ak, d)? {
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
/// Cost: the snapshot's part and the aspect's state, only for a bounded part.
pub(crate) fn note_copies(tx: &mut Tx<'_>, c: &CommitId, tid: &Tid, ak: &Ak) -> Result<()> {
    let Some(ai) = bounded_part(tx.core, c, tid, ak) else { return Ok(()) };
    let Some(ts) = tx.core.ix.commits.get(c).map(|m| m.header.ts) else { return Ok(()) };
    let (fr, abs) = tx.core.ix.snapshots.get(&(*tid, ak.clone())).into_iter().flatten().find(|x| x.1 == *c).map(|x| (x.2.clone(), x.3.clone())).unwrap_or_default();
    tx.load(tid, ak)?;
    let Some(Some(st)) = tx.core.states.get(&(*tid, ak.clone())).cloned() else { return Ok(()) };
    let mut deaths = Vec::new();
    // a valid snapshot vouches for every write it carries (spec/permissions.md §5.2)
    let fs: Vec<Fragment> = crate::apply::held_parts(tx, c, ai)?.into_iter().map(Decoded::into_fragment).collect();
    let core = &*tx.core;
    let saw = |d: &Death| took(core, tid, &fr, &abs, &d.by);
    for f in fs {
        let mut st = st.clone();
        let mut ch = Changes::new();
        st.join_into(f.clone(), None, &mut ch);
        deaths.extend(ch.into_deaths().into_iter().filter(|d| f.holds_stamp(&d.stamp) && (d.at > ts || !saw(d) && dies_in(&f, d))).map(|d| d.at.max(ts)));
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
/// order (valid writes only; a snapshot's or import's copies of writes whose own commit is held,
/// and a snapshot's of a held import's writes, removed, so they play at their own commit), then the state (live writes of dropped bodies);
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
        let kind = tx.core.ix.commits.get(c).map(|m| m.header.kind);
        let cp = kind.is_none_or(|k| !k.has_own_writes());
        // a snapshot's copies of an import's writes play at the import (its dot names the
        // origin); an import's are not removed for another import of the same origin
        let snap = kind.is_some_and(|k| k.is_compaction());
        for mut f in parts {
            let core = &*tx.core;
            f.remove_dots(&|d| un.bad(d));
            if cp {
                f.remove_writes(&|d| if snap { own_commits(core, tid, ak, d).iter().any(|(x, _)| x != c) } else { core.commit_of(tid, ak, d).is_some_and(|x| x != *c && held_part(core, &x, tid, ak).is_some()) });
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
    let mut parts = Parts::default();
    for d in &deaths {
        for (c, ai, at) in carriers(tx, &mut parts, tid, ak, d)? {
            let e = got.entry((c, ai)).or_insert((at, at));
            *e = (e.0.min(at), e.1.max(at));
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
