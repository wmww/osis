//! Deaths of writes (spec/crdt.md §4.8) for bodies with a relative keep bound (spec/commits.md
//! §5). A valid writer delta sorting after every held commit of its aspect takes its join's
//! deaths (`note_deaths`); any other marks the aspect (`Core::deaths_due`), and `settle_due`
//! replays it once per batch: over the late deltas' window when that judges every body they can
//! change (`window`), else over every held body (`replay_all`). A dropped body's writes stay,
//! value-less, as its residue (`records::DROPPED`) while a held bounded body sorts at or before
//! it, so a replay still meets a superseder whose body is gone.

use super::{body_class, bounded, check_at_most, frag, held_part};
use crate::engine::records::{self, Rd};
use crate::engine::{Core, Tx};
use crate::error::Result;
use osis_commit::Header;
use osis_core::{Ak, CommitId, Tid, Ts};
use osis_crdt::{Changes, Death, Fragment, Stamp};
use osis_store::Shred;
use std::collections::{BTreeMap, BTreeSet, HashMap};

/// What the replay of an aspect's deaths must judge (`Core::deaths_due`; persisted as the
/// aspect's mark only, which an open reads as `Full`).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Due {
    /// Every held body: a validity flip, a snapshot or import, an open.
    Full,
    /// A valid writer delta joined out of `(ts, ID)` order.
    Late(Ts, CommitId),
    /// A held bounded body carrying a write a late delta's join killed (the delta's own too).
    Killed(CommitId),
    /// A `ts` a late delta's join dated a death at.
    Hint(Ts),
    /// A body whose keep-at-most check waited for the replay.
    Recheck(CommitId, usize),
}

/// The last deaths of an aspect's held bounded bodies with one, by last death, so a window
/// finds the bodies dying after a late `ts` without reading every record (`Core::lasts`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Lasts {
    by_last: BTreeSet<(Ts, Ts, CommitId)>,
    of: HashMap<CommitId, (Ts, Ts)>,
}

impl Lasts {
    /// Sets `c`'s entry (`None`: no last death); its previous one, as `(ts, last)`.
    fn set(&mut self, c: CommitId, ts: Ts, last: Option<Ts>) -> Option<(Ts, Ts)> {
        let old = self.of.remove(&c);
        if let Some((t, l)) = old {
            self.by_last.remove(&(l, t, c));
        }
        if let Some(l) = last {
            self.of.insert(c, (ts, l));
            self.by_last.insert((l, ts, c));
        }
        old
    }
}

/// `Lasts` per aspect where loaded, journaled: a failed transaction undoes its own changes
/// (notes/node.md Rollback) and the rest stays loaded.
#[derive(Debug, Default)]
pub(crate) struct LastsIndex {
    map: HashMap<(Tid, Ak), Lasts>,
    log: Vec<LastsUndo>,
}

#[derive(Debug)]
enum LastsUndo {
    Loaded((Tid, Ak)),
    Set((Tid, Ak), CommitId, Option<(Ts, Ts)>),
    Removed((Tid, Ak), Lasts),
}

impl LastsIndex {
    pub fn get(&self, k: &(Tid, Ak)) -> Option<&Lasts> {
        self.map.get(k)
    }
    fn load(&mut self, k: (Tid, Ak), l: Lasts) {
        if let Some(old) = self.map.insert(k.clone(), l) {
            self.log.push(LastsUndo::Removed(k.clone(), old));
        }
        self.log.push(LastsUndo::Loaded(k));
    }
    fn set(&mut self, k: &(Tid, Ak), c: CommitId, ts: Ts, last: Option<Ts>) {
        if let Some(l) = self.map.get_mut(k) {
            let old = l.set(c, ts, last);
            self.log.push(LastsUndo::Set(k.clone(), c, old));
        }
    }
    fn remove(&mut self, k: &(Tid, Ak)) {
        if let Some(old) = self.map.remove(k) {
            self.log.push(LastsUndo::Removed(k.clone(), old));
        }
    }
    /// The aspects loaded (tests).
    #[cfg(test)]
    pub fn keys(&self) -> Vec<(Tid, Ak)> {
        self.map.keys().cloned().collect()
    }
}

impl crate::engine::journal::Journaled for LastsIndex {
    fn commit(&mut self) {
        self.log.clear();
    }
    fn rollback(&mut self) {
        while let Some(u) = self.log.pop() {
            match u {
                LastsUndo::Loaded(k) => {
                    self.map.remove(&k);
                }
                LastsUndo::Set(k, c, old) => {
                    if let Some(l) = self.map.get_mut(&k) {
                        l.set(c, old.map_or(Ts::default(), |x| x.0), old.map(|x| x.1));
                    }
                }
                LastsUndo::Removed(k, l) => {
                    self.map.insert(k, l);
                }
            }
        }
    }
}

/// Keeps `Core::lasts` of `(tid, ak)` (where loaded) after `c`'s record changed.
pub(crate) fn note_last(core: &mut Core, tid: &Tid, ak: &Ak, c: &CommitId, last: Option<Ts>) {
    let Some(ts) = core.commits.get(c).map(|m| m.header.ts) else { return };
    core.lasts.set(&(*tid, ak.clone()), *c, ts, last);
}

/// `Lasts` of `(tid, ak)` from the death records.
pub(crate) fn load_lasts(tx: &mut Tx<'_>, tid: &Tid, ak: &Ak) -> Result<Lasts> {
    let mut l = Lasts::default();
    let held: Vec<(Ts, CommitId)> = tx.core.by_aspect.get(&(*tid, ak.clone())).into_iter().flatten().copied().collect();
    for (ts, c) in held {
        let Some(ai) = bounded_part(tx.core, &c, tid, ak) else { continue };
        l.set(c, ts, death_of(tx, tid, ak, &c, ai)?.map(|d| d.last));
    }
    Ok(l)
}

/// `Core::lasts` of `(tid, ak)`, loaded from the records once per session.
fn lasts<'a>(tx: &'a mut Tx<'_>, tid: &Tid, ak: &Ak) -> Result<&'a Lasts> {
    let k = (*tid, ak.clone());
    if tx.core.lasts.get(&k).is_none() {
        let l = load_lasts(tx, tid, ak)?;
        tx.core.lasts.load(k.clone(), l);
    }
    tx.core.lasts.get(&k).ok_or(crate::error::Error::Corrupt("lasts"))
}

/// Below this many bodies before the last late delta, a window reads their records instead of
/// loading `Lasts`.
const LASTS_MIN: usize = 64;

const LO: CommitId = CommitId([0; 32]);
const HI: CommitId = CommitId([0xff; 32]);

/// The aspect index of `(tid, ak)` in `c` if that part is held and has a relative bound.
fn bounded_part(core: &Core, c: &CommitId, tid: &Tid, ak: &Ak) -> Option<usize> {
    held_part(core, c, tid, ak).filter(|ai| core.commits.get(c).and_then(|m| m.header.aspects.get(*ai)).is_some_and(bounded))
}

/// Whether `c` carries copies of others' writes (a snapshot or import).
fn copies(core: &Core, c: &CommitId) -> bool {
    core.commits.get(c).is_none_or(|m| !m.header.kind.has_own_writes())
}

/// The first held body of `(tid, ak)` with a relative bound by `(ts, ID)`, cached
/// (`Core::first_bounded`, kept by `index_commit` and `keep_residue`).
pub(crate) fn first_bounded(core: &mut Core, tid: &Tid, ak: &Ak) -> Option<(Ts, CommitId)> {
    let k = (*tid, ak.clone());
    if let Some(f) = core.first_bounded.get(&k) {
        return *f;
    }
    let f = core.by_aspect.get(&k).into_iter().flatten().find(|(_, c)| bounded_part(core, c, tid, ak).is_some()).copied();
    core.first_bounded.insert(k, f);
    f
}

/// The first held bounded body of `(tid, ak)` after `after`.
fn next_bounded(core: &Core, tid: &Tid, ak: &Ak, after: (Ts, CommitId)) -> Option<(Ts, CommitId)> {
    use std::ops::Bound::{Excluded, Unbounded};
    core.by_aspect.get(&(*tid, ak.clone()))?.range((Excluded(after), Unbounded)).find(|(_, c)| bounded_part(core, c, tid, ak).is_some()).copied()
}

/// A commit just indexed (`apply::index_commit`): the first held bounded body of its aspects.
pub(crate) fn note_indexed(core: &mut Core, id: &CommitId, h: &Header) {
    for a in h.aspects.iter().filter(|a| bounded(a)) {
        let k = (a.tid, a.ak.clone());
        if core.first_bounded.get(&k).is_some_and(|f| f.is_none_or(|f| (h.ts, *id) < f)) {
            core.first_bounded.insert(k, Some((h.ts, *id)));
        }
    }
}

/// Before part `ai` of `c` drops (`drop_part`): keeps its deltas' writes (`bodies`) value-less
/// as its residue when a held bounded body of the aspect sorts at or before it (they may date
/// that body's writes, spec/crdt.md §4.8; a write dies only at a greater stamp), then drops the
/// residues no held bounded body sorts at or before any more. Residues carry no app data
/// (spec/crdt.md §4.7); a snapshot's or import's keeps only copies of writes whose own commit
/// is neither held nor a residue. Cost: O(one body) (a snapshot's: plus the aspect's residue
/// keys), plus once per dropped commit the step past it.
pub(crate) fn keep_residue(tx: &mut Tx<'_>, c: &CommitId, ai: usize, bodies: &[Fragment]) -> Result<()> {
    let Some(m) = tx.core.commits.get(c) else { return Ok(()) };
    let Some(a) = m.header.aspects.get(ai) else { return Ok(()) };
    let (tid, ak, ts) = (a.tid, a.ak.clone(), m.header.ts);
    let me = (ts, *c);
    let first = first_bounded(tx.core, &tid, &ak);
    let next = if first == Some(me) { next_bounded(tx.core, &tid, &ak, me) } else { first };
    if next.is_some_and(|n| n.0 <= ts)
        && let Some((b, rest)) = bodies.split_first()
    {
        let mut f = b.clone();
        for x in rest {
            f.join_into(x.clone(), None, &mut Changes::new());
        }
        if copies(tx.core, c) {
            // copies a replay plays at their own commit (held, or a residue) are not kept: a
            // snapshot's residue would hold the aspect's whole state
            let kept = residue_ids(tx, &tid, &ak)?;
            let core = &*tx.core;
            f.remove_dots(&|d| core.commit_of(&tid, &ak, d).is_some_and(|x| x != *c && (held_part(core, &x, &tid, &ak).is_some() || kept.contains(&x))));
        }
        f.strip(&|_| true);
        // a window never reads a snapshot's residue (it replays whole there), so none is empty
        if !(f.is_empty() && copies(tx.core, c)) {
            tx.txn.put_local(&records::dropped_key(&tid, &ak, ts, c), &crate::engine::state::encode(&f)?, Shred::No)?;
        }
    }
    if first == Some(me) {
        let gone: Vec<(Ts, CommitId)> = tx.core.by_aspect.get(&(tid, ak.clone())).into_iter().flat_map(|s| s.range(me..)).take_while(|x| next.is_none_or(|n| x.0 < n.0)).copied().collect();
        for (t, x) in gone {
            tx.txn.remove_local(&records::dropped_key(&tid, &ak, t, &x), Shred::Yes)?;
        }
        tx.core.first_bounded.insert((tid, ak), next);
    }
    Ok(())
}

/// Drops every residue of `(tid, ak)` (the aspect is forgotten).
pub(crate) fn drop_residues(tx: &mut Tx<'_>, tid: &Tid, ak: &Ak) -> Result<()> {
    let p = records::aspect_key(records::DROPPED, tid, ak);
    let mut keys = Vec::new();
    tx.scan(&p, |k, _| {
        keys.push([&p[..], k].concat());
        Ok(())
    })?;
    for k in keys {
        tx.txn.remove_local(&k, Shred::Yes)?;
    }
    tx.core.first_bounded.remove(&(*tid, ak.clone()));
    tx.core.lasts.remove(&(*tid, ak.clone()));
    Ok(())
}

/// The commits of `(tid, ak)` with a residue.
fn residue_ids(tx: &mut Tx<'_>, tid: &Tid, ak: &Ak) -> Result<BTreeSet<CommitId>> {
    let mut out = BTreeSet::new();
    tx.scan(&records::aspect_key(records::DROPPED, tid, ak), |k, _| {
        let mut r = Rd::new(k);
        r.u64()?;
        out.insert(CommitId(r.arr()?));
        Ok(())
    })?;
    Ok(out)
}

fn residues(tx: &mut Tx<'_>, tid: &Tid, ak: &Ak) -> Result<BTreeMap<CommitId, Fragment>> {
    let mut raw = Vec::new();
    tx.scan(&records::aspect_key(records::DROPPED, tid, ak), |k, v| {
        let mut r = Rd::new(k);
        r.u64()?;
        raw.push((CommitId(r.arr()?), v));
        Ok(())
    })?;
    raw.into_iter().map(|(c, v)| Ok((c, crate::engine::state::decode(&v)?))).collect()
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
        for (ts, s, fr) in core.snapshots.get(&(*tid, ak.clone())).into_iter().flatten() {
            if *ts < at
                && fr.0.get(n).is_some_and(|f| *f >= dot.owner().ctr)
                && let Some(ai) = bounded_part(core, s, tid, ak)
            {
                out.push((*s, ai));
            }
        }
    }
    out
}

/// Records the deaths a join of a delta in `(ts, ID)` order reported (`replays` false): per
/// body, first and last so far, on every held body with a relative bound carrying the write;
/// drops bodies past keep at most (spec/commits.md §5).
pub(crate) fn note_deaths(tx: &mut Tx<'_>, tid: &Tid, ak: &Ak, deaths: &[Death]) -> Result<()> {
    let mut bodies = BTreeSet::new();
    for d in deaths {
        for (c, ai) in carriers(tx.core, tid, ak, &d.stamp.dot, d.at) {
            let Some(h) = tx.core.commits.get(&c).map(|m| m.header.clone()) else { continue };
            let (body, _) = body_class(tx.core, &h, &c, ai);
            let n = tx.txn.note_death(tid, ak, &body, d.at)?;
            note_last(tx.core, tid, ak, &c, Some(n.last));
            // node-sync judges the bodies a write killed again (bounds, liveness)
            tx.core.mark_changed(c);
            bodies.insert((c, ai));
        }
    }
    for (c, ai) in bodies {
        check_at_most(tx, &c, ai)?;
    }
    Ok(())
}

/// Whether a valid delta of `c` (header `h`) on `(tid, ak)` needs the aspect's deaths replayed
/// instead of taken from its join. A join reports deaths against the state, which gives each
/// write its earliest superseder (spec/crdt.md §4.8) only for a delta with a `ts` above every
/// other held commit of the aspect and carrying no copies of others' writes; and only bodies with a
/// relative bound keep deaths.
pub(crate) fn replays(core: &mut Core, c: &CommitId, h: &Header, tid: &Tid, ak: &Ak) -> bool {
    let Some(held) = core.by_aspect.get(&(*tid, ak.clone())) else { return false };
    // a stamp orders a `ts` tie by dot, not commit ID: ties replay
    let late = !h.kind.has_own_writes() || held.iter().rev().find(|x| x.1 != *c).is_some_and(|x| x.0 >= h.ts);
    late && first_bounded(core, tid, ak).is_some()
}

/// Adds `item` to the replay waiting on `(tid, ak)` (marked in the store: an open replays it
/// whole). The replay runs once, at the end of the transaction or, within a node-sync step,
/// before its deaths are next read (`Engine::settle_deaths`): a step of late deltas costs one
/// replay per aspect. Until then its death records may be off either way (a validity flip can
/// remove a superseder), so its keep-at-most bounds wait (`check_at_most`).
pub(crate) fn mark(tx: &mut Tx<'_>, tid: &Tid, ak: &Ak, item: Due) -> Result<()> {
    let k = (*tid, ak.clone());
    if !tx.core.deaths_due.contains_key(&k) {
        tx.txn.put_local(&records::aspect_key(records::DEATHS_DUE, tid, ak), &[], Shred::No)?;
    }
    tx.core.deaths_due.insert(k, item);
    Ok(())
}

/// Marks `(tid, ak)` for a replay of every held body if one has a relative bound (others'
/// writes un-merged under an invalid commit's creations).
pub(crate) fn mark_if_bounded(tx: &mut Tx<'_>, tid: &Tid, ak: &Ak) -> Result<()> {
    if first_bounded(tx.core, tid, ak).is_some() {
        mark_deaths_due(tx, tid, ak)?;
    }
    Ok(())
}

/// Marks `(tid, ak)` for a replay of every held body.
pub(crate) fn mark_deaths_due(tx: &mut Tx<'_>, tid: &Tid, ak: &Ak) -> Result<()> {
    mark(tx, tid, ak, Due::Full)
}

/// Marks `(tid, ak)` after valid delta `c` (header `h`) joined out of order (`replays`) and
/// reported `deaths` against the state: the replay judges what it can change (`window`).
pub(crate) fn mark_late(tx: &mut Tx<'_>, c: &CommitId, h: &Header, tid: &Tid, ak: &Ak, deaths: &[Death]) -> Result<()> {
    if !h.kind.has_own_writes() {
        return mark_deaths_due(tx, tid, ak);
    }
    mark(tx, tid, ak, Due::Late(h.ts, *c))?;
    let killed: BTreeSet<CommitId> = deaths.iter().flat_map(|d| carriers(tx.core, tid, ak, &d.stamp.dot, d.at)).map(|x| x.0).collect();
    for x in killed {
        mark(tx, tid, ak, Due::Killed(x))?;
    }
    if let Some(at) = deaths.iter().map(|d| d.at).max() {
        mark(tx, tid, ak, Due::Hint(at))?;
    }
    Ok(())
}

/// `Engine::settle_deaths` in `tx`.
pub(crate) fn settle_due(tx: &mut Tx<'_>) -> Result<()> {
    // one aspect at a time: settling one may add rechecks to another still marked
    while let Some((k, items)) = tx.core.deaths_due.iter().next().map(|(k, s)| (k.clone(), s.iter().cloned().collect::<Vec<_>>())) {
        let (tid, ak) = k.clone();
        // unmarked first: `check_at_most` skips marked aspects
        for i in &items {
            tx.core.deaths_due.remove(&k, i);
        }
        tx.txn.remove_local(&records::aspect_key(records::DEATHS_DUE, &tid, &ak), Shred::No)?;
        let judged = if items.contains(&Due::Full) { None } else { window(tx, &tid, &ak, &items)? };
        let Some(judged) = judged else {
            rejudge_deaths(tx, &tid, &ak)?;
            continue;
        };
        let recheck = items.iter().filter_map(|i| match i {
            Due::Recheck(c, ai) => Some((*c, *ai)),
            _ => None,
        });
        let bodies: BTreeSet<(CommitId, usize)> = judged.into_iter().chain(recheck).collect();
        for (c, ai) in bodies {
            if tx.core.commits.get(&c).and_then(|m| m.header.aspects.get(ai)).is_some_and(|a| a.retention.at_most.rel.is_some()) {
                check_at_most(tx, &c, ai)?;
            }
        }
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
    for k in v {
        tx.core.deaths_due.insert(k, Due::Full);
    }
    Ok(())
}

/// Deaths of `(tid, ak)` from scratch (`replay_all`), then its keep-at-most bounds again: after
/// a validity flip, a snapshot or import, an open, or late deltas `window` cannot judge.
pub(crate) fn rejudge_deaths(tx: &mut Tx<'_>, tid: &Tid, ak: &Ak) -> Result<()> {
    if first_bounded(tx.core, tid, ak).is_some() {
        replay_all(tx, tid, ak)?;
    }
    recheck_at_most(tx, tid, ak)
}

/// Joins `f` into `st`, collecting its deaths. A snapshot's (`copies`) copy of a write already
/// dead in the replay is not dated again (two snapshots carrying a write whose own commit is
/// not held: the later one would date it at a later winner).
fn join(st: &mut Fragment, f: Fragment, copies: bool, deaths: &mut Vec<Death>, dead: &mut BTreeSet<Stamp>) {
    let mut ch = Changes::new();
    let g = copies.then(|| f.clone());
    st.join_into(f, None, &mut ch);
    for d in ch.into_deaths() {
        if let Some(g) = &g
            && dead.contains(&d.stamp)
            && g.holds_dots(&|x| x == d.stamp.dot.owner())
        {
            continue;
        }
        dead.insert(d.stamp.clone());
        deaths.push(d);
    }
}

/// Each write dies at the earliest `ts` among the applied commits superseding it (spec/crdt.md
/// §4.8): the held bodies and residues are joined in `(ts, ID)` order (valid writes only; a
/// snapshot's or import's copies of writes whose own commit is held or has a residue removed, so
/// they play at their own commit), then the state (live writes of dropped bodies without a
/// residue); a write dies at the first join superseding it. Every held body with a relative
/// bound gets the first and last of its writes' deaths. A function of the held bodies, the
/// residues and the state. Cost: the aspect's held bodies, residues and whole state.
fn replay_all(tx: &mut Tx<'_>, tid: &Tid, ak: &Ak) -> Result<()> {
    let got = replayed(tx, tid, ak)?;
    let held: Vec<CommitId> = tx.core.by_aspect.get(&(*tid, ak.clone())).into_iter().flatten().map(|x| x.1).collect();
    for c in &held {
        let Some(ai) = bounded_part(tx.core, c, tid, ak) else { continue };
        set_deaths(tx, tid, ak, c, ai, got.get(&(*c, ai)).copied())?;
    }
    Ok(())
}

/// `replay_all`'s deaths per held bounded body.
fn replayed(tx: &mut Tx<'_>, tid: &Tid, ak: &Ak) -> Result<BTreeMap<(CommitId, usize), (Ts, Ts)>> {
    let held: Vec<CommitId> = tx.core.by_aspect.get(&(*tid, ak.clone())).into_iter().flatten().map(|x| x.1).collect();
    let invalid = crate::apply::invalid_of(tx.core, tid, ak);
    let res = residues(tx, tid, ak)?;
    let mut st = Fragment::default();
    let mut deaths = Vec::new();
    let mut dead = BTreeSet::new();
    for c in &held {
        let parts: Vec<Fragment> = match held_part(tx.core, c, tid, ak) {
            Some(ai) => {
                let _s = crate::costs::span("deaths: read bodies");
                crate::apply::held_parts(tx, c, ai)?.into_iter().map(frag).collect()
            }
            None => res.get(c).cloned().into_iter().collect(),
        };
        let _s = crate::costs::span("deaths: join");
        let cp = copies(tx.core, c);
        for mut f in parts {
            let core = &*tx.core;
            f.remove_dots(&|d| invalid.iter().any(|o| o.owns(d)) || (cp && core.commit_of(tid, ak, d).is_some_and(|x| x != *c && (held_part(core, &x, tid, ak).is_some() || res.contains_key(&x)))));
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
    Ok(got)
}

fn set_deaths(tx: &mut Tx<'_>, tid: &Tid, ak: &Ak, c: &CommitId, ai: usize, d: Option<(Ts, Ts)>) -> Result<()> {
    let Some(h) = tx.core.commits.get(c).map(|m| m.header.clone()) else { return Ok(()) };
    let (body, _) = body_class(tx.core, &h, c, ai);
    let d = d.map(|(first, last)| osis_store::Deaths { first, last });
    // node-sync judges again only the bodies whose deaths moved
    if tx.core.changed.is_some() && tx.txn.death(tid, ak, &body)? != d {
        tx.core.mark_changed(*c);
    }
    tx.txn.set_death(tid, ak, &body, d)?;
    note_last(tx.core, tid, ak, c, d.map(|x| x.last));
    Ok(())
}

fn death_of(tx: &mut Tx<'_>, tid: &Tid, ak: &Ak, c: &CommitId, ai: usize) -> Result<Option<osis_store::Deaths>> {
    let Some(h) = tx.core.commits.get(c).map(|m| m.header.clone()) else { return Ok(None) };
    let (body, _) = body_class(tx.core, &h, c, ai);
    Ok(tx.txn.death(tid, ak, &body)?)
}

/// Deaths of the bodies the late writer deltas in `items` can change, from a replay of the
/// aspect's bodies (held, or a residue) from the first of those bodies to the latest death they
/// can have; the bodies judged, or `None` when that window cannot judge them (a snapshot or
/// import at or after its start or among them, a dropped body in it without a residue).
///
/// Exact (the records before the batch being exact): a write dies only at a greater stamp, so a
/// late delta L changes only bodies sorting at or before it, and only their writes that died
/// after its `ts` (their last death is later) or were live (its join killed them: `Killed`);
/// its own writes die at or before the winner its join met (`Hint`). Every write of a body in
/// the window dies at the same superseder as in a replay of every body, since nothing before
/// the window's start supersedes it. Cost: the bodies from the first judged one to the latest
/// death among them, plus the held records before the last late delta and the commits after
/// the window's start (in memory).
fn window(tx: &mut Tx<'_>, tid: &Tid, ak: &Ak, items: &[Due]) -> Result<Option<Vec<(CommitId, usize)>>> {
    let late: Vec<(Ts, CommitId)> = items.iter().filter_map(|i| if let Due::Late(t, c) = i { Some((*t, *c)) } else { None }).collect();
    let (Some(t_min), Some(t_max)) = (late.iter().map(|x| x.0).min(), late.iter().map(|x| x.0).max()) else { return Ok(Some(Vec::new())) };
    if first_bounded(tx.core, tid, ak).is_none() {
        return Ok(Some(Vec::new()));
    }
    let k = (*tid, ak.clone());
    let mut u = t_max;
    let mut judge: BTreeMap<(Ts, CommitId), usize> = BTreeMap::new();
    // bodies at or before a late delta with a death after the first one
    let before: Vec<(Ts, CommitId)> = tx.core.by_aspect.get(&k).into_iter().flat_map(|s| s.range(..=(t_max, HI))).take(LASTS_MIN).copied().collect();
    let dying: Vec<(Ts, Ts, CommitId)> = if before.len() < LASTS_MIN && tx.core.lasts.get(&k).is_none() {
        // few bodies before: their records, without loading the index
        let mut v = Vec::new();
        for (ts, c) in before {
            if let Some(ai) = bounded_part(tx.core, &c, tid, ak)
                && let Some(d) = death_of(tx, tid, ak, &c, ai)?
            {
                v.push((d.last, ts, c));
            }
        }
        v
    } else {
        lasts(tx, tid, ak)?.by_last.range((t_min, Ts::default(), LO)..).copied().collect()
    };
    let dying = dying.into_iter().filter(|x| x.0 > t_min && x.1 <= t_max);
    for (last, ts, c) in dying {
        let Some(ai) = bounded_part(tx.core, &c, tid, ak) else { continue };
        judge.insert((ts, c), ai);
        u = u.max(last);
    }
    // bodies whose live writes a late delta killed, and the late deltas
    let named: BTreeSet<CommitId> = items.iter().filter_map(|i| if let Due::Killed(c) | Due::Late(_, c) = i { Some(*c) } else { None }).collect();
    for c in named {
        let Some(ai) = bounded_part(tx.core, &c, tid, ak) else { continue };
        let Some(ts) = tx.core.commits.get(&c).map(|m| m.header.ts) else { continue };
        if let Some(d) = death_of(tx, tid, ak, &c, ai)? {
            u = u.max(d.last);
        }
        judge.insert((ts, c), ai);
    }
    for i in items {
        if let Due::Hint(t) = i {
            u = u.max(*t);
        }
    }
    let Some(&(t_start, _)) = judge.keys().next() else { return Ok(Some(Vec::new())) };
    // a snapshot's copies play at its position with their own stamps, and its records span
    // writes from before the window
    if judge.keys().any(|(_, c)| copies(tx.core, c)) || tx.core.snapshots.get(&k).is_some_and(|v| v.iter().any(|s| s.0 >= t_start)) {
        return Ok(None);
    }
    let core = &*tx.core;
    if core.by_aspect.get(&k).into_iter().flat_map(|s| s.range((t_start, LO)..)).any(|(_, c)| copies(core, c)) {
        return Ok(None);
    }
    let fold: Vec<(Ts, CommitId)> = core.by_aspect.get(&k).into_iter().flat_map(|s| s.range((t_start, LO)..=(u, HI))).copied().collect();
    let invalid = crate::apply::invalid_of(tx.core, tid, ak);
    let mut st = Fragment::default();
    let mut deaths = Vec::new();
    let mut dead = BTreeSet::new();
    for (ts, c) in &fold {
        let parts: Vec<Fragment> = match held_part(tx.core, c, tid, ak) {
            Some(ai) => crate::apply::held_parts(tx, c, ai)?.into_iter().map(frag).collect(),
            None => match tx.txn.get_local(&records::dropped_key(tid, ak, *ts, c))? {
                Some(b) => vec![crate::engine::state::decode(&b)?],
                None => return Ok(None),
            },
        };
        for mut f in parts {
            f.remove_dots(&|d| invalid.iter().any(|o| o.owns(d)));
            join(&mut st, f, false, &mut deaths, &mut dead);
        }
    }
    let judged: BTreeSet<(CommitId, usize)> = judge.iter().map(|((_, c), ai)| (*c, *ai)).collect();
    let mut got: BTreeMap<(CommitId, usize), (Ts, Ts)> = BTreeMap::new();
    for d in &deaths {
        for k in carriers(tx.core, tid, ak, &d.stamp.dot, d.at) {
            if judged.contains(&k) {
                let e = got.entry(k).or_insert((d.at, d.at));
                *e = (e.0.min(d.at), e.1.max(d.at));
            }
        }
    }
    for (c, ai) in &judged {
        set_deaths(tx, tid, ak, c, *ai, got.get(&(*c, *ai)).copied())?;
    }
    #[cfg(debug_assertions)]
    {
        // every held bounded body as a replay of every body dates it
        let want = replayed(tx, tid, ak)?;
        let held: Vec<CommitId> = tx.core.by_aspect.get(&k).into_iter().flatten().map(|x| x.1).collect();
        for c in held {
            let Some(ai) = bounded_part(tx.core, &c, tid, ak) else { continue };
            let have = death_of(tx, tid, ak, &c, ai)?.map(|d| (d.first, d.last));
            debug_assert!(have == want.get(&(c, ai)).copied(), "window deaths of {c:?} on {tid:?} {ak:?}: {have:?}, a whole replay {:?}", want.get(&(c, ai)));
        }
        // the last-death index, where loaded, is what the records give
        if tx.core.lasts.get(&k).is_some() {
            let fresh = load_lasts(tx, tid, ak)?;
            debug_assert!(tx.core.lasts.get(&k) == Some(&fresh), "last deaths of {tid:?} {ak:?} differ from the records");
        }
    }
    Ok(Some(judged.into_iter().collect()))
}

/// Judges the keep-at-most bounds of the held bodies of `(tid, ak)` under a relative bound
/// again: their deaths or live writes may have changed (spec/commits.md §5).
fn recheck_at_most(tx: &mut Tx<'_>, tid: &Tid, ak: &Ak) -> Result<()> {
    let held: Vec<CommitId> = tx.core.by_aspect.get(&(*tid, ak.clone())).into_iter().flatten().map(|x| x.1).collect();
    for c in held {
        let Some(ai) = held_part(tx.core, &c, tid, ak) else { continue };
        if tx.core.commits.get(&c).and_then(|m| m.header.aspects.get(ai)).is_none_or(|a| a.retention.at_most.rel.is_none()) {
            continue;
        }
        check_at_most(tx, &c, ai)?;
    }
    Ok(())
}
