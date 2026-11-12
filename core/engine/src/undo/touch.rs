//! The undo index: per aspect, which held parts write each position (`osis_crdt::touches`), so
//! the state before a commit is joined from the parts writing the undone delta's positions
//! (`undo::kept_before`) and a restoring undo finds the aspect's parts not fetched yet without
//! walking its history (`undo::replaced_kept`). Derived from held bodies, built for an aspect at
//! its first undo check and kept up to date from there: every change of a commit's `Meta`
//! (`Core::put_meta`, `take_meta`) marks the commit due on the indexed aspects it lists, and the
//! next check reads what is due again. A cache: what it says is a superset, each part re-judged
//! (held, valid, kept) where used, and it is dropped when a changing transaction rolls back
//! (`Core::rollback_to`) and when it outgrows `TOUCHES_MAX`.

use crate::engine::{Core, Tx};
use crate::error::Result;
use osis_base::{Ak, CommitId, Tid, Ts};
use osis_crdt::{Pos, Seg};
use std::collections::{BTreeMap, BTreeSet, HashMap};

/// Approximate bytes the undo indexes hold (`approx`; a map key's value is shared with held
/// bodies, not counted). Performance switch: checked at each check's start, past it every index
/// is forgotten, so memory stays under it plus one aspect's index. 0: every undo check reads
/// every held part of its aspect, as with no index; infinity: every aspect checked since the
/// open stays indexed.
const TOUCHES_MAX: usize = 16 << 20;

/// A part's place in its aspect: `ts`, commit.
pub(crate) type Place = (Ts, CommitId);

#[derive(Clone, Default)]
pub(crate) struct Touches {
    aspects: HashMap<(Tid, Ak), Aspect>,
    bytes: usize,
}

#[derive(Clone, Default)]
struct Aspect {
    /// Held parts per position they write.
    by_pos: BTreeMap<Pos, BTreeSet<Place>>,
    /// What each indexed part was filed under.
    of_part: HashMap<CommitId, (Ts, Vec<Pos>)>,
    /// Parts to read again: their commit's `Meta` changed.
    due: BTreeSet<Place>,
    /// Parts not fetched yet (`Hold::Missing`).
    missing: BTreeSet<Place>,
    /// Snapshot parts: what they hold is read whole, never by position.
    snaps: BTreeSet<Place>,
}

/// What one position entry costs, roughly.
fn approx(p: &Pos) -> usize {
    2 * p.len() * std::mem::size_of::<Seg>() + 128
}

/// The entries of `by` at `p` and below it.
fn below<'a>(by: &'a BTreeMap<Pos, BTreeSet<Place>>, p: &'a [Seg]) -> impl Iterator<Item = (&'a Pos, &'a BTreeSet<Place>)> + 'a {
    by.range(p.to_vec()..).take_while(move |(k, _)| k.starts_with(p))
}

impl Touches {
    /// Commit `id`'s `Meta` changed (or went): its parts on indexed aspects are read again.
    pub(crate) fn note(&mut self, id: &CommitId, m: &crate::engine::Meta) {
        for a in &m.view.aspects {
            if let Some(x) = self.aspects.get_mut(&(a.tid, a.ak.clone())) {
                x.due.insert((m.view.ts, *id));
            }
        }
    }

    pub(crate) fn clear(&mut self) {
        *self = Touches::default();
    }

    fn unfile(&mut self, k: &(Tid, Ak), c: &CommitId) {
        let Some(a) = self.aspects.get_mut(k) else { return };
        if let Some((ts, ps)) = a.of_part.remove(c) {
            for p in ps {
                self.bytes = self.bytes.saturating_sub(approx(&p));
                if let Some(s) = a.by_pos.get_mut(&p) {
                    s.remove(&(ts, *c));
                    if s.is_empty() {
                        a.by_pos.remove(&p);
                    }
                }
            }
        }
        a.missing.retain(|x| x.1 != *c);
        a.snaps.retain(|x| x.1 != *c);
    }

    fn file(&mut self, k: &(Tid, Ak), place: Place, mut ps: Vec<Pos>) {
        let Some(a) = self.aspects.get_mut(k) else { return };
        ps.sort();
        ps.dedup();
        for p in &ps {
            self.bytes = self.bytes.saturating_add(approx(p));
            a.by_pos.entry(p.clone()).or_default().insert(place);
        }
        a.of_part.insert(place.1, (place.0, ps));
    }
}

/// Indexes `(tid, ak)`: built from its held parts on first use, else what is due read again.
pub(crate) fn ensure(tx: &mut Tx<'_>, tid: &Tid, ak: &Ak) -> Result<()> {
    let k = (*tid, ak.clone());
    if tx.core.touches.bytes > TOUCHES_MAX {
        tx.core.touches.clear();
    }
    let due: Vec<Place> = match tx.core.touches.aspects.get_mut(&k) {
        Some(a) => std::mem::take(&mut a.due).into_iter().collect(),
        None => {
            tx.core.touches.aspects.insert(k.clone(), Aspect::default());
            tx.core.ix.by_aspect.get(&k).into_iter().flatten().copied().collect()
        }
    };
    for p in due {
        examine(tx, &k, p)?;
    }
    Ok(())
}

/// Files part `place` of `k` as it is held now.
fn examine(tx: &mut Tx<'_>, k: &(Tid, Ak), place: Place) -> Result<()> {
    let (ts, c) = place;
    tx.core.touches.unfile(k, &c);
    if !tx.core.ix.by_aspect.get(k).is_some_and(|s| s.contains(&place)) {
        return Ok(());
    }
    let Some(m) = tx.core.ix.commits.get(&c) else { return Ok(()) };
    let Some(ai) = m.aspect(&k.0, &k.1) else { return Ok(()) };
    let (snap, missing, holds) = (m.view.kind.is_compaction(), m.missing(ai), m.holds(ai));
    let Some(a) = tx.core.touches.aspects.get_mut(k) else { return Ok(()) };
    // a snapshot not fetched yet blocks a restoring undo too (`undo::replaced_kept`)
    if missing {
        a.missing.insert(place);
    }
    if snap {
        a.snaps.insert(place);
        return Ok(());
    }
    if !holds {
        return Ok(());
    }
    match crate::apply::held_part(tx, &c, ai)? {
        Some(d) => tx.core.touches.file(k, (ts, c), osis_crdt::touches(d.fragment())),
        // its record not written yet in this transaction: read at the next check
        None => {
            if let Some(a) = tx.core.touches.aspects.get_mut(k) {
                a.due.insert(place);
            }
        }
    }
    Ok(())
}

/// The indexed parts of `(tid, ak)` an undo of a delta writing `need` reads (`ensure` first):
/// those writing each position, the composites' own writes above it, and every snapshot. A map
/// record keyed `k` reads every record of `k`, each with its dot's.
pub(crate) fn candidates(core: &Core, tid: &Tid, ak: &Ak, need: &[Pos]) -> BTreeSet<Place> {
    let mut out = BTreeSet::new();
    let Some(a) = core.touches.aspects.get(&(*tid, ak.clone())) else { return out };
    out.extend(a.snaps.iter().copied());
    for p in need {
        for up in (0..p.len()).filter_map(|i| p.get(..i)) {
            out.extend(a.by_pos.get(up).into_iter().flatten().copied());
        }
        // a keyed record: every record of the key, each with its dot's
        let keyed = p.split_last().and_then(|(_, key)| key.split_last().filter(|(k, _)| matches!(k, Seg::Key(_))).map(|(_, at)| (key, at)));
        match keyed {
            Some((key, at)) => {
                for (q, s) in below(&a.by_pos, key) {
                    out.extend(s.iter().copied());
                    if let Some(d @ Seg::Dot(_)) = q.last() {
                        let mut r = at.to_vec();
                        r.push(d.clone());
                        out.extend(a.by_pos.get(&r).into_iter().flatten().copied());
                    }
                }
            }
            None => below(&a.by_pos, p).for_each(|(_, s)| out.extend(s.iter().copied())),
        }
    }
    out
}

/// The indexed parts of `(tid, ak)` writing at or below `p`.
pub(crate) fn inside(core: &Core, tid: &Tid, ak: &Ak, p: &[Seg]) -> BTreeSet<Place> {
    let Some(a) = core.touches.aspects.get(&(*tid, ak.clone())) else { return BTreeSet::new() };
    below(&a.by_pos, p).flat_map(|(_, s)| s.iter().copied()).collect()
}

/// Whether a valid part of `(tid, ak)` ordered before `at` is not fetched yet (`ensure` first).
pub(crate) fn missing_before(core: &Core, tid: &Tid, ak: &Ak, at: Place) -> bool {
    let Some(a) = core.touches.aspects.get(&(*tid, ak.clone())) else { return true };
    a.missing.range(..at).any(|(_, c)| core.ix.commits.get(c).is_some_and(|m| m.aspect(tid, ak).is_some_and(|ai| m.valid_at(ai) && m.missing(ai))))
}
