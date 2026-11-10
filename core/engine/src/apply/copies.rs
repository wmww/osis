//! Which delta carries a dot (spec/permissions.md §5.2), and what held valid snapshots vouch
//! for: a valid snapshot's writes join like any write (spec/crdt.md §4.1 copy order) and are
//! never compared with their own delta's.

use crate::engine::{Core, Meta, Owned, Tx};
use crate::error::Result;
use osis_base::{Ak, CommitId, Tid};
use osis_commit::Form;
use osis_crdt::{Dot, Fragment};
use std::collections::BTreeSet;
use std::sync::Arc;

/// Whether some held commit carrying dot `d` on `(tid, ak)` (spec/permissions.md §5.2) has its
/// delta of that aspect as `f` judges it: the session-form commit whose range holds it; for
/// `Commit(c)`, `c` itself as a commit-form commit with the aspect.
pub(crate) fn any_delta(core: &Core, tid: &Tid, ak: &Ak, d: &Dot, f: &dyn Fn(&CommitId, &Meta, usize) -> bool) -> bool {
    let at = |m: &Meta| m.aspect(tid, ak);
    let d = d.origin();
    match d.src.kind() {
        osis_crdt::SourceKind::Session(_) => core.commit_of(tid, ak, d).is_some_and(|c| core.ix.commits.get(&c).is_some_and(|m| at(m).is_some_and(|ai| f(&c, m, ai)))),
        osis_crdt::SourceKind::Commit(c) => core.ix.commits.get(c).filter(|m| m.view.form == Form::Commit && m.view.kind.has_own_writes()).is_some_and(|m| at(m).is_some_and(|ai| f(c, m, ai))),
        osis_crdt::SourceKind::Derived(_) => false,
    }
}

/// Whether the delta carrying dot `d` on `(tid, ak)` was ever held here (held or dropped).
pub(crate) fn delta_received(core: &Core, tid: &Tid, ak: &Ak, d: &Dot) -> bool {
    any_delta(core, tid, ak, d, &|_, m, ai| !m.missing.contains(&ai))
}

/// Whether held snapshot `snap`'s part on `(tid, ak)` is valid (`Judge::part`: its author could
/// write the aspect at it).
pub(crate) fn snapshot_valid(core: &Core, snap: &CommitId, tid: &Tid, ak: &Ak) -> bool {
    core.ix.commits.get(snap).is_some_and(|m| m.aspect(tid, ak).is_some_and(|ai| m.valid_at(ai)))
}

/// Whether held commit `c` is a compaction snapshot whose part on `(tid, ak)` is invalid: its
/// body gives nothing (not joined, replayed or covering).
pub(crate) fn invalid_snapshot(core: &Core, c: &CommitId, tid: &Tid, ak: &Ak) -> bool {
    core.ix.commits.get(c).is_some_and(|m| m.view.kind.is_compaction()) && !snapshot_valid(core, c, tid, ak)
}

/// Writes held snapshots' copy indexes may hold in all (`Core::copy_index`).
const COPY_CACHE_MAX: usize = 1 << 20;

/// Held snapshot `s`'s writes on `(tid, ak)` by dot (`Core::copy_index`), indexed a piece at
/// a time.
pub(crate) fn copy_index(tx: &mut Tx<'_>, s: &CommitId, tid: &Tid, ak: &Ak) -> Result<Option<Arc<osis_crdt::CopyIndex>>> {
    let k = (*tid, ak.clone());
    if let Some(ix) = tx.core.copy_index.get(s).and_then(|m| m.get(&k)).cloned() {
        // debug builds: a cached index is the one its stored body or leftover gives now (the
        // cache is forgotten with every change to them, `Core::copy_index`)
        #[cfg(debug_assertions)]
        {
            let fresh = crate::costs::paused(|| build_copy_index(tx, s, tid, ak))?;
            assert_eq!(fresh.map(|x| format!("{x:?}")), Some(format!("{ix:?}")), "stale copy index of {s:?} on {tid:?} {}", ak.as_str());
        }
        return Ok(Some(ix));
    }
    let Some(ix) = build_copy_index(tx, s, tid, ak)? else { return Ok(None) };
    let ix = Arc::new(ix);
    if tx.core.copy_index.values().flat_map(|m| m.values()).map(|x| x.len()).sum::<usize>() + ix.len() > COPY_CACHE_MAX {
        tx.core.copy_index.clear();
    }
    tx.core.copy_index.entry(*s).or_default().insert(k, ix.clone());
    Ok(Some(ix))
}

/// `copy_index` read anew from what `each_held_piece` reads.
fn build_copy_index(tx: &mut Tx<'_>, s: &CommitId, tid: &Tid, ak: &Ak) -> Result<Option<osis_crdt::CopyIndex>> {
    let Some(sai) = tx.core.ix.commits.get(s).and_then(|m| m.aspect(tid, ak)) else { return Ok(None) };
    let mut ix = osis_crdt::CopyIndex::default();
    let held = super::each_held_piece(tx, s, sai, &mut |_, f| {
        ix.add(&f);
        Ok(())
    })?;
    Ok(held.map(|_| ix))
}

/// The dots among those `owned` matches under which a held valid snapshot of `(tid, ak)`
/// holds a write or a map record (`CopyIndex::held_in`): those records count whatever their own
/// delta's validity, as the snapshot's writer vouched for them (spec/permissions.md §5.2).
pub(crate) fn vouched(tx: &mut Tx<'_>, tid: &Tid, ak: &Ak, owned: &[Owned]) -> Result<BTreeSet<Dot>> {
    let mut out = BTreeSet::new();
    if owned.is_empty() {
        return Ok(out);
    }
    let snaps: Vec<CommitId> = tx.core.ix.snapshots.get(&(*tid, ak.clone())).into_iter().flatten().map(|s| s.1).filter(|s| snapshot_valid(tx.core, s, tid, ak)).collect();
    for s in snaps {
        let Some(ix) = copy_index(tx, &s, tid, ak)? else { continue };
        vouched_in(&ix, owned, &mut out);
    }
    Ok(out)
}

/// `vouched` of one snapshot's writes, indexed `ix`.
fn vouched_in(ix: &osis_crdt::CopyIndex, owned: &[Owned], out: &mut BTreeSet<Dot>) {
    for o in owned {
        let (src, lo, hi) = range_of(o);
        out.extend(ix.held_in(&src, lo, hi).filter(|d| o.owns(d)).cloned());
    }
}

/// The origin dots `o` may own: a source and a counter range.
fn range_of(o: &Owned) -> (osis_crdt::Source, u64, u64) {
    match o {
        Owned::Range { src, lo, hi } => (src.clone(), *lo, *hi),
        Owned::Commit(c) => (osis_crdt::Source::commit(*c), 0, u64::MAX),
        Owned::Dots { src, ctrs } => (src.clone(), ctrs.first().copied().unwrap_or(0), ctrs.last().map_or(0, |x| x.saturating_add(1))),
    }
}

/// Whether a valid snapshot's piece `f` joined may differ from the rebuild, so the aspect is
/// rebuilt: `f` holds a write or record of the deltas `owned` matches that un-merge removes or
/// changes (`holds_dots`), or one it vouches for (`vouched` of it is not empty), a sequence
/// element's creation copy included, since what un-merge keeps of those deltas' bodies depends
/// on it (spec/crdt.md §4.6).
pub(crate) fn vouches_any(f: &Fragment, owned: &[Owned]) -> bool {
    if owned.is_empty() {
        return false;
    }
    if f.holds_dots(&|d| owned.iter().any(|o| o.owns(d))) {
        return true;
    }
    let mut ranges: Vec<_> = owned.iter().map(range_of).collect();
    ranges.sort();
    let mut out = BTreeSet::new();
    vouched_in(&f.copy_index_in(&ranges), owned, &mut out);
    !out.is_empty()
}
