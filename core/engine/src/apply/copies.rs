//! Who owns a dot (spec/permissions.md §5.2), what held snapshots carry of writes, and where a
//! copy differs from its delta.

use crate::engine::{Core, Meta, Owned, Tx};
use crate::error::Result;
use osis_base::{Ak, CommitId, Tid, Value};
use osis_commit::{Form, Header};
use osis_crdt::{Dot, Fragment};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

/// Writes a held compaction snapshot holds under dots whose owning delta was never received here
/// (`owner_received`), per snapshot and source, counters sorted: the snapshots to compare with
/// that delta once it arrives (`uncarry`, `differing_copies`). Kept for every held snapshot whatever its validity, in
/// (snapshot, source) order whatever the arrival order. Nothing is judged per write: a valid
/// snapshot vouches for every write it carries (spec/permissions.md §5.2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Carried {
    pub snap: CommitId,
    pub src: osis_crdt::Source,
    pub ctrs: Vec<u64>,
}

/// The writes of snapshot fragment `f` of `(tid, ak)` whose owning delta was never received
/// here, by source. A record carrying no `ts` (a tombstone, a bare anchor) carries no write.
pub(crate) fn carried_of(core: &Core, tid: &Tid, ak: &Ak, f: &Fragment) -> BTreeMap<osis_crdt::Source, BTreeSet<u64>> {
    let mut out: BTreeMap<osis_crdt::Source, BTreeSet<u64>> = BTreeMap::new();
    for (d, ts) in f.writes() {
        if ts.is_some() && !d.src.is_derived() && !owner_received(core, tid, ak, &d) {
            out.entry(d.src.clone()).or_default().insert(d.ctr);
        }
    }
    out
}

/// Whether some held commit owning dot `d` on `(tid, ak)` (spec/permissions.md §5.2) has its
/// delta of that aspect as `f` judges it: the session-form commit whose range holds it; for
/// `Commit(c)`, `c` itself as a commit-form commit with the aspect.
pub(crate) fn any_owner(core: &Core, tid: &Tid, ak: &Ak, d: &Dot, f: &dyn Fn(&CommitId, &Meta, usize) -> bool) -> bool {
    let at = |m: &Meta| m.aspect(tid, ak);
    let d = d.owner();
    match d.src.kind() {
        osis_crdt::SourceKind::Session(_) => core.commit_of(tid, ak, d).is_some_and(|c| core.ix.commits.get(&c).is_some_and(|m| at(m).is_some_and(|ai| f(&c, m, ai)))),
        osis_crdt::SourceKind::Commit(c) => core.ix.commits.get(c).filter(|m| m.view.form == Form::Commit && m.view.kind.has_own_writes()).is_some_and(|m| at(m).is_some_and(|ai| f(c, m, ai))),
        osis_crdt::SourceKind::Derived(_) => false,
    }
}

/// Whether the delta owning dot `d` on `(tid, ak)` was ever held here (held or dropped).
pub(crate) fn owner_received(core: &Core, tid: &Tid, ak: &Ak, d: &Dot) -> bool {
    any_owner(core, tid, ak, d, &|_, m, ai| !m.missing.contains(&ai))
}

/// Whether the delta owning dot `d` on `(tid, ak)` is held here (not dropped).
pub(crate) fn owner_held(core: &Core, tid: &Tid, ak: &Ak, d: &Dot) -> bool {
    any_owner(core, tid, ak, d, &|_, m, ai| m.holds(ai))
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

/// Records the writes snapshot `snap` of `(tid, ak)` carries whose owning delta was never
/// received here (any snapshot held, whatever its validity), as `carried_of` found them in its
/// pieces, gathered.
pub(crate) fn note_carried_of(core: &mut Core, tid: &Tid, ak: &Ak, snap: &CommitId, carried: BTreeMap<osis_crdt::Source, BTreeSet<u64>>) {
    let k = (*tid, ak.clone());
    let before = core.ix.carried.get(&k).cloned().unwrap_or_default();
    let mut cur: Vec<Carried> = before.iter().filter(|c| c.snap != *snap).cloned().collect();
    cur.extend(carried.into_iter().map(|(src, ctrs)| Carried { snap: *snap, src, ctrs: ctrs.into_iter().collect() }));
    // in one order whatever order the snapshots arrived in
    cur.sort_by(|x, y| (x.snap, &x.src).cmp(&(y.snap, &y.src)));
    if cur == before {
        return;
    }
    if cur.is_empty() {
        core.ix.carried.remove(&k);
    } else {
        core.ix.carried.insert(k, cur);
    }
}

/// The writes of held snapshot `snap` on `(tid, ak)` whose owning delta is held (whole or as its
/// leftover), was never received here (missing), or
/// was dropped as covered with every coverer still giving its writes from a
/// held body: they go from the state when it turns invalid (spec/permissions.md §5.2), all of
/// them, also those another held valid snapshot carries (its body gives its own copy back in the
/// rebuild; the state may hold this one's differing copy, which would otherwise stay: a nested
/// write copied into its entry's key-erased record, §4.7, where the own body has it keyed), and
/// the own body or the coverers give the delta's writes back the same way. A write of a delta
/// dropped otherwise, or under a coverer dropped for its bounds (whose writes the state alone
/// holds), stays.
/// Records carrying no write (bare anchors, tombstones) count as given too: stripped, a record
/// left with no write goes (spec/crdt.md §4.2), as at a node that never joined the snapshot.
pub(crate) fn given_by(tx: &mut Tx<'_>, tid: &Tid, ak: &Ak, snap: &CommitId) -> Result<Vec<Owned>> {
    let Some(sai) = tx.core.ix.commits.get(snap).and_then(|m| m.aspect(tid, ak)) else { return Ok(Vec::new()) };
    let mut dots = Vec::new();
    super::each_held_piece(tx, snap, sai, &mut |_, f| {
        dots.extend(f.writes().into_iter().filter(|(d, _)| !d.src.is_derived()).map(|(d, _)| d));
        Ok(())
    })?;
    let mut out = Vec::new();
    let mut memo: BTreeMap<(CommitId, usize), bool> = BTreeMap::new();
    for d in dots {
        if regiven(tx, tid, ak, &d, &mut memo)? {
            out.push(d);
        }
    }
    Ok(Owned::dots(out))
}

/// Whether the writes under dot `d` on `(tid, ak)` come back from held bodies alone (`given_by`):
/// some owning delta held (whole or as its leftover); else every owner not given back by a held
/// body was never received (missing, or expired or purged while missing:
/// `retention::never_received`) or dropped as covered where no coverer is a snapshot body
/// dropped other than as covered (its writes live only in the state). Invariant: a turned-
/// invalid snapshot's copy stays in the state only where nothing held gives the write back, so
/// the rebuild equals the join of what is held whether the snapshot was ever valid here. `memo`:
/// `never_received` per dropped part (a store read).
fn regiven(tx: &mut Tx<'_>, tid: &Tid, ak: &Ak, d: &Dot, memo: &mut BTreeMap<(CommitId, usize), bool>) -> Result<bool> {
    let core = &*tx.core;
    let state_only = |s: &CommitId| core.ix.commits.get(s).is_some_and(|m| m.aspect(tid, ak).and_then(|ai| m.dropped.get(&ai)).is_some_and(|x| !x.as_cover()));
    // the owner parts dropped other than as covered; any other owner not giving decides `false`
    let (dropped, refused) = (std::cell::RefCell::new(Vec::new()), std::cell::Cell::new(false));
    let given = !owner_received(core, tid, ak, d)
        || any_owner(core, tid, ak, d, &|c, m, ai| {
            !m.missing.contains(&ai)
                && match m.dropped.get(&ai) {
                    None => true,
                    Some(x) if x.as_cover() => {
                        let gives = !crate::retention::coverers(core, c, ai).iter().any(state_only);
                        refused.set(refused.get() || !gives);
                        gives
                    }
                    Some(_) => {
                        dropped.borrow_mut().push((*c, ai));
                        false
                    }
                }
        });
    if given {
        return Ok(true);
    }
    let dropped = dropped.into_inner();
    if refused.get() || dropped.is_empty() {
        return Ok(false);
    }
    for (c, ai) in dropped {
        let x = match memo.get(&(c, ai)) {
            Some(x) => *x,
            None => {
                let x = crate::retention::never_received(tx, &c, ai)?;
                memo.insert((c, ai), x);
                x
            }
        };
        if !x {
            return Ok(false);
        }
    }
    Ok(true)
}

/// Drops the carried writes a commit owns on the aspects whose deltas it now holds (`held`):
/// its counters (session form), its whole source (commit form).
/// Returns, per such aspect, the snapshots whose copies it dropped: they are compared with the
/// delta (`differing_copies`).
pub(crate) fn uncarry(core: &mut Core, id: &CommitId, h: &Header, held: &dyn Fn(usize) -> bool) -> Vec<(Tid, Ak, BTreeSet<CommitId>)> {
    let whole = (h.kind.has_own_writes() && h.form == Form::Commit).then(|| osis_crdt::Source::commit(*id));
    let counted = (h.kind.has_own_writes() && h.form.counted()).then(|| h.form.own_source(h.author, *id));
    let mut out = Vec::new();
    if whole.is_none() && counted.is_none() {
        return out;
    }
    for (_, a) in h.aspects.iter().enumerate().filter(|(ai, _)| held(*ai)) {
        let k = (a.tid, a.ak.clone());
        let owns = |src: &osis_crdt::Source, x: u64| whole.as_ref() == Some(src) || (counted.as_ref() == Some(src) && a.lo <= x && x < a.hi);
        if !core.ix.carried.get(&k).is_some_and(|v| v.iter().any(|c| c.ctrs.iter().any(|x| owns(&c.src, *x)))) {
            continue;
        }
        let mut v = core.ix.carried.get(&k).cloned().unwrap_or_default();
        let mut snaps = BTreeSet::new();
        for c in v.iter_mut() {
            let n = c.ctrs.len();
            let src = c.src.clone();
            c.ctrs.retain(|x| !owns(&src, *x));
            if c.ctrs.len() != n {
                snaps.insert(c.snap);
            }
        }
        v.retain(|c| !c.ctrs.is_empty());
        if v.is_empty() {
            core.ix.carried.remove(&k);
        } else {
            core.ix.carried.insert(k, v);
        }
        out.push((a.tid, a.ak.clone(), snaps));
    }
    out
}

/// Writes held snapshots' copy indexes may hold in all (`Core::copy_index`).
const COPY_CACHE_MAX: usize = 1 << 20;

/// The owner dots of commit `id`'s delta `ai` (header `h`) as (source, counters `lo..hi`):
/// its counter range, or its source in commit form.
pub(crate) fn owned_ranges(h: &Header, id: &CommitId, ai: usize) -> Vec<(osis_crdt::Source, u64, u64)> {
    match (h.form, h.aspects.get(ai)) {
        (_, None) => Vec::new(),
        (_, Some(_)) if !h.kind.has_own_writes() => Vec::new(),
        (Form::Commit, Some(_)) => vec![(osis_crdt::Source::commit(*id), 1, u64::MAX)],
        (f, Some(a)) => vec![(f.own_source(h.author, *id), a.lo, a.hi)],
    }
}

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

/// Records (dot, key) a snapshot holds (`None`: any write but a keyed map entry's creation).
pub(crate) type Records = BTreeSet<(Dot, Option<Value>)>;

/// The records (dot, key: `CopyIndex::records_in`) among those `owned` matches under which a
/// held valid snapshot of `(tid, ak)` holds a write: those writes count whatever their own
/// delta's validity, as the snapshot's writer vouched for them (spec/permissions.md §5.2).
/// With them, the dots whose map record such a snapshot holds key-erased (`CopyIndex::erased_in`).
pub(crate) fn vouched(tx: &mut Tx<'_>, tid: &Tid, ak: &Ak, owned: &[Owned]) -> Result<(Records, BTreeSet<Dot>)> {
    let mut out = BTreeSet::new();
    let mut erased = BTreeSet::new();
    if owned.is_empty() {
        return Ok((out, erased));
    }
    let snaps: Vec<CommitId> = tx.core.ix.snapshots.get(&(*tid, ak.clone())).into_iter().flatten().map(|s| s.1).filter(|s| snapshot_valid(tx.core, s, tid, ak)).collect();
    for s in snaps {
        let Some(ix) = copy_index(tx, &s, tid, ak)? else { continue };
        vouched_in(&ix, owned, &mut out, &mut erased);
    }
    Ok((out, erased))
}

/// `vouched` of one snapshot's writes, indexed `ix`.
fn vouched_in(ix: &osis_crdt::CopyIndex, owned: &[Owned], out: &mut Records, erased: &mut BTreeSet<Dot>) {
    for o in owned {
        let (src, lo, hi) = range_of(o);
        out.extend(ix.records_in(&src, lo, hi).filter(|(d, _)| o.owns(d)).map(|(d, k)| (d.clone(), k.cloned())));
        erased.extend(ix.erased_in(&src, lo, hi).filter(|d| o.owns(d)).cloned());
    }
}

/// The owner dots `o` may own: a source and a counter range.
fn range_of(o: &Owned) -> (osis_crdt::Source, u64, u64) {
    match o {
        Owned::Range { src, lo, hi } => (src.clone(), *lo, *hi),
        Owned::Commit(c) => (osis_crdt::Source::commit(*c), 0, u64::MAX),
        Owned::Dots { src, ctrs } => (src.clone(), ctrs.first().copied().unwrap_or(0), ctrs.last().map_or(0, |x| x.saturating_add(1))),
    }
}

/// Whether a valid snapshot's piece `f` joined may differ from the rebuild, so the aspect is
/// rebuilt: `f` holds a write or record of the deltas `owned` matches that un-merge removes or
/// changes (`holds_dots`), or one it vouches for (`vouched` of it is not empty), a hidden
/// anchor's creation copy included, since what un-merge keeps of those deltas' bodies depends on
/// it (spec/crdt.md §4.6).
pub(crate) fn vouches_any(f: &Fragment, owned: &[Owned]) -> bool {
    if owned.is_empty() {
        return false;
    }
    if f.holds_dots(&|d| owned.iter().any(|o| o.owns(d))) {
        return true;
    }
    let mut ranges: Vec<_> = owned.iter().map(range_of).collect();
    ranges.sort();
    let (mut out, mut erased) = (Records::new(), BTreeSet::new());
    vouched_in(&f.copy_index_in(&ranges), owned, &mut out, &mut erased);
    !out.is_empty() || !erased.is_empty()
}

/// The dots under which the snapshots `snaps` hold copies of the writes of commit `id`'s delta
/// `ai` (header `h`, stored) otherwise than that delta holds them (`misstated_in`). O(delta)
/// once a snapshot is indexed.
pub(crate) fn differing_copies(tx: &mut Tx<'_>, h: &Header, id: &CommitId, ai: usize, snaps: &BTreeSet<CommitId>) -> Result<BTreeSet<Dot>> {
    let mut out = BTreeSet::new();
    let Some(a) = h.aspects.get(ai) else { return Ok(out) };
    let mut own = None;
    for s in snaps {
        if let Some(ix) = copy_index(tx, s, &a.tid, &a.ak)? {
            out.extend(misstated_in(tx, &ix, h, id, ai, &mut own)?);
        }
    }
    Ok(out)
}

/// The dots under which a snapshot (indexed `ix`) carries copies of the writes of commit `id`'s
/// held delta `ai` (header `h`) otherwise than the delta holds them (spec/permissions.md §5.2:
/// another value, `ts` or position, a dot the delta does not use, a value-less copy of a delta
/// without expiry). `own`: the delta's writes, indexed a piece at a time on first need (only
/// when the snapshot copies one of its dots).
pub(crate) fn misstated_in(tx: &mut Tx<'_>, ix: &osis_crdt::CopyIndex, h: &Header, id: &CommitId, ai: usize, own: &mut Option<osis_crdt::CopySet>) -> Result<BTreeSet<Dot>> {
    let ranges = owned_ranges(h, id, ai);
    if !ix.any_in(&ranges) {
        return Ok(BTreeSet::new());
    }
    let lax = h.aspects.get(ai).is_some_and(|_| h.expires.is_some());
    Ok(ix.misstated(&ranges, held_copies(tx, id, ai, own)?, lax))
}

/// The writes of held commit `id`'s parts on aspect `ai`, indexed into `own` a piece at a time
/// unless it is already.
pub(crate) fn held_copies<'o>(tx: &mut Tx<'_>, id: &CommitId, ai: usize, own: &'o mut Option<osis_crdt::CopySet>) -> Result<&'o osis_crdt::CopySet> {
    if own.is_none() {
        let mut set = osis_crdt::CopySet::default();
        super::each_held_piece(tx, id, ai, &mut |_, f| {
            set.add(&f);
            Ok(())
        })?;
        *own = Some(set);
    }
    Ok(own.get_or_insert_default())
}

/// Whether the delta owning dot `d` on `(tid, ak)` expires: snapshots carry its writes
/// value-less (spec/crdt.md §4.7), no misstatement.
pub(crate) fn owner_expires(core: &Core, tid: &Tid, ak: &Ak, d: &Dot) -> bool {
    any_owner(core, tid, ak, d, &|_, m, ai| m.header.aspects.get(ai).is_some_and(|_| m.header.expires.is_some()))
}

/// The dots under which held snapshot `s` of `(tid, ak)` carries copies of held deltas' writes
/// otherwise than those deltas hold them (`misstated_in`).
pub(crate) fn misstated_by(tx: &mut Tx<'_>, s: &CommitId, tid: &Tid, ak: &Ak) -> Result<BTreeSet<Dot>> {
    let mut out = BTreeSet::new();
    let Some(ix) = copy_index(tx, s, tid, ak)? else { return Ok(out) };
    let owners = {
        let core = &*tx.core;
        let found = std::cell::RefCell::new(BTreeSet::new());
        for d in ix.dots() {
            any_owner(core, tid, ak, d, &|c, m, ai| {
                if m.holds(ai) && !core.ix.void.contains(c) {
                    found.borrow_mut().insert((*c, ai));
                }
                false
            });
        }
        found.into_inner()
    };
    for (c, ai) in owners {
        let Some(h) = tx.core.ix.commits.get(&c).map(|m| m.header.clone()) else { continue };
        out.extend(misstated_in(tx, &ix, &h, &c, ai, &mut None)?);
    }
    Ok(out)
}
