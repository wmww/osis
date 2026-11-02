//! Retention (spec/commits.md §5–§6; spec/crdt.md §4.7, §4.8, §8): deaths per body from the
//! crdt change summary, keep-at-most drops (in the killing transaction for at most 0 but for
//! bodies with a live write, which get `AT_MOST_GRACE` more, else by timer), expiry at T
//! (value-less, body dropped), purge requests judged by perm at the
//! request's time (also against deltas arriving later), compaction snapshots and the covered
//! test. node-sync judges what to delete at hosts and what to re-snapshot from the commit
//! index (dropped parts, `covered`), so no queue is kept here.
//!
//! A body here is one projection class of a commit (`body_class`): its deaths are kept per part,
//! read over the class, and a part drops with the rest of its class. The class depends on what is
//! held (`reader`), so nothing kept may be keyed by it.

use crate::engine::records::{self, Rd, Wr};
use crate::engine::write::{CommitPlan, Resolved, build_and_apply};
use crate::engine::{Core, Dropped, Engine, Owned, Tx};
use crate::error::{Error, Result};
use crate::events::{Cause, Event};
use osis_commit::{Decoded, Form, Header, Kind, PurgeItem};
use osis_base::{Ak, BlobId, CommitId, Tid, Ts};
use osis_crdt::{Fragment, Frontiers};
use osis_perm::{At, Point, PurgeBy};
use osis_schema::core_types::is_role_class;
use osis_store::Shred;
use std::collections::{BTreeMap, BTreeSet};

mod deaths;
#[cfg(test)]
mod oracle;
pub(crate) mod forget;
pub(crate) mod memory;
pub mod suspect;

pub(crate) use deaths::{any_bounded, load_deaths_due, mark_deaths_due, mark_if_bounded, note_copies, note_deaths, rejudge_deaths, settle_due};

/// A body a due timer drops with a live write: its commit and every aspect of it.
pub(crate) type LiveDrop = (CommitId, Vec<(Tid, Ak)>);

const T_EXPIRY: u8 = 1;
const T_AT_MOST: u8 = 2;

/// A non-`Derived` source's bytes (its length tells the kind).
fn source_bytes(src: &osis_crdt::Source) -> Vec<u8> {
    match src.kind() {
        osis_crdt::SourceKind::Node(t) => t.as_bytes().to_vec(),
        osis_crdt::SourceKind::Session(s) => s.to_bytes().to_vec(),
        osis_crdt::SourceKind::Commit(c) => c.0.to_vec(),
        osis_crdt::SourceKind::Derived(_) => Vec::new(),
    }
}

pub(crate) fn read_source(r: &mut Rd<'_>) -> Result<osis_crdt::Source> {
    Ok(match r.u8()? {
        15 => osis_crdt::Source::node(r.tid()?),
        31 => osis_crdt::Source::session(osis_crdt::Session::from_bytes(&r.arr()?)),
        32 => osis_crdt::Source::commit(CommitId(r.arr()?)),
        _ => return Err(crate::error::Error::Corrupt("owned source")),
    })
}

/// `src` (non-`Derived`) as its length and bytes.
pub(crate) fn write_source(w: Wr, src: &osis_crdt::Source) -> Wr {
    let b = source_bytes(src);
    w.u8(b.len() as u8).raw(&b)
}

pub(crate) fn encode_owned(v: &[Owned]) -> Vec<u8> {
    let mut w = Wr::new().u32(v.len() as u32);
    for o in v {
        w = match o {
            Owned::Range { src, lo, hi } => write_source(w.u8(0), src).u64(*lo).u64(*hi),
            Owned::Commit(c) => w.u8(1).raw(&c.0),
            Owned::Dots { src, ctrs } => {
                let mut w = write_source(w.u8(2), src).u32(ctrs.len() as u32);
                for c in ctrs {
                    w = w.u64(*c);
                }
                w
            }
        };
    }
    w.take()
}

pub(crate) fn decode_owned(b: &[u8]) -> Result<Vec<Owned>> {
    let mut r = Rd::new(b);
    let mut out = Vec::new();
    for _ in 0..r.u32()? {
        out.push(match r.u8()? {
            0 => Owned::Range { src: read_source(&mut r)?, lo: r.u64()?, hi: r.u64()? },
            1 => Owned::Commit(CommitId(r.arr()?)),
            _ => {
                let src = read_source(&mut r)?;
                let mut ctrs = Vec::new();
                for _ in 0..r.u32()? {
                    ctrs.push(r.u64()?);
                }
                Owned::Dots { src, ctrs }
            }
        });
    }
    r.end()?;
    Ok(out)
}

/// The aspect index of `(tid, ak)` in known commit `c`.
fn aspect_index(core: &Core, c: &CommitId, tid: &Tid, ak: &Ak) -> Option<usize> {
    core.ix.commits.get(c)?.aspect(tid, ak)
}

/// The aspect index of `(tid, ak)` in known commit `c` and its header (`UnknownCommit`: not
/// known with that aspect).
fn known_part(core: &Core, c: &CommitId, tid: &Tid, ak: &Ak) -> Result<(usize, crate::engine::LazyHeader)> {
    let m = core.ix.commits.get(c).ok_or(Error::UnknownCommit(*c))?;
    Ok((m.aspect(tid, ak).ok_or(Error::UnknownCommit(*c))?, m.header.clone()))
}

/// The known compaction snapshots of `(tid, ak)`, held, dropped or missing.
fn snapshots_of(core: &Core, tid: &Tid, ak: &Ak) -> Vec<CommitId> {
    core.ix.by_aspect.get(&(*tid, ak.clone())).into_iter().flatten().map(|x| x.1).filter(|s| core.ix.commits.get(s).is_some_and(|m| m.view.kind.is_compaction())).collect()
}

/// Drops held snapshot part `(s, sai)` if it carries a value of a write of `owned` (purged,
/// spec/commits.md §5).
fn drop_carrying(tx: &mut Tx<'_>, s: &CommitId, sai: usize, owned: &[Owned]) -> Result<()> {
    let mut carries = false;
    crate::apply::each_held_piece(tx, s, sai, &mut |_, f| {
        if !carries {
            let mut g = f.clone();
            g.strip(&|x| owned.iter().any(|o| o.owns(x)));
            carries = g != f;
        }
        Ok(())
    })?;
    if carries {
        return drop_part(tx, s, sai);
    }
    Ok(())
}

/// The actor whose readers a delta's thing has (spec/sync.md §3 entitlement): the thing if it
/// has secrets of its own, else its owner.
fn reader(core: &Core, tid: &Tid) -> Tid {
    if core.ix.own_keys.contains(tid) {
        return *tid;
    }
    match core.created(tid) {
        Some(osis_base::CreationRecord::Thing { owner, .. }) => *owner,
        _ => *tid,
    }
}

/// The body holding aspect `ai` of a commit (spec/commits.md §5: one projection class, readable
/// subset and retention class) and the aspects it holds. The ID (of the commit, not the class) keys
/// a part's death record with its aspect: a class moves as records and keys arrive (`reader`), a
/// death record must not.
pub(crate) fn body_class(core: &Core, h: &Header, c: &CommitId, ai: usize) -> (BlobId, Vec<usize>) {
    let key = |a: &osis_commit::AspectEntry| (reader(core, &a.tid), a.retention, a.expires, a.keys.clone());
    let Some(me) = h.aspects.get(ai) else { return (BlobId(c.0), vec![ai]) };
    let k = key(me);
    let holders: Vec<usize> = h.aspects.iter().enumerate().filter(|(_, a)| key(a) == k).map(|(i, _)| i).collect();
    let mut hs = osis_base::hash::Hasher::new();
    hs.update(&c.0);
    (BlobId(hs.finalize()), holders)
}

/// The ID of the body holding aspect `ai` of known commit `c` (`body_class`).
fn body_of(core: &Core, c: &CommitId, ai: usize) -> Option<BlobId> {
    let m = core.ix.commits.get(c)?;
    Some(body_class(core, &m.header, c, ai).0)
}

/// First and last death so far over the deltas of the body holding aspect `ai` of `c`.
fn deaths_of(tx: &mut Tx<'_>, h: &Header, c: &CommitId, ai: usize) -> Result<Option<(Ts, Ts)>> {
    let (body, holders) = body_class(tx.core, h, c, ai);
    class_deaths(tx, h, &body, &holders)
}

/// First and last death so far over a body's deltas.
fn class_deaths(tx: &mut Tx<'_>, h: &Header, body: &BlobId, holders: &[usize]) -> Result<Option<(Ts, Ts)>> {
    let mut out: Option<(Ts, Ts)> = None;
    for ai in holders {
        let Some(a) = h.aspects.get(*ai) else { continue };
        if let Some(d) = tx.txn.death(&a.tid, &a.ak, body)? {
            out = Some(match out {
                Some((f, l)) => (f.min(d.first), l.max(d.last)),
                None => (d.first, d.last),
            });
        }
    }
    Ok(out)
}

/// Whether deaths count for a delta's body: only a relative keep bound reads them (spec/commits.md
/// §5), so no other body gets death records.
pub(crate) fn bounded(a: &osis_commit::AspectEntry) -> bool {
    a.retention.at_least.rel.is_some() || a.retention.at_most.rel.is_some()
}

/// The aspect index of `(tid, ak)` in held commit `c`, if that part is held (`Meta::holds`: a
/// late part still to arrive is not).
pub(crate) fn held_part(core: &Core, c: &CommitId, tid: &Tid, ak: &Ak) -> Option<usize> {
    let m = core.ix.commits.get(c)?;
    m.aspect(tid, ak).filter(|ai| m.holds(*ai))
}

pub(crate) fn check_at_most(tx: &mut Tx<'_>, c: &CommitId, ai: usize) -> Result<()> {
    // a memory delta leaves only whole (expiry, supersession, purge: `memory::vanish`) or
    // covered, as on the old lane, which ignores keep bounds: dropped here its live writes would
    // stay in the state while `memory::forget_if_spent` forgets its header and expiry timer
    if tx.is_memory_commit(c) {
        return Ok(());
    }
    let Some(m) = tx.core.ix.commits.get(c).cloned() else { return Ok(()) };
    let Some(a) = m.header.aspects.get(ai) else { return Ok(()) };
    let (body, holders) = body_class(tx.core, &m.header, c, ai);
    // deaths awaiting a recompute may be early: the recompute judges the body (`settle_due`);
    // tests may keep every body (`Engine::keep_bodies`)
    if tx.core.keep_bodies || holders.iter().filter_map(|x| m.header.aspects.get(*x)).any(|x| tx.core.ix.deaths_due.contains(&(x.tid, x.ak.clone()))) {
        return Ok(());
    }
    let d = class_deaths(tx, &m.header, &body, &holders)?;
    let live = a.retention.at_most.rel.is_some() && d.is_some() && live(tx, c, ai)?;
    let keep = osis_commit::retention::body_keep(&m.header, &a.retention, d.map(|d| d.0.wall_ms().0), d.map(|d| d.1.wall_ms().0), live);
    if let Some(t) = keep.at_most {
        // at most 0: the replacing node drops a body with no live write in the killing
        // transaction, even when the killing `ts` is ahead of its clock; one with a live write
        // keeps to the next compaction or its bound (`body_keep`), so an edit erasing part of
        // it does not re-snapshot the aspect
        let zero = a.retention.at_most.rel == Some(0) && d.is_some() && !live;
        if t <= tx.now().0 || zero {
            for x in holders {
                drop_part(tx, c, x)?;
            }
        } else {
            tx.put_timer(t, c, ai, T_AT_MOST)?;
        }
    }
    Ok(())
}

/// Drops the delta of aspect `ai` of `c` from its body (spec/commits.md §5): the commit is kept
/// without it (same header), the body's death records for it shredded, the aspect's state
/// rewritten shredded with its undo buffer cleared (node-sync deletes it at hosts, judged
/// from the dropped parts).
pub(crate) fn drop_part(tx: &mut Tx<'_>, c: &CommitId, ai: usize) -> Result<()> {
    drop_part_as(tx, c, ai, false)
}

/// `drop_part`; `cover`: dropped as covered (compaction, `Dropped::as_cover`).
fn drop_part_as(tx: &mut Tx<'_>, c: &CommitId, ai: usize, cover: bool) -> Result<()> {
    tx.core.touch();
    let Some(mut m) = tx.core.ix.commits.get(c).cloned() else { return Ok(()) };
    let Some(a) = m.header.aspects.get(ai).cloned() else { return Ok(()) };
    if a.hashes.is_empty() || m.dropped.contains_key(&ai) {
        return Ok(());
    }
    let k = (a.tid, a.ak.clone());
    let snapshot = m.header.kind.is_compaction();
    // what a snapshot carried goes with its body: whether it was live is kept (`snapshot_live`)
    let live = snapshot && snapshot_live(tx, &m.header, c, &[ai])?;
    // the held valid snapshots covering it: their copies of its writes stay its writes
    let snaps: Vec<CommitId> = tx.core.ix.snapshots.get(&k).into_iter().flatten().map(|x| x.1).filter(|s| s != c).collect();
    let mut covered_by = BTreeSet::new();
    for s in snaps {
        if covered(tx, &s, c, &a.tid, &a.ak)? == Some(true) {
            covered_by.insert(s);
        }
    }
    let as_cover = cover && !covered_by.is_empty();
    // a snapshot dropped other than as covered keeps its frontiers and `Absorbed` (counters
    // and IDs): what it gave still counts as received while it is valid (spec/commits.md §5);
    // a covered one's coverers reach them
    let gives = if snapshot && !as_cover { tx.core.ix.snapshots.get(&k).and_then(|v| v.iter().find(|x| x.1 == *c)).map(|g| (g.2.clone(), g.3.clone())) } else { None };
    // a valid snapshot's misstated copies govern while it is held (spec/permissions.md §5.2):
    // dropped, the held deltas give those writes again
    let misstated = if snapshot && m.valid_at(ai) { crate::apply::validity::misstated_by(tx, c, &a.tid, &a.ak)? } else { BTreeSet::new() };
    let (role, overreach) = (tx.core.ix.rotation_role.get(&(*c, ai)).copied(), tx.core.ix.grant_overreach.contains(&(*c, ai)));
    // a role-class body whole: what keys noted from it (`keys::keysets_of`, `forget_dropped`)
    let role_bodies: Vec<Fragment> = if is_role_class(a.ak.as_str()) { crate::apply::held_fragments(tx, c, ai)? } else { Vec::new() };
    let keysets = crate::apply::keys::keysets_of(&m.header, ai, &role_bodies);
    // what of the state holds copies of the dropped deltas' writes, shredded a piece at a time
    // while the part is still stored (none held: the state alone)
    let held = crate::apply::each_held_piece(tx, c, ai, &mut |tx, f| {
        tx.shred_bodies(&a.tid, &a.ak, &[f])?;
        tx.evict_pages(&a.tid, &a.ak);
        Ok(())
    })?;
    if held.is_empty() {
        tx.shred_bodies(&a.tid, &a.ak, &[])?;
    }
    m.dropped.insert(ai, Dropped { covered_by, as_cover, live, gives, role, overreach, keysets });
    // a part missing (again, `uncover`) and dropped is dropped, as an open reads it: received,
    // so snapshots' copies of its writes are carried writes no more
    if m.missing.remove(&ai) {
        let h = m.header.clone();
        crate::apply::validity::uncarry(tx.core, c, &h, &|x| x == ai);
    }
    if let Some(blob) = tx.get_commit(c)? {
        let rest = osis_commit::rewrite(&blob, |x, _| x == ai);
        tx.put_commit(c, &rest, &m, Shred::Yes, None)?;
    }
    let (body, _) = body_class(tx.core, &m.header, c, ai);
    let header = m.header.clone();
    let vouched = snapshot && m.valid_at(ai);
    tx.core.ix.commits.insert(*c, m);
    crate::apply::note_gives(tx.core, c);
    crate::apply::forget_snapshot(tx.core, &a.tid, &a.ak, c);
    tx.core.forget_live(&a.tid, &a.ak);
    tx.txn.drop_body(&body, &[k])?;
    crate::apply::keys::forget_dropped(tx, &header, ai, &role_bodies)?;
    // a valid snapshot dropped vouches no more for invalid deltas' writes it carried
    // (spec/permissions.md §5.2)
    if vouched && !crate::apply::invalid_of(tx.core, &a.tid, &a.ak).is_empty() && crate::apply::unmerge_fell(tx, &a.tid, &a.ak, None)? {
        tx.core.mark_aspect_changed(&a.tid, &a.ak);
    }
    if !misstated.is_empty() {
        crate::apply::rebuild_without(tx, &a.tid, &a.ak, &Owned::dots(misstated))?;
        mark_deaths_due(tx, &a.tid, &a.ak)?;
        tx.core.mark_aspect_changed(&a.tid, &a.ak);
    }
    Ok(())
}

/// The snapshots that covered dropped part `ai` of `c` when it dropped, or covered such a
/// coverer dropped in turn, and so on (`Dropped::covered_by`).
pub(crate) fn coverers(core: &Core, c: &CommitId, ai: usize) -> Vec<CommitId> {
    let Some(a) = core.ix.commits.get(c).and_then(|m| m.view.aspects.get(ai)) else { return Vec::new() };
    let (tid, ak) = (a.tid, a.ak.clone());
    let direct = |x: &CommitId| -> Vec<CommitId> {
        let Some(m) = core.ix.commits.get(x) else { return Vec::new() };
        m.aspect(&tid, &ak).and_then(|xai| m.dropped.get(&xai)).map(|d| d.covered_by.iter().copied().collect()).unwrap_or_default()
    };
    let mut seen = BTreeSet::new();
    let mut out = Vec::new();
    let mut todo = direct(c);
    while let Some(x) = todo.pop() {
        out.push(x);
        if seen.insert(x) {
            todo.extend(direct(&x));
        }
    }
    out
}

/// Whether `f` holds for one of the `coverers` of dropped part `ai` of `c`.
pub(crate) fn any_coverer(core: &Core, c: &CommitId, ai: usize, f: &dyn Fn(&CommitId) -> bool) -> bool {
    coverers(core, c, ai).iter().any(f)
}

/// Parts on `(tid, ak)` dropped as covered that no coverer carries any more (`any_coverer`: each
/// turned invalid, or was itself dropped as covered; one dropped for its bound, expiry or a
/// purge carries while valid, its writes staying in the state) are missing again
/// (spec/permissions.md §5.2): they give nothing, as at a node that never held them, until the
/// body arrives again (a node still holding it finds it uncovered and re-uploads it,
/// spec/sync.md §6; node-sync fetches it again, `Changed::undropped`). Returns the own writes of
/// the deltas among them, for the caller's rebuild to strip.
pub(crate) fn uncover(tx: &mut Tx<'_>, tid: &Tid, ak: &Ak) -> Result<Vec<Owned>> {
    let core = &*tx.core;
    let carries = |s: &CommitId| {
        let Some(m) = core.ix.commits.get(s) else { return false };
        let Some(ai) = m.aspect(tid, ak) else { return false };
        let valid = m.valid_at(ai);
        match m.dropped.get(&ai) {
            None => valid && !m.missing.contains(&ai),
            Some(d) => valid && !d.as_cover,
        }
    };
    let mut lost = Vec::new();
    for (_, c) in core.ix.by_aspect.get(&(*tid, ak.clone())).into_iter().flatten() {
        let Some(m) = core.ix.commits.get(c) else { continue };
        let Some(ai) = m.aspect(tid, ak) else { continue };
        if m.dropped.get(&ai).is_some_and(|d| d.as_cover) && !any_coverer(core, c, ai, &carries) {
            lost.push((*c, ai));
        }
    }
    let mut owned = Vec::new();
    let any = !lost.is_empty();
    if any {
        tx.core.forget_live(tid, ak);
        // until each comes back, this node may read less than one that kept it
        suspect::raise(tx, tid, ak, suspect::Why::Uncovered)?;
    }
    for (c, ai) in lost {
        // dropped as covered: no frontiers kept (`Dropped::gives`), nothing in `dropped_snapshots`;
        // the epochs it introduced or held go too (`keys::rebuild_keysets` below)
        let Some(m) = reopen(tx, &c, ai)? else { continue };
        // its residue, if it went value-less while dropped, came from its coverers' copies
        // (`make_valueless`) and goes with them. Invariant: a part dropped as covered has a
        // residue only while some coverer carries it; missing, it gives nothing (a late copy
        // joins and rebuilds the residue from its body, `on_late`).
        if let Some(a) = m.view.aspects.get(ai) {
            let key = records::residue_key(&a.tid, &a.ak, &c, ai);
            tx.txn.remove_local(&key, Shred::Yes)?;
        }
        if m.view.kind.has_own_writes() {
            owned.extend(Owned::of_view(&m.view, &c, ai));
        }
        if let Some(ch) = &mut tx.core.changed {
            ch.undropped.insert(c);
        }
    }
    if any && ak.as_str() == "keys.0" {
        crate::apply::keys::rebuild_keysets(tx, &BTreeSet::from([*tid]))?;
    }
    // held snapshots' copies of the writes of deltas now never received are carried writes
    if !owned.is_empty() {
        for s in snapshots_of(tx.core, tid, ak) {
            let Some(sai) = aspect_index(tx.core, &s, tid, ak) else { continue };
            let mut carried: BTreeMap<osis_crdt::Source, BTreeSet<u64>> = BTreeMap::new();
            let held = crate::apply::each_held_piece(tx, &s, sai, &mut |tx, f| {
                for (src, ctrs) in crate::apply::validity::carried_of(tx.core, tid, ak, &f) {
                    carried.entry(src).or_default().extend(ctrs);
                }
                Ok(())
            })?;
            if !held.is_empty() {
                crate::apply::validity::note_carried_of(tx.core, tid, ak, &s, carried);
            }
        }
    }
    Ok(owned)
}

/// Makes dropped part `ai` of `c` missing, as at a node that never received it: what its body
/// judged or gave goes too (`Dropped::role`; the header's one-delta rule for `secrets.0` stays,
/// `validity::note_required`). Its meta after.
fn reopen(tx: &mut Tx<'_>, c: &CommitId, ai: usize) -> Result<Option<crate::engine::Meta>> {
    tx.core.touch();
    let Some(mut m) = tx.core.ix.commits.get(c).cloned() else { return Ok(None) };
    // a snapshot dropped for its keep bounds gives what it gave no more (`Dropped::gives`)
    if m.dropped.remove(&ai).is_some_and(|d| d.gives.is_some())
        && let Some(a) = m.view.aspects.get(ai)
    {
        tx.core.ix.dropped_snapshots.remove(&(a.tid, a.ak.clone()), c);
    }
    m.missing.insert(ai);
    tx.core.ix.rotation_role.remove(&(*c, ai));
    let several = m.header.aspects.get(ai).is_some_and(|a| a.ak.as_str() == "secrets.0" && a.hashes.len() != 1);
    if !several {
        tx.core.ix.grant_overreach.remove(&(*c, ai));
    }
    // those are inputs of its judgment (`validity::rejudge_all` judges it again)
    tx.core.stale_commits.insert(*c);
    if let Some(blob) = tx.get_commit(c)? {
        tx.put_commit(c, &blob, &m, Shred::No, None)?;
    }
    tx.core.ix.commits.insert(*c, m.clone());
    Ok(Some(m))
}

/// Whether a late copy of dropped part `ai` of `c` joins. A body dropped for its keep bounds (or
/// as its writes died, or for carrying purged values) counts as never received (spec/commits.md
/// §5): its copy joins and is judged again (`on_late`: dropped at once if dead past its bound,
/// expired or purged; held if a validity flip made its write live again), so nodes holding the
/// same bodies read alike. One held value-less (spec/crdt.md §4.7: a copy arriving after T or
/// the purge is stripped and joined) joins only if none of its writes were kept, as when it was
/// missing at expiry or purge (no residue); `on_late` drops it again, keeping its residue. One
/// dropped as covered joins only once no cover carries it (`uncover` makes it missing). A memory
/// part vanished whole and stays gone (`memory::forget_if_spent` forgets a spent commit).
pub(crate) fn takes_late(tx: &mut Tx<'_>, c: &CommitId, ai: usize) -> Result<bool> {
    let Some(m) = tx.core.ix.commits.get(c) else { return Ok(false) };
    let (Some(d), Some(a)) = (m.dropped.get(&ai), m.header.aspects.get(ai)) else { return Ok(false) };
    if d.as_cover || m.view.memory {
        return Ok(false);
    }
    if !valueless(tx.core, c, ai) {
        return Ok(true);
    }
    let key = records::residue_key(&a.tid, &a.ak, c, ai);
    Ok(tx.txn.get_local(&key)?.is_none())
}

/// Whether delta `ai` of `c` is held value-less (`make_valueless`): its body is dropped.
fn valueless(core: &Core, c: &CommitId, ai: usize) -> bool {
    let Some(m) = core.ix.commits.get(c) else { return false };
    let (Some(a), Some(o)) = (m.header.aspects.get(ai), Owned::of(&m.header, c, ai)) else { return false };
    m.header.kind.has_own_writes() && core.ix.valueless.get(&(a.tid, a.ak.clone())).is_some_and(|v| v.contains(&o))
}

/// Reopens the dropped parts among `ais` of `c` (`takes_late`) for their late copies to join.
pub(crate) fn reopen_late(tx: &mut Tx<'_>, c: &CommitId, ais: &BTreeSet<usize>) -> Result<()> {
    for ai in ais {
        if tx.core.ix.commits.get(c).is_some_and(|m| m.dropped.contains_key(ai)) {
            reopen(tx, c, *ai)?;
        }
    }
    Ok(())
}

/// Holds the value-carrying writes of a delta value-less from now on (spec/crdt.md §4.7), and
/// keeps its writes as a residue: from its body, or for a body dropped as covered from its held
/// valid coverers' copies. A part dropped otherwise or still missing has none (`takes_late`).
fn make_valueless(tx: &mut Tx<'_>, c: &CommitId, ai: usize) -> Result<Option<(Tid, Ak)>> {
    tx.core.touch();
    let Some(m) = tx.core.ix.commits.get(c).cloned() else { return Ok(None) };
    let Some(a) = m.header.aspects.get(ai) else { return Ok(None) };
    let Some(o) = Owned::of(&m.header, c, ai).filter(|_| m.header.kind.has_own_writes()) else { return Ok(None) };
    let k = (a.tid, a.ak.clone());
    let list = tx.core.ix.valueless.entry_or_default(k.clone());
    // sorted: what the node holds, not the order it learned it in
    if let Err(i) = list.binary_search(&o) {
        list.insert(i, o.clone());
    }
    let enc = encode_owned(list);
    tx.put_aspect_local(records::VALUELESS, &a.tid, &a.ak, &enc)?;
    // the delta's writes lie where it touched the state (a page of a paged state): per piece of
    // its body, stripped there (stripping commutes with join, spec/crdt.md §4.7) and its residue
    // joined
    #[cfg(test)]
    let whole = oracle::residue(tx, &m, c, ai, &o)?;
    let mut residue: Option<Fragment> = None;
    let mut strip = |tx: &mut Tx<'_>, f: Fragment| -> Result<()> {
        let mut r = f.clone();
        r.strip(&|d| o.owns(d));
        residue.get_or_insert_default().join(r);
        tx.strip_bodies(&a.tid, &a.ak, &[f], &o)?;
        tx.evict_pages(&a.tid, &a.ak);
        Ok(())
    };
    let held = crate::apply::each_held_piece(tx, c, ai, &mut strip)?;
    if held.is_empty() && m.dropped.get(&ai).is_some_and(|d| d.as_cover) {
        // a covered body's live writes are in its coverers (a purge drops them next)
        for s in coverers(tx.core, c, ai) {
            let Some(sai) = held_part(tx.core, &s, &a.tid, &a.ak) else { continue };
            if !crate::apply::validity::snapshot_valid(tx.core, &s, &a.tid, &a.ak) {
                continue;
            }
            crate::apply::each_held_piece(tx, &s, sai, &mut |tx, mut f| {
                f.remove_writes(&|d| !o.owns(d));
                strip(tx, f)
            })?;
        }
    }
    // its residue outlives the body: in the state a later write may supersede it, and when that
    // write is un-merged the residue must supersede again (`apply::atomic::rebuilt`); kept even
    // empty, so a late copy is not taken again (`takes_late`). No body: the state alone.
    #[cfg(test)]
    assert_eq!(residue.as_ref().map(crate::engine::state::encode).transpose()?, whole.as_ref().map(crate::engine::state::encode).transpose()?, "make_valueless residue streamed vs whole");
    if residue.is_none() {
        tx.strip_bodies(&a.tid, &a.ak, &[], &o)?;
    }
    if let Some(residue) = residue {
        let memory = tx.txn.is_memory_aspect(&a.tid, &a.ak);
        let (key, enc) = (records::residue_key(&a.tid, &a.ak, c, ai), crate::engine::state::encode(&residue)?);
        tx.in_class(memory, |tx| Ok(tx.txn.put_local(&key, &enc, Shred::No)?))?;
    }
    Ok(Some(k))
}

/// Holds delta `ai` of `c` value-less (`make_valueless`) and drops its body: at expiry, or
/// purged. A memory delta vanishes whole instead (`memory::vanish`).
fn expire(tx: &mut Tx<'_>, c: &CommitId, ai: usize, changed: &mut BTreeSet<(Tid, Ak)>) -> Result<()> {
    strip_pending(tx, c, ai)?;
    if !tx.core.ix.commits.contains_key(c) {
        return Ok(());
    }
    if tx.is_memory_commit(c) {
        changed.extend(memory::vanish(tx, c, ai)?);
        // what is left of it may be superseded whole now (spec/sync.md §9); its caller forgets it
        changed.extend(memory::superseded_rest(tx, c)?);
        return Ok(());
    }
    if let Some(k) = make_valueless(tx, c, ai)? {
        changed.insert(k);
    }
    drop_part(tx, c, ai)
}

/// Parts of commit `id` held pending (stored as `blob`, header `h`) whose expiry has passed count
/// as never received (spec/commits.md §5: no copy past T): they leave the stored copy before it
/// is kept, and their aspects are flagged suspect (`suspect`: their non-value writes never join
/// here, where a node that applied them before T keeps them). The others get a timer doing the
/// same at T (`expire`). A header whose aspects are not resolved yet is timed once they are. The
/// commit's other parts apply when they would have with the part held: a commit left with no
/// part waits for its things like one with a held part (`apply::examine`).
pub(crate) fn pending_expiry(tx: &mut Tx<'_>, id: &CommitId, blob: &mut osis_commit::CommitBlob, h: &Header) -> Result<()> {
    let now = tx.now().0;
    let ais: BTreeSet<usize> = blob.parts.iter().map(|p| p.ai).collect();
    for ai in ais {
        let Some(a) = h.aspects.get(ai) else { continue };
        let Some(t) = a.expires else { continue };
        if t <= now {
            blob.parts.retain(|p| p.ai != ai);
            strip_pending(tx, id, ai)?;
            suspect::raise(tx, &a.tid, &a.ak, suspect::Why::PendingExpiry)?;
        } else {
            tx.put_timer(t, id, ai, T_EXPIRY)?;
        }
    }
    Ok(())
}

/// Part `ai` of the stored pending copy of `c`, if any, goes at its expiry (`pending_expiry`).
fn strip_pending(tx: &mut Tx<'_>, c: &CommitId, ai: usize) -> Result<()> {
    if !tx.core.ix.pending.contains_key(c) {
        return Ok(());
    }
    let Some((osis_store::PendingKind::Pending, bytes)) = tx.txn.get_pending(c)? else { return Ok(()) };
    let Ok(mut blob) = osis_commit::CommitBlob::decode(&bytes) else { return Ok(()) };
    let n = blob.parts.len();
    blob.parts.retain(|p| p.ai != ai);
    if blob.parts.len() == n {
        return Ok(());
    }
    tx.core.touch();
    tx.txn.remove_pending(c, Shred::Yes)?;
    tx.txn.put_pending(c, osis_store::PendingKind::Pending, &blob.encode())?;
    // examined again: what it waits for may have changed
    tx.core.waits.pended(c);
    if let Some(a) = blob.header.aspects.get(ai) {
        suspect::raise(tx, &a.tid, &a.ak, suspect::Why::PendingExpiry)?;
    }
    Ok(())
}

/// The retentions standing for the writes snapshot state `st` of `(tid, ak)` carries live
/// (spec/commits.md §5): each write's own delta (spec/permissions.md §5.2: the node-form delta
/// whose counter range holds it, the commit-form commit it names, the imports listing that commit
/// as an origin); for writes whose own delta's header is not held, the held snapshot bodies of
/// the aspect carrying them, and for any of those none carries, every snapshot of the aspect
/// applied here. Cost: a lookup and a header per live write; the aspect's headers (and its held
/// snapshot bodies) only when some write's own commit is not found directly.
fn own_retentions(tx: &mut Tx<'_>, tid: &Tid, ak: &Ak, st: &Fragment) -> Result<Vec<osis_schema::Retention>> {
    if osis_commit::retention::fixed_retention(ak.as_str()).is_some() {
        return Ok(Vec::new());
    }
    let entry = |h: &Header| h.aspects.iter().find(|a| a.tid == *tid && a.ak == *ak).map(|a| a.retention);
    let mut own: BTreeSet<CommitId> = BTreeSet::new();
    let mut out = Vec::new();
    // live writes whose own commit is not a held commit with its own writes on the aspect, with
    // the commit their dot names (an import's origin), if any
    let mut rest: Vec<(osis_crdt::Dot, Option<CommitId>)> = Vec::new();
    for (d, _) in st.live_writes() {
        let c = tx.core.commit_of(tid, ak, &d);
        let found = c.and_then(|c| {
            let h = &tx.core.ix.commits.get(&c)?.header;
            (!h.kind.is_compaction() && h.kind != Kind::Import).then_some(())?;
            entry(h)
        });
        match (found, c) {
            (Some(r), Some(c)) => {
                if own.insert(c) {
                    out.push(r);
                }
            }
            _ => rest.push((d, c)),
        }
    }
    if rest.is_empty() {
        return Ok(out);
    }
    let commits: Vec<CommitId> = tx.core.ix.by_aspect.get(&(*tid, ak.clone())).into_iter().flatten().map(|(_, c)| *c).collect();
    let mut imports: std::collections::BTreeMap<CommitId, Vec<osis_schema::Retention>> = Default::default();
    let mut snapshots = Vec::new();
    for c in &commits {
        let Some(h) = tx.core.ix.commits.get(c).map(|m| &m.header) else { continue };
        let Some(r) = entry(h) else { continue };
        if h.kind == Kind::Import {
            for o in &h.origins {
                imports.entry(o.commit).or_default().push(r);
            }
        } else if h.kind.is_compaction() {
            snapshots.push((*c, r));
        }
    }
    let mut unknown: BTreeSet<osis_crdt::Dot> = BTreeSet::new();
    for (d, c) in rest {
        match c.and_then(|c| imports.get(&c)) {
            Some(rs) => out.extend(rs.iter().copied()),
            None => _ = unknown.insert(d),
        }
    }
    if unknown.is_empty() {
        return Ok(out);
    }
    let mut carried = BTreeSet::new();
    for (c, r) in &snapshots {
        let Some(ai) = aspect_index(tx.core, c, tid, ak) else { continue };
        let mut carries = false;
        crate::apply::each_held_piece(tx, c, ai, &mut |_, f| {
            for (d, _) in f.live_writes() {
                if unknown.contains(&d) {
                    carries = true;
                    carried.insert(d);
                }
            }
            Ok(())
        })?;
        if carries {
            out.push(*r);
        }
    }
    if carried.len() < unknown.len() {
        out.extend(snapshots.iter().map(|x| x.1));
    }
    Ok(out)
}

fn purge_by(p: osis_schema::PurgeBy) -> PurgeBy {
    PurgeBy::from_code(p as u64).unwrap_or(PurgeBy::Nobody)
}

/// Does purge item `item` of commit `pc` (header `p`) name aspect `ai` of commit `c` (header
/// `ch`), with its author holding the right at the request's time (spec/permissions.md §8)?
fn purge_allowed(core: &Core, p: &Header, pc: &CommitId, item: &PurgeItem, ch: &Header, c: &CommitId, ai: usize) -> bool {
    let Some(a) = ch.aspects.get(ai) else { return false };
    if is_role_class(a.ak.as_str()) || a.tid != *item.tid() || a.ak != *item.ak() {
        return false;
    }
    let names = match item {
        PurgeItem::Commit { commit, .. } => commit == c,
        PurgeItem::Aspect { .. } => ch.ts < p.ts,
    };
    if !names {
        return false;
    }
    let point = Point { ts: p.ts, node: p.author, commit: *pc };
    let actor = match ch.kind {
        Kind::Import => ch.origins.first().map_or(ch.actor, |o| o.actor),
        _ => ch.actor,
    };
    core.timelines.get(&a.tid).is_some_and(|tl| tl.may_purge(&p.author, &a.tid, purge_by(a.retention.by), &actor, At::before(point)))
}

fn purge_requests(tx: &mut Tx<'_>, tid: &Tid, ak: &Ak) -> Result<Vec<CommitId>> {
    let mut out = Vec::new();
    if let Some(b) = tx.txn.get_local(&records::aspect_key(records::PURGES, tid, ak))? {
        let mut r = Rd::new(&b);
        while !r.is_empty() {
            out.push(CommitId(r.arr()?));
        }
    }
    Ok(out)
}

/// Is aspect `ai` of commit `c` (not applied yet) already purged by a held request? Such a
/// missing delta counts as held (spec/commits.md §4).
pub(crate) fn known_purged(tx: &mut Tx<'_>, ch: &Header, c: &CommitId, ai: usize) -> Result<bool> {
    let Some(a) = ch.aspects.get(ai) else { return Ok(false) };
    for pc in purge_requests(tx, &a.tid, &a.ak)? {
        let Some(p) = tx.core.ix.commits.get(&pc).map(|m| m.header.clone()) else { continue };
        if p.purge.iter().any(|item| purge_allowed(tx.core, &p, &pc, item, ch, c, ai)) {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Applies purge item `item` of commit `pc` to held delta `(c, ai)` if it may: its values go
/// value-less, its body and every snapshot body carrying them drop (node-sync re-snapshots
/// where no covering snapshot is left, spec/commits.md §5).
fn purge_one(tx: &mut Tx<'_>, pc: &CommitId, item: &PurgeItem, c: &CommitId, ai: usize, changed: &mut BTreeSet<(Tid, Ak)>) -> Result<()> {
    let (Some(p), Some(m)) = (tx.core.ix.commits.get(pc).cloned(), tx.core.ix.commits.get(c).cloned()) else { return Ok(()) };
    if !purge_allowed(tx.core, &p.header, pc, item, &m.header, c, ai) {
        return Ok(());
    }
    let Some(a) = m.header.aspects.get(ai).cloned() else { return Ok(()) };
    expire(tx, c, ai, changed)?;
    // snapshots carrying the purged values (spec/commits.md §5)
    if let Some(o) = Owned::of(&m.header, c, ai) {
        for s in snapshots_of(tx.core, &a.tid, &a.ak) {
            if let Some(sai) = aspect_index(tx.core, &s, &a.tid, &a.ak) {
                drop_carrying(tx, &s, sai, std::slice::from_ref(&o))?;
            }
        }
    }
    Ok(())
}

/// Drops held snapshot part `(s, sai)` if it carries a value of a delta a held purge request
/// purges (spec/commits.md §5): `purge_one` judges the snapshots held when the request or the
/// named delta arrives; this one a snapshot part arriving after both.
pub(crate) fn drop_purged_snapshot(tx: &mut Tx<'_>, s: &CommitId, sai: usize) -> Result<()> {
    // runs for every applied delta: the kind first, nothing cloned
    let Some(sm) = tx.core.ix.commits.get(s) else { return Ok(()) };
    if !sm.header.kind.is_compaction() {
        return Ok(());
    }
    let Some((tid, ak)) = sm.header.aspects.get(sai).map(|a| (a.tid, a.ak.clone())) else { return Ok(()) };
    let mut owned = Vec::new();
    for pc in purge_requests(tx, &tid, &ak)? {
        let Some(p) = tx.core.ix.commits.get(&pc).map(|m| m.header.clone()) else { continue };
        for item in &p.purge {
            let named: Vec<CommitId> = match item {
                PurgeItem::Commit { commit, .. } => vec![*commit],
                PurgeItem::Aspect { .. } => tx.core.ix.by_aspect.get(&(tid, ak.clone())).into_iter().flatten().map(|x| x.1).collect(),
            };
            for c in named.into_iter().filter(|c| c != s) {
                let (Some(m), Some(ai)) = (tx.core.ix.commits.get(&c).cloned(), aspect_index(tx.core, &c, &tid, &ak)) else { continue };
                if purge_allowed(tx.core, &p, &pc, item, &m.header, &c, ai)
                    && let Some(o) = Owned::of(&m.header, &c, ai)
                {
                    owned.push(o);
                }
            }
        }
    }
    if owned.is_empty() {
        return Ok(());
    }
    drop_carrying(tx, s, sai, &owned)
}

/// After a commit applied: its expiry (now or by timer), its purge request against held
/// deltas, and earlier purge requests against its deltas.
pub(crate) fn on_apply(tx: &mut Tx<'_>, id: &CommitId, changed: &mut BTreeSet<(Tid, Ak)>) -> Result<()> {
    let Some(h) = tx.core.ix.commits.get(id).map(|m| m.header.clone()) else { return Ok(()) };
    let mut purged = BTreeSet::new();
    on_parts(tx, id, &h, &(0..h.aspects.len()).collect(), &mut purged)?;
    if h.ephemeral.is_some() {
        let aspects = h.aspects.iter().map(|a| (a.tid, a.ak.clone())).collect();
        changed.extend(memory::drop_superseded(tx, &aspects, Some(h.author), Some(id))?);
        memory::drop_covered(tx, &aspects, Some(id))?;
    }
    for item in &h.purge {
        let held: Vec<CommitId> = tx.core.ix.by_aspect.get(&(*item.tid(), item.ak().clone())).map(|s| s.iter().map(|x| x.1).collect()).unwrap_or_default();
        for c in held {
            if let Some(ai) = aspect_index(tx.core, &c, item.tid(), item.ak()) {
                purge_one(tx, id, item, &c, ai, &mut purged)?;
            }
        }
        let key = records::aspect_key(records::PURGES, item.tid(), item.ak());
        let mut b = tx.txn.get_local(&key)?.unwrap_or_default();
        if !b.chunks(32).any(|x| x == id.0) {
            b.extend_from_slice(&id.0);
            tx.txn.put_local(&key, &b, Shred::No)?;
            tx.core.waits.wake(item.tid(), item.ak());
        }
    }
    purged_changed(tx, purged, changed);
    Ok(())
}

/// After late parts `ais` of applied commit `id` joined: `on_apply` for them. One held
/// value-less (reopened by `takes_late`, or missing again after `uncover`) drops again, now
/// keeping its residue, even if the purge that made it so is no longer judged allowed.
pub(crate) fn on_late(tx: &mut Tx<'_>, id: &CommitId, ais: &BTreeSet<usize>, changed: &mut BTreeSet<(Tid, Ak)>) -> Result<()> {
    let Some(h) = tx.core.ix.commits.get(id).map(|m| m.header.clone()) else { return Ok(()) };
    let mut purged = BTreeSet::new();
    on_parts(tx, id, &h, ais, &mut purged)?;
    if h.ephemeral.is_some() {
        let aspects = ais.iter().filter_map(|ai| h.aspects.get(*ai)).map(|a| (a.tid, a.ak.clone())).collect();
        changed.extend(memory::drop_superseded(tx, &aspects, Some(h.author), Some(id))?);
        memory::drop_covered(tx, &aspects, Some(id))?;
    }
    for ai in ais.iter().copied() {
        if valueless(tx.core, id, ai) && tx.core.ix.commits.get(id).is_some_and(|m| !m.dropped.contains_key(&ai)) {
            expire(tx, id, ai, &mut purged)?;
        }
    }
    // a body dropped for its keep bounds and joined again: its bound judged again (deaths the
    // join met are noted by it, `note_deaths`; a bound passed with a live write drops it too)
    for ai in ais.iter().copied() {
        if tx.core.ix.commits.get(id).is_some_and(|m| m.holds(ai)) {
            check_at_most(tx, id, ai)?;
        }
    }
    purged_changed(tx, purged, changed);
    Ok(())
}

/// Parts `ais` of applied commit `id`: expiry (now or by timer), held purge requests naming
/// them, held snapshots' parts carrying purged values.
fn on_parts(tx: &mut Tx<'_>, id: &CommitId, h: &Header, ais: &BTreeSet<usize>, purged: &mut BTreeSet<(Tid, Ak)>) -> Result<()> {
    for ai in ais.iter().copied() {
        let Some(a) = h.aspects.get(ai) else { continue };
        if let Some(t) = a.expires {
            if t <= tx.now().0 {
                expire(tx, id, ai, purged)?;
            } else {
                tx.put_timer(t, id, ai, T_EXPIRY)?;
            }
        }
        // purge requests held before this delta arrived
        for pc in purge_requests(tx, &a.tid, &a.ak)? {
            let items: Vec<PurgeItem> = tx.core.ix.commits.get(&pc).map(|p| p.header.purge.clone()).unwrap_or_default();
            for item in items {
                purge_one(tx, &pc, &item, id, ai, purged)?;
            }
        }
        drop_purged_snapshot(tx, id, ai)?;
    }
    Ok(())
}

fn purged_changed(tx: &mut Tx<'_>, purged: BTreeSet<(Tid, Ak)>, changed: &mut BTreeSet<(Tid, Ak)>) {
    for (t, a) in &purged {
        tx.core.mark_aspect_changed(t, a);
    }
    if !purged.is_empty() {
        tx.core.events.queue(Event::Changed { cause: Cause::Purge, changed: purged.iter().cloned().collect() });
        changed.extend(purged);
    }
}

/// A due timer: its store key, commit, aspect index and kind (`T_EXPIRY`, `T_AT_MOST`).
type Due = (Vec<u8>, CommitId, usize, u8);

/// The timers due by the corrected clock, and when the first of the others is (`u64::MAX`: none).
fn due_timers(tx: &mut Tx<'_>) -> Result<(Vec<Due>, u64)> {
    let now = tx.now().0;
    let mut due = Vec::new();
    let mut next = u64::MAX;
    tx.scan(records::TIMER, |k, v| {
        let (t, c, ai) = records::parse_timer(k)?;
        if t <= now {
            due.push((k.to_vec(), c, ai, v.first().copied().unwrap_or(0)));
        } else {
            next = next.min(t);
        }
        Ok(())
    })?;
    Ok((due, next))
}

impl Engine {
    /// Batches deaths recomputes (spec/crdt.md §4.8): while on, a validity flip or an un-merge
    /// marks its aspect and the recompute waits for the next read of deaths or bounds, so a
    /// node-sync step costs one recompute per aspect; off settles what waits. node-sync turns
    /// it on for each step.
    pub fn defer_deaths(&mut self, on: bool) -> Result<()> {
        self.core.defer_deaths = on;
        if on { Ok(()) } else { self.settle_deaths() }
    }

    /// Recomputes the deaths of the aspects marked by `mark_deaths_due`, in one transaction:
    /// every transaction ends with it unless `Core::defer_deaths` (node-sync's steps), and every
    /// read of deaths or bounds runs it first.
    pub fn settle_deaths(&mut self) -> Result<()> {
        if self.core.ix.deaths_due.is_empty() {
            return Ok(());
        }
        self.run(settle_due)
    }

    /// Runs what is due by the corrected clock: expiries, keep-at-most drops, and commits
    /// parked for drift. The commits whose timers fired are marked changed (`Core::changed`).
    pub fn tick(&mut self) -> Result<()> {
        self.settle_deaths()?;
        let r = self.run(|tx| {
            let mut changed = BTreeSet::new();
            let (due, next) = due_timers(tx)?;
            // the timers these put lower it again
            tx.core.timer_floor = next;
            for (k, c, ai, kind) in due {
                // a memory commit's timer is memory work: what it writes stays in memory
                let memory = tx.is_memory_commit(&c);
                let mut ch = BTreeSet::new();
                tx.in_class(memory, |tx| {
                    // judged again by node-sync whatever the timer did
                    tx.core.mark_changed(c);
                    tx.txn.remove_local(&[records::TIMER, &k].concat(), Shred::No)?;
                    match kind {
                        T_EXPIRY => expire(tx, &c, ai, &mut ch)?,
                        // judged again: liveness may have changed since the timer was set
                        _ => check_at_most(tx, &c, ai)?,
                    }
                    memory::forget_if_spent(tx, &c)?;
                    for (t, a) in &ch {
                        tx.core.mark_aspect_changed(t, a);
                    }
                    Ok(())
                })?;
                changed.extend(ch);
            }
            if !changed.is_empty() {
                tx.core.events.queue(Event::Changed { cause: Cause::Expiry, changed: changed.into_iter().collect() });
            }
            Ok(())
        });
        if r.is_err() {
            // the timers stay: due again
            self.core.timer_floor = 0;
        }
        r?;
        self.reexamine()
    }

    /// The bodies the due keep-at-most timers will drop with a live write, as (commit, every
    /// aspect of the body): a node that may write them snapshots them first (spec/commits.md
    /// §5).
    pub fn due_live_drops(&mut self) -> Result<Vec<LiveDrop>> {
        let due = self.run(|tx| {
            let mut out = Vec::new();
            for (_, c, ai, _) in due_timers(tx)?.0.into_iter().filter(|x| x.3 == T_AT_MOST) {
                let Some(h) = tx.core.ix.commits.get(&c).map(|m| m.header.clone()) else { continue };
                let (_, holders) = body_class(tx.core, &h, &c, ai);
                let aspects: Vec<(Tid, Ak)> = holders.iter().filter_map(|x| h.aspects.get(*x)).map(|a| (a.tid, a.ak.clone())).collect();
                out.push((c, aspects));
            }
            Ok(out)
        })?;
        let mut out = Vec::new();
        for (c, aspects) in due {
            let Some((t, a)) = aspects.first().cloned() else { continue };
            if self.body_not_dropped(&c, &t, &a) && self.body_keep(&c, &t, &a)?.at_most.is_some_and(|b| b <= self.now().0) && self.body_live(&c, &t, &a)? {
                out.push((c, aspects));
            }
        }
        Ok(out)
    }

    /// Whether an expiry or keep-at-most timer, durable or ephemeral, is due by the corrected
    /// clock: in memory, no store read (a timer removed without running may leave a false
    /// `true`, which the next `tick` clears).
    pub fn timers_due(&self) -> bool {
        let now = self.now().0;
        self.core.timer_floor <= now || self.next_ephemeral_timer().is_some_and(|t| t <= now)
    }

    /// When the next expiry or keep-at-most timer is due (corrected wall ms).
    pub fn next_timer(&mut self) -> Result<Option<u64>> {
        self.run(|tx| {
            let first = tx.txn.scan_local(records::TIMER, &[], 1)?;
            Ok(first.first().and_then(|(k, _)| k.get(records::TIMER.len()..)).and_then(|k| records::parse_timer(k).ok()).map(|(t, _, _)| t))
        })
    }

    /// When the next pending commit's missing delta counts as held by the clock (corrected wall
    /// ms): a tick then applies it.
    pub fn next_wait_due(&self) -> Option<u64> {
        self.core.waits.next_due()
    }

    /// Drops a body (compaction between the bounds, executed by node-sync): aspect `ak` of
    /// commit `c`.
    pub fn drop_body(&mut self, c: &CommitId, tid: &Tid, ak: &Ak) -> Result<()> {
        let (c, tid, ak) = (*c, *tid, ak.clone());
        self.run(|tx| {
            let ai = aspect_index(tx.core, &c, &tid, &ak).ok_or(Error::UnknownCommit(c))?;
            drop_part_as(tx, &c, ai, true)
        })
    }

    /// Keep bounds of a held body (wall ms): (keep at least, keep at most).
    pub fn body_keep(&mut self, c: &CommitId, tid: &Tid, ak: &Ak) -> Result<osis_commit::retention::Keep> {
        self.settle_deaths()?;
        let (c, tid, ak) = (*c, *tid, ak.clone());
        let (h, r, d) = self.run(|tx| {
            let (ai, h) = known_part(tx.core, &c, &tid, &ak)?;
            let r = h.aspects.get(ai).ok_or(Error::UnknownCommit(c))?.retention;
            let d = deaths_of(tx, &h, &c, ai)?;
            Ok((h, r, d))
        })?;
        let live = r.at_most.rel.is_some() && d.is_some() && self.body_live(&c, &tid, &ak)?;
        Ok(osis_commit::retention::body_keep(&h, &r, d.map(|d| d.0.wall_ms().0), d.map(|d| d.1.wall_ms().0), live))
    }

    /// Whether snapshot `s` is a carrier only on `(tid, ak)` (`osis_commit::retention::carrier_only`
    /// of its retention there): it drops no body as covered and covers none for must-hold.
    pub fn carrier_only(&self, s: &CommitId, tid: &Tid, ak: &Ak) -> bool {
        self.header(s).and_then(|h| h.aspects.iter().find(|a| a.tid == *tid && a.ak == *ak).map(|a| osis_commit::retention::carrier_only(&a.retention))).unwrap_or(false)
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
    /// dot its deltas own survives there; unknown counts as live). A body without one needs no
    /// carrier before it leaves a label (spec/sync.md §7); one with one gets `AT_MOST_GRACE`
    /// (spec/commits.md §5). Writes the state does not hold count
    /// dead: superseded, purged or expired ones, and those of deltas invalid here or undone (they
    /// are stripped from the state; they count live again once a validity flip or a redo puts
    /// them back). Any write counts: resets, tombstones and value-less writes too. Kept per body
    /// until its aspect's state changes (`Core::live_bodies`).
    pub fn body_live(&mut self, c: &CommitId, tid: &Tid, ak: &Ak) -> Result<bool> {
        let key = (*c, *tid, ak.clone());
        if let Some(v) = self.core.live_bodies.get(&key) {
            return Ok(*v);
        }
        let (c, tid, ak) = (*c, *tid, ak.clone());
        let live = self.run(|tx| match aspect_index(tx.core, &c, &tid, &ak) {
            Some(ai) => {
                let r = live(tx, &c, ai)?;
                #[cfg(test)]
                assert_eq!(r, oracle::live(tx, &c, ai)?, "live streamed vs whole");
                Ok(Some(r))
            }
            None => Ok(None),
        })?;
        // an unknown commit counts live, uncached (its apply may change nothing here)
        let Some(live) = live else { return Ok(true) };
        self.core.live_bodies.insert(key, live);
        Ok(live)
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

    /// Writes a compaction snapshot of `(tid, ak)` from this node's whole state (spec/commits.md
    /// §2, spec/crdt.md §8): values of deltas with an expiry and of purged writes go
    /// value-less; frontiers from the receipt record. A carrier-only one included. On a `~`
    /// aspect a memory commit: deltas with an expiry left out whole, frontiers continuing from
    /// the held valid memory snapshots'.
    pub fn snapshot(&mut self, tid: &Tid, ak: &Ak) -> Result<Option<CommitId>> {
        self.snapshot_if(tid, ak, false)
    }

    /// `snapshot` for compaction: none when it would be a carrier only (spec/commits.md §5:
    /// it would drop nothing).
    pub fn compaction_snapshot(&mut self, tid: &Tid, ak: &Ak) -> Result<Option<CommitId>> {
        self.snapshot_if(tid, ak, true)
    }

    fn snapshot_if(&mut self, tid: &Tid, ak: &Ak, compaction: bool) -> Result<Option<CommitId>> {
        let (tid, ak) = (*tid, ak.clone());
        if ak.as_str() == "roles.0" || ak.as_str() == "tenures.0" {
            return Err(Error::Misuse("roles.0 and tenures.0 are compacted by roster snapshots"));
        }
        if ak.as_str() == "created.0" {
            return Err(Error::Misuse("created.0 is kept forever, never compacted"));
        }
        // a memory aspect's snapshot is a memory commit (spec/commits.md §2); signals are never
        // held
        let memory = match ak.lifetime() {
            osis_schema::Lifetime::Durable => false,
            osis_schema::Lifetime::Ephemeral => true,
            osis_schema::Lifetime::Signal => return Err(Error::Misuse("a signal aspect holds no state to compact")),
        };
        self.run(|tx| {
            if memory {
                tx.set_memory();
            }
            let node = tx.core.id.tid();
            let ts = tx.core.hlc.next();
            // a snapshot needs the strictest role a write it carries could need (tests may write
            // one a receiver judges invalid)
            let need = if tx.core.skip_writer_rules { crate::engine::write::required_role(ak.as_str()) } else { crate::engine::write::snapshot_role(ak.as_str()) };
            if !(memory && tx.core.skip_writer_rules) {
                crate::engine::write::check_role_with(tx.core, tx.core.id.tid(), &|_| None, &tid, ak.as_str(), need, ts)?;
            }
            if tx.state(&tid, &ak)?.is_none() {
                return Ok(None);
            }
            let expiring: Vec<(CommitId, Owned)> = tx
                .core
                .ix.by_aspect
                .get(&(tid, ak.clone()))
                .into_iter()
                .flatten()
                .filter_map(|(_, c)| {
                    let m = tx.core.ix.commits.get(c)?;
                    let ai = m.aspect(&tid, &ak)?;
                    m.header.aspects.get(ai)?.expires?;
                    Some((*c, Owned::of(&m.header, c, ai)?))
                })
                .collect();
            let st = if memory {
                // an expiring memory write vanishes whole at T (spec/crdt.md §4.7): no snapshot
                // carries it, nor counts it received, so it goes from every holder alike
                let gone: Vec<Owned> = expiring.iter().map(|x| x.1.clone()).collect();
                let skip: BTreeSet<CommitId> = expiring.iter().map(|x| x.0).collect();
                let (st, _) = crate::apply::rebuilt(tx, &tid, &ak, &gone, &skip)?;
                let Some(st) = st else { return Ok(None) };
                st
            } else {
                let Some(mut st) = tx.state(&tid, &ak)?.cloned() else { return Ok(None) };
                if !expiring.is_empty() {
                    st.strip(&|d| expiring.iter().any(|o| o.1.owns(d)));
                }
                st
            };
            if ak.as_str() == "secrets.0" && !crate::apply::keys::may_compact(tx.core, &tid, &st) {
                return Err(Error::Misuse("secrets.0 keys an epoch not established here (spec/crypto.md §4)"));
            }
            // a part still missing gives this state nothing (applied without it, spec/commits.md
            // §4): an expiring one's writes would go value-less here anyway
            let valid_on = |c: &CommitId| tx.core.ix.commits.get(c).is_some_and(|m| m.aspect(&tid, &ak).is_some_and(|ai| m.valid_at(ai) && (!m.missing.contains(&ai) || m.header.aspects.get(ai).is_some_and(|a| a.expires.is_some()))));
            let left_out = |c: &CommitId| memory && expiring.iter().any(|x| x.0 == *c);
            // frontiers cover only counters whose writes this state reflects: applied, valid
            // (and for memory, not expiring). A memory commit is forgotten once covered, its
            // counters with it: there the held valid snapshots' frontiers count as reflected (their
            // writes are joined), and own ranges continue from them
            let mut frontiers = Frontiers::default();
            if memory {
                for (_, s, fr, _) in tx.core.ix.snapshots.get(&(tid, ak.clone())).into_iter().flatten() {
                    if valid_on(s) {
                        for (src, f) in fr.sources() {
                            if f > frontiers.of(&src) {
                                frontiers.insert(&src, f);
                            }
                        }
                    }
                }
            }
            let from = (tid, ak.clone(), osis_crdt::Source::node(Tid::from_bytes([0; 15])));
            for ((_, _, n), ranges) in tx.core.ix.ranges.range(from..).take_while(|((t, a, _), _)| *t == tid && *a == ak) {
                let mut next = frontiers.of(n).saturating_add(1);
                for (lo, (hi, c)) in ranges {
                    if memory && *hi <= next {
                        continue;
                    }
                    // contiguous (a memory range may start below a snapshot's frontier)
                    let joins = *lo == next || (memory && *lo < next);
                    if !joins || !valid_on(c) || left_out(c) {
                        break;
                    }
                    next = *hi;
                }
                if next > 1 {
                    frontiers.insert(n, next - 1);
                }
            }
            // commits judged by ID (commit form, imports) whose valid writes the state reflects
            let mut absorbed = std::collections::BTreeMap::new();
            for (_, c) in tx.core.ix.by_aspect.get(&(tid, ak.clone())).into_iter().flatten() {
                let Some(m) = tx.core.ix.commits.get(c) else { continue };
                if by_id(m.header.kind, m.header.form) && valid_on(c) && !left_out(c) {
                    absorbed.insert(*c, m.header.author);
                }
            }
            let kind = if is_role_class(ak.as_str()) { Kind::RoleSnapshot } else { Kind::ContentSnapshot };
            // bounds from the retention of the writes it carries, schema known here or not
            // (spec/commits.md §5); a memory one's are `writer` without bounds (spec/commits.md §2)
            let retention = if memory {
                osis_schema::Retention { by: osis_schema::PurgeBy::Writer, ..Default::default() }
            } else {
                osis_commit::retention::snapshot_retention(ak.as_str(), own_retentions(tx, &tid, &ak, &st)?, ts.wall_ms().0)
            };
            if compaction && osis_commit::retention::carrier_only(&retention) {
                return Ok(None);
            }
            // the records of the memory things it is on or places beside it (spec/commits.md §2)
            let records = if memory {
                let placed = crate::ephemeral::def_of(&st).map(|(i, s)| i.into_iter().chain(s).collect::<Vec<_>>()).unwrap_or_default();
                crate::engine::write::memory_records(tx.core, &tid, &ak, placed.into_iter())
            } else {
                Vec::new()
            };
            // a memory snapshot is commit form (spec/commits.md §3)
            let form = if memory { Form::Commit } else { Form::Node };
            let plan = CommitPlan { kind, ts, actor: node, form, creates: Default::default(), purge: Vec::new(), undoes: None, frontier: None, origins: Vec::new(), signer: tx.core.id.tid(), blind: crate::engine::write::draw_blind(&mut *tx.rng) };
            let d = Resolved { tid, ak, fragment: st, lo: 0, hi: 0, schema: None, retention: Some(retention), expires: None, frontiers: Some((frontiers, absorbed)), chunks: Vec::new(), split: false, records };
            build_and_apply(tx, plan, vec![d]).map(Some)
        })
    }

    /// Is the body of `ak` in commit `c` covered by snapshot commit `s` (spec/commits.md §5):
    /// joining each of its deltas into the snapshot's fragment leaves its canonical bytes
    /// unchanged, and for a node-form body, the snapshot's frontier holds its counters, for a
    /// body judged by commit ID, the snapshot lists it as absorbed (so every holder of the
    /// snapshot counts the dropped body's delta as listed in atomic apply, spec/crdt.md §8). A
    /// carrier only covers none. `None` when either is not held (nothing is established).
    pub fn covered(&mut self, s: &CommitId, c: &CommitId, tid: &Tid, ak: &Ak) -> Result<Option<bool>> {
        let (s, c, tid, ak) = (*s, *c, *tid, ak.clone());
        self.run(|tx| {
            let r = covered(tx, &s, &c, &tid, &ak)?;
            #[cfg(test)]
            {
                let w = oracle::covered(tx, &s, &c, &tid, &ak)?;
                assert_eq!(r, w, "covered streamed vs whole");
            }
            Ok(r)
        })
    }
}

/// Whether part `ai` of snapshot `s` is a carrier only (`osis_commit::retention::carrier_only`).
fn carrier_at(core: &Core, s: &CommitId, ai: usize) -> bool {
    core.ix.commits.get(s).and_then(|m| m.header.aspects.get(ai).map(|a| osis_commit::retention::carrier_only(&a.retention))).unwrap_or(false)
}

/// Whether frontiers `fr` miss some of the counters below `hi` of commit `c` (header `h`), a
/// node- or session-form commit with own writes (judged by counters); `false` for others.
fn unseen_by(fr: &osis_crdt::Frontiers, h: &Header, c: &CommitId, hi: u64) -> bool {
    if !h.form.counted() || !h.kind.has_own_writes() {
        return false;
    }
    let src = h.form.own_source(h.author, *c);
    fr.sources().find(|(s, _)| *s == src).is_none_or(|(_, f)| f.saturating_add(1) < hi)
}

/// Whether a commit's writes are judged by its ID (commit form, imports: snapshots list them
/// absorbed) rather than by counters under a frontier.
fn by_id(kind: Kind, form: Form) -> bool {
    kind == Kind::Import || (form == Form::Commit && kind.has_own_writes())
}

/// `Engine::covered` in `tx`: the body whole, the snapshot a piece at a time (its part at the
/// body's positions, `Fragment::part_at`, and each piece's copies of the body's writes against
/// the body's part at the piece's positions: a copy lies where its write does). Cost: the body
/// and the snapshot's part at its positions, about twice the body; both whole only with a
/// pull decoder walking them side by side (issues/durable-decode-bound.md).
pub(crate) fn covered(tx: &mut Tx<'_>, s: &CommitId, c: &CommitId, tid: &Tid, ak: &Ak) -> Result<Option<bool>> {
    let (Some(sai), Some(cai)) = (aspect_index(tx.core, s, tid, ak), aspect_index(tx.core, c, tid, ak)) else { return Ok(None) };
    // an invalid snapshot gives nothing, so covers nothing (spec/permissions.md §5.2); a
    // carrier only covers none (spec/commits.md §5)
    if !crate::apply::validity::snapshot_valid(tx.core, s, tid, ak) || carrier_at(tx.core, s, sai) {
        return Ok(Some(false));
    }
    // a snapshot body still to arrive (or missing again, `uncover`): nothing is established
    // without its content (a delta's frontier or absorbed check below stands alone)
    if tx.core.ix.commits.get(c).is_some_and(|m| m.view.kind.is_compaction() && m.missing.contains(&cai)) {
        return Ok(None);
    }
    let Some(m) = tx.core.ix.commits.get(c).cloned() else { return Ok(None) };
    let held = crate::apply::held_parts(tx, c, cai)?;
    let other = match held.as_slice() {
        [Decoded::Snapshot(o)] => Some((o.frontiers.clone(), o.absorbed.clone())),
        _ => None,
    };
    let is_snapshot = m.header.kind.is_compaction();
    let mut body: Vec<Fragment> = held.into_iter().map(Decoded::into_fragment).collect();
    // a valid snapshot body's copies all count (spec/permissions.md §5.2): it must carry them
    // all; an invalid one gives nothing, its copies of writes a received valid delta supplies
    // are left out
    if is_snapshot && !crate::apply::validity::snapshot_valid(tx.core, c, tid, ak) {
        let core = &*tx.core;
        for b in &mut body {
            b.strip_copies(&|d| crate::apply::validity::any_owner(core, tid, ak, d, &|_, m, ai| !m.missing.contains(&ai) && m.valid_at(ai)));
        }
    }
    // the snapshot's copies of the body's writes are the body's (a copy at another
    // value, `ts` or position, or under a dot the body owns but lacks, joins as
    // unchanged): under its own dots, or a snapshot body's carried writes (records
    // without a `ts`, such as the entry another's write is nested in, are no writes)
    let mut ranges: Vec<(osis_crdt::Source, u64, u64)> = if is_snapshot {
        body.iter().flat_map(|b| b.writes()).filter(|w| w.1.is_some()).map(|(d, _)| (d.src.clone(), d.ctr, d.ctr.saturating_add(1))).collect()
    } else {
        crate::apply::validity::owned_ranges(&m.header, c, cai)
    };
    ranges.sort();
    ranges.dedup();
    let held = !body.is_empty();
    let mut joined = Fragment::default();
    for b in body {
        joined.join(b);
    }
    let mut part = Fragment::default();
    let mut outside = false;
    let gives = crate::apply::each_held_piece(tx, s, sai, &mut |_, p| {
        // a copy in `p` is compared with the body's write at its position
        outside = outside || !p.copy_index().outside(&ranges, &osis_crdt::CopySet::of(&[&joined.part_at(&p)])).is_empty();
        part.join(p.part_at(&joined));
        Ok(())
    })?;
    // the snapshot not held: nothing is established
    let [g] = gives.as_slice() else { return Ok(None) };
    if let Some((fr, abs)) = g {
        let h = &m.header;
        let unseen = h.aspects.get(cai).is_some_and(|a| unseen_by(fr, h, c, a.hi));
        if unseen || (by_id(h.kind, h.form) && !abs.iter().any(|x| x.0 == *c)) {
            return Ok(Some(false));
        }
        // a snapshot covers another only if its frontiers hold the other's too: otherwise a
        // holder of it alone does not count as listed what the other's frontier listed
        if let Some((ofr, oabs)) = &other
            && (ofr.sources().any(|(s, f)| fr.of(&s) < f) || oabs.keys().any(|c| !abs.iter().any(|x| x.0 == *c)))
        {
            return Ok(Some(false));
        }
    }
    // a body this node holds no delta of joins nothing: covered, unless still to come with an
    // expiry: a snapshot carries none of its values (spec/crdt.md §8), so it must still join
    if !held {
        let awaited = m.missing.contains(&cai) && m.header.aspects.get(cai).is_some_and(|a| a.expires.is_some());
        return Ok(Some(!awaited));
    }
    // joining the body changes the snapshot's canonical bytes, judged on its part at the
    // body's positions (the rest is left as it is)
    let before = crate::engine::state::encode(&part)?;
    part.join(joined);
    if crate::engine::state::encode(&part)? != before {
        return Ok(Some(false));
    }
    Ok(Some(!outside))
}

/// `Engine::body_live` of the body holding aspect `ai` of `c`, judged against the state in
/// `tx`: a function of the commits applied (the join's), so alike at nodes that applied the
/// same ones.
fn live(tx: &mut Tx<'_>, c: &CommitId, ai: usize) -> Result<bool> {
    let Some(h) = tx.core.ix.commits.get(c).map(|m| m.header.clone()) else { return Ok(true) };
    let (_, holders) = body_class(tx.core, &h, c, ai);
    if h.kind.is_compaction() {
        return snapshot_live(tx, &h, c, &holders);
    }
    for x in holders {
        let Some(a) = h.aspects.get(x) else { continue };
        let Some(o) = Owned::of(&h, c, x) else { return Ok(true) };
        let owns = |st: &Fragment| st.holds_owned_write(&|src, lo, hi| o.owns_range(src, lo, hi));
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
/// (spec/commits.md §5; kept frontiers, `Dropped::gives`, reach dead writes too), so whether it
/// was live then is kept (`Dropped::live`): dropped dead it stays dead (undo and redo write
/// new dots; a write a validity flip brings back comes from a held body,
/// which carries it at hosts itself); dropped live, it is
/// live while the state holds a write stamped at or before its `ts` (the header's `ts` bounds
/// what it carried) or one without a `ts` (a bare anchor it may carry): an
/// over-approximation, so its delete at hosts waits for a carrier (spec/sync.md §7).
/// Never held: a write stamped at or before its `ts`.
fn snapshot_live(tx: &mut Tx<'_>, h: &Header, c: &CommitId, holders: &[usize]) -> Result<bool> {
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

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use crate::Mutation;
    use crate::flows::{Demotion, PreSync};
    use crate::local_peer::LocalPeer;
    use osis_base::{Ak, Role, Value, WallMs};
    use osis_schema::core_types as ct;

    // spec/sync.md §7 (a body with live writes needs a carrier), spec/permissions.md §5.2: a
    // write made invalid (a backdated removal of its author) counts dead; a re-grant that makes
    // it valid again counts it live again.
    #[test]
    fn body_live_follows_validity_spec_sync_7() {
        let mut lp = LocalPeer::new(2, 951, WallMs(1_700_000_000_000)).unwrap();
        lp.sync_all().unwrap();
        let (a, w) = (lp.peers[0].engine.tid(), lp.peers[1].engine.tid());
        let ak = Ak::new("x:a.0").unwrap();
        let mut m = Mutation::new();
        let t = lp.peers[0].engine.new_thing(&mut m, a);
        m.set(t, &ak, &Value::Int(0)).unwrap();
        lp.peers[0].commit(m).unwrap();
        let write = ct::Edge { role: Role::Write, until: None, invite: None, since: None, tied: None };
        lp.peers[0].engine.grant(&t, &w, &write).unwrap();
        lp.sync_all().unwrap();
        let before = lp.peers[0].engine.now();
        lp.advance(60_000);
        let mut m = Mutation::new();
        m.set(t, &ak, &Value::Int(1)).unwrap();
        let c = lp.peers[1].commit(m).unwrap().unwrap();
        lp.sync(1, 0).unwrap();
        let e = &mut lp.peers[0].engine;
        assert!(e.body_live(&c, &t, &ak).unwrap(), "W's write is the value");
        e.demote(&t, &Demotion { holder: w, new: None, presync: PreSync::Backdated(before) }).unwrap();
        assert!(!e.body_live(&c, &t, &ak).unwrap(), "invalid after the backdated removal: dead");
        e.grant(&t, &w, &write).unwrap();
        assert!(e.body_live(&c, &t, &ak).unwrap(), "valid again after the re-grant: live");
    }

    // spec/sync.md §6 (work sets): node-sync's change hook marks a commit whose validity flipped
    // (a backdated removal of its author), and one whose body was dropped; nothing is kept
    // until node-sync asks.
    #[test]
    fn changed_marks_flips_and_drops_spec_sync_6() {
        let mut lp = LocalPeer::new(2, 952, WallMs(1_700_000_000_000)).unwrap();
        lp.sync_all().unwrap();
        let (a, w) = (lp.peers[0].engine.tid(), lp.peers[1].engine.tid());
        let ak = Ak::new("x:a.0").unwrap();
        let mut m = Mutation::new();
        let t = lp.peers[0].engine.new_thing(&mut m, a);
        m.set(t, &ak, &Value::Int(0)).unwrap();
        let first = lp.peers[0].commit(m).unwrap().unwrap();
        let write = ct::Edge { role: Role::Write, until: None, invite: None, since: None, tied: None };
        lp.peers[0].engine.grant(&t, &w, &write).unwrap();
        lp.sync_all().unwrap();
        let before = lp.peers[0].engine.now();
        lp.advance(60_000);
        let mut m = Mutation::new();
        m.set(t, &ak, &Value::Int(1)).unwrap();
        let c = lp.peers[1].commit(m).unwrap().unwrap();
        let e = &mut lp.peers[0].engine;
        assert!(e.core.changed.is_none(), "kept only for node-sync");
        assert!(e.take_changed().is_empty());
        lp.sync(1, 0).unwrap();
        let e = &mut lp.peers[0].engine;
        assert!(e.take_changed().commits.contains(&c), "applied");
        e.demote(&t, &Demotion { holder: w, new: None, presync: PreSync::Backdated(before) }).unwrap();
        let got = e.take_changed();
        assert!(got.commits.contains(&c), "the flipped commit");
        assert!(!got.commits.contains(&first), "not every commit on the flipped aspect");
        assert!(got.aspects.contains(&(t, ak.clone())), "the flipped aspect's state");
        e.drop_body(&first, &t, &ak).unwrap();
        assert!(e.take_changed().commits.contains(&first), "dropped");
    }
}
