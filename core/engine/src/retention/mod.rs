//! Retention (spec/commits.md §5–§6; spec/crdt.md §4.7, §4.8, §8): deaths per body from the
//! crdt change summary, keep-at-most drops (in the killing transaction for at most 0 but for
//! bodies with a live write, which get `AT_MOST_GRACE` more, else by timer), expiry at T
//! (value-less, body dropped), purge requests judged by perm at the
//! request's time (also against deltas arriving later), compaction snapshots and the covered
//! test. node-sync judges what to delete at hosts and what to re-snapshot from the commit
//! index (dropped parts, `covered`), so no queue is kept here.
//!
//! Here: bodies dropping and coming back, value-less deltas, what runs on apply and by timer.
//! `purge`: purge requests. `pending`: parts held while their commit waits. `snapshot`: compaction.
//! `bounds`: a body's keep bounds and liveness. `deaths`: dating them.
//!
//! A body here is one projection class of a commit (`body_class`): its deaths are kept per part,
//! read over the class, and a part drops with the rest of its class. The class depends on what is
//! held (`reader`), so nothing kept may be keyed by it.

use crate::engine::records::{self, Rd, Wr};
use crate::engine::{Core, DropFor, Dropped, Engine, Owned, Tx};
use crate::error::{Error, Result};
use crate::events::{Cause, Event};
use osis_commit::{Form, Header, Kind};
use osis_base::{Ak, BlobId, CommitId, Tid, Ts};
use osis_crdt::Fragment;
use osis_schema::core_types::is_role_class;
use osis_store::Shred;
use std::collections::{BTreeMap, BTreeSet};

mod bounds;
mod deaths;
mod pending;
mod purge;
mod snapshot;
#[cfg(test)]
mod oracle;
pub(crate) mod forget;
pub(crate) mod memory;
pub mod suspect;

pub(crate) use bounds::drop_from;
use bounds::{live, snapshot_live};
pub(crate) use pending::{emptied, forget_stripped, is_stripped, pending_drops, pending_expired, stripped_joined, stripped_of};
use pending::{purge_pending, strip_pending};
use purge::drop_purged_snapshot;
pub(crate) use purge::{counts_as_purged, known_purged, lasting, purged_aspects, purged_by, rejudge_purges, requests_resting_on, snapshot_right};
pub(crate) use snapshot::covered;
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
    if owned.is_empty() {
        return Ok(());
    }
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
        return drop_part_for(tx, s, sai, DropFor::Purge);
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
        // it does not re-snapshot the aspect. `t` is `body_keep`'s: past the first death only
        // under a purge request's floor, which this does not cut short
        let zero = a.retention.at_most.rel == Some(0) && !live && d.is_some_and(|d| t <= d.0.wall_ms().0);
        if t <= tx.now().0 || zero {
            // a part of the body still missing has nothing here to drop: it stays missing (never
            // received, fetched as such), as at a node that judged the body before it was held
            for x in holders.into_iter().filter(|x| !m.missing.contains(x)) {
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
    drop_part_for(tx, c, ai, DropFor::Other)
}

/// `drop_part`, saying why.
fn drop_part_for(tx: &mut Tx<'_>, c: &CommitId, ai: usize, why: DropFor) -> Result<()> {
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
    // as covered only with a coverer: the others come back on arrival alone
    let why = if why == DropFor::Cover && covered_by.is_empty() { DropFor::Other } else { why };
    // a snapshot dropped other than as covered still stands in for what it was stamped after
    // (spec/commits.md §4, §5), held when it dropped or not (a part missing, as after a purge
    // fell, needs no body for that: its header says it all); a coverer, stamped no earlier,
    // does for a covered one
    let stands_in = snapshot && why != DropFor::Cover;
    // a valid snapshot's misstated copies govern while it is held (spec/permissions.md §5.2):
    // dropped, the held deltas give those writes again
    let misstated = if snapshot && m.valid_at(ai) { crate::apply::copies::misstated_by(tx, c, &a.tid, &a.ak)? } else { BTreeSet::new() };
    let (role, overreach) = (tx.core.ix.rotation_role.get(&(*c, ai)).copied(), tx.core.ix.grant_overreach.contains(&(*c, ai)));
    // a role-class body whole: what keys noted from it (`keys::keysets_of`, `forget_dropped`)
    // and the names its boxes to the holders its edge writes put carry (`keys::names_of`: a
    // grant's or raise's, which a later boxer of the holder must hold)
    let role_bodies: Vec<Fragment> = if is_role_class(a.ak.as_str()) { crate::apply::held_fragments(tx, c, ai)? } else { Vec::new() };
    let keysets = crate::apply::keys::keysets_of(&m.header, ai, &role_bodies);
    let put: BTreeSet<Tid> = tx.core.timelines.get(&a.tid).and_then(|tl| tl.role_commit(c)).map(|mc| mc.ops.iter().filter(|op| op.target == a.tid && op.edge.is_some()).map(|op| op.holder).collect()).unwrap_or_default();
    let names = crate::apply::keys::names_of(&m.header, ai, &role_bodies, &put);
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
    m.dropped.insert(ai, Dropped { covered_by, why, live, stands_in, role, overreach, keysets, names });
    // a setting not held binds nothing (`validity::never_could_set`)
    if a.ak.as_str() == osis_commit::retention::REQUIRED {
        let mut settings = tx.core.ix.required.get(&a.tid).cloned().unwrap_or_default();
        settings.retain(|x| x.0.commit != *c);
        if settings.is_empty() {
            tx.core.ix.required.remove(&a.tid);
        } else {
            tx.core.ix.required.insert(a.tid, settings);
        }
    }
    // a part missing (again, `uncover`) and dropped is dropped, as an open reads it: received,
    // so snapshots' copies of its writes are carried writes no more
    if m.missing.remove(&ai) {
        let h = m.header.clone();
        crate::apply::copies::uncarry(tx.core, c, &h, &|x| x == ai);
    }
    if let Some(blob) = tx.get_commit(c)? {
        let rest = osis_commit::rewrite(&blob, |x, _| x == ai);
        tx.put_commit(c, &rest, &m, Shred::Yes, None)?;
    }
    let (body, _) = body_class(tx.core, &m.header, c, ai);
    let header = m.header.clone();
    let vouched = snapshot && m.valid_at(ai);
    tx.core.put_meta(*c, m);
    crate::apply::note_stands_in(tx.core, c);
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

/// Parts on `(tid, ak)` dropped as covered that no coverer carries any more (each turned
/// invalid, or was itself dropped as covered; one dropped for its bound, expiry or a
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
            Some(d) => valid && !d.as_cover(),
        }
    };
    let mut lost = Vec::new();
    for (_, c) in core.ix.by_aspect.get(&(*tid, ak.clone())).into_iter().flatten() {
        let Some(m) = core.ix.commits.get(c) else { continue };
        let Some(ai) = m.aspect(tid, ak) else { continue };
        if m.dropped.get(&ai).is_some_and(|d| d.as_cover()) && !coverers(core, c, ai).iter().any(&carries) {
            lost.push((*c, ai));
        }
    }
    let mut owned = Vec::new();
    let any = !lost.is_empty();
    if any {
        tx.core.forget_live(tid, ak);
        // until each comes back, this node may read less than one that kept it
        suspect::raise(tx, tid, ak, suspect::Why::Uncovered, &lost)?;
    }
    for (c, ai) in lost {
        // dropped as covered: nothing in `dropped_snapshots` (`Dropped::stands_in`);
        // the epochs it introduced or held go too (`keys::rebuild_keysets` below)
        let Some(m) = reopen_to_fetch(tx, &c, ai)? else { continue };
        // its residue, if it went value-less while dropped, came from its coverers' copies
        // (`make_valueless`) and goes with them. Invariant: a part dropped as covered has a
        // residue only while some coverer carries it; missing, it gives nothing (a late copy
        // joins and rebuilds the residue from its body, `on_late`). Out of the list its purge fell,
        // and the row waits for a rise (`make_valueless`).
        if valueless(tx.core, &c, ai)
            && let Some(a) = m.view.aspects.get(ai)
        {
            let key = records::residue_key(&a.tid, &a.ak, &c, ai);
            tx.txn.remove_local(&key, Shred::Yes)?;
        }
        owned.extend(writes_of(tx.core, &m.header, &c, ai));
    }
    if any && ak.as_str() == "keys.0" {
        crate::apply::keys::rebuild_keysets(tx, &BTreeSet::from([*tid]))?;
    }
    if !owned.is_empty() {
        note_carried_again(tx, tid, ak)?;
    }
    Ok(owned)
}

/// Held snapshots' copies of the writes of deltas now never received are carried writes.
fn note_carried_again(tx: &mut Tx<'_>, tid: &Tid, ak: &Ak) -> Result<()> {
    for s in snapshots_of(tx.core, tid, ak) {
        let Some(sai) = aspect_index(tx.core, &s, tid, ak) else { continue };
        let mut carried: BTreeMap<osis_crdt::Source, BTreeSet<u64>> = BTreeMap::new();
        let held = crate::apply::each_held_piece(tx, &s, sai, &mut |tx, f| {
            for (src, ctrs) in crate::apply::copies::carried_of(tx.core, tid, ak, &f) {
                carried.entry(src).or_default().extend(ctrs);
            }
            Ok(())
        })?;
        if !held.is_empty() {
            crate::apply::copies::note_carried_of(tx.core, tid, ak, &s, carried);
        }
    }
    Ok(())
}

/// The parts of `(tid, ak)` dropped for breaking the required retention that are valid now are
/// missing again (spec/permissions.md §8): they give nothing until the body arrives again
/// (node-sync fetches it, `Changed::undropped`; a holder uploads it, it is must-hold there).
pub(crate) fn unbreak(tx: &mut Tx<'_>, tid: &Tid, ak: &Ak) -> Result<()> {
    let core = &*tx.core;
    let back: Vec<(CommitId, usize)> = core.ix.by_aspect.get(&(*tid, ak.clone())).into_iter().flatten().filter_map(|(_, c)| {
        let m = core.ix.commits.get(c)?;
        let ai = m.aspect(tid, ak)?;
        (m.valid_at(ai) && m.dropped.get(&ai).is_some_and(|d| d.why == DropFor::Broke)).then_some((*c, ai))
    }).collect();
    for (c, ai) in back {
        reopen_to_fetch(tx, &c, ai)?;
    }
    Ok(())
}

/// Makes dropped part `ai` of `c` missing, as at a node that never received it: what its body
/// judged or gave goes too (`Dropped::role`; the header's one-delta rule for `secrets.0` stays,
/// `validity::note_required`). Its meta after.
fn reopen(tx: &mut Tx<'_>, c: &CommitId, ai: usize) -> Result<Option<crate::engine::Meta>> {
    tx.core.touch();
    let Some(mut m) = tx.core.ix.commits.get(c).cloned() else { return Ok(None) };
    // missing again, a dropped snapshot stands in no more (`Dropped::stands_in`)
    if m.dropped.remove(&ai).is_some_and(|d| d.stands_in)
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
    tx.core.put_meta(*c, m.clone());
    Ok(Some(m))
}

/// `reopen`, and node-sync fetches it again (`Changed::undropped`).
fn reopen_to_fetch(tx: &mut Tx<'_>, c: &CommitId, ai: usize) -> Result<Option<crate::engine::Meta>> {
    let m = reopen(tx, c, ai)?;
    if let Some(ch) = &mut tx.core.changed {
        ch.undropped.insert(*c);
    }
    Ok(m)
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
    if m.view.memory || m.dropped.get(&ai).is_none_or(|d| d.as_cover()) {
        return Ok(false);
    }
    Ok(!valueless(tx.core, c, ai) || never_received(tx, c, ai)?)
}

/// Whether dropped part `ai` of `c` was never received: held value-less (expired or purged
/// while missing) with no residue (`make_valueless` keeps one, even empty, from a held body or
/// its coverers' copies). What a snapshot gave under its dots is the snapshot's alone
/// (`copies::given_by`).
pub(crate) fn never_received(tx: &mut Tx<'_>, c: &CommitId, ai: usize) -> Result<bool> {
    let Some(m) = tx.core.ix.commits.get(c) else { return Ok(false) };
    let (Some(d), Some(a)) = (m.dropped.get(&ai), m.header.aspects.get(ai)) else { return Ok(false) };
    if d.as_cover() || !valueless(tx.core, c, ai) {
        return Ok(false);
    }
    let key = records::residue_key(&a.tid, &a.ak, c, ai);
    Ok(tx.txn.get_local(&key)?.is_none())
}

/// Whether delta `ai` of `c` is held value-less (`make_valueless`): its body is dropped.
pub(crate) fn valueless(core: &Core, c: &CommitId, ai: usize) -> bool {
    core.ix.commits.get(c).is_some_and(|m| !gone_of(core, &m.header, c, ai).is_empty())
}

/// The owners of the writes delta `ai` of `id` holds as its own: its counters or commit ID, an
/// import's origins' dots on its aspect (it holds them under `Commit(origin)`, spec/permissions.md
/// §7; `Owned::of` names only its empty range), a snapshot's none (it copies). What invalidity,
/// expiry and purge of the delta take (an import has no expiry).
///
/// Invariant (security, spec/requirements.md Purge): an import going value-less takes every
/// write under these dots on the aspect, in every body and while a request on an import listing the
/// origin stands (`rejudge_purges`), whichever of the request, the import, another import listing
/// the origin and a snapshot came first: a function of the held set, since `Owned::Commit(origin)`
/// on the value-less list strips every later join (`strip_valueless`). It never takes what the
/// import does not hold by right: an origin with a delta on the thing owns its dots there (the
/// import is void, §7), judged here when the origin arrived first and by `origin_arrived` when it
/// comes later.
/// Complete for an import's values: a held import holds no stamp outside its origins' sources
/// but anchors' creations and sibling keys (refused as bad input, `apply::judge_part`).
pub(crate) fn writes_of(core: &Core, h: &Header, id: &CommitId, ai: usize) -> Vec<Owned> {
    let Some(a) = h.aspects.get(ai) else { return Vec::new() };
    if h.kind == Kind::Import {
        return h.origins.iter().filter(|o| !crate::apply::copies::owns_commit_dots(core, &o.commit, &a.tid, &a.ak)).map(|o| Owned::Commit(o.commit)).collect();
    }
    if h.kind.has_own_writes() { Owned::of(h, id, ai).into_iter().collect() } else { Vec::new() }
}

/// `writes_of` the value-less list of the aspect names.
pub(crate) fn gone_of(core: &Core, h: &Header, id: &CommitId, ai: usize) -> Vec<Owned> {
    let Some(v) = h.aspects.get(ai).and_then(|a| core.ix.valueless.get(&(a.tid, a.ak.clone()))) else { return Vec::new() };
    // sorted (`make_valueless`)
    writes_of(core, h, id, ai).into_iter().filter(|o| v.binary_search(o).is_ok()).collect()
}

/// Commit-form commit `id` (header `h`) first held: its `Commit(id)` dots on its aspects are its
/// own (spec/permissions.md §5.2). Any the value-less lists name there came from an import
/// listing it, now void (§7): off the lists, as if the origin had come first (`writes_of`), and
/// `apply::unjoin_void` rebuilds the aspect from what is held. A snapshot or import already
/// dropped for carrying them stays dropped: a limit (spec/commits.md §5), a hostile creator's only.
pub(crate) fn origin_arrived(tx: &mut Tx<'_>, id: &CommitId, h: &Header) -> Result<()> {
    if h.form != Form::Commit || !h.kind.has_own_writes() {
        return Ok(());
    }
    let o = Owned::Commit(*id);
    for a in &h.aspects {
        off_valueless(tx, &a.tid, &a.ak, std::slice::from_ref(&o));
    }
    Ok(())
}

/// Takes `gone` off the value-less list of `(tid, ak)`.
fn off_valueless(tx: &mut Tx<'_>, tid: &Tid, ak: &Ak, gone: &[Owned]) {
    let k = (*tid, ak.clone());
    let Some(list) = tx.core.ix.valueless.get(&k) else { return };
    if !gone.iter().any(|o| list.binary_search(o).is_ok()) {
        return;
    }
    tx.core.touch();
    let list = tx.core.ix.valueless.entry_or_default(k.clone());
    list.retain(|x| !gone.contains(x));
    if list.is_empty() {
        tx.core.ix.valueless.remove(&k);
    }
    tx.core.valueless_dirty.insert(k);
}

/// The held imports listing an origin of import `h` on its aspect `ai`, `h`'s own included once
/// held; none for any other kind.
fn sharing(core: &Core, h: &Header, ai: usize) -> BTreeSet<CommitId> {
    let Some(a) = h.aspects.get(ai).filter(|_| h.kind == Kind::Import) else { return BTreeSet::new() };
    h.origins.iter().flat_map(|o| core.ix.imports.get(&(a.tid, o.commit)).into_iter().flatten().copied()).collect()
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
/// keeps its writes as a residue: from its body and `kept` (its stripped deltas no stored copy
/// holds, `stripped_joined`), or for a body dropped as covered from its held valid coverers'
/// copies. A part dropped otherwise or still missing has none (`takes_late`).
fn make_valueless(tx: &mut Tx<'_>, c: &CommitId, ai: usize, kept: &[Fragment]) -> Result<Option<(Tid, Ak)>> {
    let o = tx.core.ix.commits.get(c).map(|m| writes_of(tx.core, &m.header, c, ai)).unwrap_or_default();
    valueless_as(tx, c, ai, &o, kept)
}

/// `make_valueless` for its writes under `o`.
fn valueless_as(tx: &mut Tx<'_>, c: &CommitId, ai: usize, o: &[Owned], kept: &[Fragment]) -> Result<Option<(Tid, Ak)>> {
    tx.core.touch();
    let Some(m) = tx.core.ix.commits.get(c).cloned() else { return Ok(None) };
    let Some(a) = m.header.aspects.get(ai) else { return Ok(None) };
    if o.is_empty() {
        return Ok(None);
    }
    let owns = |d: &osis_crdt::Dot| o.iter().any(|x| x.owns(d));
    let k = (a.tid, a.ak.clone());
    let list = tx.core.ix.valueless.entry_or_default(k.clone());
    // sorted: what the node holds, not the order it learned it in
    let mut new = Vec::new();
    for x in o {
        if let Err(i) = list.binary_search(x) {
            list.insert(i, x.clone());
            new.push(x);
        }
    }
    tx.core.valueless_dirty.insert(k.clone());
    // the delta's writes lie where it touched the state (a page of a paged state): per piece of
    // its body, stripped there (stripping commutes with join, spec/crdt.md §4.7) and its residue
    // joined
    #[cfg(test)]
    let whole = oracle::residue(tx, &m, c, ai, o, &writes_of(tx.core, &m.header, c, ai), kept)?;
    let mut residue: Option<Fragment> = None;
    let mut merged = false;
    // value-less for all its writes, not only those going now: a residue outlives the body, so a
    // later purge of the others has no copy here to reach
    let all = writes_of(tx.core, &m.header, c, ai);
    let mut strip = |tx: &mut Tx<'_>, f: Fragment| -> Result<()> {
        let mut r = f.clone();
        r.strip(&|d| all.iter().any(|x| x.owns(d)));
        residue.get_or_insert_default().join(r);
        merged |= tx.strip_bodies(&a.tid, &a.ak, &[f], o)?;
        tx.evict_pages(&a.tid, &a.ak);
        Ok(())
    };
    let held = crate::apply::each_held_piece(tx, c, ai, &mut strip)?;
    for f in kept {
        strip(tx, f.clone())?;
    }
    if held.is_empty() && m.dropped.get(&ai).is_some_and(|d| d.as_cover()) {
        // a covered body's live writes are in its coverers (a purge drops them next)
        for s in coverers(tx.core, c, ai) {
            let Some(sai) = held_part(tx.core, &s, &a.tid, &a.ak) else { continue };
            if !crate::apply::copies::snapshot_valid(tx.core, &s, &a.tid, &a.ak) {
                continue;
            }
            crate::apply::each_held_piece(tx, &s, sai, &mut |tx, mut f| {
                f.remove_writes(&|d| !owns(d));
                // a copy of none of them is no residue: a second request, the carrying coverers
                // gone with the first, must not replace the row with nothing
                if f == Fragment::default() {
                    return Ok(());
                }
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
        merged |= tx.strip_bodies(&a.tid, &a.ak, &[], o)?;
    }
    // stripping an entry's key merged its records (spec/crdt.md §4.7) where one superseded
    // something in the other: dated from the bodies (spec/commits.md §5)
    if merged {
        mark_if_bounded(tx, &a.tid, &a.ak)?;
    }
    let key = records::residue_key(&a.tid, &a.ak, c, ai);
    if let Some(residue) = residue {
        let memory = tx.txn.is_memory_aspect(&a.tid, &a.ak);
        let enc = crate::engine::state::encode(&residue)?;
        tx.in_class(memory, |tx| Ok(tx.txn.put_local(&key, &enc, Shred::No)?))?;
    } else if !new.is_empty() {
        rejoin_residue(tx, &a.tid, &a.ak, c, ai)?;
    }
    // so do the rows of the other imports of an origin back on the list
    let origins = new.iter().filter_map(|x| if let Owned::Commit(o) = x { Some(*o) } else { None });
    let others: BTreeSet<CommitId> = origins.flat_map(|o| tx.core.ix.imports.get(&(a.tid, o)).into_iter().flatten().copied()).filter(|i| i != c).collect();
    for i in others {
        if let Some(iai) = aspect_index(tx.core, &i, &a.tid, &a.ak) {
            rejoin_residue(tx, &a.tid, &a.ak, &i, iai)?;
        }
    }
    Ok(Some(k))
}

/// A residue row from when a purge since fallen stood counts again (`residues`): its writes rejoin
/// the state, as at a node that never saw the fall.
fn rejoin_residue(tx: &mut Tx<'_>, tid: &Tid, ak: &Ak, c: &CommitId, ai: usize) -> Result<()> {
    let Some(b) = tx.txn.get_local(&records::residue_key(tid, ak, c, ai))? else { return Ok(()) };
    crate::apply::join_into_state(tx, tid, ak, crate::engine::state::decode(&b)?, false, false)?;
    tx.core.forget_live(tid, ak);
    mark_if_bounded(tx, tid, ak)
}

/// Holds delta `ai` of `c` value-less (`make_valueless`) and drops its body: at expiry, or
/// `purged`. A memory delta vanishes whole instead (`memory::vanish`). A part of it waiting in
/// the stored pending copy goes at expiry (`strip_pending`); purged, it is held value-less, as
/// `pending_drops` holds it (`purge_pending`). A part missing is dropped
/// too (counts as never received: no fetch, a copy joins value-less), with no residue
/// (`never_received`).
fn hold_valueless(tx: &mut Tx<'_>, c: &CommitId, ai: usize, purged: bool, changed: &mut BTreeSet<(Tid, Ak)>) -> Result<()> {
    if purged {
        purge_pending(tx, c, ai)?;
    } else {
        strip_pending(tx, c, ai, true)?;
    }
    if !tx.core.ix.commits.contains_key(c) {
        return Ok(());
    }
    if tx.is_memory_commit(c) {
        changed.extend(memory::vanish(tx, c, ai)?);
        // what is left of it may be superseded whole now (spec/sync.md §9); its caller forgets it
        changed.extend(memory::superseded_rest(tx, c)?);
        return Ok(());
    }
    if let Some(k) = make_valueless(tx, c, ai, &[])? {
        changed.insert(k);
    }
    drop_part_for(tx, c, ai, if purged { DropFor::Purge } else { DropFor::Other })?;
    // the other imports listing its origins hold those writes too (spec/permissions.md §7)
    let Some(h) = tx.core.ix.commits.get(c).map(|m| m.header.clone()) else { return Ok(()) };
    let Some(a) = h.aspects.get(ai) else { return Ok(()) };
    for i in sharing(tx.core, &h, ai) {
        if let Some(iai) = aspect_index(tx.core, &i, &a.tid, &a.ak) {
            drop_gone(tx, &i, iai, changed)?;
        }
    }
    Ok(())
}

/// Part `ai` of `c` holding writes the value-less list names, a part not dropped yet (a late copy
/// held value-less, an import listing a purged origin): held value-less for those writes alone,
/// and dropped.
fn drop_gone(tx: &mut Tx<'_>, c: &CommitId, ai: usize, changed: &mut BTreeSet<(Tid, Ak)>) -> Result<()> {
    let Some(m) = tx.core.ix.commits.get(c).filter(|m| !m.dropped.contains_key(&ai)) else { return Ok(()) };
    let gone = gone_of(tx.core, &m.header, c, ai);
    if gone.is_empty() {
        return Ok(());
    }
    strip_pending(tx, c, ai, true)?;
    if let Some(k) = valueless_as(tx, c, ai, &gone, &[])? {
        changed.insert(k);
    }
    drop_part_for(tx, c, ai, DropFor::Purge)
}

/// Writes the value-less lists changed in this transaction, each once however many parts joined it.
pub(crate) fn persist_valueless(tx: &mut Tx<'_>) -> Result<()> {
    for (tid, ak) in std::mem::take(&mut tx.core.valueless_dirty) {
        match tx.core.ix.valueless.get(&(tid, ak.clone())) {
            Some(list) => {
                let enc = encode_owned(list);
                tx.put_aspect_local(records::VALUELESS, &tid, &ak, &enc)?;
            }
            None => {
                tx.txn.remove_local(&records::aspect_key(records::VALUELESS, &tid, &ak), Shred::No)?;
            }
        }
    }
    Ok(())
}

/// After a commit applied: its expiry (now or by timer), its purge request against held
/// deltas, and earlier purge requests against its deltas.
pub(crate) fn on_apply(tx: &mut Tx<'_>, id: &CommitId, changed: &mut BTreeSet<(Tid, Ak)>) -> Result<()> {
    let Some(h) = tx.core.ix.commits.get(id).map(|m| m.header.clone()) else { return Ok(()) };
    let mut purged = BTreeSet::new();
    on_parts(tx, id, &h, &(0..h.aspects.len()).collect(), &mut purged, changed)?;
    purge::apply_request(tx, id, &h, &mut purged)?;
    purged_changed(tx, purged, changed);
    Ok(())
}

/// After late parts `ais` of applied commit `id` joined: `on_apply` for them.
pub(crate) fn on_late(tx: &mut Tx<'_>, id: &CommitId, ais: &BTreeSet<usize>, changed: &mut BTreeSet<(Tid, Ak)>) -> Result<()> {
    let Some(h) = tx.core.ix.commits.get(id).map(|m| m.header.clone()) else { return Ok(()) };
    let mut purged = BTreeSet::new();
    on_parts(tx, id, &h, ais, &mut purged, changed)?;
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
/// them, held snapshots' parts carrying purged values, and on a memory commit what it supersedes
/// or covers. One held value-less (reopened by `takes_late`, or missing again after `uncover`)
/// drops again, now keeping its residue: the list holds only what is past its expiry or a standing
/// purge drops (`rejudge_purges` takes the rest out); so does an import listing a purged origin
/// (`drop_gone`).
fn on_parts(tx: &mut Tx<'_>, id: &CommitId, h: &Header, ais: &BTreeSet<usize>, purged: &mut BTreeSet<(Tid, Ak)>, changed: &mut BTreeSet<(Tid, Ak)>) -> Result<()> {
    for ai in ais.iter().copied() {
        let Some(a) = h.aspects.get(ai) else { continue };
        if let Some(t) = a.expires {
            if t <= tx.now().0 {
                hold_valueless(tx, id, ai, false, purged)?;
            } else {
                tx.put_timer(t, id, ai, T_EXPIRY)?;
            }
        }
        purge::purge_arrived(tx, id, h, ai, purged)?;
        drop_purged_snapshot(tx, id, ai)?;
        drop_gone(tx, id, ai, purged)?;
    }
    if h.ephemeral.is_some() {
        let aspects = ais.iter().filter_map(|ai| h.aspects.get(*ai)).map(|a| (a.tid, a.ak.clone())).collect();
        changed.extend(memory::drop_superseded(tx, &aspects, Some(h.author), Some(id))?);
        memory::drop_covered(tx, &aspects, Some(id))?;
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
                        T_EXPIRY => hold_valueless(tx, &c, ai, false, &mut ch)?,
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
            drop_part_for(tx, &c, ai, DropFor::Cover)
        })
    }

    /// Drops what goes without a right (spec/permissions.md §8): the held deltas that break their
    /// thing's required retention and that this node received after the `required.0^`
    /// delta they break, so a backdated change takes no body it already held, and `required.0^`
    /// deltas by a node that never could set one: those of `only`, else all. Returns their
    /// commits.
    pub fn drop_broken(&mut self, only: Option<&BTreeSet<CommitId>>) -> Result<Vec<CommitId>> {
        let core = &self.core;
        if core.ix.required.is_empty() {
            return Ok(Vec::new());
        }
        let candidates: BTreeSet<CommitId> = match only {
            Some(o) => o.clone(),
            None => core.ix.required.keys().flat_map(|t| core.ix.by_thing.get(t).into_iter().flatten().copied()).collect(),
        };
        let mut due: Vec<(CommitId, usize)> = Vec::new();
        for c in &candidates {
            let Some(m) = core.ix.commits.get(c) else { continue };
            // no header decoded for a commit all valid
            for ai in (0..m.valid.len()).filter(|ai| !m.valid_at(*ai) && m.holds(*ai)) {
                let Some(a) = m.header.aspects.get(ai) else { continue };
                if crate::apply::validity::never_could_set(core, &m.header, a) || crate::apply::validity::broken_by(core, &m.header, c, ai).is_some_and(|p| core.ix.commits.get(&p.commit).is_some_and(|s| s.received < m.received)) {
                    due.push((*c, ai));
                }
            }
        }
        let out = due.iter().map(|x| x.0).collect::<BTreeSet<_>>().into_iter().collect();
        if !due.is_empty() {
            self.run(|tx| {
                for (c, ai) in &due {
                    drop_part_for(tx, c, *ai, DropFor::Broke)?;
                }
                Ok(())
            })?;
        }
        Ok(out)
    }
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
        let write = ct::Edge { role: Role::Write, until: None, invite: None, since: None, tied: None, keyset: None };
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
        e.demote(&t, &Demotion { holder: w, new: None, presync: PreSync::Backdated(before), keep: None }).unwrap();
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
        let write = ct::Edge { role: Role::Write, until: None, invite: None, since: None, tied: None, keyset: None };
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
        e.demote(&t, &Demotion { holder: w, new: None, presync: PreSync::Backdated(before), keep: None }).unwrap();
        let got = e.take_changed();
        assert!(got.commits.contains(&c), "the flipped commit");
        assert!(!got.commits.contains(&first), "not every commit on the flipped aspect");
        assert!(got.aspects.contains(&(t, ak.clone())), "the flipped aspect's state");
        e.drop_body(&first, &t, &ak).unwrap();
        assert!(e.take_changed().commits.contains(&first), "dropped");
    }
}
