//! Retention (spec/commits.md §5–§6; spec/crdt.md §4.7, §4.8, §8): deaths per body from the
//! crdt change summary, keep-at-most drops (in the killing transaction for at most 0 but for
//! bodies with a live write, which get `AT_MOST_GRACE` more, else by timer), expiry at T
//! (value-less, body dropped), purge requests judged by perm at the
//! request's time (also against deltas arriving later), compaction snapshots and the covered
//! test. node-sync judges what to delete at blind nodes and what to re-snapshot from the commit
//! index (dropped parts, `covered`), so no queue is kept here.
//!
//! A body here is one delta (one commit's deltas on one aspect): finer than a projection, so
//! a projection's bounds are those of its deltas. Its death records use the commit ID as the
//! store's body ID.

use crate::engine::records::{self, Rd, Wr};
use crate::engine::write::{CommitPlan, Resolved, build_and_apply};
use crate::engine::{Core, Engine, Owned, Tx};
use crate::error::{Error, Result};
use crate::events::{Cause, Event};
use osis_commit::{Decoded, Form, Header, Kind, PurgeItem};
use osis_base::{Ak, BlobId, CommitId, Tid, Ts};
use osis_crdt::{Fragment, Frontiers};
use osis_perm::{At, Point, PurgeBy};
use osis_schema::core_types::is_membership_class;
use osis_store::Shred;
use std::collections::BTreeSet;

mod deaths;
pub(crate) mod forget;

pub(crate) use deaths::{load_deaths_due, mark_deaths_due, mark_if_bounded, note_copies, note_deaths, rejudge_deaths, settle_due};

/// A body a due timer drops with a live write: its commit and every aspect of it.
pub(crate) type LiveDrop = (CommitId, Vec<(Tid, Ak)>);

const T_EXPIRY: u8 = 1;
const T_AT_MOST: u8 = 2;

pub(crate) fn encode_owned(v: &[Owned]) -> Vec<u8> {
    let mut w = Wr::new().u32(v.len() as u32);
    for o in v {
        w = match o {
            Owned::Node { node, lo, hi } => w.u8(0).raw(node.as_bytes()).u64(*lo).u64(*hi),
            Owned::Commit(c) => w.u8(1).raw(&c.0),
            Owned::Dots { src, ctrs } => {
                let b = match src.kind() {
                    osis_crdt::SourceKind::Node(t) => t.as_bytes().to_vec(),
                    osis_crdt::SourceKind::Commit(c) => c.0.to_vec(),
                    osis_crdt::SourceKind::Derived(_) => Vec::new(),
                };
                let mut w = w.u8(2).u8(b.len() as u8).raw(&b).u32(ctrs.len() as u32);
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
            0 => Owned::Node { node: r.tid()?, lo: r.u64()?, hi: r.u64()? },
            1 => Owned::Commit(CommitId(r.arr()?)),
            _ => {
                let src = match r.u8()? {
                    15 => osis_crdt::Source::node(r.tid()?),
                    32 => osis_crdt::Source::commit(CommitId(r.arr()?)),
                    _ => return Err(crate::error::Error::Corrupt("owned source")),
                };
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

fn aspect_index(tx: &Tx<'_>, c: &CommitId, tid: &Tid, ak: &Ak) -> Option<usize> {
    tx.core.ix.commits.get(c)?.header.aspects.iter().position(|a| a.tid == *tid && a.ak == *ak)
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
/// subset and retention class) and the aspects it holds. Its ID keys the death records.
pub(crate) fn body_class(core: &Core, h: &Header, c: &CommitId, ai: usize) -> (BlobId, Vec<usize>) {
    let key = |a: &osis_commit::AspectEntry| (reader(core, &a.tid), a.retention, a.expires, a.keys.clone());
    let Some(me) = h.aspects.get(ai) else { return (BlobId(c.0), vec![ai]) };
    let k = key(me);
    let members: Vec<usize> = h.aspects.iter().enumerate().filter(|(_, a)| key(a) == k).map(|(i, _)| i).collect();
    let first = members.first().copied().unwrap_or(ai) as u32;
    let mut hs = osis_base::hash::Hasher::new();
    hs.update(&c.0);
    hs.update(&first.to_be_bytes());
    (BlobId(hs.finalize()), members)
}

/// First and last death so far over a body's deltas.
pub(crate) fn class_deaths(tx: &mut Tx<'_>, h: &Header, body: &BlobId, members: &[usize]) -> Result<Option<(Ts, Ts)>> {
    let mut out: Option<(Ts, Ts)> = None;
    for ai in members {
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

/// The aspect index of `(tid, ak)` in held commit `c`, if that part is held (not dropped, not
/// still to arrive).
pub(crate) fn held_part(core: &Core, c: &CommitId, tid: &Tid, ak: &Ak) -> Option<usize> {
    let m = core.ix.commits.get(c)?;
    let ai = m.header.aspects.iter().position(|a| a.tid == *tid && a.ak == *ak)?;
    // a part that never arrived (`missing`, a late part) is not held
    (!m.dropped.contains(&(ai, 0)) && !m.missing.contains(&ai)).then_some(ai)
}

pub(crate) fn check_at_most(tx: &mut Tx<'_>, c: &CommitId, ai: usize) -> Result<()> {
    let Some(m) = tx.core.ix.commits.get(c).cloned() else { return Ok(()) };
    let Some(a) = m.header.aspects.get(ai) else { return Ok(()) };
    let (body, members) = body_class(tx.core, &m.header, c, ai);
    // deaths awaiting a recompute may be early: the recompute judges the body (`settle_due`);
    // tests may keep every body (`Engine::keep_bodies`)
    if tx.core.keep_bodies || members.iter().filter_map(|x| m.header.aspects.get(*x)).any(|x| tx.core.ix.deaths_due.contains(&(x.tid, x.ak.clone()))) {
        return Ok(());
    }
    let d = class_deaths(tx, &m.header, &body, &members)?;
    let live = a.retention.at_most.rel.is_some() && d.is_some() && live(tx, c, ai)?;
    let keep = osis_commit::retention::body_keep(&m.header, &a.retention, d.map(|d| d.0.wall_ms().0), d.map(|d| d.1.wall_ms().0), live);
    if let Some(t) = keep.at_most {
        // at most 0: the replacing node drops a body with no live write in the killing
        // transaction, even when the killing `ts` is ahead of its clock; one with a live write
        // keeps to the next compaction or its bound (`body_keep`), so an edit erasing part of
        // it does not re-snapshot the aspect
        let zero = a.retention.at_most.rel == Some(0) && d.is_some() && !live;
        if t <= tx.now().0 || zero {
            for x in members {
                drop_part(tx, c, x)?;
            }
        } else {
            tx.txn.put_local(&records::timer_key(t, c, ai), &[T_AT_MOST], Shred::No)?;
        }
    }
    Ok(())
}

/// Drops the delta of aspect `ai` of `c` from its body (spec/commits.md §5): the commit is kept
/// without it (same header), the body's death records for it shredded, the aspect's state
/// rewritten shredded with its undo buffer cleared (node-sync deletes it at blind nodes, judged
/// from the dropped parts).
pub(crate) fn drop_part(tx: &mut Tx<'_>, c: &CommitId, ai: usize) -> Result<()> {
    drop_part_as(tx, c, ai, false)
}

/// `drop_part`; `cover`: dropped as covered (compaction, `Meta::cover_drops`).
fn drop_part_as(tx: &mut Tx<'_>, c: &CommitId, ai: usize, cover: bool) -> Result<()> {
    tx.core.touch();
    let Some(mut m) = tx.core.ix.commits.get(c).cloned() else { return Ok(()) };
    let Some(a) = m.header.aspects.get(ai).cloned() else { return Ok(()) };
    let n = a.hashes.len();
    if (0..n).all(|di| m.dropped.contains(&(ai, di))) {
        return Ok(());
    }
    // what a snapshot carried goes with its body: whether it was live is kept (`snapshot_live`)
    if m.header.kind.is_compaction() && snapshot_live(tx, &m.header, c, &[ai])? {
        m.live_drops.insert(ai);
    }
    // the held valid snapshots covering it: their copies of its writes stay its writes
    let snaps: Vec<CommitId> = tx.core.ix.snapshots.get(&(a.tid, a.ak.clone())).into_iter().flatten().map(|x| x.1).filter(|s| s != c).collect();
    let mut by = BTreeSet::new();
    for s in snaps {
        if covered(tx, &s, c, &a.tid, &a.ak)? == Some(true) {
            by.insert(s);
        }
    }
    if !by.is_empty() {
        m.covered_by.insert(ai, by);
        if cover {
            m.cover_drops.insert(ai);
        }
    }
    // a snapshot dropped other than as covered keeps its frontiers and `Absorbed` (counters
    // and IDs): what it gave still counts as received while it is valid (spec/commits.md §5);
    // a covered one's coverers reach them
    let kept = !m.cover_drops.contains(&ai) && m.header.kind.is_compaction();
    if let Some(g) = tx.core.ix.snapshots.get(&(a.tid, a.ak.clone())).and_then(|v| v.iter().find(|x| x.1 == *c)).filter(|_| kept) {
        m.gives.insert(ai, (g.2.clone(), g.3.clone()));
    }
    for di in 0..n {
        m.dropped.insert((ai, di));
    }
    // a part missing (again, `uncover`) and dropped is dropped, as an open reads it: received,
    // so snapshots' copies of its writes are carried writes no more
    if m.missing.remove(&ai) {
        let h = m.header.clone();
        crate::apply::validity::uncarry(tx.core, c, &h, &|x| x == ai);
    }
    // the dropped deltas, to find what of the state holds copies of their writes
    let bodies: Vec<Fragment> = crate::apply::held_parts(tx, c, ai)?.into_iter().map(Decoded::into_fragment).collect();
    if let Some(blob) = tx.get_commit(c)? {
        let rest = osis_commit::rewrite(&blob, |x, _| x == ai);
        tx.put_commit(c, &rest, &m, Shred::Yes, None)?;
    }
    let (body, _) = body_class(tx.core, &m.header, c, ai);
    let vouched = m.header.kind.is_compaction() && m.valid.get(ai).copied().unwrap_or(false);
    tx.core.ix.commits.insert(*c, m);
    crate::apply::note_gives(tx.core, c);
    crate::apply::forget_snapshot(tx.core, &a.tid, &a.ak, c);
    tx.core.forget_live(&a.tid, &a.ak);
    tx.txn.drop_body(&body, &[(a.tid, a.ak.clone())])?;
    tx.shred_bodies(&a.tid, &a.ak, &bodies)?;
    // a valid snapshot dropped vouches no more for invalid deltas' writes it carried
    // (spec/permissions.md §5.2)
    if vouched && !crate::apply::invalid_of(tx.core, &a.tid, &a.ak).is_empty() && crate::apply::unmerge_fell(tx, &a.tid, &a.ak, None)? {
        tx.core.mark_aspect_changed(&a.tid, &a.ak);
    }
    Ok(())
}

/// Parts on `(tid, ak)` dropped as covered (`Meta::cover_drops`) that no coverer carries any
/// more (each turned invalid, or was itself dropped as covered under covers none of which does;
/// one dropped for its bound, expiry or a purge carries while valid;
/// `Meta::covered_by`) are missing again (spec/permissions.md §5.2): they give nothing, as at a node that never held
/// them, until the body arrives again (a node still holding it finds it uncovered and
/// re-uploads it, spec/sync.md §6; node-sync fetches it again, `Changed::undropped`). Returns
/// the own writes of the deltas among them, for the caller's rebuild to strip.
pub(crate) fn uncover(tx: &mut Tx<'_>, tid: &Tid, ak: &Ak) -> Result<Vec<Owned>> {
    fn carries(core: &Core, s: &CommitId, tid: &Tid, ak: &Ak, seen: &mut BTreeSet<CommitId>) -> bool {
        let Some(m) = core.ix.commits.get(s) else { return false };
        let Some(ai) = m.view.aspects.iter().position(|a| a.tid == *tid && a.ak == *ak) else { return false };
        let valid = m.valid.get(ai).copied().unwrap_or(false);
        if !m.dropped.contains(&(ai, 0)) {
            return !m.missing.contains(&ai) && valid;
        }
        // dropped other than as covered (bound, purge, expiry): its writes stay in the state and
        // it never comes back as missing, so it carries while valid
        if valid && !m.cover_drops.contains(&ai) {
            return true;
        }
        // a coverer dropped in turn carries what its coverers carry (`apply::covers_dropped`)
        seen.insert(*s) && m.covered_by.get(&ai).is_some_and(|ss| ss.iter().any(|x| carries(core, x, tid, ak, seen)))
    }
    let held: Vec<CommitId> = tx.core.ix.by_aspect.get(&(*tid, ak.clone())).into_iter().flatten().map(|x| x.1).collect();
    let mut lost = Vec::new();
    for c in held {
        let Some(m) = tx.core.ix.commits.get(&c) else { continue };
        let Some(ai) = m.view.aspects.iter().position(|a| a.tid == *tid && a.ak == *ak) else { continue };
        if m.dropped.contains(&(ai, 0)) && m.cover_drops.contains(&ai) && !carries(tx.core, &c, tid, ak, &mut BTreeSet::new()) {
            lost.push((c, ai));
        }
    }
    let mut owned = Vec::new();
    if !lost.is_empty() {
        tx.core.forget_live(tid, ak);
    }
    for (c, ai) in lost {
        tx.core.touch();
        let Some(mut m) = tx.core.ix.commits.get(&c).cloned() else { continue };
        m.dropped.retain(|x| x.0 != ai);
        m.missing.insert(ai);
        m.live_drops.remove(&ai);
        m.covered_by.remove(&ai);
        m.cover_drops.remove(&ai);
        if m.gives.remove(&ai).is_some() {
            tx.core.ix.dropped_snapshots.remove(&(*tid, ak.clone()), &c);
        }
        if m.view.kind.has_own_writes() {
            owned.extend(Owned::of_view(&m.view, &c, ai));
        }
        if let Some(blob) = tx.get_commit(&c)? {
            tx.put_commit(&c, &blob, &m, Shred::No, None)?;
        }
        tx.core.ix.commits.insert(c, m);
        if let Some(ch) = &mut tx.core.changed {
            ch.undropped.insert(c);
        }
    }
    // held snapshots' copies of the writes of deltas now never received are carried writes
    if !owned.is_empty() {
        let held: Vec<CommitId> = tx.core.ix.by_aspect.get(&(*tid, ak.clone())).into_iter().flatten().map(|x| x.1).filter(|s| tx.core.ix.commits.get(s).is_some_and(|m| crate::apply::is_kind_snapshot(m.view.kind))).collect();
        for s in held {
            let Some(sai) = aspect_index(tx, &s, tid, ak) else { continue };
            for d in crate::apply::held_parts(tx, &s, sai)? {
                if let Decoded::Snapshot(sn) = d {
                    crate::apply::validity::note_carried(tx.core, tid, ak, &s, &sn.fragment);
                }
            }
        }
    }
    Ok(owned)
}

/// Holds the value-carrying writes of a delta value-less from now on (spec/crdt.md §4.7).
fn make_valueless(tx: &mut Tx<'_>, c: &CommitId, ai: usize) -> Result<Option<(Tid, Ak)>> {
    tx.core.touch();
    let Some(m) = tx.core.ix.commits.get(c).cloned() else { return Ok(None) };
    let Some(a) = m.header.aspects.get(ai) else { return Ok(None) };
    let Some(o) = Owned::of(&m.header, c, ai).filter(|_| m.header.kind.has_own_writes()) else { return Ok(None) };
    let k = (a.tid, a.ak.clone());
    let list = tx.core.ix.valueless.entry_or_default(k.clone());
    if !list.contains(&o) {
        list.push(o.clone());
    }
    let enc = encode_owned(list);
    tx.txn.put_local(&records::aspect_key(records::VALUELESS, &a.tid, &a.ak), &enc, Shred::No)?;
    // the delta's writes lie where it touched the state (a page of a paged state)
    let bodies: Vec<Fragment> = crate::apply::held_parts(tx, c, ai)?.into_iter().map(Decoded::into_fragment).collect();
    tx.strip_bodies(&a.tid, &a.ak, &bodies, &o)?;
    Ok(Some(k))
}

fn expire(tx: &mut Tx<'_>, c: &CommitId, ai: usize, changed: &mut BTreeSet<(Tid, Ak)>) -> Result<()> {
    if let Some(k) = make_valueless(tx, c, ai)? {
        changed.insert(k);
    }
    drop_part(tx, c, ai)
}

/// Does a held delta of `(tid, ak)` name a schema (snapshots included)?
fn typed(core: &Core, tid: &Tid, ak: &Ak) -> bool {
    let commits = core.ix.by_aspect.get(&(*tid, ak.clone())).into_iter().flatten().filter_map(|(_, c)| core.ix.commits.get(c));
    commits.into_iter().any(|m| m.header.aspects.iter().any(|a| a.tid == *tid && a.ak == *ak && a.schema.is_some()))
}

fn purge_by(p: osis_schema::PurgeBy) -> PurgeBy {
    PurgeBy::from_code(p as u64).unwrap_or(PurgeBy::Nobody)
}

/// Does purge item `item` of commit `pc` (header `p`) name aspect `ai` of commit `c` (header
/// `ch`), with its author holding the right at the request's time (spec/permissions.md §8)?
fn purge_allowed(core: &Core, p: &Header, pc: &CommitId, item: &PurgeItem, ch: &Header, c: &CommitId, ai: usize) -> bool {
    let Some(a) = ch.aspects.get(ai) else { return false };
    if is_membership_class(a.ak.as_str()) || a.tid != *item.tid() || a.ak != *item.ak() {
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
    if let Some(k) = make_valueless(tx, c, ai)? {
        changed.insert(k);
    }
    drop_part(tx, c, ai)?;
    // snapshots carrying the purged values (spec/commits.md §5)
    if let Some(o) = Owned::of(&m.header, c, ai) {
        let snaps: Vec<CommitId> = tx.core.ix.by_aspect.get(&(a.tid, a.ak.clone())).into_iter().flatten().map(|x| x.1).filter(|s| tx.core.ix.commits.get(s).is_some_and(|x| crate::apply::is_kind_snapshot(x.header.kind))).collect();
        for s in snaps {
            let Some(sai) = aspect_index(tx, &s, &a.tid, &a.ak) else { continue };
            for d in crate::apply::held_parts(tx, &s, sai)? {
                let f = d.into_fragment();
                let mut g = f.clone();
                g.strip(&|x| o.owns(x));
                if g != f {
                    drop_part(tx, &s, sai)?;
                    break;
                }
            }
        }
    }
    Ok(())
}

/// Drops held snapshot part `(s, sai)` if it carries a value of a delta a held purge request
/// purges (spec/commits.md §5): `purge_one` judges the snapshots held when the request or the
/// named delta arrives; this one a snapshot part arriving after both.
pub(crate) fn drop_purged_snapshot(tx: &mut Tx<'_>, s: &CommitId, sai: usize) -> Result<()> {
    let Some(sm) = tx.core.ix.commits.get(s).cloned() else { return Ok(()) };
    let Some(a) = sm.header.aspects.get(sai).cloned() else { return Ok(()) };
    if !crate::apply::is_kind_snapshot(sm.header.kind) {
        return Ok(());
    }
    let mut owned = Vec::new();
    for pc in purge_requests(tx, &a.tid, &a.ak)? {
        let Some(p) = tx.core.ix.commits.get(&pc).map(|m| m.header.clone()) else { continue };
        for item in &p.purge {
            let named: Vec<CommitId> = match item {
                PurgeItem::Commit { commit, .. } => vec![*commit],
                PurgeItem::Aspect { .. } => tx.core.ix.by_aspect.get(&(a.tid, a.ak.clone())).into_iter().flatten().map(|x| x.1).collect(),
            };
            for c in named.into_iter().filter(|c| c != s) {
                let (Some(m), Some(ai)) = (tx.core.ix.commits.get(&c).cloned(), aspect_index(tx, &c, &a.tid, &a.ak)) else { continue };
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
    for d in crate::apply::held_parts(tx, s, sai)? {
        let f = d.into_fragment();
        let mut g = f.clone();
        g.strip(&|x| owned.iter().any(|o| o.owns(x)));
        if g != f {
            return drop_part(tx, s, sai);
        }
    }
    Ok(())
}

/// After a commit applied: its expiry (now or by timer), its purge request against held
/// deltas, and earlier purge requests against its deltas.
pub(crate) fn on_apply(tx: &mut Tx<'_>, id: &CommitId, changed: &mut BTreeSet<(Tid, Ak)>) -> Result<()> {
    let Some(m) = tx.core.ix.commits.get(id).cloned() else { return Ok(()) };
    let h = m.header.clone();
    let mut purged = BTreeSet::new();
    for (ai, a) in h.aspects.iter().enumerate() {
        if let Some(t) = a.expires {
            if t <= tx.now().0 {
                expire(tx, id, ai, &mut purged)?;
            } else {
                tx.txn.put_local(&records::timer_key(t, id, ai), &[T_EXPIRY], Shred::No)?;
            }
        }
        // purge requests held before this delta arrived
        {
            for pc in purge_requests(tx, &a.tid, &a.ak)? {
                let items: Vec<PurgeItem> = tx.core.ix.commits.get(&pc).map(|p| p.header.purge.clone()).unwrap_or_default();
                for item in items {
                    purge_one(tx, &pc, &item, id, ai, &mut purged)?;
                }
            }
            drop_purged_snapshot(tx, id, ai)?;
        }
    }
    if !h.purge.is_empty() {
        for item in &h.purge {
            let held: Vec<CommitId> = tx.core.ix.by_aspect.get(&(*item.tid(), item.ak().clone())).map(|s| s.iter().map(|x| x.1).collect()).unwrap_or_default();
            for c in held {
                if let Some(ai) = aspect_index(tx, &c, item.tid(), item.ak()) {
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
    }
    for (t, a) in &purged {
        tx.core.mark_aspect_changed(t, a);
    }
    if !purged.is_empty() {
        tx.core.events.queue(Event::Changed { cause: Cause::Purge, changed: purged.iter().cloned().collect() });
        changed.extend(purged);
    }
    Ok(())
}

impl Engine {
    /// Replays the deaths of the aspects marked by `mark_deaths_due`, in one transaction: every
    /// transaction ends with it unless `Core::defer_deaths` (node-sync's steps), and every read
    /// of deaths or bounds runs it first.
    /// Batches deaths replays (spec/crdt.md §4.8): while on, a commit out of order marks its
    /// aspect and the replay waits for the next read of deaths or bounds, so ingesting many
    /// commits costs one replay per aspect; off replays what waits. node-sync turns it on for
    /// each step.
    pub fn defer_deaths(&mut self, on: bool) -> Result<()> {
        self.core.defer_deaths = on;
        if on { Ok(()) } else { self.settle_deaths() }
    }

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
        self.run(|tx| {
            let now = tx.now().0;
            let mut due = Vec::new();
            tx.scan(records::TIMER, |k, v| {
                let (t, c, ai) = records::parse_timer(k)?;
                if t <= now {
                    due.push((k.to_vec(), c, ai, v.first().copied().unwrap_or(0)));
                }
                Ok(())
            })?;
            let mut changed = BTreeSet::new();
            for (k, c, ai, kind) in due {
                // judged again by node-sync whatever the timer did
                tx.core.mark_changed(c);
                tx.txn.remove_local(&[records::TIMER, &k].concat(), Shred::No)?;
                match kind {
                    T_EXPIRY => expire(tx, &c, ai, &mut changed)?,
                    // judged again: liveness may have changed since the timer was set
                    _ => check_at_most(tx, &c, ai)?,
                }
            }
            for (t, a) in &changed {
                tx.core.mark_aspect_changed(t, a);
            }
            if !changed.is_empty() {
                tx.core.events.queue(Event::Changed { cause: Cause::Expiry, changed: changed.into_iter().collect() });
            }
            Ok(())
        })?;
        self.reexamine()
    }

    /// The bodies the due keep-at-most timers will drop with a live write, as (commit, every
    /// aspect of the body): a node that may write them snapshots them first (spec/commits.md
    /// §5).
    pub fn due_live_drops(&mut self) -> Result<Vec<LiveDrop>> {
        let due = self.run(|tx| {
            let now = tx.now().0;
            let mut due = Vec::new();
            tx.scan(records::TIMER, |k, v| {
                let (t, c, ai) = records::parse_timer(k)?;
                if t <= now && v.first() == Some(&T_AT_MOST) {
                    due.push((c, ai));
                }
                Ok(())
            })?;
            let mut out = Vec::new();
            for (c, ai) in due {
                let Some(h) = tx.core.ix.commits.get(&c).map(|m| m.header.clone()) else { continue };
                let (_, members) = body_class(tx.core, &h, &c, ai);
                let aspects: Vec<(Tid, Ak)> = members.iter().filter_map(|x| h.aspects.get(*x)).map(|a| (a.tid, a.ak.clone())).collect();
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

    /// When the next expiry or keep-at-most timer is due (corrected wall ms).
    pub fn next_timer(&mut self) -> Result<Option<u64>> {
        self.run(|tx| {
            let first = tx.txn.scan_local(records::TIMER, &[], 1)?;
            Ok(first.first().and_then(|(k, _)| k.get(records::TIMER.len()..)).and_then(|k| records::parse_timer(k).ok()).map(|(t, _, _)| t))
        })
    }

    /// Drops a body (compaction between the bounds, executed by node-sync): aspect `ak` of
    /// commit `c`.
    pub fn drop_body(&mut self, c: &CommitId, tid: &Tid, ak: &Ak) -> Result<()> {
        let (c, tid, ak) = (*c, *tid, ak.clone());
        self.run(|tx| {
            let ai = aspect_index(tx, &c, &tid, &ak).ok_or(Error::UnknownCommit(c))?;
            drop_part_as(tx, &c, ai, true)
        })
    }

    /// Keep bounds of a held body (wall ms): (keep at least, keep at most).
    pub fn body_keep(&mut self, c: &CommitId, tid: &Tid, ak: &Ak) -> Result<osis_commit::retention::Keep> {
        self.settle_deaths()?;
        let (c, tid, ak) = (*c, *tid, ak.clone());
        let (h, r, d) = self.run(|tx| {
            let ai = aspect_index(tx, &c, &tid, &ak).ok_or(Error::UnknownCommit(c))?;
            let h = tx.core.ix.commits.get(&c).map(|m| m.header.clone()).ok_or(Error::UnknownCommit(c))?;
            let r = h.aspects.get(ai).ok_or(Error::UnknownCommit(c))?.retention;
            let (body, members) = body_class(tx.core, &h, &c, ai);
            let d = class_deaths(tx, &h, &body, &members)?;
            Ok((h, r, d))
        })?;
        let live = r.at_most.rel.is_some() && d.is_some() && self.body_live(&c, &tid, &ak)?;
        Ok(osis_commit::retention::body_keep(&h, &r, d.map(|d| d.0.wall_ms().0), d.map(|d| d.1.wall_ms().0), live))
    }

    /// First and last death so far of the writes of the body holding aspect `ak` of `c`.
    pub fn deaths(&mut self, c: &CommitId, tid: &Tid, ak: &Ak) -> Result<Option<(Ts, Ts)>> {
        self.settle_deaths()?;
        let (c, tid, ak) = (*c, *tid, ak.clone());
        self.run(|tx| {
            let ai = aspect_index(tx, &c, &tid, &ak).ok_or(Error::UnknownCommit(c))?;
            let h = tx.core.ix.commits.get(&c).map(|m| m.header.clone()).ok_or(Error::UnknownCommit(c))?;
            let (body, members) = body_class(tx.core, &h, &c, ai);
            class_deaths(tx, &h, &body, &members)
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
        let live = self.run(|tx| match aspect_index(tx, &c, &tid, &ak) {
            Some(ai) => live(tx, &c, ai).map(Some),
            None => Ok(None),
        })?;
        // an unknown commit counts live, uncached (its apply may change nothing here)
        let Some(live) = live else { return Ok(true) };
        self.core.live_bodies.insert(key, live);
        Ok(live)
    }

    /// Whether `c` is known with an aspect `(tid, ak)` whose body is not dropped: true for a
    /// missing part too (`Engine::aspect_dump` shows which).
    pub fn body_not_dropped(&self, c: &CommitId, tid: &Tid, ak: &Ak) -> bool {
        let Some(m) = self.core.ix.commits.get(c) else { return false };
        let Some(ai) = m.header.aspects.iter().position(|a| a.tid == *tid && a.ak == *ak) else { return false };
        !m.dropped.contains(&(ai, 0))
    }

    /// Writes a compaction snapshot of `(tid, ak)` from this node's whole state (spec/commits.md
    /// §2, spec/crdt.md §8): values of deltas with an expiry and of purged writes go
    /// value-less; frontiers from the receipt record.
    pub fn snapshot(&mut self, tid: &Tid, ak: &Ak) -> Result<Option<CommitId>> {
        let (tid, ak) = (*tid, ak.clone());
        if ak.as_str() == "/members" || ak.as_str() == "/tenures" {
            return Err(Error::Misuse("/members and /tenures are compacted by roster snapshots"));
        }
        self.run(|tx| {
            let node = tx.core.id.tid();
            let ts = tx.core.hlc.next();
            crate::engine::write::check_authority(tx.core, tx.core.id.tid(), &Default::default(), &tid, ak.as_str(), ts)?;
            tx.load(&tid, &ak)?;
            let Some(mut st) = tx.core.states.get(&(tid, ak.clone())).cloned().flatten() else { return Ok(None) };
            if ak.as_str() == "/secrets" && !crate::apply::keys::may_compact(tx.core, &tid, &st) {
                return Err(Error::Misuse("/secrets keys an epoch not established here (spec/crypto.md §4)"));
            }
            let expiring: Vec<Owned> = tx
                .core
                .ix.by_aspect
                .get(&(tid, ak.clone()))
                .into_iter()
                .flatten()
                .filter_map(|(_, c)| {
                    let m = tx.core.ix.commits.get(c)?;
                    let ai = m.header.aspects.iter().position(|a| a.tid == tid && a.ak == ak)?;
                    m.header.aspects.get(ai)?.expires?;
                    Owned::of(&m.header, c, ai)
                })
                .collect();
            if !expiring.is_empty() {
                st.strip(&|d| expiring.iter().any(|o| o.owns(d)));
            }
            // frontiers cover only counters whose writes this state reflects: applied, valid
            let mut fr = std::collections::BTreeMap::new();
            let from = (tid, ak.clone(), Tid::from_bytes([0; 15]));
            for ((_, _, n), ranges) in tx.core.ix.ranges.range(from..).take_while(|((t, a, _), _)| *t == tid && *a == ak) {
                let mut next = 1u64;
                for (lo, (hi, c)) in ranges {
                    let ok = tx.core.ix.commits.get(c).is_some_and(|m| m.header.aspects.iter().zip(&m.valid).any(|(x, v)| *v && x.tid == tid && x.ak == ak));
                    if *lo != next || !ok {
                        break;
                    }
                    next = *hi;
                }
                if next > 1 {
                    fr.insert(*n, next - 1);
                }
            }
            let frontiers = Frontiers(fr);
            // commits judged by ID (commit form, imports) whose valid writes the state reflects
            let mut absorbed = std::collections::BTreeMap::new();
            for (_, c) in tx.core.ix.by_aspect.get(&(tid, ak.clone())).into_iter().flatten() {
                let Some(m) = tx.core.ix.commits.get(c) else { continue };
                let by_id = m.header.kind == Kind::Import || (m.header.form == Form::Commit && m.header.kind.has_own_writes());
                if by_id && m.header.aspects.iter().zip(&m.valid).any(|(x, v)| *v && x.tid == tid && x.ak == ak) {
                    absorbed.insert(*c, m.header.author);
                }
            }
            let kind = if is_membership_class(ak.as_str()) { Kind::MembershipSnapshot } else { Kind::ContentSnapshot };
            // the schema's default bounds: core, or a known schema declaring the AK; none for an
            // untyped aspect (no held delta names a schema), and no snapshot for a typed one
            // whose schema this node does not know (spec/commits.md §5)
            let schema = if ak.is_core() { Some(std::sync::Arc::new(osis_schema::core_schema().clone())) } else { tx.core.schemas.values().find(|s| s.aspects.contains_key(ak.as_str())).cloned() };
            if schema.is_none() && typed(tx.core, &tid, &ak) {
                return Ok(None);
            }
            let plan = CommitPlan { kind, ts, actor: node, form: Form::Node, creates: Default::default(), purge: Vec::new(), undoes: None, frontier: None, origins: Vec::new(), signer: tx.core.id.tid(), blind: crate::engine::write::draw_blind(&mut *tx.rng) };
            let d = Resolved { tid, ak, fragment: st, lo: 0, hi: 0, schema, schema_ref: None, retention: None, expires: None, frontiers: Some((frontiers, absorbed)), chunks: Vec::new(), split: false };
            build_and_apply(tx, plan, vec![d]).map(Some)
        })
    }

    /// Is the body of `ak` in commit `c` covered by snapshot commit `s` (spec/commits.md §5):
    /// joining each of its deltas into the snapshot's fragment leaves its canonical bytes
    /// unchanged, and for a node-form body, the snapshot's frontier holds its counters, for a
    /// body judged by commit ID, the snapshot lists it as absorbed (so every holder of the
    /// snapshot counts the body as received once it is dropped, spec/crdt.md §8).
    /// `None` when either is not held (nothing is established).
    pub fn covered(&mut self, s: &CommitId, c: &CommitId, tid: &Tid, ak: &Ak) -> Result<Option<bool>> {
        let (s, c, tid, ak) = (*s, *c, *tid, ak.clone());
        self.run(|tx| covered(tx, &s, &c, &tid, &ak))
    }
}

/// `Engine::covered` in `tx`.
fn covered(tx: &mut Tx<'_>, s: &CommitId, c: &CommitId, tid: &Tid, ak: &Ak) -> Result<Option<bool>> {
    let (s, c, tid, ak) = (*s, *c, *tid, ak.clone());
    let (Some(sai), Some(cai)) = (aspect_index(tx, &s, &tid, &ak), aspect_index(tx, &c, &tid, &ak)) else { return Ok(None) };
    // an invalid snapshot gives nothing, so covers nothing (spec/permissions.md §5.2)
    if !crate::apply::validity::snapshot_valid(tx.core, &s, &tid, &ak) {
        return Ok(Some(false));
    }
    // a snapshot body still to arrive (or missing again, `uncover`): nothing is established
    // without its content (a delta's frontier or absorbed check below stands alone)
    if tx.core.ix.commits.get(&c).is_some_and(|m| m.view.kind.is_compaction() && m.missing.contains(&cai)) {
        return Ok(None);
    }
    let parts = crate::apply::held_parts(tx, &s, sai)?;
    if let (Some(m), [osis_commit::Decoded::Snapshot(sn)]) = (tx.core.ix.commits.get(&c), parts.as_slice())
        && m.header.form == osis_commit::Form::Node
        && m.header.kind.has_own_writes()
        && let Some(a) = m.header.aspects.get(cai)
        && sn.frontiers.0.get(&m.header.author).is_none_or(|f| f.saturating_add(1) < a.hi)
    {
        return Ok(Some(false));
    }
    if let (Some(m), [osis_commit::Decoded::Snapshot(sn)]) = (tx.core.ix.commits.get(&c), parts.as_slice())
        && (m.header.kind == Kind::Import || (m.header.form == osis_commit::Form::Commit && m.header.kind.has_own_writes()))
        && !sn.absorbed.contains_key(&c)
    {
        return Ok(Some(false));
    }
    let held = crate::apply::held_parts(tx, &c, cai)?;
    // a snapshot covers another only if its frontiers hold the other's too: otherwise a
    // holder of it alone does not count what the other's frontier gave as received
    if let ([osis_commit::Decoded::Snapshot(sn)], [osis_commit::Decoded::Snapshot(other)]) = (parts.as_slice(), held.as_slice())
        && (other.frontiers.0.iter().any(|(n, f)| sn.frontiers.0.get(n).is_none_or(|g| g < f)) || other.absorbed.keys().any(|c| !sn.absorbed.contains_key(c)))
    {
        return Ok(Some(false));
    }
    let snap: Vec<Fragment> = parts.into_iter().map(Decoded::into_fragment).collect();
    let [snap] = snap.as_slice() else { return Ok(None) };
    // a body this node holds no delta of joins nothing: covered
    if held.is_empty() {
        return Ok(Some(true));
    }
    let Some(m) = tx.core.ix.commits.get(&c).cloned() else { return Ok(None) };
    let is_snapshot = m.header.kind.is_compaction();
    let mut body: Vec<Fragment> = held.into_iter().map(Decoded::into_fragment).collect();
    // a snapshot body's copies of writes a received valid delta supplies count for
    // nothing (spec/permissions.md §5.2): what it must carry is the rest, its copies of
    // invalid deltas' writes included (it vouches for them)
    if is_snapshot {
        for b in &mut body {
            crate::apply::strip_copies_where(tx.core, &tid, &ak, b, &|_, m, ai| m.valid.get(ai).copied().unwrap_or(false));
        }
    }
    let before = crate::engine::state::encode(snap)?;
    let mut j = snap.clone();
    for b in &body {
        j.join(b.clone());
    }
    if crate::engine::state::encode(&j)? != before {
        return Ok(Some(false));
    }
    // the snapshot's copies of the body's writes are the body's (a copy at another
    // value, `ts` or position, or under a dot the body owns but lacks, joins as
    // unchanged): under its own dots, or a snapshot body's carried writes (records
    // without a `ts`, such as the entry another's write is nested in, are no writes)
    let mut ranges: Vec<(osis_crdt::Source, u64, u64)> = if is_snapshot {
        body.iter().flat_map(|b| b.writes()).filter(|w| w.1.is_some()).map(|(d, _)| (d.src.clone(), d.ctr, d.ctr.saturating_add(1))).collect()
    } else {
        crate::apply::validity::owned_ranges(&m.header, &c, cai)
    };
    ranges.sort();
    ranges.dedup();
    let body: Vec<&Fragment> = body.iter().collect();
    let Some(ix) = crate::apply::validity::copy_index(tx, &s, &tid, &ak, Some(snap))? else { return Ok(None) };
    Ok(Some(ix.outside(&ranges, &body).is_empty()))
}

/// `Engine::body_live` of the body holding aspect `ai` of `c`, judged against the state in
/// `tx`: a function of the commits applied (the join's), so alike at nodes that applied the
/// same ones.
fn live(tx: &mut Tx<'_>, c: &CommitId, ai: usize) -> Result<bool> {
    let Some(h) = tx.core.ix.commits.get(c).map(|m| m.header.clone()) else { return Ok(true) };
    let (_, members) = body_class(tx.core, &h, c, ai);
    if h.kind.is_compaction() {
        return snapshot_live(tx, &h, c, &members);
    }
    for x in members {
        let Some(a) = h.aspects.get(x) else { continue };
        let Some(o) = Owned::of(&h, c, x) else { return Ok(true) };
        // the pages holding the dots of every delta of the body (all pages when one is not
        // held or not a delta)
        tx.load_lazy(&a.tid, &a.ak)?;
        let parts = crate::apply::held_parts(tx, c, x)?;
        let mut touches = Vec::new();
        for d in &parts {
            match d {
                osis_commit::Decoded::Delta(d) => touches.push(crate::engine::pages::touch_of(&d.fragment, tx.core.pages.get(&(a.tid, a.ak.clone())))),
                osis_commit::Decoded::Snapshot(_) => touches.push(None),
            }
        }
        if touches.is_empty() {
            touches.push(None);
        }
        for t in &touches {
            tx.ensure_touch(&a.tid, &a.ak, t)?;
        }
        let Some(Some(st)) = tx.core.states.get(&(a.tid, a.ak.clone())) else { continue };
        if st.holds_owned_write(&|src, lo, hi| o.owns_range(src, lo, hi)) {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Whether a compaction snapshot carries a write still live in this node's state (`body_live`;
/// live writes as for deltas, `Fragment::live_writes`: no element or entry tombstone): held, a
/// write it carries (by dot) is there. Dropped, which writes it carried went with the body
/// (spec/commits.md §5; kept frontiers, `Meta::gives`, reach dead writes too), so whether it
/// was live then is kept (`Meta::live_drops`): dropped dead it stays dead (undo and redo write
/// new dots; a write a validity flip brings back comes from a held body,
/// which carries it at blind nodes itself); dropped live, it is
/// live while the state holds a write stamped at or before its `ts` (the header's `ts` bounds
/// what it carried) or one without a `ts` (a bare anchor it may carry): an
/// over-approximation, so its delete at blind nodes waits for a carrier (spec/sync.md §7).
/// Never held: a write stamped at or before its `ts`.
fn snapshot_live(tx: &mut Tx<'_>, h: &Header, c: &CommitId, members: &[usize]) -> Result<bool> {
    let m = tx.core.ix.commits.get(c).map(|m| (m.dropped.clone(), m.live_drops.clone()));
    let (dropped, live_drops) = m.unwrap_or_default();
    for x in members {
        let Some(a) = h.aspects.get(*x) else { continue };
        let k = (a.tid, a.ak.clone());
        let parts = crate::apply::held_parts(tx, c, *x)?;
        if parts.is_empty() && dropped.contains(&(*x, 0)) && !live_drops.contains(x) {
            continue;
        }
        tx.load(&a.tid, &a.ak)?;
        let Some(Some(st)) = tx.core.states.get(&k) else { continue };
        let writes = st.live_writes();
        if parts.is_empty() {
            let tsless = dropped.contains(&(*x, 0));
            if writes.iter().any(|(_, t)| t.map_or(tsless, |t| t <= h.ts)) {
                return Ok(true);
            }
            continue;
        }
        // by dot: bare anchors and other writes without a `ts` count too
        let live: BTreeSet<osis_crdt::Dot> = writes.into_iter().map(|(d, _)| d).collect();
        for p in parts {
            if p.into_fragment().live_writes().into_iter().any(|(d, _)| live.contains(&d)) {
                return Ok(true);
            }
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
        let ak = Ak::new("/x/a").unwrap();
        let mut m = Mutation::new();
        let t = lp.peers[0].engine.new_thing(&mut m, a);
        m.set(t, &ak, &Value::Int(0)).unwrap();
        lp.peers[0].commit(m).unwrap();
        let write = ct::Edge { role: Role::Write, until: None, invite: None, since: None };
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
        e.demote(&t, &Demotion { member: w, new: None, presync: PreSync::Backdated(before) }).unwrap();
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
        let ak = Ak::new("/x/a").unwrap();
        let mut m = Mutation::new();
        let t = lp.peers[0].engine.new_thing(&mut m, a);
        m.set(t, &ak, &Value::Int(0)).unwrap();
        let first = lp.peers[0].commit(m).unwrap().unwrap();
        let write = ct::Edge { role: Role::Write, until: None, invite: None, since: None };
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
        e.demote(&t, &Demotion { member: w, new: None, presync: PreSync::Backdated(before) }).unwrap();
        let got = e.take_changed();
        assert!(got.commits.contains(&c), "the flipped commit");
        assert!(!got.commits.contains(&first), "not every commit on the flipped aspect");
        assert!(got.aspects.contains(&(t, ak.clone())), "the flipped aspect's state");
        e.drop_body(&first, &t, &ak).unwrap();
        assert!(e.take_changed().commits.contains(&first), "dropped");
    }
}
