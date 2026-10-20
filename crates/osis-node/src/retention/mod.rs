//! Retention (spec/commits.md §5–§6; spec/crdt.md §4.7, §4.8, §8): deaths per body from the
//! crdt change summary, keep-at-most drops (in the killing transaction for at most 0, else by
//! timer), expiry at T (value-less, body dropped), purge requests judged by perm at the
//! request's time (also against deltas arriving later), compaction snapshots and the covered
//! test, and the queues node-sync executes (deletions at blind nodes, re-snapshots).
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
use osis_core::{Ak, BlobId, CommitId, Tid, Ts, WallMs};
use osis_crdt::{Death, Fragment, Frontiers};
use osis_perm::{At, Point, PurgeBy};
use osis_schema::core_types::is_membership_class;
use osis_store::Shred;
use std::collections::BTreeSet;

pub(crate) mod forget;

/// A deletion obligation: (log sequence, commit, tid, ak, time).
pub type Deletion = (u64, CommitId, Tid, Ak, WallMs);

const T_EXPIRY: u8 = 1;
const T_AT_MOST: u8 = 2;

pub(crate) fn encode_owned(v: &[Owned]) -> Vec<u8> {
    let mut w = Wr::new().u32(v.len() as u32);
    for o in v {
        w = match o {
            Owned::Node { node, lo, hi } => w.u8(0).raw(node.as_bytes()).u64(*lo).u64(*hi),
            Owned::Commit(c) => w.u8(1).raw(&c.0),
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
            _ => Owned::Commit(CommitId(r.arr()?)),
        });
    }
    r.end()?;
    Ok(out)
}

fn aspect_index(tx: &Tx<'_>, c: &CommitId, tid: &Tid, ak: &Ak) -> Option<usize> {
    tx.core.commits.get(c)?.header.aspects.iter().position(|a| a.tid == *tid && a.ak == *ak)
}

/// The actor whose readers a delta's thing has (spec/sync.md §3 entitlement): the thing if it
/// has secrets of its own, else its owner.
fn reader(core: &Core, tid: &Tid) -> Tid {
    if core.own_keys.contains(tid) {
        return *tid;
    }
    match core.created(tid) {
        Some(osis_core::CreationRecord::Thing { owner, .. }) => *owner,
        _ => *tid,
    }
}

/// The body holding aspect `ai` of a commit (spec/commits.md §5: one projection class, readable
/// subset and retention class) and the aspects it holds. Its ID keys the death records.
pub(crate) fn body_class(core: &Core, h: &Header, c: &CommitId, ai: usize) -> (BlobId, Vec<usize>) {
    let key = |a: &osis_commit::AspectEntry| (reader(core, &a.tid), a.retention, a.expires, a.tokens.clone());
    let Some(me) = h.aspects.get(ai) else { return (BlobId(c.0), vec![ai]) };
    let k = key(me);
    let members: Vec<usize> = h.aspects.iter().enumerate().filter(|(_, a)| key(a) == k).map(|(i, _)| i).collect();
    let first = members.first().copied().unwrap_or(ai) as u32;
    let mut hs = osis_core::hash::Hasher::new();
    hs.update(&c.0);
    hs.update(&first.to_be_bytes());
    (BlobId(hs.finalize()), members)
}

/// First and last death so far over a body's deltas.
fn class_deaths(tx: &mut Tx<'_>, h: &Header, body: &BlobId, members: &[usize]) -> Result<Option<(Ts, Ts)>> {
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

/// Records deaths per body and drops bodies past keep at most (spec/commits.md §5).
pub(crate) fn note_deaths(tx: &mut Tx<'_>, tid: &Tid, ak: &Ak, deaths: &[Death]) -> Result<()> {
    let mut bodies = BTreeSet::new();
    for d in deaths {
        let Some(c) = tx.core.commit_of(tid, ak, &d.stamp.dot) else { continue };
        let Some(ai) = aspect_index(tx, &c, tid, ak) else { continue };
        let Some(h) = tx.core.commits.get(&c).map(|m| m.header.clone()) else { continue };
        let (body, _) = body_class(tx.core, &h, &c, ai);
        tx.txn.note_death(tid, ak, &body, d.at)?;
        bodies.insert((c, ai));
    }
    for (c, ai) in bodies {
        check_at_most(tx, &c, ai)?;
    }
    Ok(())
}

fn check_at_most(tx: &mut Tx<'_>, c: &CommitId, ai: usize) -> Result<()> {
    let Some(m) = tx.core.commits.get(c).cloned() else { return Ok(()) };
    let Some(a) = m.header.aspects.get(ai) else { return Ok(()) };
    let (body, members) = body_class(tx.core, &m.header, c, ai);
    let d = class_deaths(tx, &m.header, &body, &members)?;
    let keep = osis_commit::retention::body_keep(&m.header, &a.retention, d.map(|d| d.0.wall_ms().0), d.map(|d| d.1.wall_ms().0));
    if let Some(t) = keep.at_most {
        // at most 0: the replacing node drops in the killing transaction, even when the
        // killing `ts` is ahead of its clock
        let zero = a.retention.at_most.rel == Some(0) && d.is_some();
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
/// rewritten shredded with its undo buffer cleared; node-sync is told to delete it at blind
/// nodes.
pub(crate) fn drop_part(tx: &mut Tx<'_>, c: &CommitId, ai: usize) -> Result<()> {
    tx.core.touch();
    let Some(mut m) = tx.core.commits.get(c).cloned() else { return Ok(()) };
    let Some(a) = m.header.aspects.get(ai).cloned() else { return Ok(()) };
    let n = a.hashes.len();
    if (0..n).all(|di| m.dropped.contains(&(ai, di))) {
        return Ok(());
    }
    for di in 0..n {
        m.dropped.insert((ai, di));
    }
    if let Some(blob) = tx.get_commit(c)? {
        let rest = osis_commit::rewrite(&blob, |x, _| x == ai);
        tx.put_commit(c, &rest, &m, Shred::Yes)?;
    }
    let (body, _) = body_class(tx.core, &m.header, c, ai);
    tx.core.commits.insert(*c, m);
    tx.txn.drop_body(&body, &[(a.tid, a.ak.clone())])?;
    tx.load(&a.tid, &a.ak)?;
    let st = tx.core.states.get(&(a.tid, a.ak.clone())).cloned().flatten();
    tx.set_state(&a.tid, &a.ak, st, Shred::Yes, true)?;
    let now = tx.now();
    let entry = Wr::new().raw(&c.0).raw(a.tid.as_bytes()).bytes(a.ak.as_str().as_bytes()).u64(now.0).take();
    tx.txn.log_append(records::DELETIONS, &entry)?;
    Ok(())
}

/// Holds the value-carrying writes of a delta value-less from now on (spec/crdt.md §4.7).
fn make_valueless(tx: &mut Tx<'_>, c: &CommitId, ai: usize) -> Result<Option<(Tid, Ak)>> {
    tx.core.touch();
    let Some(m) = tx.core.commits.get(c).cloned() else { return Ok(None) };
    let Some(a) = m.header.aspects.get(ai) else { return Ok(None) };
    let Some(o) = Owned::of(&m.header, c, ai).filter(|_| m.header.kind.has_own_writes()) else { return Ok(None) };
    let k = (a.tid, a.ak.clone());
    let list = tx.core.valueless.entry(k.clone()).or_default();
    if !list.contains(&o) {
        list.push(o);
    }
    let enc = encode_owned(list);
    tx.txn.put_local(&records::aspect_key(records::VALUELESS, &a.tid, &a.ak), &enc, Shred::No)?;
    tx.load(&a.tid, &a.ak)?;
    if let Some(mut st) = tx.core.states.get(&k).cloned().flatten() {
        crate::apply::strip_valueless(tx.core, &a.tid, &a.ak, &mut st);
        tx.set_state(&a.tid, &a.ak, Some(st), Shred::Yes, true)?;
    }
    Ok(Some(k))
}

fn expire(tx: &mut Tx<'_>, c: &CommitId, ai: usize, changed: &mut BTreeSet<(Tid, Ak)>) -> Result<()> {
    if let Some(k) = make_valueless(tx, c, ai)? {
        changed.insert(k);
    }
    drop_part(tx, c, ai)
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
        let Some(p) = tx.core.commits.get(&pc).map(|m| m.header.clone()) else { continue };
        if p.purge.iter().any(|item| purge_allowed(tx.core, &p, &pc, item, ch, c, ai)) {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Applies purge item `item` of commit `pc` to held delta `(c, ai)` if it may: its values go
/// value-less, its body and every snapshot body carrying them drop, a re-snapshot is queued.
fn purge_one(tx: &mut Tx<'_>, pc: &CommitId, item: &PurgeItem, c: &CommitId, ai: usize, changed: &mut BTreeSet<(Tid, Ak)>) -> Result<()> {
    let (Some(p), Some(m)) = (tx.core.commits.get(pc).cloned(), tx.core.commits.get(c).cloned()) else { return Ok(()) };
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
        let snaps: Vec<CommitId> = tx.core.by_aspect.get(&(a.tid, a.ak.clone())).into_iter().flatten().map(|x| x.1).filter(|s| tx.core.commits.get(s).is_some_and(|x| crate::apply::is_kind_snapshot(x.header.kind))).collect();
        for s in snaps {
            let Some(sai) = aspect_index(tx, &s, &a.tid, &a.ak) else { continue };
            for d in crate::apply::held_parts(tx, &s, sai)? {
                let f = frag(d);
                let mut g = f.clone();
                g.strip(&|x| o.owns(x));
                if g != f {
                    drop_part(tx, &s, sai)?;
                    break;
                }
            }
        }
    }
    let entry = Wr::new().raw(a.tid.as_bytes()).bytes(a.ak.as_str().as_bytes()).take();
    tx.txn.log_append(records::RESNAPSHOT, &entry)?;
    Ok(())
}

/// After a commit applied: its expiry (now or by timer), its purge request against held
/// deltas, and earlier purge requests against its deltas.
pub(crate) fn on_apply(tx: &mut Tx<'_>, id: &CommitId, changed: &mut BTreeSet<(Tid, Ak)>) -> Result<()> {
    let Some(m) = tx.core.commits.get(id).cloned() else { return Ok(()) };
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
                let items: Vec<PurgeItem> = tx.core.commits.get(&pc).map(|p| p.header.purge.clone()).unwrap_or_default();
                for item in items {
                    purge_one(tx, &pc, &item, id, ai, &mut purged)?;
                }
            }
        }
    }
    if !h.purge.is_empty() {
        for item in &h.purge {
            let held: Vec<CommitId> = tx.core.by_aspect.get(&(*item.tid(), item.ak().clone())).map(|s| s.iter().map(|x| x.1).collect()).unwrap_or_default();
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
            }
        }
    }
    if !purged.is_empty() {
        tx.core.events.queue(Event::Changed { cause: Cause::Purge, changed: purged.iter().cloned().collect() });
        changed.extend(purged);
    }
    Ok(())
}

impl Engine {
    /// Runs what is due by the corrected clock: expiries, keep-at-most drops, and commits
    /// parked for drift.
    pub fn tick(&mut self) -> Result<()> {
        self.tick_drops().map(|_| ())
    }

    /// `tick`, returning how many timers fired (node-sync forgets the dropped bodies' blobs).
    pub(crate) fn tick_drops(&mut self) -> Result<usize> {
        let n = self.run(|tx| {
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
            let n = due.len();
            for (k, c, ai, kind) in due {
                tx.txn.remove_local(&[records::TIMER, &k].concat(), Shred::No)?;
                match kind {
                    T_EXPIRY => expire(tx, &c, ai, &mut changed)?,
                    _ => drop_part(tx, &c, ai)?,
                }
            }
            if !changed.is_empty() {
                tx.core.events.queue(Event::Changed { cause: Cause::Expiry, changed: changed.into_iter().collect() });
            }
            Ok(n)
        })?;
        self.reexamine()?;
        Ok(n)
    }

    /// When the next expiry or keep-at-most timer is due (corrected wall ms).
    pub(crate) fn next_timer(&mut self) -> Result<Option<u64>> {
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
            drop_part(tx, &c, ai)
        })
    }

    /// Keep bounds of a held body (wall ms): (keep at least, keep at most).
    pub fn body_keep(&mut self, c: &CommitId, tid: &Tid, ak: &Ak) -> Result<osis_commit::retention::Keep> {
        let (c, tid, ak) = (*c, *tid, ak.clone());
        self.run(|tx| {
            let ai = aspect_index(tx, &c, &tid, &ak).ok_or(Error::UnknownCommit(c))?;
            let m = tx.core.commits.get(&c).cloned().ok_or(Error::UnknownCommit(c))?;
            let a = m.header.aspects.get(ai).ok_or(Error::UnknownCommit(c))?;
            let (body, members) = body_class(tx.core, &m.header, &c, ai);
            let d = class_deaths(tx, &m.header, &body, &members)?;
            Ok(osis_commit::retention::body_keep(&m.header, &a.retention, d.map(|d| d.0.wall_ms().0), d.map(|d| d.1.wall_ms().0)))
        })
    }

    /// First and last death so far of the writes of the body holding aspect `ak` of `c`.
    pub fn deaths(&mut self, c: &CommitId, tid: &Tid, ak: &Ak) -> Result<Option<(Ts, Ts)>> {
        let (c, tid, ak) = (*c, *tid, ak.clone());
        self.run(|tx| {
            let ai = aspect_index(tx, &c, &tid, &ak).ok_or(Error::UnknownCommit(c))?;
            let h = tx.core.commits.get(&c).map(|m| m.header.clone()).ok_or(Error::UnknownCommit(c))?;
            let (body, members) = body_class(tx.core, &h, &c, ai);
            class_deaths(tx, &h, &body, &members)
        })
    }

    /// Whether a body is held (not dropped).
    pub fn holds_body(&self, c: &CommitId, tid: &Tid, ak: &Ak) -> bool {
        let Some(m) = self.core.commits.get(c) else { return false };
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
            crate::engine::write::check_authority(tx.core, tx.core.id.tid(), &[], &tid, ak.as_str(), ts)?;
            tx.load(&tid, &ak)?;
            let Some(mut st) = tx.core.states.get(&(tid, ak.clone())).cloned().flatten() else { return Ok(None) };
            if ak.as_str() == "/secrets" && !crate::apply::keys::may_compact(tx.core, &tid, &st) {
                return Err(Error::Misuse("/secrets keys an epoch not established here (spec/crypto.md §4)"));
            }
            let expiring: Vec<Owned> = tx
                .core
                .by_aspect
                .get(&(tid, ak.clone()))
                .into_iter()
                .flatten()
                .filter_map(|(_, c)| {
                    let m = tx.core.commits.get(c)?;
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
            for ((t, a, n), ranges) in tx.core.ranges.iter() {
                if *t != tid || *a != ak {
                    continue;
                }
                let mut next = 1u64;
                for (lo, (hi, c)) in ranges {
                    let ok = tx.core.commits.get(c).is_some_and(|m| m.header.aspects.iter().zip(&m.valid).any(|(x, v)| *v && x.tid == tid && x.ak == ak));
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
            let kind = if is_membership_class(ak.as_str()) { Kind::MembershipSnapshot } else { Kind::ContentSnapshot };
            // the schema's default bounds: core, or a registered schema declaring the AK
            let schema = if ak.is_core() { Some(std::sync::Arc::new(osis_schema::core_schema().clone())) } else { tx.core.schemas.values().find(|s| s.aspects.contains_key(ak.as_str())).cloned() };
            let plan = CommitPlan { kind, ts, actor: node, form: Form::Node, creates: Vec::new(), purge: Vec::new(), undoes: None, frontier: None, origins: Vec::new(), signer: tx.core.id.tid() };
            let d = Resolved { tid, ak, fragment: st, lo: 0, hi: 0, schema, retention: None, expires: None, frontiers: Some(frontiers), chunks: Vec::new(), split: false };
            build_and_apply(tx, plan, vec![d]).map(Some)
        })
    }

    /// Is the body of `ak` in commit `c` covered by snapshot commit `s` (spec/commits.md §5):
    /// joining each of its deltas into the snapshot's fragment leaves its canonical bytes
    /// unchanged, and for a node-form body, the snapshot's frontier holds its counters (so every
    /// holder of the snapshot counts the body as received once it is dropped, spec/crdt.md §8).
    /// `None` when either is not held (nothing is established).
    pub fn covered(&mut self, s: &CommitId, c: &CommitId, tid: &Tid, ak: &Ak) -> Result<Option<bool>> {
        let (s, c, tid, ak) = (*s, *c, *tid, ak.clone());
        self.run(|tx| {
            let (Some(sai), Some(cai)) = (aspect_index(tx, &s, &tid, &ak), aspect_index(tx, &c, &tid, &ak)) else { return Ok(None) };
            let parts = crate::apply::held_parts(tx, &s, sai)?;
            if let (Some(m), [osis_commit::Decoded::Snapshot(sn)]) = (tx.core.commits.get(&c), parts.as_slice())
                && m.header.form == osis_commit::Form::Node
                && m.header.kind.has_own_writes()
                && let Some(a) = m.header.aspects.get(cai)
                && sn.frontiers.0.get(&m.header.author).is_none_or(|f| f.saturating_add(1) < a.hi)
            {
                return Ok(Some(false));
            }
            let held = crate::apply::held_parts(tx, &c, cai)?;
            // a snapshot covers another only if its frontiers hold the other's too: otherwise a
            // holder of it alone does not count what the other's frontier gave as received
            if let ([osis_commit::Decoded::Snapshot(sn)], [osis_commit::Decoded::Snapshot(other)]) = (parts.as_slice(), held.as_slice())
                && other.frontiers.0.iter().any(|(n, f)| sn.frontiers.0.get(n).is_none_or(|g| g < f))
            {
                return Ok(Some(false));
            }
            let snap: Vec<Fragment> = parts.into_iter().map(frag).collect();
            let [snap] = snap.as_slice() else { return Ok(None) };
            let body: Vec<Fragment> = held.into_iter().map(frag).collect();
            let before = crate::engine::state::encode(snap)?;
            let mut j = snap.clone();
            for b in body {
                j.join(b);
            }
            Ok(Some(crate::engine::state::encode(&j)? == before))
        })
    }

    /// Deletion obligations for node-sync: (commit, tid, ak, time), oldest first, from `from`.
    pub fn deletions(&mut self, from: u64, limit: usize) -> Result<Vec<Deletion>> {
        self.run(|tx| {
            let mut out = Vec::new();
            for (seq, b) in tx.txn.log_scan(records::DELETIONS, from, limit)? {
                let mut r = Rd::new(&b);
                let c = CommitId(r.arr()?);
                let t = r.tid()?;
                let ak = Ak::new(std::str::from_utf8(r.bytes()?).map_err(|_| Error::Corrupt("ak"))?).map_err(|_| Error::Corrupt("ak"))?;
                out.push((seq, c, t, ak, WallMs(r.u64()?)));
            }
            Ok(out)
        })
    }
}

fn frag(d: Decoded) -> Fragment {
    match d {
        Decoded::Delta(x) => x.fragment,
        Decoded::Snapshot(x) => x.fragment,
    }
}
