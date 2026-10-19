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
use crate::engine::{Engine, Owned, Tx};
use crate::error::{Error, Result};
use crate::events::{Cause, Event};
use osis_commit::{Decoded, Form, Kind, PurgeItem};
use osis_core::{Ak, BlobId, CommitId, Tid, Ts, WallMs};
use osis_crdt::{Death, Fragment, Frontiers};
use osis_perm::{At, Point, PurgeBy};
use osis_schema::core_types::is_membership_class;
use osis_store::Shred;
use std::collections::BTreeSet;

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

/// Records deaths per body and drops bodies past keep at most (spec/commits.md §5).
pub(crate) fn note_deaths(tx: &mut Tx<'_>, tid: &Tid, ak: &Ak, deaths: &[Death]) -> Result<()> {
    let mut bodies = BTreeSet::new();
    for d in deaths {
        let Some(c) = tx.core.commit_of(tid, ak, &d.stamp.dot) else { continue };
        tx.txn.note_death(tid, ak, &BlobId(c.0), d.at)?;
        bodies.insert(c);
    }
    for c in bodies {
        check_at_most(tx, &c, tid, ak)?;
    }
    Ok(())
}

fn check_at_most(tx: &mut Tx<'_>, c: &CommitId, tid: &Tid, ak: &Ak) -> Result<()> {
    let Some(ai) = aspect_index(tx, c, tid, ak) else { return Ok(()) };
    let Some(m) = tx.core.commits.get(c).cloned() else { return Ok(()) };
    let Some(a) = m.header.aspects.get(ai) else { return Ok(()) };
    let d = tx.txn.death(tid, ak, &BlobId(c.0))?;
    let keep = osis_commit::retention::body_keep(&m.header, &a.retention, d.map(|d| d.first.wall_ms().0), d.map(|d| d.last.wall_ms().0));
    if let Some(t) = keep.at_most {
        if t <= tx.now().0 {
            drop_part(tx, c, ai)?;
        } else {
            tx.txn.put_local(&records::timer_key(t, c, ai), &[T_AT_MOST], Shred::No)?;
        }
    }
    Ok(())
}

/// Drops the body of aspect `ai` of `c` (spec/commits.md §5): the commit is kept without that
/// delta (same header), its death records shredded, the aspect's state rewritten shredded with
/// its undo buffer cleared; node-sync is told to delete it at blind nodes.
pub(crate) fn drop_part(tx: &mut Tx<'_>, c: &CommitId, ai: usize) -> Result<()> {
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
    tx.core.commits.insert(*c, m);
    tx.txn.drop_body(&BlobId(c.0), &[(a.tid, a.ak.clone())])?;
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

/// Applies purge item `item` of commit `pc` to held delta `(c, ai)` if it names it and its
/// author held the right at the request's time (spec/permissions.md §8).
fn purge_one(tx: &mut Tx<'_>, pc: &CommitId, item: &PurgeItem, c: &CommitId, ai: usize, changed: &mut BTreeSet<(Tid, Ak)>) -> Result<()> {
    let (Some(p), Some(m)) = (tx.core.commits.get(pc).cloned(), tx.core.commits.get(c).cloned()) else { return Ok(()) };
    let Some(a) = m.header.aspects.get(ai) else { return Ok(()) };
    if is_membership_class(a.ak.as_str()) || a.tid != *item.tid() || a.ak != *item.ak() {
        return Ok(());
    }
    let names = match item {
        PurgeItem::Commit { commit, .. } => commit == c,
        PurgeItem::Aspect { .. } => m.header.ts < p.header.ts,
    };
    if !names {
        return Ok(());
    }
    let point = Point { ts: p.header.ts, node: p.header.author, commit: *pc };
    let actor = match m.header.kind {
        Kind::Import => m.header.origins.first().map_or(m.header.actor, |o| o.actor),
        _ => m.header.actor,
    };
    let allowed = tx.core.timelines.get(&a.tid).is_some_and(|tl| tl.may_purge(&p.header.author, &a.tid, purge_by(a.retention.by), &actor, At::before(point)));
    if !allowed {
        return Ok(());
    }
    if let Some(k) = make_valueless(tx, c, ai)? {
        changed.insert(k);
    }
    drop_part(tx, c, ai)?;
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
        let key = records::aspect_key(records::PURGES, &a.tid, &a.ak);
        if let Some(b) = tx.txn.get_local(&key)? {
            let mut r = Rd::new(&b);
            let mut reqs = Vec::new();
            while !r.is_empty() {
                reqs.push(CommitId(r.arr()?));
            }
            for pc in reqs {
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
                tx.txn.remove_local(&[records::TIMER, &k].concat(), Shred::No)?;
                match kind {
                    T_EXPIRY => expire(tx, &c, ai, &mut changed)?,
                    _ => drop_part(tx, &c, ai)?,
                }
            }
            if !changed.is_empty() {
                tx.core.events.queue(Event::Changed { cause: Cause::Expiry, changed: changed.into_iter().collect() });
            }
            Ok(())
        })?;
        self.reexamine()
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
            let d = tx.txn.death(&tid, &ak, &BlobId(c.0))?;
            Ok(osis_commit::retention::body_keep(&m.header, &a.retention, d.map(|d| d.first.wall_ms().0), d.map(|d| d.last.wall_ms().0)))
        })
    }

    /// First and last death so far of a body's writes.
    pub fn deaths(&mut self, c: &CommitId, tid: &Tid, ak: &Ak) -> Result<Option<(Ts, Ts)>> {
        let (c, tid, ak) = (*c, *tid, ak.clone());
        self.run(|tx| Ok(tx.txn.death(&tid, &ak, &BlobId(c.0))?.map(|d| (d.first, d.last))))
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
            if crate::engine::write::role_of(tx.core, &node, &tid, ts) < Some(crate::engine::write::required_role(ak.as_str())) {
                return Err(Error::Permission { tid });
            }
            tx.load(&tid, &ak)?;
            let Some(mut st) = tx.core.states.get(&(tid, ak.clone())).cloned().flatten() else { return Ok(None) };
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
            let r = crate::apply::receipt::get(tx, &tid, &ak)?;
            let frontiers = Frontiers(r.nodes.keys().map(|n| (*n, r.contiguous(n, u64::MAX))).filter(|x| x.1 > 0).collect());
            let kind = if is_membership_class(ak.as_str()) { Kind::MembershipSnapshot } else { Kind::ContentSnapshot };
            let schema = ak.is_core().then(|| std::sync::Arc::new(osis_schema::core_schema().clone()));
            let plan = CommitPlan { kind, ts, actor: node, form: Form::Node, creates: Vec::new(), purge: Vec::new(), undoes: None, frontier: None, origins: Vec::new() };
            let d = Resolved { tid, ak, fragment: st, lo: 0, hi: 0, schema, retention: None, expires: None, frontiers: Some(frontiers) };
            build_and_apply(tx, plan, vec![d]).map(Some)
        })
    }

    /// Is the body of `ak` in commit `c` covered by snapshot commit `s` (spec/commits.md §5):
    /// joining each of its deltas into the snapshot's fragment leaves its canonical bytes
    /// unchanged. `None` when either is not held (nothing is established).
    pub fn covered(&mut self, s: &CommitId, c: &CommitId, tid: &Tid, ak: &Ak) -> Result<Option<bool>> {
        let (s, c, tid, ak) = (*s, *c, *tid, ak.clone());
        self.run(|tx| {
            let (Some(sai), Some(cai)) = (aspect_index(tx, &s, &tid, &ak), aspect_index(tx, &c, &tid, &ak)) else { return Ok(None) };
            let snap: Vec<Fragment> = crate::apply::held_parts(tx, &s, sai)?.into_iter().map(frag).collect();
            let [snap] = snap.as_slice() else { return Ok(None) };
            let body: Vec<Fragment> = crate::apply::held_parts(tx, &c, cai)?.into_iter().map(frag).collect();
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
