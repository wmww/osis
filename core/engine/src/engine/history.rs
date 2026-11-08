//! An aspect's history (notes/api.md History): the commits holding a delta on it, each read from its
//! own body, whatever the state says of it, paged by `(ts, ID)` off `by_aspect` (a page costs its
//! rows, no walk); and which entries changed (`Core::history_changes`). A memory aspect's held
//! commits and own batches live in `ephemeral` and join here; they are bounded by its caps.

use super::{Engine, Tx};
use crate::error::Result;
use crate::events::BatchId;
use osis_base::{Ak, CommitId, Tid, Ts, Value, WallMs};
use osis_commit::Kind;
use std::collections::{BTreeMap, BTreeSet};
use std::ops::Bound::{Excluded, Unbounded};

/// A place in an aspect's history. `HistoryPos::time(ts)` is one before every entry stamped `ts`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct HistoryPos {
    pub ts: Ts,
    pub id: BatchId,
}

impl HistoryPos {
    pub fn time(ts: Ts) -> HistoryPos {
        HistoryPos { ts, id: BatchId::Commit(CommitId([0; 32])) }
    }
}

/// Where a page starts, and which way it goes: `Newest` and `Before` towards older entries,
/// `Oldest` and `After` towards newer ones. Neither bound counts itself.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HistoryFrom {
    Newest,
    Oldest,
    Before(HistoryPos),
    After(HistoryPos),
}

/// What is here of an entry's body.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RowBody {
    /// Its read (`None`: it holds no whole value, a removal). May hold links.
    Held(Option<Value>),
    /// Held, and past the byte bound asked for.
    TooLarge,
    /// A held purge request dropped it: the earliest by `(ts, ID)`.
    Purged(CommitId),
    /// Gone for another reason: expiry, a keep bound, compaction.
    Dropped,
    /// Its header is here and its body is not.
    NotFetched,
}

/// One entry, what its signed header says and what this node judged.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HistoryRow {
    pub id: BatchId,
    /// `None`: an own ephemeral batch with no commit.
    pub kind: Option<Kind>,
    pub actor: Tid,
    pub node: Tid,
    pub ts: Ts,
    pub received: WallMs,
    pub valid: bool,
    pub body: RowBody,
}

impl HistoryRow {
    /// What its body takes of a page's byte bound (a body past it ends the page).
    fn bytes(&self) -> usize {
        match &self.body {
            RowBody::Held(Some(v)) => osis_base::cbor::encode(v).len(),
            RowBody::TooLarge => usize::MAX,
            _ => 0,
        }
    }
}

/// The commit a place orders by on a durable aspect: an ephemeral ID, from another aspect, orders
/// after every commit of its `ts`, as `BatchId` does.
fn commit_at(id: BatchId) -> CommitId {
    id.commit().unwrap_or(CommitId([0xff; 32]))
}

/// Up to `n` places of `from`, in its direction, in a set ordered by place.
fn walk<'a, I>(set: &'a BTreeSet<I>, from: HistoryFrom, n: usize, key: impl Fn(HistoryPos) -> I, pos: impl Fn(&I) -> HistoryPos + 'a) -> Vec<HistoryPos>
where
    I: Ord,
{
    match from {
        HistoryFrom::Newest => set.iter().rev().take(n).map(pos).collect(),
        HistoryFrom::Oldest => set.iter().take(n).map(pos).collect(),
        HistoryFrom::Before(p) => set.range(..key(p)).rev().take(n).map(pos).collect(),
        HistoryFrom::After(p) => set.range((Excluded(key(p)), Unbounded)).take(n).map(pos).collect(),
    }
}

/// Entry of commit `c` on `(tid, ak)`; `None` when it has no delta there.
fn commit_row(tx: &mut Tx<'_>, c: &CommitId, tid: &Tid, ak: &Ak, budget: usize) -> Result<Option<HistoryRow>> {
    let Some(m) = tx.core.ix.commits.get(c) else { return Ok(None) };
    let Some(ai) = m.aspect(tid, ak) else { return Ok(None) };
    // a bare leftover (expired, purged) shows as what took its values, not as its read
    let (holds, valid, received, kind, actor, node, ts) = (m.holds(ai) && !m.bare(ai), m.valid_at(ai), m.received, m.view.kind, m.view.actor, m.view.author, m.view.ts);
    let header = m.header.clone();
    let dropped = m.body_gone(ai);
    let body = if holds {
        // past its expiry the next tick drops it: no read shows it until then
        if header.aspects.get(ai).and(header.expires).is_some_and(|t| t <= tx.now().0) {
            RowBody::Dropped
        } else {
            held_body(tx, c, ai, budget)?
        }
    } else if let Some(by) = crate::retention::purged_by(tx, &header, c, ai)? {
        RowBody::Purged(by)
    } else if dropped {
        RowBody::Dropped
    } else {
        RowBody::NotFetched
    };
    Ok(Some(HistoryRow { id: BatchId::Commit(*c), kind: Some(kind), actor, node, ts, received, valid, body }))
}

/// The read of a held part, its pieces joined up to `budget` bytes.
fn held_body(tx: &mut Tx<'_>, c: &CommitId, ai: usize, budget: usize) -> Result<RowBody> {
    let mut out: Option<osis_crdt::Fragment> = None;
    let mut over = false;
    crate::apply::each_held_piece(tx, c, ai, &mut |_, f| {
        if over {
            return Ok(());
        }
        match &mut out {
            Some(o) => {
                o.join(f);
            }
            None => out = Some(f),
        }
        over = out.as_ref().is_some_and(|o| o.approx_bytes() > budget);
        Ok(())
    })?;
    Ok(match out {
        _ if over => RowBody::TooLarge,
        Some(f) => RowBody::Held(f.read_written()),
        None => RowBody::NotFetched,
    })
}

impl Engine {
    /// Turns `Event::History` on for this open: a transaction changing many commits then lists them
    /// all, so it stays off until someone listens. It stays on: no count to keep right.
    pub fn watch_history(&mut self) {
        self.core.history_watched = true;
    }

    /// A page of `(tid, ak)`'s history: at most `limit` entries from `from`, stopping early past
    /// `budget` bytes of bodies, and whether more lie that way. What is not held reads as such: a
    /// purged, dropped or not fetched body's entry stays where it is.
    pub fn history(&mut self, tid: &Tid, ak: &Ak, from: HistoryFrom, limit: usize, budget: usize) -> Result<(Vec<HistoryRow>, bool)> {
        let k = (*tid, ak.clone());
        let memory = ak.ephemeral();
        let mut places = if memory {
            // this session's own batches from the log; their commits are the same writes
            let mut set = self.memory_places(tid, ak);
            set.extend(self.core.ix.by_aspect.get(&k).into_iter().flatten().filter(|(_, c)| !self.own_memory_commit(c)).map(|(ts, c)| HistoryPos { ts: *ts, id: BatchId::Commit(*c) }));
            walk(&set, from, limit.saturating_add(1), |p| p, |p| *p)
        } else {
            let empty = BTreeSet::new();
            let set = self.core.ix.by_aspect.get(&k).unwrap_or(&empty);
            walk(set, from, limit.saturating_add(1), |p| (p.ts, commit_at(p.id)), |x| HistoryPos { ts: x.0, id: BatchId::Commit(x.1) })
        };
        let mut more = places.len() > limit;
        places.truncate(limit);
        let mut own: BTreeMap<BatchId, HistoryRow> = BTreeMap::new();
        if memory {
            for p in &places {
                if let Some(r) = self.memory_row(tid, ak, &p.id, budget) {
                    own.insert(p.id, r);
                }
            }
        }
        let rows = self.run(|tx| {
            let mut rows = Vec::with_capacity(places.len());
            let mut used = 0usize;
            for (n, p) in places.iter().enumerate() {
                if used > budget {
                    more = more || n < places.len();
                    break;
                }
                let row = match (own.remove(&p.id), p.id) {
                    (Some(r), _) => Some(r),
                    (None, BatchId::Commit(c)) => commit_row(tx, &c, tid, ak, budget)?,
                    (None, BatchId::Ephemeral(_)) => None,
                };
                if let Some(r) = row {
                    used = used.saturating_add(r.bytes());
                    rows.push(r);
                }
            }
            Ok(rows)
        })?;
        Ok((rows, more))
    }

    /// The entry of `id` in `(tid, ak)`'s history, `None` when it has none (any more).
    pub fn history_entry(&mut self, tid: &Tid, ak: &Ak, id: &BatchId, budget: usize) -> Result<Option<HistoryRow>> {
        if let Some(r) = self.memory_row(tid, ak, id, budget) {
            return Ok(Some(r));
        }
        let BatchId::Commit(c) = id else { return Ok(None) };
        self.run(|tx| commit_row(tx, c, tid, ak, budget))
    }
}
