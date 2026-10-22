//! What examining a pending commit read (spec/commits.md §4), so `Engine::reexamine` reads,
//! decodes and verifies again only the commits whose inputs may have changed: re-examining
//! every pending commit after every applied one made a first sync O(commits × pending).
//!
//! A commit waits for a creation record (`UnknownCreated`, `MissingChain`) or for deltas
//! (`WaitDeltas`). Its examination read the commit (fixed), the held set, what the node syncs,
//! the corrected clock (drift, expiry) and, for missing deltas, the receipt and purge records
//! of their aspects. A wait on a thing the node starts or stops syncing is judged again; the
//! cache is dropped on a change of the clock offset, a rollback that changed anything, a
//! reload. Kept only for commits whose
//! header is inline (no header-list blobs) and that carry no `/secrets` part (pending boxes
//! are read at every examination).
//!
//! - A record wait for `t` stands while the held edge writes are the same (`Held::edges`:
//!   the author's certificates, `validity::reaches`) and `t`'s record is still held or not as
//!   before; records held only accumulate, so every lookup that found one finds the same.
//! - A delta wait is re-judged (`still_waits`, without decoding) once anything of the held set
//!   changed (perm judges purge rights), a receipt or purge record of a missing delta's
//!   aspect was written (`Waits::wake`), or the earliest expiry of its missing deltas passed;
//!   the rest of the examination (records, chain, signature) gave the same answer.

use super::Reason;
use crate::engine::{Core, Tx};
use crate::error::Result;
use osis_commit::Header;
use osis_core::format::MAX_DRIFT_MS;
use osis_core::{Ak, CommitId, Tid};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

enum On {
    /// The creation record of `tid`: held (`true`) or not when examined.
    Record { tid: Tid, had: bool },
    /// The missing deltas, and the earliest expiry among them.
    Deltas { missing: Vec<(usize, usize)>, expiry: Option<u64> },
}

pub(crate) struct Wait {
    pub header: Arc<Header>,
    reason: Reason,
    on: On,
    /// `Held::generation` and `Held::edges` when examined.
    generation: u64,
    edges: u64,
    /// The corrected clock when examined.
    now: u64,
}

#[derive(Default)]
pub(crate) struct Waits {
    by_id: BTreeMap<CommitId, Wait>,
    /// Delta waits by the aspects of their missing deltas.
    by_aspect: BTreeMap<(Tid, Ak), BTreeSet<CommitId>>,
    /// Waits by the things their commits have deltas on.
    by_thing: BTreeMap<Tid, BTreeSet<CommitId>>,
    /// Waits whose inputs changed since examined: receipt or purge records of a delta wait's
    /// aspect, what the node syncs of their things.
    woken: BTreeSet<CommitId>,
}

impl Waits {
    pub fn get(&self, id: &CommitId) -> Option<&Wait> {
        self.by_id.get(id)
    }

    pub fn remove(&mut self, id: &CommitId) {
        if let Some(w) = self.by_id.remove(id) {
            if let On::Deltas { missing, .. } = &w.on {
                for k in aspects(&w.header, missing) {
                    unindex(&mut self.by_aspect, &k, id);
                }
            }
            for t in things(&w.header) {
                unindex(&mut self.by_thing, &t, id);
            }
        }
        self.woken.remove(id);
    }

    pub fn clear(&mut self) {
        *self = Waits::default();
    }

    /// A receipt or purge record of `(tid, ak)` was written.
    pub fn wake(&mut self, tid: &Tid, ak: &Ak) {
        if let Some(s) = self.by_aspect.get(&(*tid, ak.clone())) {
            self.woken.extend(s.iter().copied());
        }
    }

    /// This node starts or stops syncing `tid` (`Engine::set_syncing`).
    pub fn wake_thing(&mut self, tid: &Tid) {
        if let Some(s) = self.by_thing.get(tid) {
            self.woken.extend(s.iter().copied());
        }
    }

    /// Forgets the waits of commits no longer pending.
    pub fn retain(&mut self, pending: impl Fn(&CommitId) -> bool) {
        let gone: Vec<CommitId> = self.by_id.keys().filter(|id| !pending(id)).copied().collect();
        for id in gone {
            self.remove(&id);
        }
    }

    fn insert(&mut self, id: CommitId, w: Wait) {
        self.remove(&id);
        if let On::Deltas { missing, .. } = &w.on {
            for k in aspects(&w.header, missing) {
                self.by_aspect.entry(k).or_default().insert(id);
            }
        }
        for t in things(&w.header) {
            self.by_thing.entry(t).or_default().insert(id);
        }
        self.by_id.insert(id, w);
    }
}

fn unindex<K: Ord>(m: &mut BTreeMap<K, BTreeSet<CommitId>>, k: &K, id: &CommitId) {
    if let Some(s) = m.get_mut(k) {
        s.remove(id);
        if s.is_empty() {
            m.remove(k);
        }
    }
}

fn things(h: &Header) -> BTreeSet<Tid> {
    h.aspects.iter().map(|a| a.tid).collect()
}

fn aspects(h: &Header, missing: &[(usize, usize)]) -> BTreeSet<(Tid, Ak)> {
    missing.iter().filter_map(|(ai, _)| h.aspects.get(*ai)).map(|a| (a.tid, a.ak.clone())).collect()
}

/// Notes what examining pending commit `id` (`blob`, after `examine`) read, if it can be judged
/// again from that alone.
pub(crate) fn note(core: &mut Core, id: CommitId, blob: &osis_commit::CommitBlob, inline: bool, reason: &Reason, now: u64) {
    if !inline || blob.parts.iter().any(|p| blob.header.aspects.get(p.ai).is_none_or(|a| a.ak.as_str() == "/secrets")) {
        return;
    }
    let on = match reason {
        Reason::UnknownCreated(t) | Reason::MissingChain(t) => On::Record { tid: *t, had: core.created(t).is_some() },
        Reason::WaitDeltas => {
            let missing = blob.missing();
            let expiry = missing.iter().filter_map(|(ai, _)| blob.header.aspects.get(*ai)).filter_map(|a| a.expires).min();
            On::Deltas { missing, expiry }
        }
        _ => return,
    };
    let w = Wait { header: Arc::new(blob.header.clone()), reason: reason.clone(), on, generation: core.held.generation(), edges: core.held.edges(), now };
    core.waits.insert(id, w);
}

/// Whether pending commit `id` certainly still waits as when last examined (memory only):
/// `reexamine` leaves it out.
pub(crate) fn unchanged(core: &Core, id: &CommitId, now: u64) -> bool {
    let Some(w) = core.waits.by_id.get(id) else { return false };
    if core.pending.get(id) != Some(&w.reason) || core.waits.woken.contains(id) || now < w.now || core.held.edges() != w.edges {
        return false;
    }
    match &w.on {
        On::Record { tid, had } => core.created(tid).is_some() == *had,
        On::Deltas { expiry, .. } => core.held.generation() == w.generation && expiry.is_none_or(|e| now < e),
    }
}

/// Whether pending commit `id`, a delta wait whose inputs may have changed, still waits for its
/// deltas: judged from its missing deltas alone, without reading the commit. `false`: examine
/// it again.
pub(crate) fn still_waits(tx: &mut Tx<'_>, id: &CommitId) -> Result<bool> {
    let Some(w) = tx.core.waits.by_id.get(id) else { return Ok(false) };
    let On::Deltas { missing, .. } = &w.on else { return Ok(false) };
    let now = tx.now().0;
    if tx.core.pending.get(id) != Some(&w.reason) || now < w.now || tx.core.held.edges() != w.edges {
        return Ok(false);
    }
    let (h, missing) = (w.header.clone(), missing.clone());
    // the drift bound held when examined, and the clock has not gone back since
    debug_assert!(h.author == tx.core.id.tid() || h.ts.wall_ms().0 <= now.saturating_add(MAX_DRIFT_MS));
    let waits = super::waits_for_deltas(tx, &h, id, missing.iter().copied())?;
    if waits {
        // judged again now: left out until something changes once more
        let generation = tx.core.held.generation();
        let next = missing.iter().filter_map(|(ai, _)| h.aspects.get(*ai)).filter_map(|a| a.expires).filter(|e| *e > now).min();
        tx.core.waits.woken.remove(id);
        if let Some(w) = tx.core.waits.by_id.get_mut(id) {
            w.generation = generation;
            w.now = now;
            w.on = On::Deltas { missing, expiry: next };
        }
    }
    Ok(waits)
}
