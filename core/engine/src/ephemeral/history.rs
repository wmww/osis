//! A memory aspect's side of its history (`engine::history`): this session's own batches from
//! the undo log (their memory commits are the same writes again, so those are left out), beside
//! the held memory commits of other nodes and earlier sessions, which Core lists like durable
//! ones. Both are bounded by the ephemeral caps, so a page may gather them all.

use crate::engine::Engine;
use crate::engine::history::{HistoryPos, HistoryRow, RowBody};
use crate::events::ChangeId;
use osis_base::{Ak, Tid};
use std::collections::BTreeSet;

impl Engine {
    /// Whether own batch delta `d` on `(tid, ak)` is gone whole (expired or superseded: no write
    /// of it has a held commit, spec/crdt.md §4.7).
    pub(super) fn own_gone(&self, tid: &Tid, ak: &Ak, d: &osis_crdt::Fragment) -> bool {
        let writes = d.writes();
        !writes.is_empty() && writes.iter().all(|(x, _)| self.core.commit_of(tid, ak, x).is_none())
    }

    /// Whether held commit `c` is one of this session's own memory commits (listed by the log
    /// as the batch that made it, not as a commit).
    pub(crate) fn own_memory_commit(&self, c: &osis_base::CommitId) -> bool {
        self.core.ix.commits.get(c).is_some_and(|m| m.view.memory && m.view.author == self.tid() && matches!(m.view.form, osis_commit::Form::Session(n) if n == self.core.session.nonce || n == self.core.expiring.nonce))
    }

    /// The places of this session's own batches on `(tid, ak)`.
    pub(crate) fn memory_places(&self, tid: &Tid, ak: &Ak) -> BTreeSet<HistoryPos> {
        let mut out = BTreeSet::new();
        for e in &self.eph.log.entries {
            if e.aspects.iter().any(|a| a.tid == *tid && a.ak == *ak && !self.own_gone(tid, ak, &a.delta)) {
                out.insert(HistoryPos { ts: e.ts, id: e.id });
            }
        }
        out
    }

    /// The entry of own batch `id` on `(tid, ak)` from the undo log.
    pub(crate) fn memory_row(&self, tid: &Tid, ak: &Ak, id: &ChangeId, budget: usize) -> Option<HistoryRow> {
        let read = |f: &osis_crdt::Fragment| if f.approx_bytes() > budget { RowBody::TooLarge } else { RowBody::Held(f.read()) };
        let e = self.eph.log.entries.iter().find(|e| e.id == *id)?;
        let a = e.aspects.iter().find(|a| a.tid == *tid && a.ak == *ak && !self.own_gone(tid, ak, &a.delta))?;
        let kind = id.commit().and_then(|c| self.header(&c)).map(|h| h.kind);
        Some(HistoryRow { id: *id, kind, actor: e.actor, node: self.tid(), ts: e.ts, received: e.received, valid: true, body: read(&a.delta) })
    }

    /// `Event::History` for these memory entries, at once: no transaction to wait for.
    pub(crate) fn memory_touched(&mut self, changes: Vec<(Tid, Ak, ChangeId)>) {
        self.core.history_touched(changes);
        self.core.events.flush();
    }
}
