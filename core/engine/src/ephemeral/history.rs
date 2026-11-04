//! A memory aspect's side of its history (`engine::history`): this session's own batches from
//! the undo log (their memory commits are the same writes again, so those are left out), beside
//! the held memory commits of other nodes and earlier sessions, which Core lists like durable
//! ones. Both are bounded by the ephemeral caps, so a page may gather them all.

use crate::engine::Engine;
use crate::engine::history::{HistoryPos, HistoryRow, RowBody};
use crate::events::ChangeId;
use osis_base::{Ak, Tid, Ts};
use std::collections::BTreeSet;

impl Engine {
    /// Whether own batch delta `d` on `(tid, ak)` is gone whole (expired or superseded, spec/crdt.md
    /// §4.7: no write of it is in the state; one covered by a snapshot is, under its dot).
    pub(super) fn own_gone(&mut self, tid: &Tid, ak: &Ak, d: &osis_crdt::Fragment) -> bool {
        let writes = d.writes();
        if writes.is_empty() {
            return false;
        }
        let Ok(Some(st)) = self.state(tid, ak) else { return true };
        let held: BTreeSet<osis_crdt::Dot> = st.writes().into_iter().map(|(x, _)| x).collect();
        !writes.iter().any(|(x, _)| held.contains(x))
    }

    /// Whether held commit `c` is one of this session's own memory commits: a batch's (listed by
    /// the log as the batch that made it, not as a commit) or a compaction snapshot this node
    /// wrote (no change).
    pub(crate) fn own_memory_commit(&self, c: &osis_base::CommitId) -> bool {
        self.core.ix.commits.get(c).is_some_and(|m| m.view.memory && m.view.author == self.tid() && (m.view.kind.is_compaction() || matches!(m.view.form, osis_commit::Form::Session(n) if self.core.own_session(&n))))
    }

    /// The places of this session's own batches on `(tid, ak)`.
    pub(crate) fn memory_places(&mut self, tid: &Tid, ak: &Ak) -> BTreeSet<HistoryPos> {
        let mut out = BTreeSet::new();
        let entries: Vec<(Ts, ChangeId, Vec<osis_crdt::Fragment>)> = self.eph.log.entries.iter().map(|e| (e.ts, e.id, e.aspects.iter().filter(|a| a.tid == *tid && a.ak == *ak).map(|a| a.delta.clone()).collect())).collect();
        for (ts, id, deltas) in entries {
            if deltas.iter().any(|d| !self.own_gone(tid, ak, d)) {
                out.insert(HistoryPos { ts, id });
            }
        }
        out
    }

    /// The entry of own batch `id` on `(tid, ak)` from the undo log.
    pub(crate) fn memory_row(&mut self, tid: &Tid, ak: &Ak, id: &ChangeId, budget: usize) -> Option<HistoryRow> {
        let read = |f: &osis_crdt::Fragment| if f.approx_bytes() > budget { RowBody::TooLarge } else { RowBody::Held(f.read_written()) };
        let e = self.eph.log.entries.iter().find(|e| e.id == *id)?;
        let deltas: Vec<osis_crdt::Fragment> = e.aspects.iter().filter(|a| a.tid == *tid && a.ak == *ak).map(|a| a.delta.clone()).collect();
        let (ts, actor, received) = (e.ts, e.actor, e.received);
        let a = deltas.into_iter().find(|d| !self.own_gone(tid, ak, d))?;
        let kind = id.commit().and_then(|c| self.header(&c)).map(|h| h.kind);
        Some(HistoryRow { id: *id, kind, actor, node: self.tid(), ts, received, valid: true, body: read(&a) })
    }

    /// `Event::History` for these memory entries, at once: no transaction to wait for.
    pub(crate) fn memory_touched(&mut self, changes: Vec<(Tid, Ak, ChangeId)>) {
        self.core.history_touched(changes);
        self.core.events.flush();
    }
}
