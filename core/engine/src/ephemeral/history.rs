//! A memory aspect's side of its history (`engine::history`): held commits of other nodes and
//! earlier sessions, and this session's own batches (`own` held commits are the same writes again).
//! Both are bounded by the ephemeral caps, so a page may gather them all.

use super::in_ranges;
use crate::engine::Engine;
use crate::engine::history::{HistoryPos, HistoryRow, RowBody};
use crate::events::ChangeId;
use osis_base::{Ak, Tid};
use std::collections::BTreeSet;

impl Engine {
    /// Whether own batch delta `d` on `(tid, ak)` has expired.
    pub(super) fn own_expired(&self, tid: &Tid, ak: &Ak, d: &osis_crdt::Fragment) -> bool {
        let Some(a) = self.eph.aspects.get(tid).and_then(|m| m.get(ak)) else { return false };
        let src = &self.eph.src;
        !a.expired.is_empty() && d.holds_dots(&|x| in_ranges(x, src, &a.expired))
    }

    /// The places of `(tid, ak)`'s entries kept in memory.
    pub(crate) fn memory_places(&self, tid: &Tid, ak: &Ak) -> BTreeSet<HistoryPos> {
        let now = self.now().0;
        let mut out = BTreeSet::new();
        for (c, ai) in self.eph.aspects.get(tid).and_then(|m| m.get(ak)).map(|a| &a.parts).into_iter().flatten() {
            let Some(h) = self.eph.remote.held.get(c).filter(|h| !h.own) else { continue };
            if h.header.aspects.get(*ai).and_then(|a| a.expires).is_none_or(|t| t > now) {
                out.insert(HistoryPos { ts: h.header.ts, id: ChangeId::Commit(*c) });
            }
        }
        for e in &self.eph.log.entries {
            if e.aspects.iter().any(|a| a.tid == *tid && a.ak == *ak && !self.own_expired(tid, ak, &a.delta)) {
                out.insert(HistoryPos { ts: e.ts, id: e.id });
            }
        }
        out
    }

    /// The entry of `id` on `(tid, ak)` kept in memory.
    pub(crate) fn memory_row(&self, tid: &Tid, ak: &Ak, id: &ChangeId, budget: usize) -> Option<HistoryRow> {
        let read = |f: &osis_crdt::Fragment| if f.approx_bytes() > budget { RowBody::TooLarge } else { RowBody::Held(f.read()) };
        if let Some(e) = self.eph.log.entries.iter().find(|e| e.id == *id)
            && let Some(a) = e.aspects.iter().find(|a| a.tid == *tid && a.ak == *ak && !self.own_expired(tid, ak, &a.delta))
        {
            let kind = id.commit().and_then(|c| self.header(&c)).map(|h| h.kind);
            return Some(HistoryRow { id: *id, kind, actor: e.actor, node: self.tid(), ts: e.ts, received: e.received, valid: true, body: read(&a.delta) });
        }
        let c = id.commit()?;
        let h = self.eph.remote.held.get(&c).filter(|h| !h.own)?;
        let p = h.parts.iter().find(|p| h.header.aspects.get(p.ai).is_some_and(|a| a.tid == *tid && a.ak == *ak && a.expires.is_none_or(|t| t > self.now().0)))?;
        Some(HistoryRow { id: *id, kind: Some(h.header.kind), actor: h.header.actor, node: h.header.author, ts: h.header.ts, received: h.received, valid: p.valid, body: read(&p.fragment) })
    }

    /// `Event::History` for these memory entries, at once: no transaction to wait for.
    pub(crate) fn memory_touched(&mut self, changes: Vec<(Tid, Ak, ChangeId)>) {
        self.core.history_touched(changes);
        self.core.events.flush();
    }

    /// The parts `(ai)` of held commit `c` not this session's own, as history changes.
    pub(crate) fn held_changes(h: &super::remote::Held, c: &osis_base::CommitId, ais: impl IntoIterator<Item = usize>) -> Vec<(Tid, Ak, ChangeId)> {
        if h.own {
            return Vec::new();
        }
        ais.into_iter().filter_map(|ai| h.header.aspects.get(ai)).map(|a| (a.tid, a.ak.clone(), ChangeId::Commit(*c))).collect()
    }
}
