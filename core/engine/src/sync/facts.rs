//! What `read` judges one body at a sync ID on beside `BodyFacts` (spec/sync-judgement.md §2-§3,
//! spec/sync-compaction.md §1), and what moves its judgement: the commits held (a feed) and the
//! falls on a body's aspects. Each field is a direct statement of its spec clause over what the
//! engine holds; the ones not built say so and answer the side that keeps data.

use super::{BodyFacts, MustNot, ReadFacts};
use crate::engine::{DropFor, Engine};
use crate::error::Result;
use osis_base::{CommitId, SyncId};
use std::collections::BTreeSet;

impl Engine {
    /// spec/sync-judgement.md §2 must-not-hold (the clauses only the engine judges), §3 Role
    /// entries first, Dropped bodies, Neither; spec/sync-compaction.md §1 Carriers.
    /// - `must_not`: purged (a held request purges a part of the body, `purged_by`). Not built:
    ///   a strict subset of another held blob of the commit, a superseded or ended card commit
    ///   (`None` for them: the body is kept).
    /// - `own`: written here. `role`: a role commit or a purge request.
    /// - `carriers`: per part of the body a held valid snapshot under S covers, the snapshots
    ///   covering it (one of each must be held where the body leaves).
    /// - `later_unheld`: snapshots of the body's aspects stamped later than it whose part is
    ///   dropped here, each with whether it was dropped as invalid.
    /// - `neither`: not built (false: the body is logged and relayed again after a delete).
    /// - `missing`: a part of the body counts as never received (dropped as covered, its cover
    ///   gone, or found valid again).
    pub(crate) fn read_facts_now(&mut self, s: &SyncId, c: &CommitId) -> Result<ReadFacts> {
        let body: BodyFacts = self.body_facts_now(s, c)?;
        let mut f = ReadFacts { body, must_not: None, own: false, role: false, carriers: Vec::new(), later_unheld: Vec::new(), neither: false, missing: false };
        let bodies = self.sync_bodies_now(c)?;
        let (Some(b), Some(m), Some(h)) = (bodies.get(s).cloned(), self.core.ix.commits.get(c).cloned(), self.header(c)) else { return Ok(f) };
        f.own = m.origin == crate::events::Origin::Local;
        f.role = h.kind.is_role() || m.view.purges;
        f.missing = b.parts.iter().any(|ai| m.missing(*ai));
        let id = *c;
        for ai in &b.parts {
            let hh = h.clone();
            if self.run(|tx| crate::retention::purged_by(tx, &hh, &id, *ai))?.is_some() {
                f.must_not = Some(MustNot::Purged);
                break;
            }
        }
        for ai in &b.parts {
            let Some(a) = h.aspects.get(*ai) else { continue };
            let snaps: Vec<CommitId> = self.core.ix.snapshots.get(&(a.tid, a.ak.clone())).into_iter().flatten().map(|x| x.1).filter(|x| x != c).collect();
            let mut covering = BTreeSet::new();
            for x in snaps {
                if self.covered(&x, c, &a.tid, &a.ak)? == Some(true) {
                    covering.insert(x);
                }
                let Some(sm) = self.core.ix.commits.get(&x) else { continue };
                let later = self.header(&x).is_some_and(|sh| sh.ts > h.ts);
                if later && let Some(sai) = self.header(&x).and_then(|sh| sh.aspect_index(&a.tid, a.ak.as_str())) && let Some(d) = sm.dropped(sai) {
                    f.later_unheld.push((x, d.why == DropFor::Invalid));
                }
            }
            if !covering.is_empty() {
                f.carriers.push(covering);
            }
        }
        f.later_unheld.sort();
        f.later_unheld.dedup();
        Ok(f)
    }

    /// Falls of held parts on commit `c`'s aspects so far, summed (spec/sync-judgement.md §4: a
    /// stand compares marks).
    pub(crate) fn body_fall_mark_now(&mut self, c: &CommitId) -> u64 {
        let Some(h) = self.header(c) else { return 0 };
        h.aspects.iter().map(|a| self.fall_mark_now(&a.tid, &a.ak)).fold(0u64, u64::saturating_add)
    }
}
