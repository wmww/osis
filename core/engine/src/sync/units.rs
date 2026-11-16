//! Sync units and the node closure (spec/sync.md Sync units, Holding and release): what a sync ID
//! carries, walked by strongs within what the root may read; the node closure, walked sync unit
//! by sync unit from the node root. Filled by lane (b) of issues/reference-graph.md.

use crate::engine::Engine;
use osis_base::Tid;
use std::collections::BTreeSet;
use std::sync::Arc;

impl Engine {
    /// The sync unit of `t` (spec/sync.md Sync units): `t` and what it reaches by strongs and
    /// itself may read, stopping at the first thing it may not read.
    pub fn sync_unit(&self, t: &Tid) -> Arc<BTreeSet<Tid>> {
        let _ = t;
        todo!("refgraph: (b) sync unit walk")
    }

    /// Whether `t`'s sync unit is known whole here: no thing in it holds a part that may hold a
    /// strong as a header only (spec/sync-judgement.md §2, §3 Header-only parts).
    pub fn unit_settled(&mut self, t: &Tid) -> crate::error::Result<bool> {
        let _ = t;
        todo!("refgraph: (b) whether the sync unit is known whole")
    }

    /// The things whose sync unit holds `t` (spec/sync.md Sync units).
    pub fn units_holding(&self, t: &Tid) -> BTreeSet<Tid> {
        let _ = t;
        todo!("refgraph: (b) sync units holding t")
    }
}
