//! The node root and the account root (spec/sync-set.md §1): the one local thing per node whose
//! closure the node holds, and the private thing beside the account its nodes read. Filled by
//! lane (b) of issues/reference-graph.md.

use crate::engine::Engine;
use crate::error::Result;
use osis_base::{Strong, Tid};

impl Engine {
    /// This node's node root (spec/sync-set.md §1): local, no sync ID, referenced by nothing.
    pub fn node_root(&self) -> Option<Tid> {
        todo!("refgraph: (b) the node root")
    }

    /// This node's account root (spec/sync-set.md §1), strongly referenced from the node root.
    pub fn account_root(&self) -> Option<Tid> {
        todo!("refgraph: (b) the account root")
    }

    /// Adds `s` to the node root's `holds.0` (spec/data-model.md §8, spec/sync-set.md §1).
    pub fn hold(&mut self, s: Strong) -> Result<()> {
        let _ = s;
        todo!("refgraph: (b) a strong from the node root")
    }

    /// Removes `s` from the node root's `holds.0`: what only it held leaves the node closure
    /// (spec/sync-set.md §3).
    pub fn unhold(&mut self, s: Strong) -> Result<()> {
        let _ = s;
        todo!("refgraph: (b) removing a strong from the node root")
    }
}
