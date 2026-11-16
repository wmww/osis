//! Release (spec/sync-set.md §3): a thing leaving the node closure is dropped once the sync pass
//! in flight with the connected peers has ended, never waiting for an absent peer; removing a
//! strong costs at most the subtree it held (notes/closure-model.md). Filled by lane (b) of
//! issues/reference-graph.md.

use crate::engine::Engine;
use crate::error::Result;
use osis_base::Tid;
use std::collections::BTreeSet;

impl Engine {
    /// The things that left the node closure since `released` last took them: what sync drops
    /// once its pass in flight ends (spec/sync-set.md §3).
    pub fn left_closure(&mut self) -> Result<BTreeSet<Tid>> {
        todo!("refgraph: (b) what left the node closure")
    }

    /// Drops what `ts` left behind here: their local copies, as `forget_local` forgets them
    /// (spec/sync-set.md §3).
    pub fn released(&mut self, ts: &BTreeSet<Tid>) -> Result<()> {
        let _ = ts;
        todo!("refgraph: (b) release")
    }
}
