//! Tickets in sync (spec/sync-inbox.md §5, spec/sync.md §3): the sync secrets and sync IDs the
//! tickets a node holds give it. Filled by lane (c) of
//! issues/reference-graph.md.

use crate::engine::Engine;
use osis_base::SyncId;
use osis_crypto::{Epoch, Secret32};

impl Engine {
    /// The sync secrets of kept-unread `s`'s thing that the tickets held here give, by epoch
    /// (spec/sync.md §3).
    pub fn ticket_sync_secrets(&mut self, s: &SyncId) -> Vec<(Epoch, Secret32)> {
        let _ = s;
        todo!("refgraph: (c) sync secrets from held tickets")
    }
}
