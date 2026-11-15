//! The sync IDs this node syncs: the engine's sync set (per sync ID, `Engine::sync_held`), and
//! each sync ID that left it while it waits to stop (spec/sync-set.md §3: it stays a member of
//! its shared sets as before). `leave` alone follows the engine's and writes them into the store
//! (`Store::set_holdings`); every other module (store, opens, dials, read, unread, streams,
//! status) follows them there, each by its own `SyncsFollow` (the store's feed of moved sync IDs)
//! or by stamped reads (`Store::synced`, `Store::holding`), never the engine's sync set. So a
//! leaving sync ID is synced everywhere until `leave` stops it.

use crate::store::Store;
use osis_base::SyncId;
use osis_base::memo::Feed;
pub use osis_engine::sync::Held;
use std::collections::{BTreeMap, BTreeSet};

/// One module's cursor over the sync IDs this node syncs (the store's `syncs_feed`): what moved
/// since its last settle, O(moved). Its first settle lists every one.
#[derive(Clone, Default)]
pub struct SyncsFollow {
    feed: Option<Feed<SyncId>>,
    seen: BTreeMap<SyncId, Held>,
}

impl SyncsFollow {
    /// The sync IDs whose entry moved since the last call, each with its entry then and now
    /// (`None`: not synced).
    pub fn settle(&mut self, store: &Store) -> Vec<(SyncId, Option<Held>, Option<Held>)> {
        let ids: BTreeSet<SyncId> = match self.feed.as_mut() {
            Some(f) => f.added().into_iter().collect(),
            None => {
                self.feed = Some(store.syncs_feed());
                store.syncs().into_keys().chain(self.seen.keys().copied()).collect()
            }
        };
        let mut out = Vec::new();
        for s in ids {
            let now = store.synced(&s);
            let was = match now {
                Some(h) => self.seen.insert(s, h),
                None => self.seen.remove(&s),
            };
            if was != now {
                out.push((s, was, now));
            }
        }
        out
    }
}

impl std::fmt::Debug for SyncsFollow {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SyncsFollow").field("seen", &self.seen).finish_non_exhaustive()
    }
}
