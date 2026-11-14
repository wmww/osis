//! What waits for sync's word (spec/sync-status.md §1-§2): self-removals whose lost secrets drop
//! once the removal is held elsewhere (spec/permissions.md §3 Lost access), and the complete
//! passes of an actor's sync ID that the re-seal and history-add triggers read
//! (spec/permissions.md §3).

use crate::engine::{Engine, Tx};
use crate::error::{Error, Result};
use osis_base::{CommitId, Tid, WallMs};
use osis_store::Shred;
use std::collections::BTreeSet;
use std::sync::Arc;

/// `hw/` + commit ID: a self-removal waiting to be held elsewhere.
pub(crate) const WAITING: &[u8] = b"hw/";

/// Loads the waiting self-removals (an open or reload).
pub(crate) fn load(tx: &mut Tx<'_>) -> Result<()> {
    let ids = tx.scan_keys(WAITING, "held elsewhere wait", CommitId)?;
    tx.core.ix.held_wait.extend(ids);
    Ok(())
}

/// Self-removal `c` waits to be held elsewhere before the secrets it gave up drop, in `c`'s own
/// transaction.
pub(crate) fn wait(tx: &mut Tx<'_>, c: CommitId) -> Result<()> {
    if tx.core.ix.held_wait.insert(c) {
        tx.txn.put_local(&[WAITING, &c.0].concat(), &[], Shred::No)?;
    }
    Ok(())
}

impl Engine {
    /// The self-removals waiting to be held elsewhere (spec/sync-status.md §2).
    pub(crate) fn waiting_held_elsewhere_now(&self) -> Arc<BTreeSet<CommitId>> {
        Arc::new(self.core.ix.held_wait.iter().copied().collect())
    }

    /// Sync saw `c` held elsewhere: it waits no more and the secrets this node lost drop
    /// (`drop_lost_secrets`, spec/permissions.md §3 Lost access).
    pub(crate) fn held_elsewhere_now(&mut self, c: &CommitId) -> Result<()> {
        let c = *c;
        let was = self.run(|tx| {
            let was = tx.core.ix.held_wait.remove(&c);
            if was {
                tx.txn.remove_local(&[WAITING, &c.0].concat(), Shred::No)?;
            }
            Ok(was)
        })?;
        if was && self.core.ix.held_wait.is_empty() {
            self.drop_lost_secrets()?;
        }
        Ok(())
    }

    /// Sync read every source of `actor`'s sync IDs to its end in a pass begun at `began`
    /// (spec/sync-status.md §1). Kept in memory: a restart needs a new pass.
    pub(crate) fn note_complete_pass_now(&mut self, actor: &Tid, began: WallMs) {
        let e = self.core.passes.entry(*actor).or_insert(began);
        *e = (*e).max(began);
    }

    /// Whether a complete pass of `actor`'s sync IDs began after every role commit on it this node
    /// received from elsewhere (spec/permissions.md §3: the re-seal trigger waits for one).
    pub(crate) fn complete_pass(&self, actor: &Tid) -> bool {
        let Some(began) = self.core.passes.get(actor).copied() else { return false };
        let roles = ["roles.0", "secrets.0", "keys.0"].map(|a| osis_base::Ak::new(a).map_err(|_| Error::Misuse("ak")));
        let latest = roles
            .into_iter()
            .flatten()
            .flat_map(|ak| self.core.ix.by_aspect.get(&(*actor, ak)).into_iter().flatten().map(|(_, c)| *c).collect::<Vec<_>>())
            .filter_map(|c| self.core.ix.commits.get(&c).filter(|m| m.origin == crate::events::Origin::Remote).map(|m| m.received))
            .max();
        latest.is_none_or(|t| t <= began)
    }
}
