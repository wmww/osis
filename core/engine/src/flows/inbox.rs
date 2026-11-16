//! The inbox thing and its open signals (spec/sync-inbox.md §1, §2, §5): `ticket@~0`,
//! `removal@~0` and `stranded@~0`, fired sealed by anyone holding the inbox's public key record,
//! promoted by a writer. Filled by lane (c) of issues/reference-graph.md.

use crate::engine::{Engine, Tx};
use crate::error::Result;
use osis_base::{CommitId, Tid, Ticket};

/// Fires on `holder`'s inbox the ticket role commit `c` owes it about `things` (spec/sync-inbox.md
/// §5): a grant's, a key change's or a re-seal's.
pub(crate) fn fire_ticket(tx: &mut Tx<'_>, holder: Tid, c: CommitId, things: &[Tid]) -> Result<()> {
    let _ = (tx, holder, c, things);
    // refgraph: (c) fire the ticket
    Ok(())
}

/// Fires on `holder`'s inbox the removal notice of role commit `c` lowering its edge on `target`
/// below read (spec/sync-inbox.md §5).
pub(crate) fn fire_removal(tx: &mut Tx<'_>, holder: Tid, c: CommitId, target: Tid) -> Result<()> {
    let _ = (tx, holder, c, target);
    // refgraph: (c) fire the removal notice
    Ok(())
}

impl Engine {
    /// Account `a`'s inbox thing, as its `keys.0` names it (spec/sync-inbox.md §1); an actor with
    /// own keys that is no account is its own inbox.
    pub fn inbox_thing(&mut self, a: &Tid) -> Option<Tid> {
        let _ = a;
        todo!("refgraph: (c) the inbox thing")
    }

    /// The held ticket for `t` this node can open (spec/data-model.md §8 Tickets, spec/sync-set.md §2):
    /// found among the known references by `t`'s tid.
    pub fn ticket_for(&mut self, t: &Tid) -> Result<Option<Ticket>> {
        let _ = t;
        todo!("refgraph: (c) ticket lookup")
    }

    /// Acts on a removal notice fired on this account's inbox (spec/sync-inbox.md §5): checked
    /// against the member list held for its thing, then the thing released or a copy retained.
    pub fn take_removal_notice(&mut self, fire: &CommitId) -> Result<()> {
        let _ = fire;
        todo!("refgraph: (c) removal notices")
    }

    /// Fires a stranded notice on the thing of sync ID `s` (spec/sync-inbox.md §5), naming
    /// `holder` for its writers to re-seal.
    pub fn fire_stranded(&mut self, s: &osis_base::SyncId, holder: &Tid) -> Result<()> {
        let _ = (s, holder);
        todo!("refgraph: (c) stranded notices")
    }
}
