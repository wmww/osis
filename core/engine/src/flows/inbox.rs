//! The inbox thing and its open signals (spec/sync-inbox.md §1, §2, §5): `ticket@~0`,
//! `removal@~0` and `stranded@~0`, fired sealed by anyone holding the inbox's public key record,
//! promoted by a writer. Filled by lane (c) of issues/reference-graph.md.

use super::Done;
use crate::engine::{Engine, Tx};
use crate::error::Result;
use crate::Mutation;
use osis_base::format::INBOX_LIFETIME_MS;
use osis_base::{Ak, CommitId, Tid, Ticket};
use osis_schema::core_types::{self as ct, RetentionEntry, RetentionSetting};
use std::collections::BTreeMap;

/// Arriving tickets (spec/sync-inbox.md §1).
pub const TICKET_FIRE: &str = Ak::check("ticket@~0", true);
/// Removal notices.
pub const REMOVAL_FIRE: &str = Ak::check("removal@~0", true);
/// Stranded notices.
pub const STRANDED_FIRE: &str = Ak::check("stranded@~0", true);

/// Gives the account's new inbox `i` own keys and its history setting: each of its three signals
/// kept `INBOX_LIFETIME` (spec/sync-inbox.md §1), in the account's creation.
pub(crate) fn make_inbox(tx: &mut Tx<'_>, i: Tid, done: &mut Done) -> Result<()> {
    crate::rotation::own_secrets(tx, i, done)?;
    let keep = RetentionEntry { history: Some(osis_schema::History::Keep { until: None, after: Some(INBOX_LIFETIME_MS) }), ..RetentionEntry::default() };
    let mut rules = BTreeMap::new();
    for k in [TICKET_FIRE, REMOVAL_FIRE, STRANDED_FIRE] {
        rules.insert(super::ak(k)?, keep);
    }
    let mut m = Mutation::new();
    m.set(i, &ct::RETENTION, &RetentionSetting::from(rules))?;
    done.add(Engine::commit_tx(tx, m)?);
    Ok(())
}

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
        if self.core.is_account(a) {
            return self.get_typed(a, &ct::KEYS).ok().flatten().and_then(|k| k.inbox).map(Tid::from);
        }
        self.core.has_own_secrets(a).then_some(*a)
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
