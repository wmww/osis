//! The account's tickets (spec/sync-set.md §1): D's ticket for each independent thing the walk
//! enters at a strong outside the node root's local part, at a current epoch.
//!
//! Each thing entering the node closure (`Engine::closure_feed`) is followed by one `Effects` key
//! over what the engine reads to judge it (`Engine::account_ticket_due`: how the walk enters it,
//! its epochs, D's `tickets.0`); due, this node writes the ticket (`write_account_ticket`), so a
//! newer epoch writes a fresh one. A thing out of the node closure is followed no more; its
//! tickets go in the transaction releasing it (the engine's).

use super::Here;
use crate::types::Result;
use osis_base::memo::{Effects, Feed};
use osis_base::{Role, Tid};

#[derive(Clone)]
pub(super) struct AccountTickets {
    feed: Option<Feed<Tid>>,
    due: Effects<Tid, Option<Role>>,
}

impl Default for AccountTickets {
    fn default() -> Self {
        AccountTickets { feed: None, due: Effects::new("inbox: account tickets") }
    }
}

impl AccountTickets {
    pub(super) fn start(&mut self, h: &mut Here<'_>) -> Result<()> {
        self.feed = Some(h.engine.closure_feed());
        for t in h.engine.sync_things()?.iter() {
            self.due.want(*t);
        }
        Ok(())
    }

    pub(super) fn settle(&mut self, h: &mut Here<'_>) -> Result<bool> {
        if let Some(f) = self.feed.as_mut() {
            for t in f.added() {
                self.due.want(t);
            }
        }
        let mut acted = false;
        for t in self.due.due() {
            if !h.engine.in_sync_things(&t)? {
                self.due.unwant(&t);
                continue;
            }
            let engine = &mut *h.engine;
            let Some((_, Some(_))) = self.due.try_settle(&t, || engine.account_ticket_due(&t))? else { continue };
            osis_base::costs::count("inbox: account ticket written", 1);
            h.engine.write_account_ticket(&t)?;
            acted = true;
        }
        Ok(acted)
    }
}
