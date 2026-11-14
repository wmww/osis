//! Lifecycle duties the engine judges and sync drives, each as an `Effects` value over what makes
//! it due (notes/sync-driver.md, Duties).
//!
//! - **Lifetimes** (spec/commits.md §5 Lifetimes): the engine's judgment (`Engine::judge_lifetimes`)
//!   runs when its work list or the rights mark moved (`Engine::lifetimes_due`, stamped), and its
//!   held things again when a sync ID this node syncs is newly heard out. A group is heard out
//!   when every sync ID this node syncs of it is: one no peer shares (no connection has it open,
//!   no kept record lists it: `Opens::shared`, as a leave's wait reads it) at once, else once its
//!   sources are (spec/sync-status.md §1, `Status::heard_out`); a group with none here is at once
//!   (a thing under no sync ID is judged at once). So a node alone (one device, no contact
//!   sharing the group) releases at once, and one whose sharing peers are away releases nothing
//!   under what they share.
//!
//! - **Role duties** (spec/permissions.md §2 Finalize, §3 Required rotation and Lost access): the
//!   engine's `role_duties` (finalizes and rotations owed before this node next encrypts, then the
//!   lost-access drop) runs when `Engine::role_duties_due` (its work list and the memo clock up to
//!   its first entry, stamped) settles true: a role commit applied from elsewhere, or an `until`
//!   passing with nothing written (the clock's wake).
//!
//! A duty whose drop forgot things makes the engine read its store again (`Engine::loads`): the
//! driver ends the settle and restarts the modules (notes/sync-driver.md, Failures).
//!
//! State: the sync IDs synced here with their things (`SyncsFollow`), each one's heard-out value
//! and whether one became heard out since the last judgment. Bounded by the sync IDs synced; a
//! restart settles every key afresh (every held thing is judged again once heard out).

use crate::set::SyncsFollow;
use crate::store::Store;
use crate::types::Result;
use osis_base::memo::Effects;
use osis_base::{SyncId, Tid};
use osis_engine::Engine;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone)]
pub struct Life {
    syncs: SyncsFollow,
    /// Per thing, the sync IDs this node syncs of it.
    ids: BTreeMap<Tid, BTreeSet<SyncId>>,
    /// Per sync ID synced, whether it is heard out, as last settled.
    heard: Effects<SyncId, bool>,
    heard_now: BTreeMap<SyncId, bool>,
    /// `Engine::lifetimes_due` (work due, things held), as last settled.
    due: Effects<(), (bool, bool)>,
    last: (bool, bool),
    /// A sync ID became heard out since the last judgment: the held things are judged again.
    newly: bool,
    /// `Engine::role_duties_due`, as last settled.
    roles: Effects<(), bool>,
}

impl Default for Life {
    fn default() -> Life {
        let mut due = Effects::new("life: lifetimes due");
        due.want(());
        let mut roles = Effects::new("life: role duties due");
        roles.want(());
        Life { syncs: SyncsFollow::default(), ids: BTreeMap::new(), heard: Effects::new("life: heard out"), heard_now: BTreeMap::new(), due, last: (false, false), newly: false, roles }
    }
}

impl std::fmt::Debug for Life {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Life").field("last", &self.last).field("newly", &self.newly).finish_non_exhaustive()
    }
}

impl Life {
    /// Follows what moved; runs each duty when due. `heard_out(s)`: S heard out now (stamped
    /// reads; no peer sharing S counts as heard out). Whether one ran (the engine's rows moved:
    /// the next round settles them).
    pub fn settle(&mut self, engine: &mut Engine, store: &Store, heard_out: impl FnMut(&SyncId) -> Result<bool>) -> Result<bool> {
        // the role duties first: a finalize or rotation goes before anything encrypts again
        if !self.roles.due().is_empty()
            && let Some((_, true)) = self.roles.settle(&(), || engine.role_duties_due())
        {
            if let Err(e) = engine.role_duties() {
                // due again at the next settle (the failing step restarts anyway)
                self.roles.unwant(&());
                self.roles.want(());
                return Err(e.into());
            }
            return Ok(true);
        }
        self.lifetimes(engine, store, heard_out)
    }

    fn lifetimes(&mut self, engine: &mut Engine, store: &Store, mut heard_out: impl FnMut(&SyncId) -> Result<bool>) -> Result<bool> {
        for (s, was, now) in self.syncs.settle(store) {
            if let Some((t, _)) = was
                && let Some(ids) = self.ids.get_mut(&t)
            {
                ids.remove(&s);
                if ids.is_empty() {
                    self.ids.remove(&t);
                }
            }
            match now {
                Some((t, _)) => {
                    self.ids.entry(t).or_default().insert(s);
                    self.heard.want(s);
                }
                None => {
                    self.heard.unwant(&s);
                    self.heard_now.remove(&s);
                }
            }
        }
        for s in self.heard.due() {
            if let Some((was, now)) = self.heard.try_settle(&s, || heard_out(&s))? {
                self.newly |= now && was != Some(true);
                self.heard_now.insert(s, now);
            }
        }
        if !self.due.due().is_empty()
            && let Some((_, v)) = self.due.try_settle(&(), || engine.lifetimes_due())?
        {
            self.last = v;
        }
        let (work, held) = self.last;
        if !work && !(held && self.newly) {
            return Ok(false);
        }
        let (ids, heard_now) = (&self.ids, &self.heard_now);
        // a group is heard out when every sync ID synced of it is (none: at once)
        let heard = |g: &Tid| ids.get(g).is_none_or(|ss| ss.iter().all(|s| heard_now.get(s) == Some(&true)));
        engine.judge_lifetimes(&heard, self.newly)?;
        self.newly = false;
        Ok(true)
    }
}
