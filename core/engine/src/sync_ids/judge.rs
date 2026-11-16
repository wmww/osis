//! The judgment J of a connection (spec/sync-opens.md §4): whether its proven key
//! actors hold a thing here, have left it, or are unknown to it, read from the rosters this node
//! holds and nothing else. `Judge` is built once per use: the roster walks are per actor, the
//! lookups per thing.

use crate::engine::{Core, Engine};
use crate::error::Result;
use osis_base::{CreationRecord, Role, Tid};
use osis_crypto::VerifyingKey;
use std::collections::{BTreeMap, BTreeSet};

/// J(L) for a connection's proven actors (spec/sync-opens.md §4).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Judgment {
    /// A proven actor holds L's read role here now.
    Holder,
    /// Every grant path seen here for every proven actor that ever held L has ended (a role
    /// below read held now, sync, is no departure).
    Departed,
    /// No path to L seen here: blocks nothing.
    Unknown,
}

/// J over one set of proven actors.
pub struct Judge<'a> {
    core: &'a Core,
    actors: Vec<Tid>,
    /// `Timeline::roles_ever` of each actor, once, when a thing it does not hold is asked about.
    ever: BTreeMap<Tid, BTreeMap<Tid, Role>>,
}

impl Core {
    /// Whether `x` is another node of this node's account: on D's roster as this node reads it
    /// (spec/permissions.md §1, §5.4 Roster). A node removed is not.
    pub fn own_node(&self, x: &Tid) -> bool {
        let Some((p, _)) = self.account_devices() else { return false };
        *x != self.id.tid() && self.devices_roster(&p).contains(x)
    }

    /// J over `actors`: the actors a connection proved by their own key or, for an account, by
    /// its key at an epoch open here (`Proven`); never one read from group data.
    pub fn judge(&self, actors: impl IntoIterator<Item = Tid>) -> Judge<'_> {
        Judge { core: self, actors: actors.into_iter().collect(), ever: BTreeMap::new() }
    }
}

impl Judge<'_> {
    /// J of `thing`: the holders of the actor whose read role reads it (`Core::reader_of`), now
    /// (spec/permissions.md §2: a grant past its `until` counts as removed): read on the memo
    /// clock, so a follower of J is due again when an `until` passes.
    pub fn of(&mut self, thing: &Tid) -> Judgment {
        let a = self.core.reader_of(thing);
        for x in &self.actors {
            if *x == a || self.core.role_now(x, &a) >= Some(Role::Read) {
                return Judgment::Holder;
            }
        }
        // a holder of a role below read (sync) holds L still: it has not departed
        if self.actors.iter().any(|x| self.core.role_now(x, &a).is_some()) {
            return Judgment::Unknown;
        }
        let core = self.core;
        for x in &self.actors {
            let reached = self.ever.entry(*x).or_insert_with(|| core.timelines.get(x).map(|tl| tl.roles_ever(x)).unwrap_or_default());
            if reached.contains_key(&a) {
                return Judgment::Departed;
            }
        }
        Judgment::Unknown
    }
}

impl Engine {
    /// The signing keys of the key actors on `g`'s read role's roster here that a claim set lists
    /// by static entry (spec/sync-ids.md §3): not a node, not an account. O(roster).
    pub fn static_listed(&mut self, g: &Tid) -> Result<Vec<VerifyingKey>> {
        let a = self.core.reader_of(g);
        let holders: BTreeSet<Tid> = self.core.key_holders(&a).into_iter().map(|h| h.0).filter(|m| self.core.is_key_actor(m)).collect();
        let mut out = Vec::new();
        for m in holders {
            if self.is_node(&m)? {
                continue;
            }
            if let Some(CreationRecord::KeyActor { public_key, account: false, .. }) = self.core.created(&m) {
                out.extend(VerifyingKey::from_slice(public_key).ok());
            }
        }
        Ok(out)
    }
}
