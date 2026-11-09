//! The judgment J of a connection (issues/net-shared-set.md, Words): whether its proven key
//! actors hold a thing here, have left it, or are unknown to it, read from the rosters this node
//! holds and nothing else. `Judge` is built once per use: the roster walks are per actor, the
//! lookups per thing.

use crate::engine::{Core, Engine};
use crate::error::Result;
use osis_base::{CreationRecord, Role, Tid};
use osis_crypto::VerifyingKey;
use osis_perm::{At, Timeline};
use std::collections::{BTreeMap, BTreeSet};

/// J(L) for a connection's proven actors (issues/net-shared-set.md, Words).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Judgment {
    /// A proven actor holds L's read role here now.
    Holder,
    /// Every grant path seen here for every proven actor that ever held L has ended.
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
    /// J over `actors`. Invariant: only actors that proved their own key belong here, never an
    /// account: a chain or an account key proves no removal it omits (`Proven::accounts`).
    pub fn judge(&self, actors: impl IntoIterator<Item = Tid>) -> Judge<'_> {
        Judge { core: self, actors: actors.into_iter().collect(), ever: BTreeMap::new() }
    }
}

impl Judge<'_> {
    fn timeline(&self, a: &Tid) -> Option<&Timeline> {
        self.core.timelines.get(a)
    }

    /// J of `thing`: the holders of the actor whose read role reads it (`Core::reader_of`).
    pub fn of(&mut self, thing: &Tid) -> Judgment {
        let a = self.core.reader_of(thing);
        for x in &self.actors {
            if *x == a || self.timeline(x).is_some_and(|tl| tl.role(x, &a, At::KEYS) >= Some(Role::Read)) {
                return Judgment::Holder;
            }
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

    /// Whether any actor is **known** here: a holder of anything through the rosters this node
    /// holds. A departed actor is not (it holds nothing).
    pub fn known(&self) -> bool {
        self.actors.iter().any(|x| self.timeline(x).is_some_and(|tl| tl.roles_of(x, At::KEYS).keys().any(|t| t != x)))
    }
}

impl Engine {
    /// The signing keys of the key actors on `g`'s read role's roster here that a claim set lists
    /// by static entry (spec/sync.md §2): not a node, not an account. O(roster).
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
