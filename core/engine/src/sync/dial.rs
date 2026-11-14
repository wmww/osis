//! Whom a node dials and where (spec/sync-opens.md §1 Where to dial, Whom to dial): `dial_peers`
//! per sync ID, from the dial records it holds (its own nodes' `reach.0`, contacts' `dial^.0`, a
//! grant's dial hint in a sync record), and what this node publishes of itself
//! (`publish_reach`). For dialing only, never proof.

use super::{DialHint, Holding};
use crate::engine::Engine;
use crate::error::Result;
use crate::Mutation;
use osis_base::{Address, SyncId, Tid, peer_url};
use osis_schema::core_types as ct;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

/// A node's URLs from its `reach.0` items: the one `peer://` URL listing them (what its `dial^.0`
/// entry and its grants' dial hints carry).
pub(crate) fn urls_of(items: &[String]) -> Vec<String> {
    vec![peer_url(items)]
}

/// The address a dial record gives: its key at its first URL (none: not dialable).
fn address(key: &[u8], urls: &[String]) -> Option<Address> {
    Some(Address { url: urls.first()?.clone(), key: key.try_into().ok()? })
}

/// Whether this node lists itself in its account's profile dial list (`dial^.0`), so its
/// account's contacts can dial it. Every node does: the reversible reading while which nodes a
/// profile lists is Tess's open question (issues/sync-tess-calls.md).
fn lists_on_profile() -> bool {
    true
}

impl Engine {
    /// See `Engine::dial_peers`.
    pub(crate) fn dial_peers_now(&mut self, s: &SyncId) -> Result<Arc<Vec<Address>>> {
        let Some((t, holding)) = self.sync_holder(s)? else { return Ok(Arc::default()) };
        let mut out: BTreeMap<[u8; 32], Address> = BTreeMap::new();
        let own = self.core.account_devices();
        // own nodes whose sync sets hold S's thing, by their `reach.0`
        if let Some((_, d)) = own {
            let synced = self.get_typed(&d, &ct::SYNCED)?.unwrap_or_default();
            for (n, _) in self.core.key_holders(&d) {
                if !self.core.own_node(&n) || !self.closure(synced.get(&n).unwrap_or(&d)).contains(&t) {
                    continue;
                }
                if let Some(r) = self.get_typed(&n, &ct::REACH)? {
                    out.entry(r.dialable).or_insert(Address { url: peer_url(&r.items), key: r.dialable });
                }
            }
        }
        match holding {
            // the listed nodes of the accounts holding sync or above on S's thing
            Holding::Read => {
                for a in self.holder_accounts(&t) {
                    if own.is_some_and(|(p, _)| p == a) {
                        continue;
                    }
                    for (k, urls) in self.dial_list(&a)? {
                        if let Some(x) = address(&k, &urls) {
                            out.entry(x.key).or_insert(x);
                        }
                    }
                }
            }
            // its granter, by the grant's dial hint
            Holding::Unread => {
                for DialHint { dialable, urls } in self.sync_record_now(&t).iter().flat_map(|r| r.dials.iter()) {
                    if let Some(x) = address(dialable, urls) {
                        out.entry(x.key).or_insert(x);
                    }
                }
            }
        }
        Ok(Arc::new(out.into_values().collect()))
    }

    /// The accounts holding a role on `t`'s reader actor, directly or through the actors holding
    /// it (every role is sync or above), by the rosters held here.
    fn holder_accounts(&self, t: &Tid) -> BTreeSet<Tid> {
        let start = self.core.reader_of(t);
        let mut seen = BTreeSet::from([start]);
        let mut todo = vec![start];
        let mut out = BTreeSet::new();
        while let Some(x) = todo.pop() {
            for (m, _) in self.core.key_holders(&x) {
                if !seen.insert(m) {
                    continue;
                }
                if self.core.is_account(&m) {
                    out.insert(m);
                } else if !self.core.is_key_actor(&m) {
                    todo.push(m);
                }
            }
        }
        out
    }

    /// Account `a`'s profile (spec/permissions.md §1): the thing created with `a` (in the commit
    /// creating it, which `a` authors: a record needs no authority, so another author's commit
    /// carrying `a`'s record again creates no profile of `a`'s) whose first admin is `a`, other
    /// than its devices actor. `None` until that commit is held here.
    pub fn profile_of(&self, a: &Tid) -> Option<Tid> {
        let created = ct::CREATED.name();
        let by = self.core.ix.by_aspect.get(&(*a, created.clone()))?;
        let meta = by.iter().filter_map(|(_, c)| self.core.ix.commits.get(c)).find(|m| m.header.author == *a)?;
        meta.view.aspects.iter().filter(|x| x.ak == created && x.tid != *a).map(|x| x.tid).find(|x| self.core.first_admin(x) == Some(*a) && self.core.devices_of(x).is_none())
    }

    /// Account `a`'s dial list: `dial^.0` on its profile, as held here.
    fn dial_list(&mut self, a: &Tid) -> Result<ct::DialList> {
        let Some(p) = self.profile_of(a) else { return Ok(ct::DialList::new()) };
        Ok(self.get_typed(&p, &ct::DIAL)?.unwrap_or_default())
    }

    /// Publishes where this node is dialed (spec/sync-transport.md §3, §5 Key change): its
    /// `reach.0` (dialable key `dialable`, the `peer://` items it listens at, its account), and
    /// its own entry in its account's profile dial list (`dial^.0`, spec/sync-set.md §1) in place
    /// of the one under its key before. Each only where it changed; the entry once the profile is
    /// held here (a node paired a moment ago writes it at a later call). A node of no account
    /// publishes nothing.
    pub fn publish_reach(&mut self, dialable: [u8; 32], items: Vec<String>) -> Result<()> {
        let Some((p, _)) = self.core.account_devices() else { return Ok(()) };
        let me = self.core.id.tid();
        let reach = ct::Reach { dialable, items, account: Some(p) };
        let before = self.get_typed(&me, &ct::REACH)?;
        if before.as_ref() != Some(&reach) {
            // a commit of its own, touching nothing else (spec/permissions.md §4)
            let mut m = Mutation::new();
            m.set(me, &ct::REACH, &reach)?;
            self.commit(m)?;
        }
        let Some(profile) = self.profile_of(&p).filter(|x| self.core.writable(x) && lists_on_profile()) else { return Ok(()) };
        let mut list = self.get_typed(&profile, &ct::DIAL)?.unwrap_or_default();
        let old = list.clone();
        if let Some(b) = before.filter(|b| b.dialable != dialable) {
            list.remove(b.dialable.as_slice());
        }
        list.insert(dialable.to_vec(), urls_of(&reach.items));
        if list != old {
            let mut m = Mutation::new();
            m.set(profile, &ct::DIAL, &list)?;
            self.commit(m)?;
        }
        Ok(())
    }
}
