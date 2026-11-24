//! Whom a node dials and where (spec/sync-opens.md §1 Where to dial, Whom to dial): `dial_peers`
//! per sync ID, from the `dial.0` lists of S's things held here (spec/sync-set.md §1), and this
//! node's own entry (`publish_reach`). For dialing only, never proof.

use super::{Holding, RosterHolders};
use crate::engine::Engine;
use crate::error::Result;
use crate::Mutation;
use osis_base::{Address, SyncId, peer_url};
use osis_schema::core_types as ct;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

/// The address a dial record gives: its key at its first URL (none: not dialable).
fn address(key: &[u8], urls: &[String]) -> Option<Address> {
    Some(Address { url: urls.first()?.clone(), key: key.try_into().ok()? })
}

impl Engine {
    /// See `Engine::dial_peers`.
    pub(crate) fn dial_peers_now(&mut self, s: &SyncId) -> Result<Arc<Vec<Address>>> {
        let Some((things, holding)) = self.synced_things(s)? else { return Ok(Arc::default()) };
        let mut out: BTreeMap<[u8; 32], Address> = BTreeMap::new();
        if holding != Holding::Unread {
            for t in &things {
                for (k, urls) in self.get_typed(t, &ct::DIAL)?.unwrap_or_default() {
                    if let Some(x) = address(&k, &urls) {
                        out.entry(x.key).or_insert(x);
                    }
                }
            }
        }
        Ok(Arc::new(out.into_values().collect()))
    }

    /// S's things and how this node holds S; a sync ID left that sync still syncs: as read while
    /// its things' read secrets are held.
    fn synced_things(&mut self, s: &SyncId) -> Result<Option<super::Held>> {
        Ok(match self.sync_holder(s)? {
            Some(x) => Some(x),
            None => {
                let things: BTreeSet<_> = self.opening_things(s)?.into_iter().collect();
                (!things.is_empty()).then_some((things, Holding::Read))
            }
        })
    }

    /// See `Engine::roster_holders`: the holders other than this node, by who they are, not where
    /// they are dialed.
    pub(crate) fn roster_holders_now(&mut self, s: &SyncId) -> Result<Arc<RosterHolders>> {
        let Some((things, holding)) = self.synced_things(s)? else { return Ok(Arc::default()) };
        // kept unread: kept for the things that granted it, which the rosters here do not name
        if holding == Holding::Unread {
            return Ok(Arc::new(RosterHolders { anyone: true, ..RosterHolders::default() }));
        }
        let me = self.core.me();
        let holders = things.iter().flat_map(|t| self.core.holder_keys_of(self.core.reader_of(t))).filter(|a| *a != me).collect();
        Ok(Arc::new(RosterHolders { anyone: false, holders }))
    }

    /// Publishes where this node is dialed (spec/sync-transport.md §3, §5 Key change): its own
    /// entry, dialable key `dialable` to the `peer://` URL of the items it listens at, in its node
    /// thing's `dial.0` (spec/sync-set.md §1), in place of the one under its key before. Only
    /// where it changed.
    pub fn publish_reach(&mut self, dialable: [u8; 32], items: Vec<String>) -> Result<()> {
        let me = self.core.me();
        let mut list = self.get_typed(&me, &ct::DIAL)?.unwrap_or_default();
        let old = list.clone();
        list.retain(|k, _| k.as_slice() == dialable.as_slice());
        list.insert(dialable.to_vec(), vec![peer_url(&items)]);
        if list != old {
            let mut m = Mutation::new();
            m.set(me, &ct::DIAL, &list)?;
            self.commit(m)?;
        }
        Ok(())
    }
}
