//! Whom a node dials and where (spec/sync-opens.md §1 Where to dial, Whom to dial): `dial_peers`
//! per sync ID, from the `dial.0` lists of S's things held here (spec/sync-set.md §1), and this
//! node's own entries (`publish_reach`). For dialing only, never proof.

use super::Holding;
use crate::engine::Engine;
use crate::error::Result;
use crate::Mutation;
use osis_base::{Address, SyncId, Tid, Value, peer_url};
use osis_crdt::{Op, PathOp, PathSeg};
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
    pub(crate) fn synced_things(&mut self, s: &SyncId) -> Result<Option<super::Held>> {
        Ok(match self.sync_holder(s)? {
            Some(x) => Some(x),
            None => {
                let things: BTreeSet<_> = self.opening_things(s)?.into_iter().collect();
                (!things.is_empty()).then_some((things, Holding::Read))
            }
        })
    }

    /// Publishes where this node is dialed (spec/sync-transport.md §3, §5 Key change;
    /// spec/sync-set.md §1): its own entry, dialable key `dialable` to the `peer://` URL of the
    /// items it listens at, in the `dial.0` of each of `on` it may write (its account and the
    /// account's profile), in place of its entry under an earlier key; other nodes' entries
    /// stay. Its node root's `dial.0` (local: read by nobody else) keeps its own entry, the
    /// record of which key it published last. Only where it changed.
    pub fn publish_reach(&mut self, dialable: [u8; 32], items: Vec<String>, on: &[Tid]) -> Result<()> {
        self.write_reach(dialable, vec![peer_url(&items)], on)
    }

    /// `publish_reach` again with what this node published last (its node root's entry), on
    /// `on`: where the things it keeps its entry on changed. Nothing before its first listen.
    pub fn publish_reach_on(&mut self, on: &[Tid]) -> Result<()> {
        let root = self.core.node_root.ok_or(crate::error::Error::Misuse("no node root"))?;
        let last = self.get_typed(&root, &ct::DIAL)?.unwrap_or_default().into_iter().next();
        let Some((key, url)) = last else { return Ok(()) };
        let Ok(key) = <[u8; 32]>::try_from(key.as_slice()) else { return Ok(()) };
        self.write_reach(key, url, on)
    }

    /// `publish_reach`'s writes: this node's entry `dialable` to `url`.
    fn write_reach(&mut self, dialable: [u8; 32], url: Vec<String>, on: &[Tid]) -> Result<()> {
        let root = self.core.node_root.ok_or(crate::error::Error::Misuse("no node root"))?;
        let mine: Vec<Vec<u8>> = self.get_typed(&root, &ct::DIAL)?.unwrap_or_default().into_keys().filter(|k| k.as_slice() != dialable.as_slice()).collect();
        let mut m = Mutation::new();
        for t in std::iter::once(root).chain(on.iter().copied()) {
            if t != root && self.role_on(&t) < Some(osis_base::Role::Write) {
                continue;
            }
            // its own entries alone, so each entry's writer is the node it is of (a remover drops a
            // removed node's by who wrote them, spec/permissions.md §8 Removing)
            let list = self.get_typed(&t, &ct::DIAL)?.unwrap_or_default();
            for k in mine.iter().filter(|k| list.contains_key(*k)) {
                m.op(t, &ct::DIAL, PathOp { path: Vec::new(), op: Op::Remove(Value::Bytes(k.clone())) })?;
            }
            if list.get(dialable.as_slice()) != Some(&url) {
                m.op(t, &ct::DIAL, PathOp { path: vec![PathSeg::Key(Value::Bytes(dialable.to_vec()))], op: Op::Set(osis_schema::Codec::to_value(&url)) })?;
            }
        }
        if !m.is_empty() {
            self.commit(m)?;
        }
        Ok(())
    }
}
