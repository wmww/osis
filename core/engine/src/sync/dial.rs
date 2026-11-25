//! Whom a node dials and where (spec/sync-opens.md §1 Where to dial, Whom to dial): `dial_peers`
//! per sync ID, from the `dial.0` lists of S's things held here (spec/sync-set.md §1), and this
//! node's own entries (`publish_reach`). For dialing only, never proof.

use super::Holding;
use crate::engine::Engine;
use crate::error::Result;
use crate::Mutation;
use osis_base::{Address, SyncId, Tid, Value, Weak, peer_url};
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
                for d in self.get_typed(t, &ct::DIAL)?.unwrap_or_default().into_values() {
                    if let Some(x) = address(&d.key, &d.urls) {
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
    /// spec/sync-set.md §1): its own entry, keyed by its node thing, dialable key `dialable` to
    /// the `peer://` URL of the items it listens at, in the `dial.0` of each of `on` it may write
    /// (its account and the account's profile); other nodes' entries stay. Its node root's
    /// `dial.0` (local: read by nobody else) keeps its own entry, the record of what it published
    /// last. Only where it changed.
    pub fn publish_reach(&mut self, dialable: [u8; 32], items: Vec<String>, on: &[Tid]) -> Result<()> {
        self.write_reach(ct::Dial { key: dialable.to_vec(), urls: vec![peer_url(&items)] }, on)
    }

    /// `publish_reach` again with what this node published last (its node root's entry), on
    /// `on`: where the things it keeps its entry on changed. Nothing before its first listen.
    pub fn publish_reach_on(&mut self, on: &[Tid]) -> Result<()> {
        let root = self.core.node_root.ok_or(crate::error::Error::Misuse("no node root"))?;
        let me = Weak(self.core.me());
        let Some(last) = self.get_typed(&root, &ct::DIAL)?.unwrap_or_default().remove(&me) else { return Ok(()) };
        self.write_reach(last, on)
    }

    /// `publish_reach_on` the things its node root's `dial_on^.0` names: each such thing
    /// writable here since (an account's, arriving after its pairing) gets the entry it lacks.
    /// O(the things named).
    pub fn refresh_reach(&mut self) -> Result<()> {
        let Some(root) = self.core.node_root else { return Ok(()) };
        let on: Vec<Tid> = self.get_typed(&root, &ct::DIAL_ON)?.unwrap_or_default().into_iter().map(|w| w.0).collect();
        if on.is_empty() {
            return Ok(());
        }
        self.publish_reach_on(&on)
    }

    /// `publish_reach`'s writes: this node's entry `d`.
    fn write_reach(&mut self, d: ct::Dial, on: &[Tid]) -> Result<()> {
        let root = self.core.node_root.ok_or(crate::error::Error::Misuse("no node root"))?;
        let me = Weak(self.core.me());
        let mut m = Mutation::new();
        for t in std::iter::once(root).chain(on.iter().copied()) {
            // a node writes only what it holds: a thing not here yet (an account just paired
            // into) gets the entry at the next listen
            if t != root && (self.role_on(&t) < Some(osis_base::Role::Write) || !self.core.writable(&t)) {
                continue;
            }
            if self.get_typed(&t, &ct::DIAL)?.unwrap_or_default().get(&me) != Some(&d) {
                m.op(t, &ct::DIAL, PathOp { path: vec![PathSeg::Key(Value::Weak(me.0))], op: Op::Set(osis_schema::Codec::to_value(&d)) })?;
            }
        }
        if !m.is_empty() {
            self.commit(m)?;
        }
        Ok(())
    }
}
