//! The serving side for sync IDs this node keeps and cannot read (issues/net-one-peer.md step 3,
//! Opens; issues/net-shared-set.md, Peers that cannot read): their heads come from the hub's
//! store, whose head credentials (sync key, deposit key, the claim set's static entries) go in
//! the filter to every connection; a member opened by one is served from the hub's store (its
//! rows, its ephemeral entries as the log's memory part, its relay-only entries past the hub's
//! relay gate) and ends through the event of a head that no longer bears it. This node tests
//! nothing for them and pulls none.

use super::state::hub_err;
use super::{Action, ConnId, SyncEngine};
use crate::error::Result;
use osis_base::{BlobId, LabelId};
use osis_crypto::{Signature, WRAP_LEN};
use osis_host::MemEvent;
use osis_label::{ClaimSet, Step};
use osis_proto::{Code, LabelStore};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

/// An unread sync ID's head at the hub's store, with its claim set when held.
#[derive(Clone)]
pub(crate) struct UnreadHead {
    pub(crate) step: Step,
    pub(crate) claims: Option<Arc<ClaimSet>>,
}

/// What node sync keeps of the unread sync IDs.
#[derive(Clone, Default)]
pub(crate) struct Unread {
    /// The heads as of the hub store's heads generation.
    heads: Option<(u64, Arc<BTreeMap<LabelId, UnreadHead>>)>,
    /// The generation `changed_at` was last stamped for.
    stamped: Option<u64>,
    /// The unread sync IDs some shared set holds (the hub's store keeps their ephemeral events).
    streamed: BTreeSet<LabelId>,
}

impl SyncEngine {
    fn hub(&self) -> std::sync::MutexGuard<'_, osis_host::HostStore> {
        self.hub_store.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// The unread sync IDs' heads, read again only when one moved (`heads_generation`).
    pub(crate) fn unread_heads(&mut self) -> Result<Arc<BTreeMap<LabelId, UnreadHead>>> {
        // the read set first: a label turning read leaves this map
        self.labels();
        let generation = self.hub().heads_generation();
        if let Some((g, h)) = &self.unread.heads
            && *g == generation
        {
            return Ok(h.clone());
        }
        let heads = {
            let hub = self.hub();
            let mut heads = BTreeMap::new();
            for l in hub.unread_labels().map_err(hub_err)? {
                if let Some((step, claims)) = hub.head_step(&l).map_err(hub_err)? {
                    heads.insert(l, UnreadHead { step, claims });
                }
            }
            Arc::new(heads)
        };
        self.unread.heads = Some((generation, heads.clone()));
        Ok(heads)
    }

    /// Whether `l` is a sync ID this node keeps and does not read.
    pub(crate) fn is_unread(&mut self, l: &LabelId) -> Result<bool> {
        Ok(self.unread_heads()?.contains_key(l))
    }

    /// What the hub changed of the unread sync IDs since the last step: a head moved (their
    /// credentials are stamped again and every connection re-judged), and the ephemeral entries
    /// of those streamed, taken into the log's memory part.
    pub(super) fn unread_moved(&mut self) {
        let (generation, memory) = {
            let mut hub = self.hub();
            (hub.heads_generation(), hub.take_memory())
        };
        if self.unread.stamped != Some(generation) {
            self.unread.stamped = Some(generation);
            self.changed_due = true;
        }
        let now = self.now();
        for e in memory {
            match e {
                MemEvent::Added(l, b) => self.state.mem_log.added(l, b, now),
                MemEvent::Deleted(l, b) => self.state.mem_log.deleted(l, b, now),
                MemEvent::Gone(l, b) => self.state.mem_log.gone(l, b),
            }
        }
    }

    /// The unread sync IDs some shared set holds now: the hub keeps their ephemeral events for
    /// the log's memory part, a newly streamed one's live entries listed there first; one no
    /// longer streamed leaves it.
    pub(super) fn unread_restream(&mut self) -> Result<()> {
        let heads = self.unread_heads()?;
        let now: BTreeSet<LabelId> = self.records.shared.values().flat_map(|s| s.member_ids().collect::<Vec<_>>()).filter(|l| heads.contains_key(l)).collect();
        if now == self.unread.streamed {
            return Ok(());
        }
        let wall = self.now();
        let added: Vec<LabelId> = now.difference(&self.unread.streamed).copied().collect();
        for l in self.unread.streamed.difference(&now) {
            self.state.mem_log.forget(l);
        }
        let live: Vec<(LabelId, Vec<BlobId>)> = {
            let mut hub = self.hub();
            hub.set_streamed(now.clone());
            added.iter().map(|l| (*l, hub.ephemeral_live(l))).collect()
        };
        for (l, bs) in live {
            for b in bs {
                self.state.mem_log.added(l, b, wall);
            }
        }
        self.unread.streamed = now;
        Ok(())
    }

    /// Entry `b` of unread `l` as the hub's store holds it, durable or ephemeral: its wrap and
    /// stamp.
    pub(crate) fn unread_entry(&mut self, l: &LabelId, b: &BlobId) -> Result<Option<([u8; WRAP_LEN], Option<Signature>)>> {
        if !self.is_unread(l)? {
            return Ok(None);
        }
        Ok(self.hub().entry(l, b).map_err(hub_err)?.map(|m| (m.wrap, m.stamp)))
    }

    /// Blob bytes as the hub's store holds them (memory entries included).
    pub(crate) fn unread_blob(&self, b: &BlobId) -> Result<Option<Vec<u8>>> {
        self.hub().blob(b).map_err(hub_err)
    }

    /// What a holder of static entry `entry` needs to read unread `l` (a static entry's Hit): the
    /// head's entry box for it and the path from the genesis step to the head.
    pub(crate) fn unread_grant(&mut self, l: &LabelId, entry: &[u8; 32]) -> Result<Option<osis_proto::msg::EntryGrant>> {
        let heads = self.unread_heads()?;
        let Some(entry_box) = heads.get(l).and_then(|h| h.claims.as_ref()).and_then(|c| c.entries.get(entry)).cloned() else { return Ok(None) };
        let path = self.hub().path(l).map_err(hub_err)?;
        Ok(Some(osis_proto::msg::EntryGrant { entry_box, path }))
    }

    /// Where a member of unread `l` opened by a credential its head no longer bears ends
    /// (`until`): the head's event, the one that ended it, else the log's end.
    pub(crate) fn unread_until(&mut self, l: &LabelId) -> Result<u64> {
        self.engine.run(|tx| {
            let at = super::state::hub(tx)?.node_log(|t| t.log_head_at(l))?;
            Ok(match at {
                Some(p) => p,
                None => super::state::hub(tx)?.node_log(|t| t.log_end())?,
            })
        })
    }

    /// A Deposit item for unread inbox `l` (issues/net-shared-set.md, Deposits): taken as a
    /// Deposit by the hub's store (its signature, budget, rate, caps: spec/sync.md §5), its
    /// subscribers told: 0, refused for now (4, 5, 12), else 14.
    pub(crate) fn unread_deposit(&mut self, conn: ConnId, l: LabelId, blob: &[u8], wrap: [u8; WRAP_LEN], sig: &Signature, out: &mut Vec<Action>) -> Result<Code> {
        let now = self.now();
        let code = {
            let mut hub = self.hub();
            let Some(k) = hub.head_keys(&l).map_err(hub_err)? else { return Ok(Code::NOT_ADMITTED) };
            let mut struck = false;
            let (code, signed) = osis_proto::serving::deposit(&mut *hub, now, &l, &k, blob, wrap, sig, &mut struck).map_err(hub_err)?;
            // refused for now passes on (spec/sync.md §10, Deposit items); any other refusal is 14
            match code {
                Code::OK | Code::RATE_LIMITED | Code::BUDGET_FULL | Code::STORAGE_CAP if signed => code,
                _ => Code::NOT_ADMITTED,
            }
        };
        if code == Code::OK {
            self.hub_down(conn, osis_host::Down::Changed(l), out);
        }
        Ok(code)
    }
}
