//! What node sync reads of the sync IDs this store keeps and it does not read (issues/net-one-peer.md
//! step 3, Opens; issues/net-shared-set.md, Peers that cannot read): their heads and claim sets
//! (the filter's sync-key, deposit-key and static-entry entries, a static entry's grant), a
//! generation that moves with any head, and the ephemeral entries of those its shared sets serve
//! (`set_streamed`), whose adds and removals it takes as its log's memory part (`take_memory`).

use super::{EphRemove, HostStore};
use osis_base::{BlobId, LabelId};
use osis_proto::msg::{ClaimSet, Step};
use osis_proto::{LabelStore, StoreError};
use std::collections::BTreeSet;
use std::sync::Arc;

/// An ephemeral entry event of a streamed sync ID (`HostStore::take_memory`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MemEvent {
    /// Added, or its wrap or stamp changed (a promotion).
    Added(LabelId, BlobId),
    /// Deleted (a delete, a replacement, an eviction).
    Deleted(LabelId, BlobId),
    /// Gone with no event of its own (expired).
    Gone(LabelId, BlobId),
}

/// A head step and its claim set, when held.
pub type HeadStep = (Step, Option<Arc<ClaimSet>>);

/// Labels read per page while listing.
const PAGE: usize = 256;

impl HostStore {
    /// The sync IDs this store keeps that node sync does not read (`reads`).
    pub fn unread_labels(&self) -> Result<Vec<LabelId>, StoreError> {
        let mut out = Vec::new();
        let mut after = None;
        loop {
            let page = self.labels_after(after.as_ref(), PAGE)?;
            let Some(last) = page.last().copied() else { return Ok(out) };
            let n = page.len();
            out.extend(page.into_iter().filter(|l| !self.reads(l)));
            if n < PAGE {
                return Ok(out);
            }
            after = Some(last);
        }
    }

    /// `label`'s head step and its claim set, when held.
    pub fn head_step(&self, label: &LabelId) -> Result<Option<HeadStep>, StoreError> {
        let Some(k) = self.head_keys(label)? else { return Ok(None) };
        let claims = self.claim_set(label, &k.head.id())?;
        Ok(Some((k.head, claims)))
    }

    /// `label`'s path from its genesis step to its head (by the child index, a step read per
    /// step), without claim sets.
    pub fn path(&self, label: &LabelId) -> Result<Vec<Step>, StoreError> {
        let mut out: Vec<Step> = Vec::new();
        while let Some(id) = self.child(label, out.last().map(Step::id).as_ref())? {
            let Some(s) = self.step(label, &id)? else { break };
            out.push(s);
        }
        Ok(out)
    }

    /// Moves when any head of this store moves, a label goes, or the set node sync reads
    /// changes: what the unread heads' credentials were read under (in memory).
    pub fn heads_generation(&self) -> u64 {
        self.heads_gen
    }

    /// The unread sync IDs node sync's shared sets serve: their ephemeral entries' adds and
    /// removals are kept for `take_memory` from now on, the others' not.
    pub fn set_streamed(&mut self, labels: BTreeSet<LabelId>) {
        self.mem.retain(|e| match e {
            MemEvent::Added(l, _) | MemEvent::Deleted(l, _) | MemEvent::Gone(l, _) => labels.contains(l),
        });
        self.streamed = labels;
    }

    /// The live ephemeral entries of `label`, oldest add first.
    pub fn ephemeral_live(&self, label: &LabelId) -> Vec<BlobId> {
        self.eph.labels.get(label).map(|e| e.order.values().copied().collect()).unwrap_or_default()
    }

    /// The ephemeral entry events of the streamed sync IDs since the last call, in order.
    pub fn take_memory(&mut self) -> Vec<MemEvent> {
        std::mem::take(&mut self.mem)
    }

    /// Notes an ephemeral event of `label` for node sync when it is streamed.
    pub(super) fn note_memory(&mut self, label: &LabelId, e: MemEvent) {
        if self.streamed.contains(label) {
            self.mem.push(e);
            self.moved = true;
        }
    }

    /// The event `how` makes of a removed ephemeral entry.
    pub(super) fn memory_removed(label: LabelId, blob: BlobId, how: EphRemove) -> MemEvent {
        match how {
            EphRemove::Expire => MemEvent::Gone(label, blob),
            EphRemove::Delete(_) | EphRemove::Evict => MemEvent::Deleted(label, blob),
        }
    }
}
