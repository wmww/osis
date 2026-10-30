//! What the server engine asks of a blind node's storage (spec/sync.md §4): the `LabelStore`
//! trait, which osis-server implements over osis-store, and `MemoryLabelStore` for tests.

use crate::msg::{ClaimSet, Code, Signature, Step, StepId, Wrap};
use osis_crypto::VerifyingKey;
use osis_base::format::TOMBSTONE_LIFETIME_MS;
use osis_base::{BlobId, Classified, ErrorClass, LabelId};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::Arc;

/// A storage failure. Always `Local`: never attributed to the peer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoreError(pub String);

impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "label store: {}", self.0)
    }
}

impl std::error::Error for StoreError {}

impl Classified for StoreError {
    fn class(&self) -> ErrorClass {
        ErrorClass::Local
    }
}

/// One live entry of a label.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EntryMeta {
    pub wrap: Wrap,
    /// None: deposited.
    pub stamp: Option<Signature>,
    pub size: u64,
    /// Sequence number of its latest add event.
    pub add_seq: u64,
    pub pending_delete: Option<u64>,
}

/// A log record (spec/sync.md §4); add events take wrap and stamp from the live entry.
#[derive(Clone, Debug, PartialEq, Eq)]
#[allow(clippy::large_enum_variant)] // steps carry parsed keys; boxing buys nothing here
pub enum LogRecord {
    Added(BlobId),
    Deleted(BlobId),
    Pending(BlobId, u64),
    Head(Step),
}

/// An entry to add or replace, already authorized by the engine. An ephemeral entry
/// (`ephemeral`, from the blob's prefix class) is held in memory only, under a per-label byte
/// cap (spec/sync.md §4, §5); a presence entry (`presence`, ephemeral too) is removed when the
/// connections that uploaded it have closed (`presence_gone`) and leaves no tombstone.
#[derive(Clone, Copy, Debug)]
pub struct Put<'a> {
    pub blob_id: BlobId,
    pub blob: &'a [u8],
    pub wrap: Wrap,
    pub stamp: Option<Signature>,
    pub expiry: Option<u64>,
    pub ephemeral: bool,
    pub presence: bool,
}

/// What remains of a label's deposit budget.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Budget {
    pub entries_left: u64,
    pub bytes_left: u64,
}

/// Longest registration path `path` walks (a guard against a corrupt store).
const MAX_PATH: usize = 1 << 20;

/// Earlier distinct keys per role an Upload, Deposit or Delete is answered code 9 for rather
/// than refused (each a signature check per refused item). Minor consequence: past it a signer
/// that far behind gets code 1 and learns no head; 0 would refuse every earlier key, infinity
/// would cost a check per key the label ever had.
pub const OLDER_KEYS: usize = 8;

/// A role key a step registers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StepKey {
    Sync,
    Write,
    Delete,
    Deposit,
}

impl StepKey {
    pub const ALL: [StepKey; 4] = [StepKey::Sync, StepKey::Write, StepKey::Delete, StepKey::Deposit];

    pub fn of(self, s: &Step) -> &VerifyingKey {
        match self {
            StepKey::Sync => &s.keys.sync,
            StepKey::Write => &s.keys.write,
            StepKey::Delete => &s.keys.delete,
            StepKey::Deposit => &s.keys.deposit,
        }
    }
}

/// What an Upload, Deposit or Delete is checked against: the head step and, per `StepKey`, up to
/// `OLDER_KEYS` distinct earlier keys of the path, newest first, never the head's. A store keeps
/// it as the head advances (`child`), so a check reads no path however long.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HeadKeys {
    pub head: Step,
    pub older: [Vec<VerifyingKey>; 4],
}

impl HeadKeys {
    pub fn genesis(head: Step) -> HeadKeys {
        HeadKeys { head, older: Default::default() }
    }

    /// The keys once `step` (a child of the head) is the head.
    pub fn child(&self, step: Step) -> HeadKeys {
        let older = StepKey::ALL.map(|k| {
            let (old, new) = (*k.of(&self.head), *k.of(&step));
            let i = k as usize;
            let mut v = Vec::with_capacity(OLDER_KEYS);
            for pk in std::iter::once(&old).chain(self.older.get(i).into_iter().flatten()) {
                if *pk != new && !v.contains(pk) && v.len() < OLDER_KEYS {
                    v.push(*pk);
                }
            }
            v
        });
        HeadKeys { head: step, older }
    }

    /// The keys of a whole path (genesis first); none when empty.
    pub fn of_path(path: &[Step]) -> Option<HeadKeys> {
        let head = path.last()?;
        let older = StepKey::ALL.map(|k| {
            let mut v = Vec::new();
            for pk in path.iter().rev().map(|s| k.of(s)) {
                if v.len() >= OLDER_KEYS {
                    break;
                }
                if pk != k.of(head) && !v.contains(pk) {
                    v.push(*pk);
                }
            }
            v
        });
        Some(HeadKeys { head: head.clone(), older })
    }
}

/// Blind-node state per label. Mutations append their log records; the store applies policy
/// (storage caps, the ephemeral cap, deposit budget, rate limits on wrap replacements and
/// deletes) and
/// answers with a status code.
pub trait LabelStore {
    /// The head's step ID; none for an unknown label.
    fn head(&self, label: &LabelId) -> Result<Option<StepId>, StoreError>;
    /// A step on the label's path.
    fn step(&self, label: &LabelId, id: &StepId) -> Result<Option<Step>, StoreError>;
    /// The claim set of a step on the path, while held.
    fn claim_set(&self, label: &LabelId, id: &StepId) -> Result<Option<Arc<ClaimSet>>, StoreError>;
    /// Registration path from the genesis step to the head; empty for an unknown label.
    fn path(&self, label: &LabelId) -> Result<Vec<Step>, StoreError> {
        let mut path = Vec::new();
        let mut at = self.head(label)?;
        while let Some(id) = at {
            if path.len() >= MAX_PATH {
                return Err(StoreError("registration path too long".into()));
            }
            let s = self.step(label, &id)?.ok_or_else(|| StoreError("step missing on the path".into()))?;
            at = s.prev;
            path.push(s);
        }
        path.reverse();
        Ok(path)
    }
    /// The head and earlier keys checks use; none for an unknown label. Stores that persist
    /// labels keep it per head (`HeadKeys::child`) rather than walk the path.
    fn head_keys(&self, label: &LabelId) -> Result<Option<HeadKeys>, StoreError> {
        Ok(HeadKeys::of_path(&self.path(label)?))
    }
    /// Whether a new label may be registered here (a verified genesis step): `Code::OK`, or a
    /// refusal such as code 12 at a node-wide storage cap (spec/wire.md §11.2 Register).
    fn admit_label(&self, _label: &LabelId) -> Result<Code, StoreError> {
        Ok(Code::OK)
    }
    /// Whether `dialable` (a verified member proof's key) is the dialable key of a node of a
    /// current reader of the label (a member peer serving it, spec/sync.md §5): the label then
    /// opens (no entry box). Blind nodes: never.
    fn member_open(&self, _dialable: &[u8; 32], _label: &LabelId) -> Result<bool, StoreError> {
        Ok(false)
    }
    /// Appends a verified step (a child of the head, or a new label's genesis) and logs it.
    fn push_step(&mut self, label: &LabelId, step: Step, claim_set: Option<ClaimSet>) -> Result<(), StoreError>;
    fn entry(&self, label: &LabelId, blob_id: &BlobId) -> Result<Option<EntryMeta>, StoreError>;
    fn tombstoned(&self, label: &LabelId, blob_id: &BlobId) -> Result<bool, StoreError>;
    fn blob(&self, blob_id: &BlobId) -> Result<Option<Vec<u8>>, StoreError>;
    /// Adds an entry or replaces a held one's wrap and stamp (a stamp clears the deposited flag);
    /// a deposit of a held blob, or an identical re-upload, changes nothing. Logs an add when
    /// something changed.
    fn put(&mut self, label: &LabelId, put: Put<'_>) -> Result<Code, StoreError>;
    fn budget(&self, label: &LabelId) -> Result<Budget, StoreError>;
    /// Removes an entry, leaving a tombstone (none for a presence entry), and logs the deletion
    /// (or refuses, e.g. code 4).
    fn delete(&mut self, label: &LabelId, blob_id: &BlobId, now: u64) -> Result<Code, StoreError>;
    /// Sets a pending deletion time (the earliest wins) and logs it if it changed.
    fn schedule_delete(&mut self, label: &LabelId, blob_id: &BlobId, at: u64) -> Result<Code, StoreError>;
    /// The label log's instance ID and its last sequence number (0: empty).
    fn log_head(&self, label: &LabelId) -> Result<([u8; 16], u64), StoreError>;
    /// Records with sequence numbers above `after`, at most `max`; `None` when the log no longer
    /// reaches `after`.
    fn log_after(&self, label: &LabelId, after: u64, max: usize) -> Result<Option<Vec<(u64, LogRecord)>>, StoreError>;
    /// Live entries with IDs above `after` (from the lowest when none), ascending, at most `max`.
    fn live_by_id(&self, label: &LabelId, after: Option<&BlobId>, max: usize) -> Result<Vec<(BlobId, EntryMeta)>, StoreError>;
    /// IDs of the live entries in `[lower, upper)` (no upper: to the end), sorted. A Reconcile
    /// reads only the ranges it asks (spec/wire.md §11.3), so its cost follows them, not the label.
    fn live_ids_in(&self, label: &LabelId, lower: &BlobId, upper: Option<&BlobId>) -> Result<Vec<BlobId>, StoreError>;
    /// IDs of the live entries, sorted.
    fn live_ids(&self, label: &LabelId) -> Result<Vec<BlobId>, StoreError> {
        self.live_ids_in(label, &BlobId([0; 32]), None)
    }
    /// Removes presence entry `blob_id` once every connection that uploaded it has closed
    /// (spec/sync.md §5): logged, no tombstone (only its author uploads it, again on reconnect).
    /// Whether a presence entry was held.
    fn presence_gone(&mut self, label: &LabelId, blob_id: &BlobId) -> Result<bool, StoreError>;
    /// Admits a stamped relay-only upload (spec/sync.md §5; `RelayGate::admit`).
    fn relay(&mut self, label: &LabelId, blob_id: &BlobId, size: usize, expiry: Option<u64>, now: u64) -> Result<crate::RelayVerdict, StoreError>;
}

#[derive(Clone, Debug, Default)]
struct LabelState {
    log_id: [u8; 16],
    steps: BTreeMap<StepId, (Step, Option<Arc<ClaimSet>>)>,
    head: Option<StepId>,
    keys: Option<HeadKeys>,
    entries: BTreeMap<BlobId, (EntryMeta, Option<u64>)>,
    tombstones: BTreeMap<BlobId, u64>,
    log: Vec<(u64, LogRecord)>,
    /// Records at or below this sequence number were dropped.
    horizon: u64,
    next_seq: u64,
    /// Ephemeral entries and their bytes; the presence ones among them.
    ephemeral: BTreeSet<BlobId>,
    ephemeral_bytes: u64,
    presence: BTreeSet<BlobId>,
}

impl LabelState {
    fn append(&mut self, r: LogRecord) -> u64 {
        self.next_seq += 1;
        self.log.push((self.next_seq, r));
        self.next_seq
    }

    /// Claim slots of the head's set (0 when not held).
    fn head_claims(&self) -> u64 {
        self.head.and_then(|h| self.steps.get(&h)).and_then(|(_, c)| c.as_ref()).map_or(0, |c| c.claims.len() as u64)
    }
}

/// In-memory blind-node store with the recommended deposit budget (spec/sync.md §5).
#[derive(Clone, Debug, Default)]
pub struct MemoryLabelStore {
    seed: [u8; 32],
    labels: BTreeMap<LabelId, LabelState>,
    blobs: HashMap<BlobId, (Vec<u8>, usize)>,
    /// Entries per label beyond which uploads get code 12.
    pub entry_cap: Option<usize>,
    /// Ephemeral entry bytes per label beyond which ephemeral uploads get code 12.
    pub ephemeral_cap: Option<u64>,
    /// (dialable key, label) pairs a member proof opens (`member_open`; member-peer tests).
    pub member_labels: BTreeSet<([u8; 32], LabelId)>,
    /// `blob` calls so far (cost tests).
    pub blob_reads: std::cell::Cell<u64>,
    /// IDs `live_ids_in` returned so far (cost tests).
    pub ids_read: std::cell::Cell<u64>,
    /// `step` calls so far (cost tests).
    pub step_reads: std::cell::Cell<u64>,
    pub relays: crate::RelayGate,
}

/// Deposit budget unit (spec/sync.md §5 recommended minimum).
pub const DEPOSIT_ENTRY_BYTES: u64 = 32 * 1024;

fn unknown() -> StoreError {
    StoreError("unknown label".into())
}

impl MemoryLabelStore {
    /// `seed` names this instance's logs (log IDs derive from it).
    pub fn new(seed: [u8; 32]) -> MemoryLabelStore {
        MemoryLabelStore { seed, ..Default::default() }
    }

    fn state(&self, label: &LabelId) -> Option<&LabelState> {
        self.labels.get(label)
    }

    fn state_mut(&mut self, label: &LabelId) -> Result<&mut LabelState, StoreError> {
        self.labels.get_mut(label).ok_or_else(unknown)
    }

    fn unref(&mut self, blob_id: &BlobId) {
        if let Some((_, n)) = self.blobs.get_mut(blob_id) {
            *n = n.saturating_sub(1);
            if *n == 0 {
                self.blobs.remove(blob_id);
            }
        }
    }

    /// Drops log records up to `seq` (cursors below it become invalid).
    pub fn truncate_log(&mut self, label: &LabelId, seq: u64) {
        if let Some(s) = self.labels.get_mut(label) {
            s.log.retain(|(n, _)| *n > seq);
            s.horizon = s.horizon.max(seq);
        }
    }

    /// Drops a step's claim set (as after `MEMBERSHIP_KEEP`).
    pub fn drop_claim_set(&mut self, label: &LabelId, id: &StepId) {
        if let Some((_, c)) = self.labels.get_mut(label).and_then(|s| s.steps.get_mut(id)) {
            *c = None;
        }
    }

    /// Expires entries (no tombstone, no event), executes pending deletions, drops old tombstones.
    pub fn sweep(&mut self, now: u64) {
        let labels: Vec<LabelId> = self.labels.keys().copied().collect();
        for label in labels {
            let Some(s) = self.labels.get_mut(&label) else { continue };
            let expired: Vec<BlobId> = s.entries.iter().filter(|(_, (_, exp))| exp.is_some_and(|t| t <= now)).map(|(k, _)| *k).collect();
            let due: Vec<BlobId> = s.entries.iter().filter(|(_, (m, _))| m.pending_delete.is_some_and(|t| t <= now)).map(|(k, _)| *k).collect();
            s.tombstones.retain(|_, t| t.saturating_add(TOMBSTONE_LIFETIME_MS) > now);
            for id in &expired {
                s.presence.remove(id);
                if let Some((m, _)) = s.entries.remove(id)
                    && s.ephemeral.remove(id)
                {
                    s.ephemeral_bytes = s.ephemeral_bytes.saturating_sub(m.size);
                }
            }
            for id in &expired {
                self.unref(id);
            }
            for id in due {
                let _ = self.delete(&label, &id, now);
            }
        }
    }

    /// Deposited entries and their bytes.
    fn deposited(s: &LabelState) -> (u64, u64) {
        s.entries.values().filter(|(m, _)| m.stamp.is_none()).fold((0, 0), |(n, b), (m, _)| (n + 1, b + m.size))
    }
}

impl LabelStore for MemoryLabelStore {
    fn member_open(&self, dialable: &[u8; 32], label: &LabelId) -> Result<bool, StoreError> {
        Ok(self.member_labels.contains(&(*dialable, *label)))
    }

    fn head(&self, label: &LabelId) -> Result<Option<StepId>, StoreError> {
        Ok(self.state(label).and_then(|s| s.head))
    }

    fn step(&self, label: &LabelId, id: &StepId) -> Result<Option<Step>, StoreError> {
        self.step_reads.set(self.step_reads.get() + 1);
        Ok(self.state(label).and_then(|s| s.steps.get(id)).map(|(s, _)| s.clone()))
    }

    fn head_keys(&self, label: &LabelId) -> Result<Option<HeadKeys>, StoreError> {
        Ok(self.state(label).and_then(|s| s.keys.clone()))
    }

    fn claim_set(&self, label: &LabelId, id: &StepId) -> Result<Option<Arc<ClaimSet>>, StoreError> {
        Ok(self.state(label).and_then(|s| s.steps.get(id)).and_then(|(_, c)| c.clone()))
    }

    fn push_step(&mut self, label: &LabelId, step: Step, claim_set: Option<ClaimSet>) -> Result<(), StoreError> {
        let seed = self.seed;
        let s = self.labels.entry(*label).or_insert_with(|| {
            let mut log_id = [0u8; 16];
            let h = osis_base::hash::hash(&[&seed[..], &label.0[..]].concat());
            log_id.copy_from_slice(h.get(..16).unwrap_or(&[0; 16]));
            LabelState { log_id, ..Default::default() }
        });
        let id = step.id();
        s.append(LogRecord::Head(step.clone()));
        s.keys = Some(match s.keys.take() {
            Some(k) => k.child(step.clone()),
            None => HeadKeys::genesis(step.clone()),
        });
        s.steps.insert(id, (step, claim_set.map(Arc::new)));
        s.head = Some(id);
        Ok(())
    }

    fn entry(&self, label: &LabelId, blob_id: &BlobId) -> Result<Option<EntryMeta>, StoreError> {
        Ok(self.state(label).and_then(|s| s.entries.get(blob_id)).map(|(m, _)| m.clone()))
    }

    fn tombstoned(&self, label: &LabelId, blob_id: &BlobId) -> Result<bool, StoreError> {
        Ok(self.state(label).is_some_and(|s| s.tombstones.contains_key(blob_id)))
    }

    fn blob(&self, blob_id: &BlobId) -> Result<Option<Vec<u8>>, StoreError> {
        self.blob_reads.set(self.blob_reads.get() + 1);
        Ok(self.blobs.get(blob_id).map(|(b, _)| b.clone()))
    }

    fn put(&mut self, label: &LabelId, put: Put<'_>) -> Result<Code, StoreError> {
        let (cap, ecap) = (self.entry_cap, self.ephemeral_cap);
        let s = self.state_mut(label)?;
        let held = s.entries.get(&put.blob_id).map(|(m, _)| m.clone());
        if let Some(m) = &held
            && (put.stamp.is_none() || (m.wrap == put.wrap && m.stamp == put.stamp))
        {
            return Ok(Code::OK);
        }
        if held.is_none() && cap.is_some_and(|c| s.entries.len() >= c) {
            return Ok(Code::STORAGE_CAP);
        }
        // an unstamped ephemeral blob never gets here (the server engine refuses it for every
        // store, spec/sync.md §5)
        if put.ephemeral && held.is_none() {
            if ecap.is_some_and(|c| s.ephemeral_bytes + put.blob.len() as u64 > c) {
                return Ok(Code::STORAGE_CAP);
            }
            s.ephemeral_bytes += put.blob.len() as u64;
            s.ephemeral.insert(put.blob_id);
            if put.presence {
                s.presence.insert(put.blob_id);
            }
        }
        if put.stamp.is_none() {
            let (n, bytes) = Self::deposited(s);
            let max = 64 + 4 * s.head_claims();
            if n + 1 > max || bytes + put.blob.len() as u64 > max * DEPOSIT_ENTRY_BYTES {
                return Ok(Code::BUDGET_FULL);
            }
        }
        let seq = s.append(LogRecord::Added(put.blob_id));
        let pending = held.as_ref().and_then(|m| m.pending_delete);
        let meta = EntryMeta { wrap: put.wrap, stamp: put.stamp, size: put.blob.len() as u64, add_seq: seq, pending_delete: pending };
        s.entries.insert(put.blob_id, (meta, put.expiry));
        if held.is_none() {
            let e = self.blobs.entry(put.blob_id).or_insert_with(|| (put.blob.to_vec(), 0));
            e.1 += 1;
        }
        Ok(Code::OK)
    }

    fn budget(&self, label: &LabelId) -> Result<Budget, StoreError> {
        let s = self.state(label).ok_or_else(unknown)?;
        let (n, bytes) = Self::deposited(s);
        let max = 64 + 4 * s.head_claims();
        Ok(Budget { entries_left: max.saturating_sub(n), bytes_left: (max * DEPOSIT_ENTRY_BYTES).saturating_sub(bytes) })
    }

    fn delete(&mut self, label: &LabelId, blob_id: &BlobId, now: u64) -> Result<Code, StoreError> {
        let s = self.state_mut(label)?;
        let Some((m, _)) = s.entries.remove(blob_id) else {
            return Ok(Code::OK);
        };
        if s.ephemeral.remove(blob_id) {
            s.ephemeral_bytes = s.ephemeral_bytes.saturating_sub(m.size);
        }
        if !s.presence.remove(blob_id) {
            s.tombstones.insert(*blob_id, now);
        }
        s.append(LogRecord::Deleted(*blob_id));
        self.unref(blob_id);
        Ok(Code::OK)
    }

    fn presence_gone(&mut self, label: &LabelId, blob_id: &BlobId) -> Result<bool, StoreError> {
        let Some(s) = self.labels.get_mut(label) else { return Ok(false) };
        if !s.presence.remove(blob_id) {
            return Ok(false);
        }
        if let Some((m, _)) = s.entries.remove(blob_id)
            && s.ephemeral.remove(blob_id)
        {
            s.ephemeral_bytes = s.ephemeral_bytes.saturating_sub(m.size);
        }
        s.append(LogRecord::Deleted(*blob_id));
        self.unref(blob_id);
        Ok(true)
    }

    fn schedule_delete(&mut self, label: &LabelId, blob_id: &BlobId, at: u64) -> Result<Code, StoreError> {
        let s = self.state_mut(label)?;
        let Some((m, _)) = s.entries.get_mut(blob_id) else { return Ok(Code::OK) };
        if m.pending_delete.is_some_and(|t| t <= at) {
            return Ok(Code::OK);
        }
        m.pending_delete = Some(at);
        s.append(LogRecord::Pending(*blob_id, at));
        Ok(Code::OK)
    }

    fn log_head(&self, label: &LabelId) -> Result<([u8; 16], u64), StoreError> {
        let s = self.state(label).ok_or_else(unknown)?;
        Ok((s.log_id, s.next_seq))
    }

    fn log_after(&self, label: &LabelId, after: u64, max: usize) -> Result<Option<Vec<(u64, LogRecord)>>, StoreError> {
        let s = self.state(label).ok_or_else(unknown)?;
        if after < s.horizon || after > s.next_seq {
            return Ok(None);
        }
        let start = s.log.partition_point(|(n, _)| *n <= after);
        Ok(Some(s.log.iter().skip(start).take(max).cloned().collect()))
    }

    fn live_by_id(&self, label: &LabelId, after: Option<&BlobId>, max: usize) -> Result<Vec<(BlobId, EntryMeta)>, StoreError> {
        let s = self.state(label).ok_or_else(unknown)?;
        let range = match after {
            Some(a) => s.entries.range((std::ops::Bound::Excluded(*a), std::ops::Bound::Unbounded)),
            None => s.entries.range(..),
        };
        Ok(range.take(max).map(|(k, (m, _))| (*k, m.clone())).collect())
    }

    fn live_ids_in(&self, label: &LabelId, lower: &BlobId, upper: Option<&BlobId>) -> Result<Vec<BlobId>, StoreError> {
        let Some(s) = self.state(label) else { return Ok(Vec::new()) };
        let ids: Vec<BlobId> = match upper {
            Some(u) if u <= lower => Vec::new(),
            Some(u) => s.entries.range(*lower..*u).map(|(k, _)| *k).collect(),
            None => s.entries.range(*lower..).map(|(k, _)| *k).collect(),
        };
        self.ids_read.set(self.ids_read.get() + ids.len() as u64);
        Ok(ids)
    }

    fn relay(&mut self, label: &LabelId, blob_id: &BlobId, size: usize, expiry: Option<u64>, now: u64) -> Result<crate::RelayVerdict, StoreError> {
        Ok(self.relays.admit(label, blob_id, size, expiry, now))
    }
}

#[cfg(test)]
pub(crate) mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing)]
    use super::*;
    use osis_crypto::{Secret32, SigningSecret};

    pub(crate) fn secret(n: u8) -> SigningSecret {
        SigningSecret::from_seed(&Secret32::from_bytes([n; 32]))
    }

    fn key(n: u8) -> VerifyingKey {
        secret(n).verifying_key()
    }

    /// A path whose role keys follow `pick(step, role)` (keys from a small pool, so they repeat).
    pub(crate) fn path(n: usize, pick: impl Fn(usize, usize) -> u8) -> Vec<Step> {
        let f = crate::examples::Fixture::new(0x10);
        let mut path: Vec<Step> = Vec::new();
        for i in 0..n {
            let mut s = f.genesis.clone();
            s.prev = path.last().map(|p| p.id());
            s.keys.sync = key(pick(i, 0));
            s.keys.write = key(pick(i, 1));
            s.keys.delete = key(pick(i, 2));
            s.keys.deposit = key(pick(i, 3));
            path.push(s);
        }
        path
    }

    // the head keys kept step by step (`child`) are those of the whole path: up to OLDER_KEYS
    // distinct earlier keys per role, newest first, never the head's
    #[test]
    fn head_keys_incremental() {
        for seed in 0..64u64 {
            let pick = |i: usize, r: usize| {
                let h = osis_base::hash::hash(&[seed.to_le_bytes(), (i as u64).to_le_bytes(), (r as u64).to_le_bytes()].concat());
                // role 3 keeps one key throughout on even seeds
                if r == 3 && seed % 2 == 0 { 1 } else { 1 + h[0] % (2 + (seed % 14) as u8) }
            };
            let p = path(40, pick);
            let mut k = HeadKeys::genesis(p[0].clone());
            for i in 1..p.len() {
                k = k.child(p[i].clone());
                assert_eq!(Some(&k), HeadKeys::of_path(&p[..=i]).as_ref(), "seed {seed} step {i}");
            }
        }
    }
}
