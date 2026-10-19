//! What the server engine asks of a blind node's storage (spec/sync.md §4): the `LabelStore`
//! trait, which osis-server implements over osis-store, and `MemoryLabelStore` for tests.

use crate::msg::{Code, Sig, Wrap};
use osis_core::format::TOMBSTONE_LIFETIME_MS;
use osis_core::{BlobId, Classified, ErrorClass, LabelId};
use std::collections::{BTreeMap, HashMap};

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

/// A registered step: canonical `Step` bytes, and its claim set when the registrar sent it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredStep {
    pub step: Vec<u8>,
    pub claim_set: Option<Vec<u8>>,
}

/// One live entry of a label.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EntryMeta {
    pub wrap: Wrap,
    /// None: deposited.
    pub stamp: Option<Sig>,
    pub size: u64,
    /// Sequence number of its latest add event.
    pub add_seq: u64,
    pub pending_delete: Option<u64>,
}

/// A log record (spec/sync.md §4); add events take wrap and stamp from the live entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LogRecord {
    Added(BlobId),
    Deleted(BlobId),
    Pending(BlobId, u64),
    Head(Vec<u8>),
}

/// An entry to add or replace, already authorized by the engine.
#[derive(Clone, Copy, Debug)]
pub struct Put<'a> {
    pub blob_id: BlobId,
    pub blob: &'a [u8],
    pub wrap: Wrap,
    pub stamp: Option<Sig>,
    pub expiry: Option<u64>,
}

/// What remains of a label's deposit budget.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Budget {
    pub entries_left: u64,
    pub bytes_left: u64,
}

/// Blind-node state per label. Mutations append their log records; the store applies policy
/// (storage caps, deposit budget, rate limits) and answers with a status code.
pub trait LabelStore {
    /// Registration path from the genesis step to the head; empty for an unknown label.
    fn path(&self, label: &LabelId) -> Result<Vec<StoredStep>, StoreError>;
    /// Appends a verified step (a child of the head, or a new label's genesis) and logs it.
    fn push_step(&mut self, label: &LabelId, step: StoredStep) -> Result<(), StoreError>;
    fn entry(&self, label: &LabelId, blob_id: &BlobId) -> Result<Option<EntryMeta>, StoreError>;
    fn tombstoned(&self, label: &LabelId, blob_id: &BlobId) -> Result<bool, StoreError>;
    fn blob(&self, blob_id: &BlobId) -> Result<Option<Vec<u8>>, StoreError>;
    /// Adds an entry or replaces a held one's wrap and stamp (a stamp clears the deposited flag);
    /// a deposit (`stamp` none) of a held blob changes nothing. Logs an add on `Code::OK`.
    fn put(&mut self, label: &LabelId, put: Put<'_>) -> Result<Code, StoreError>;
    fn budget(&self, label: &LabelId) -> Result<Budget, StoreError>;
    /// Removes an entry, leaving a tombstone, and logs the deletion.
    fn delete(&mut self, label: &LabelId, blob_id: &BlobId, now: u64) -> Result<(), StoreError>;
    /// Sets a pending deletion time (the earliest wins) and logs it if it changed.
    fn schedule_delete(&mut self, label: &LabelId, blob_id: &BlobId, at: u64) -> Result<(), StoreError>;
    /// The label log's instance ID and its last sequence number (0: empty).
    fn log_head(&self, label: &LabelId) -> Result<([u8; 16], u64), StoreError>;
    /// Records with sequence numbers above `after`, at most `max`; `None` when the log no longer
    /// reaches `after`.
    fn log_after(&self, label: &LabelId, after: u64, max: usize) -> Result<Option<Vec<(u64, LogRecord)>>, StoreError>;
    /// Live entries whose latest add is above `after`, in add order, at most `max`.
    fn live_after(&self, label: &LabelId, after: u64, max: usize) -> Result<Vec<(BlobId, EntryMeta)>, StoreError>;
    /// IDs of the live entries, sorted.
    fn live_ids(&self, label: &LabelId) -> Result<Vec<BlobId>, StoreError>;
}

#[derive(Clone, Debug, Default)]
struct LabelState {
    log_id: [u8; 16],
    path: Vec<StoredStep>,
    entries: BTreeMap<BlobId, (EntryMeta, Option<u64>)>,
    tombstones: BTreeMap<BlobId, u64>,
    log: Vec<(u64, LogRecord)>,
    /// Records at or below this sequence number were dropped.
    horizon: u64,
    next_seq: u64,
}

impl LabelState {
    fn append(&mut self, r: LogRecord) -> u64 {
        self.next_seq += 1;
        self.log.push((self.next_seq, r));
        self.next_seq
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
}

/// Deposit budget unit (spec/sync.md §5 recommended minimum).
pub const DEPOSIT_ENTRY_BYTES: u64 = 32 * 1024;

impl MemoryLabelStore {
    /// `seed` names this instance's logs (log IDs derive from it).
    pub fn new(seed: [u8; 32]) -> MemoryLabelStore {
        MemoryLabelStore { seed, ..Default::default() }
    }

    fn state(&self, label: &LabelId) -> Option<&LabelState> {
        self.labels.get(label)
    }

    fn state_mut(&mut self, label: &LabelId) -> Result<&mut LabelState, StoreError> {
        self.labels.get_mut(label).ok_or_else(|| StoreError("unknown label".into()))
    }

    fn unref(&mut self, blob_id: &BlobId) {
        if let Some((_, n)) = self.blobs.get_mut(blob_id) {
            *n = n.saturating_sub(1);
            if *n == 0 {
                self.blobs.remove(blob_id);
            }
        }
    }

    /// Drops log records up to `seq` (cursors at or below it become invalid).
    pub fn truncate_log(&mut self, label: &LabelId, seq: u64) {
        if let Some(s) = self.labels.get_mut(label) {
            s.log.retain(|(n, _)| *n > seq);
            s.horizon = s.horizon.max(seq);
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
                s.entries.remove(id);
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

    fn budget_max(s: &LabelState) -> u64 {
        let claims = s.path.last().and_then(|h| h.claim_set.as_ref()).and_then(|c| crate::label::ClaimSet::parse(c).ok()).map_or(0, |c| c.claims.len() as u64);
        64 + 4 * claims
    }
}

impl LabelStore for MemoryLabelStore {
    fn path(&self, label: &LabelId) -> Result<Vec<StoredStep>, StoreError> {
        Ok(self.state(label).map(|s| s.path.clone()).unwrap_or_default())
    }

    fn push_step(&mut self, label: &LabelId, step: StoredStep) -> Result<(), StoreError> {
        let seed = self.seed;
        let s = self.labels.entry(*label).or_insert_with(|| {
            let mut log_id = [0u8; 16];
            let h = osis_core::hash::hash(&[&seed[..], &label.0[..]].concat());
            log_id.copy_from_slice(h.get(..16).unwrap_or(&[0; 16]));
            LabelState { log_id, ..Default::default() }
        });
        s.append(LogRecord::Head(step.step.clone()));
        s.path.push(step);
        Ok(())
    }

    fn entry(&self, label: &LabelId, blob_id: &BlobId) -> Result<Option<EntryMeta>, StoreError> {
        Ok(self.state(label).and_then(|s| s.entries.get(blob_id)).map(|(m, _)| m.clone()))
    }

    fn tombstoned(&self, label: &LabelId, blob_id: &BlobId) -> Result<bool, StoreError> {
        Ok(self.state(label).is_some_and(|s| s.tombstones.contains_key(blob_id)))
    }

    fn blob(&self, blob_id: &BlobId) -> Result<Option<Vec<u8>>, StoreError> {
        Ok(self.blobs.get(blob_id).map(|(b, _)| b.clone()))
    }

    fn put(&mut self, label: &LabelId, put: Put<'_>) -> Result<Code, StoreError> {
        let cap = self.entry_cap;
        let s = self.state_mut(label)?;
        let held = s.entries.contains_key(&put.blob_id);
        if held && put.stamp.is_none() {
            return Ok(Code::OK);
        }
        if !held && cap.is_some_and(|c| s.entries.len() >= c) {
            return Ok(Code::STORAGE_CAP);
        }
        if put.stamp.is_none() {
            let (n, bytes) = Self::deposited(s);
            let max = Self::budget_max(s);
            if n + 1 > max || bytes + put.blob.len() as u64 > max * DEPOSIT_ENTRY_BYTES {
                return Ok(Code::BUDGET_FULL);
            }
        }
        let seq = s.append(LogRecord::Added(put.blob_id));
        let pending = s.entries.get(&put.blob_id).and_then(|(m, _)| m.pending_delete);
        let meta = EntryMeta { wrap: put.wrap, stamp: put.stamp, size: put.blob.len() as u64, add_seq: seq, pending_delete: pending };
        s.entries.insert(put.blob_id, (meta, put.expiry));
        if !held {
            let e = self.blobs.entry(put.blob_id).or_insert_with(|| (put.blob.to_vec(), 0));
            e.1 += 1;
        }
        Ok(Code::OK)
    }

    fn budget(&self, label: &LabelId) -> Result<Budget, StoreError> {
        let s = self.state(label).ok_or_else(|| StoreError("unknown label".into()))?;
        let (n, bytes) = Self::deposited(s);
        let max = Self::budget_max(s);
        Ok(Budget { entries_left: max.saturating_sub(n), bytes_left: (max * DEPOSIT_ENTRY_BYTES).saturating_sub(bytes) })
    }

    fn delete(&mut self, label: &LabelId, blob_id: &BlobId, now: u64) -> Result<(), StoreError> {
        let s = self.state_mut(label)?;
        if s.entries.remove(blob_id).is_none() {
            return Ok(());
        }
        s.tombstones.insert(*blob_id, now);
        s.append(LogRecord::Deleted(*blob_id));
        self.unref(blob_id);
        Ok(())
    }

    fn schedule_delete(&mut self, label: &LabelId, blob_id: &BlobId, at: u64) -> Result<(), StoreError> {
        let s = self.state_mut(label)?;
        let Some((m, _)) = s.entries.get_mut(blob_id) else { return Ok(()) };
        if m.pending_delete.is_some_and(|t| t <= at) {
            return Ok(());
        }
        m.pending_delete = Some(at);
        s.append(LogRecord::Pending(*blob_id, at));
        Ok(())
    }

    fn log_head(&self, label: &LabelId) -> Result<([u8; 16], u64), StoreError> {
        let s = self.state(label).ok_or_else(|| StoreError("unknown label".into()))?;
        Ok((s.log_id, s.next_seq))
    }

    fn log_after(&self, label: &LabelId, after: u64, max: usize) -> Result<Option<Vec<(u64, LogRecord)>>, StoreError> {
        let s = self.state(label).ok_or_else(|| StoreError("unknown label".into()))?;
        if after < s.horizon || after > s.next_seq {
            return Ok(None);
        }
        let start = s.log.partition_point(|(n, _)| *n <= after);
        Ok(Some(s.log.iter().skip(start).take(max).cloned().collect()))
    }

    fn live_after(&self, label: &LabelId, after: u64, max: usize) -> Result<Vec<(BlobId, EntryMeta)>, StoreError> {
        let s = self.state(label).ok_or_else(|| StoreError("unknown label".into()))?;
        let mut live: Vec<(BlobId, EntryMeta)> = s.entries.iter().filter(|(_, (m, _))| m.add_seq > after).map(|(k, (m, _))| (*k, m.clone())).collect();
        live.sort_by_key(|(_, m)| m.add_seq);
        live.truncate(max);
        Ok(live)
    }

    fn live_ids(&self, label: &LabelId) -> Result<Vec<BlobId>, StoreError> {
        Ok(self.state(label).map(|s| s.entries.keys().copied().collect()).unwrap_or_default())
    }
}
