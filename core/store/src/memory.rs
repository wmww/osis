//! `MemoryBackend` (tests, simulator) and the shared fault plan that also drives `MemoryRoot`.

use crate::backend::{Backend, BackendError, KeyValue, Op, WriteBatch, blob_slice, lock};
use osis_base::BlobId;
use std::collections::{BTreeMap, HashMap};
use std::ops::Bound;
use std::sync::{Arc, Mutex, MutexGuard};

/// What happens at the planned write.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Fault {
    /// That write fails without effect; later writes work.
    Fail,
    /// That write and every later one fail without effect until `Faults::revive`: power loss.
    Crash,
    /// That write reaches storage but its sync fails (`BackendError::Unsynced`): it reads as
    /// written, and a power cut (`MemoryBackend::power_cut`, `MemoryRoot::power_cut`) drops it.
    /// Later syncs never make it durable (a failed fsync drops the pages from write-back); only
    /// writing it again does.
    Unsynced,
}

/// Whether a durable write that `Faults::check` lets through reaches the disk.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Synced {
    Yes,
    /// It reads as written, but its sync fails (`Fault::Unsynced`).
    No,
}

#[derive(Clone, Debug, Default)]
struct FaultState {
    writes: u64,
    plan: Option<(u64, Fault)>,
    dead: bool,
    /// A planned `Fail` happened since the last `take_failed`.
    failed: bool,
    /// `forbid_writes`: on, and the writes refused so far.
    forbid: bool,
    forbidden: u64,
}

/// A fault plan shared by the backends and root storages of one simulated device. Every durable
/// write (a backend `commit`, a root `store`) counts as one write, numbered from 0.
#[derive(Clone, Debug, Default)]
pub struct Faults(Arc<Mutex<FaultState>>);

impl Faults {
    pub fn new() -> Faults {
        Faults::default()
    }
    /// Injects `fault` at write number `n` (counted from now on: the counter is reset).
    pub fn at(&self, n: u64, fault: Fault) {
        let mut s = self.lock();
        s.writes = 0;
        s.plan = Some((n, fault));
    }
    /// Clears the plan and the crash: the device is powered up again.
    pub fn revive(&self) {
        let mut s = self.lock();
        s.plan = None;
        s.dead = false;
    }
    /// Tests: while on, every durable write fails without effect and is counted in `forbidden`,
    /// so a test can assert that memory-only work never writes.
    pub fn forbid_writes(&self, on: bool) {
        self.lock().forbid = on;
    }
    /// Durable writes refused by `forbid_writes` so far.
    pub fn forbidden(&self) -> u64 {
        self.lock().forbidden
    }
    /// Writes counted since the last `at` (or creation).
    pub fn writes(&self) -> u64 {
        self.lock().writes
    }
    pub fn crashed(&self) -> bool {
        self.lock().dead
    }
    /// Whether a planned `Fail` happened since the last call.
    pub fn take_failed(&self) -> bool {
        std::mem::take(&mut self.lock().failed)
    }
    /// Called before a durable write: `Err` means the write must not take effect; `Synced::No`
    /// that it takes effect but fails `BackendError::Unsynced` (`Fault::Unsynced`).
    pub fn check(&self) -> Result<Synced, BackendError> {
        let mut s = self.lock();
        if s.dead {
            return Err(BackendError::Crashed);
        }
        if s.forbid {
            s.forbidden = s.forbidden.saturating_add(1);
            return Err(BackendError::Fault);
        }
        let n = s.writes;
        s.writes = n.saturating_add(1);
        match s.plan {
            Some((at, Fault::Fail)) if at == n => {
                s.failed = true;
                Err(BackendError::Fault)
            }
            Some((at, Fault::Crash)) if at == n => {
                s.dead = true;
                Err(BackendError::Crashed)
            }
            Some((at, Fault::Unsynced)) if at == n => Ok(Synced::No),
            _ => Ok(Synced::Yes),
        }
    }
    /// Tests only (world copies, `osis_base::copying`): the copy's plan, as this one stands. One
    /// plan shared by a device's backend and root stays one plan in the copy.
    #[doc(hidden)]
    pub fn test_copy(&self) -> Faults {
        Faults(osis_base::copying::remap(&self.0, |m| Mutex::new(lock(m).clone())))
    }
    fn lock(&self) -> MutexGuard<'_, FaultState> {
        lock(&self.0)
    }
}

/// Rows and blobs.
#[derive(Clone, Debug, Default)]
struct Image {
    kv: BTreeMap<Vec<u8>, Vec<u8>>,
    blobs: HashMap<BlobId, Vec<u8>>,
}

impl Image {
    fn apply(&mut self, op: Op) {
        match op {
            Op::Put(k, v) => {
                self.kv.insert(k, v);
            }
            Op::Delete(k) => {
                self.kv.remove(&k);
            }
            Op::PutBlob(id, b) => {
                self.blobs.insert(id, b);
            }
            Op::DeleteBlob(id) => {
                self.blobs.remove(&id);
            }
        }
    }
}

#[derive(Clone, Debug, Default)]
struct Data {
    /// What reads see.
    live: Image,
    /// What a power cut leaves, where it differs from `live` (a write whose sync failed).
    disk: Option<Image>,
    /// Every value ever written, if recording: what a forensic look at freed pages could find.
    history: Option<Vec<KeyValue>>,
    /// Every blob put (`Some`) and free (`None`), if recording.
    blob_history: Vec<(BlobId, Option<Vec<u8>>)>,
    /// If recording, the key each row value was sealed under, by its AEAD tag (its last 16
    /// bytes): not evidence, only which key a row opens under (`forensic::Evidence::sealed`).
    sealed: HashMap<[u8; 16], [u8; 32]>,
    /// Commits so far (what a file backend fsyncs).
    syncs: u64,
    io: Io,
}

/// Rows and blobs read and written through a `MemoryBackend`, with their bytes: the store work
/// an operation did (scale tests count it at two sizes).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Io {
    /// Rows a `get` found or a `scan` returned, and blobs or blob ranges read.
    pub reads: u64,
    pub read_bytes: u64,
    /// Rows and blobs put or deleted.
    pub writes: u64,
    pub written_bytes: u64,
}

impl std::ops::Sub for Io {
    type Output = Io;
    fn sub(self, o: Io) -> Io {
        Io { reads: self.reads - o.reads, read_bytes: self.read_bytes - o.read_bytes, writes: self.writes - o.writes, written_bytes: self.written_bytes - o.written_bytes }
    }
}

/// In-memory backend. Clones share the data, so a test keeps a handle, "crashes" the store and
/// reopens over the same durable state.
#[derive(Clone, Debug, Default)]
pub struct MemoryBackend {
    data: Arc<Mutex<Data>>,
    faults: Faults,
}

impl MemoryBackend {
    pub fn new() -> MemoryBackend {
        MemoryBackend::default()
    }
    pub fn with_faults(faults: Faults) -> MemoryBackend {
        MemoryBackend { data: Arc::default(), faults }
    }
    /// Records every value and blob written from now on (`history`, `blob_history`), for
    /// shredding tests.
    pub fn record_history(&self) {
        let mut d = self.lock();
        if d.history.is_none() {
            d.history = Some(Vec::new());
        }
    }
    /// Every (key, value) ever put while recording, overwritten and deleted ones included.
    pub fn history(&self) -> Vec<KeyValue> {
        self.lock().history.clone().unwrap_or_default()
    }
    /// Every blob put (`Some(bytes)`) and freed (`None`) while recording, in order.
    pub fn blob_history(&self) -> Vec<(BlobId, Option<Vec<u8>>)> {
        self.lock().blob_history.clone()
    }
    /// The key each row value written while recording was sealed under, by its tag (debug
    /// builds, `Backend::note_sealed`).
    #[doc(hidden)]
    pub fn sealed(&self) -> HashMap<[u8; 16], [u8; 32]> {
        self.lock().sealed.clone()
    }
    /// The bytes held: row keys and values, and blobs (measures).
    pub fn held_bytes(&self) -> u64 {
        let (rows, blobs, _) = self.held_split();
        rows + blobs
    }
    /// The bytes held in rows, and in blobs with their number (measures).
    pub fn held_split(&self) -> (u64, u64, u64) {
        let d = self.lock();
        let rows: usize = d.live.kv.iter().map(|(k, v)| k.len() + v.len()).sum();
        (rows as u64, d.live.blobs.values().map(Vec::len).sum::<usize>() as u64, d.live.blobs.len() as u64)
    }
    /// An independent copy of the durable state, recorded history and counters, sharing the
    /// faults: a backup, or one device set up once and run down several paths.
    pub fn copy(&self) -> MemoryBackend {
        MemoryBackend { data: Arc::new(Mutex::new(self.lock().clone())), faults: self.faults.clone() }
    }
    /// Tests only (world copies, `osis_base::copying`): an exact copy of the data, recorded
    /// history, counters and fault plan (`Faults::test_copy`), sharing none of them; two handles
    /// on one data stay one data in the copy. A copy of a live node's store, never for a
    /// product: a node and its copy would reuse one identity, session and rng stream.
    #[doc(hidden)]
    pub fn test_copy(&self) -> MemoryBackend {
        MemoryBackend { data: osis_base::copying::remap(&self.data, |m| Mutex::new(lock(m).clone())), faults: self.faults.test_copy() }
    }
    /// Drops every value and blob (a removed database file).
    pub fn erase(&self) {
        let mut d = self.lock();
        d.live = Image::default();
        d.disk = None;
    }
    /// Power loss: what reads see falls back to what reached the disk, dropping writes whose
    /// sync failed (`Fault::Unsynced`).
    pub fn power_cut(&self) {
        let mut d = self.lock();
        if let Some(disk) = d.disk.take() {
            d.live = disk;
        }
    }
    /// The live key-value pairs.
    pub fn dump(&self) -> Vec<KeyValue> {
        self.lock().live.kv.iter().map(|(k, v)| (k.clone(), v.clone())).collect()
    }
    pub fn faults(&self) -> &Faults {
        &self.faults
    }
    /// Commits so far: a file backend's fsyncs.
    pub fn syncs(&self) -> u64 {
        self.lock().syncs
    }
    /// Store work so far (all clones share it).
    pub fn io(&self) -> Io {
        self.lock().io
    }
    fn lock(&self) -> MutexGuard<'_, Data> {
        lock(&self.data)
    }
}

impl Backend for MemoryBackend {
    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, BackendError> {
        let mut d = self.lock();
        let v = d.live.kv.get(key).cloned();
        d.io.read(v.as_ref().map(|v| key.len() + v.len()));
        Ok(v)
    }

    fn scan(&self, start: &[u8], end: Option<&[u8]>, limit: usize) -> Result<Vec<KeyValue>, BackendError> {
        let mut d = self.lock();
        let hi = match end {
            Some(e) => Bound::Excluded(e),
            None => Bound::Unbounded,
        };
        if end.is_some_and(|e| e <= start) {
            return Ok(Vec::new());
        }
        let rows: Vec<KeyValue> = d.live.kv.range::<[u8], _>((Bound::Included(start), hi)).take(limit).map(|(k, v)| (k.clone(), v.clone())).collect();
        for (k, v) in &rows {
            d.io.read(Some(k.len() + v.len()));
        }
        Ok(rows)
    }

    fn commit(&mut self, batch: WriteBatch) -> Result<(), BackendError> {
        let sync = self.faults.check()?;
        let mut d = self.lock();
        let d = &mut *d;
        if sync == Synced::No {
            // the old disk image stays; an earlier failed sync's one stays as it was
            if d.disk.is_none() {
                d.disk = Some(d.live.clone());
            }
        } else {
            d.syncs += 1;
            if let Some(disk) = &mut d.disk {
                batch.ops.iter().for_each(|op| disk.apply(op.clone()));
            }
        }
        for op in batch.ops {
            d.io.writes += 1;
            d.io.written_bytes += match &op {
                Op::Put(k, v) => k.len() + v.len(),
                Op::Delete(k) => k.len(),
                Op::PutBlob(_, b) => b.len(),
                Op::DeleteBlob(_) => 0,
            } as u64;
            if let Some(h) = d.history.as_mut() {
                match &op {
                    Op::Put(k, v) => h.push((k.clone(), v.clone())),
                    Op::PutBlob(id, b) => d.blob_history.push((*id, Some(b.clone()))),
                    Op::DeleteBlob(id) => d.blob_history.push((*id, None)),
                    Op::Delete(_) => {}
                }
            }
            d.live.apply(op);
        }
        if sync == Synced::No {
            return Err(BackendError::Unsynced);
        }
        Ok(())
    }

    fn note_sealed(&self, value: &[u8], key: &[u8; 32]) {
        let mut d = self.lock();
        if d.history.is_some()
            && let Some(tag) = value.len().checked_sub(16).and_then(|n| value.get(n..)).and_then(|t| <[u8; 16]>::try_from(t).ok())
        {
            d.sealed.insert(tag, *key);
        }
    }

    fn read_blob(&self, id: &BlobId, offset: u64, len: usize) -> Result<Option<Vec<u8>>, BackendError> {
        let mut d = self.lock();
        let b = d.live.blobs.get(id).map(|b| blob_slice(b, offset, len));
        d.io.read(b.as_ref().map(Vec::len));
        Ok(b)
    }

    fn blob_len(&self, id: &BlobId) -> Result<Option<u64>, BackendError> {
        Ok(self.lock().live.blobs.get(id).map(|b| b.len() as u64))
    }

    fn test_copy_boxed(&self) -> Option<Box<dyn Backend>> {
        Some(Box::new(self.test_copy()))
    }
}

impl Io {
    fn read(&mut self, found: Option<usize>) {
        if let Some(n) = found {
            self.reads += 1;
            self.read_bytes += n as u64;
        }
    }
}
