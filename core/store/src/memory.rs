//! `MemoryBackend` (tests, simulator) and the shared fault plan that also drives `MemoryRoot`.

use crate::backend::{Backend, BackendError, KeyValue, Op, WriteBatch, blob_slice};
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
}

#[derive(Clone, Debug, Default)]
struct FaultState {
    writes: u64,
    plan: Option<(u64, Fault)>,
    dead: bool,
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
    /// Called before a durable write: `Err` means the write must not take effect.
    pub fn check(&self) -> Result<(), BackendError> {
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
            Some((at, Fault::Fail)) if at == n => Err(BackendError::Fault),
            Some((at, Fault::Crash)) if at == n => {
                s.dead = true;
                Err(BackendError::Crashed)
            }
            _ => Ok(()),
        }
    }
    /// Tests only (world copies, `osis_base::copying`): the copy's plan, as this one stands. One
    /// plan shared by a device's backend and root stays one plan in the copy.
    #[doc(hidden)]
    pub fn test_copy(&self) -> Faults {
        Faults(osis_base::copying::remap(&self.0, |m| Mutex::new(m.lock().unwrap_or_else(std::sync::PoisonError::into_inner).clone())))
    }
    fn lock(&self) -> MutexGuard<'_, FaultState> {
        self.0.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

#[derive(Clone, Debug, Default)]
struct Data {
    kv: BTreeMap<Vec<u8>, Vec<u8>>,
    blobs: HashMap<BlobId, Vec<u8>>,
    /// Every value ever written, if recording: what a forensic look at freed pages could find.
    history: Option<Vec<KeyValue>>,
    /// Every blob put (`Some`) and free (`None`), if recording.
    blob_history: Vec<(BlobId, Option<Vec<u8>>)>,
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
    /// The bytes held: row keys and values, and blobs (measures).
    pub fn held_bytes(&self) -> u64 {
        let d = self.lock();
        let rows: usize = d.kv.iter().map(|(k, v)| k.len() + v.len()).sum();
        (rows + d.blobs.values().map(Vec::len).sum::<usize>()) as u64
    }
    /// The bytes held in rows, and in blobs with their number (measures).
    pub fn held_split(&self) -> (u64, u64, u64) {
        let d = self.lock();
        let rows: usize = d.kv.iter().map(|(k, v)| k.len() + v.len()).sum();
        (rows as u64, d.blobs.values().map(Vec::len).sum::<usize>() as u64, d.blobs.len() as u64)
    }
    /// An independent copy of the durable state, as a backup takes it (sharing the faults, no
    /// history).
    pub fn copy(&self) -> MemoryBackend {
        let d = self.lock();
        let data = Data { kv: d.kv.clone(), blobs: d.blobs.clone(), history: None, blob_history: Vec::new(), syncs: 0, io: Io::default() };
        MemoryBackend { data: Arc::new(Mutex::new(data)), faults: self.faults.clone() }
    }
    /// An independent copy of the durable state and of what was recorded (sharing the faults):
    /// one device set up once, then run down several paths.
    pub fn fork(&self) -> MemoryBackend {
        let d = self.lock();
        let data = Data { kv: d.kv.clone(), blobs: d.blobs.clone(), history: d.history.clone(), blob_history: d.blob_history.clone(), syncs: d.syncs, io: d.io };
        MemoryBackend { data: Arc::new(Mutex::new(data)), faults: self.faults.clone() }
    }
    /// Tests only (world copies, `osis_base::copying`): an exact copy of the data, recorded
    /// history, counters and fault plan (`Faults::test_copy`), sharing none of them; two handles
    /// on one data stay one data in the copy. A copy of a live node's store, never for a
    /// product: a node and its copy would reuse one identity, session and rng stream.
    #[doc(hidden)]
    pub fn test_copy(&self) -> MemoryBackend {
        MemoryBackend { data: osis_base::copying::remap(&self.data, |m| Mutex::new(m.lock().unwrap_or_else(std::sync::PoisonError::into_inner).clone())), faults: self.faults.test_copy() }
    }
    /// Drops every value and blob (a removed database file).
    pub fn erase(&self) {
        let mut d = self.lock();
        d.kv.clear();
        d.blobs.clear();
    }
    /// The live key-value pairs.
    pub fn dump(&self) -> Vec<KeyValue> {
        self.lock().kv.iter().map(|(k, v)| (k.clone(), v.clone())).collect()
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
        self.data.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

impl Backend for MemoryBackend {
    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, BackendError> {
        let mut d = self.lock();
        let v = d.kv.get(key).cloned();
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
        let rows: Vec<KeyValue> = d.kv.range::<[u8], _>((Bound::Included(start), hi)).take(limit).map(|(k, v)| (k.clone(), v.clone())).collect();
        for (k, v) in &rows {
            d.io.read(Some(k.len() + v.len()));
        }
        Ok(rows)
    }

    fn commit(&mut self, batch: WriteBatch) -> Result<(), BackendError> {
        self.faults.check()?;
        let mut d = self.lock();
        d.syncs += 1;
        for op in batch.ops {
            d.io.writes += 1;
            d.io.written_bytes += match &op {
                Op::Put(k, v) => k.len() + v.len(),
                Op::Delete(k) => k.len(),
                Op::PutBlob(_, b) => b.len(),
                Op::DeleteBlob(_) => 0,
            } as u64;
            match op {
                Op::Put(k, v) => {
                    if let Some(h) = d.history.as_mut() {
                        h.push((k.clone(), v.clone()));
                    }
                    d.kv.insert(k, v);
                }
                Op::Delete(k) => {
                    d.kv.remove(&k);
                }
                Op::PutBlob(id, b) => {
                    if d.history.is_some() {
                        d.blob_history.push((id, Some(b.clone())));
                    }
                    d.blobs.insert(id, b);
                }
                Op::DeleteBlob(id) => {
                    if d.history.is_some() {
                        d.blob_history.push((id, None));
                    }
                    d.blobs.remove(&id);
                }
            }
        }
        Ok(())
    }

    fn get_blob(&self, id: &BlobId) -> Result<Option<Vec<u8>>, BackendError> {
        let mut d = self.lock();
        let b = d.blobs.get(id).cloned();
        d.io.read(b.as_ref().map(Vec::len));
        Ok(b)
    }

    fn read_blob(&self, id: &BlobId, offset: u64, len: usize) -> Result<Option<Vec<u8>>, BackendError> {
        let mut d = self.lock();
        let b = d.blobs.get(id).map(|b| blob_slice(b, offset, len));
        d.io.read(b.as_ref().map(Vec::len));
        Ok(b)
    }

    fn blob_len(&self, id: &BlobId) -> Result<Option<u64>, BackendError> {
        Ok(self.lock().blobs.get(id).map(|b| b.len() as u64))
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

/// Any backend with a fault plan on its commits: crash tests over the file backend.
pub struct FaultyBackend<B> {
    pub inner: B,
    faults: Faults,
}

impl<B: Backend> FaultyBackend<B> {
    pub fn new(inner: B, faults: Faults) -> FaultyBackend<B> {
        FaultyBackend { inner, faults }
    }
}

impl<B: Backend> Backend for FaultyBackend<B> {
    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, BackendError> {
        self.inner.get(key)
    }
    fn scan(&self, start: &[u8], end: Option<&[u8]>, limit: usize) -> Result<Vec<KeyValue>, BackendError> {
        self.inner.scan(start, end, limit)
    }
    fn commit(&mut self, batch: WriteBatch) -> Result<(), BackendError> {
        self.faults.check()?;
        self.inner.commit(batch)
    }
    fn get_blob(&self, id: &BlobId) -> Result<Option<Vec<u8>>, BackendError> {
        self.inner.get_blob(id)
    }
    fn read_blob(&self, id: &BlobId, offset: u64, len: usize) -> Result<Option<Vec<u8>>, BackendError> {
        self.inner.read_blob(id, offset, len)
    }
    fn blob_len(&self, id: &BlobId) -> Result<Option<u64>, BackendError> {
        self.inner.blob_len(id)
    }
}
