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

#[derive(Debug, Default)]
struct FaultState {
    writes: u64,
    plan: Option<(u64, Fault)>,
    dead: bool,
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
    fn lock(&self) -> MutexGuard<'_, FaultState> {
        self.0.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

#[derive(Debug, Default)]
struct Data {
    kv: BTreeMap<Vec<u8>, Vec<u8>>,
    blobs: HashMap<BlobId, Vec<u8>>,
    /// Every value ever written, if recording: what a forensic look at freed pages could find.
    history: Option<Vec<KeyValue>>,
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
    /// Records every value written from now on (`history`), for shredding tests.
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
    /// The live key-value pairs.
    pub fn dump(&self) -> Vec<KeyValue> {
        self.lock().kv.iter().map(|(k, v)| (k.clone(), v.clone())).collect()
    }
    pub fn faults(&self) -> &Faults {
        &self.faults
    }
    fn lock(&self) -> MutexGuard<'_, Data> {
        self.data.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

impl Backend for MemoryBackend {
    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, BackendError> {
        Ok(self.lock().kv.get(key).cloned())
    }

    fn scan(&self, start: &[u8], end: Option<&[u8]>, limit: usize) -> Result<Vec<KeyValue>, BackendError> {
        let d = self.lock();
        let hi = match end {
            Some(e) => Bound::Excluded(e),
            None => Bound::Unbounded,
        };
        if end.is_some_and(|e| e <= start) {
            return Ok(Vec::new());
        }
        Ok(d.kv
            .range::<[u8], _>((Bound::Included(start), hi))
            .take(limit)
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect())
    }

    fn commit(&mut self, batch: WriteBatch) -> Result<(), BackendError> {
        self.faults.check()?;
        let mut d = self.lock();
        for op in batch.ops {
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
                    d.blobs.insert(id, b);
                }
                Op::DeleteBlob(id) => {
                    d.blobs.remove(&id);
                }
            }
        }
        Ok(())
    }

    fn get_blob(&self, id: &BlobId) -> Result<Option<Vec<u8>>, BackendError> {
        Ok(self.lock().blobs.get(id).cloned())
    }

    fn read_blob(&self, id: &BlobId, offset: u64, len: usize) -> Result<Option<Vec<u8>>, BackendError> {
        Ok(self.lock().blobs.get(id).map(|b| blob_slice(b, offset, len)))
    }

    fn blob_len(&self, id: &BlobId) -> Result<Option<u64>, BackendError> {
        Ok(self.lock().blobs.get(id).map(|b| b.len() as u64))
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
