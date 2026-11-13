#![allow(dead_code)]
//! Shared test setup: a device (backend + root storage) per backend kind.

use osis_base::{Ak, BlobId, Tid};
use osis_crypto::SeededRng;
use osis_store::{Backend, BackendError, Faults, KeyValue, MemoryBackend, MemoryRoot, RootStorage, Store, StoreConfig, WriteBatch};
use redb::StorageBackend;
use redb::backends::FileBackend;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

/// Small pages and a small key tree so tests exercise splits and several tree levels.
pub fn cfg() -> StoreConfig {
    StoreConfig { arity: 8, depth: 4, page_max: 512, ..StoreConfig::default() }
}

pub fn tid(n: u8) -> Tid {
    Tid::from_bytes([n; 15])
}

pub fn ak(s: &str) -> Ak {
    Ak::new(s).unwrap()
}

/// A simulated device: durable state that survives "crashes" (dropping the store).
pub trait Device {
    fn backend(&self) -> Box<dyn Backend>;
    fn root(&self) -> Box<dyn RootStorage>;
    fn faults(&self) -> &Faults;
    fn name(&self) -> &'static str;
    /// The bytes of the backend's file, if it has one.
    fn file(&self) -> Option<Vec<u8>> {
        None
    }
}

pub struct MemDevice {
    pub backend: MemoryBackend,
    pub root: MemoryRoot,
    pub faults: Faults,
}

impl MemDevice {
    pub fn new() -> MemDevice {
        let faults = Faults::new();
        MemDevice { backend: MemoryBackend::with_faults(faults.clone()), root: MemoryRoot::with_faults(faults.clone()), faults }
    }
}

impl Device for MemDevice {
    fn backend(&self) -> Box<dyn Backend> {
        Box::new(self.backend.clone())
    }
    fn root(&self) -> Box<dyn RootStorage> {
        Box::new(self.root.clone())
    }
    fn faults(&self) -> &Faults {
        &self.faults
    }
    fn name(&self) -> &'static str {
        "memory"
    }
}

pub struct FileDevice {
    pub dir: std::path::PathBuf,
    pub faults: Faults,
    /// `n > 0`: the `n`th write of the redb file from now fails (`FaultyFile`).
    pub trap: Arc<AtomicUsize>,
}

impl FileDevice {
    /// A redb file and a file root in a fresh temp directory (default-test disk rule: own temp dir only).
    pub fn new(name: &str) -> FileDevice {
        let dir = std::env::temp_dir().join(format!("osis-store-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let faults = Faults::new();
        FileDevice { dir, faults, trap: Arc::new(AtomicUsize::new(0)) }
    }
}

impl Drop for FileDevice {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

impl Device for FileDevice {
    fn backend(&self) -> Box<dyn Backend> {
        let (path, faults, trap) = (self.dir.join("db"), self.faults.clone(), self.trap.clone());
        let inner = osis_store::RedbBackend::with_storage(move || {
            let mut o = std::fs::OpenOptions::new();
            // created owner-only, as `RedbBackend::open` creates it
            #[cfg(unix)]
            std::os::unix::fs::OpenOptionsExt::mode(&mut o, 0o600);
            let file = o.read(true).write(true).create(true).truncate(false).open(&path)?;
            let file = FileBackend::new(file).map_err(std::io::Error::other)?;
            Ok(FaultyFile { file, faults: faults.clone(), trap: trap.clone() })
        })
        .unwrap();
        Box::new(FaultyRedb { inner, faults: self.faults.clone(), trap: self.trap.clone() })
    }
    fn root(&self) -> Box<dyn RootStorage> {
        Box::new(osis_store::FileRoot::with_faults(self.dir.join("root"), self.faults.clone()))
    }
    fn faults(&self) -> &Faults {
        &self.faults
    }
    fn name(&self) -> &'static str {
        "redb"
    }
    fn file(&self) -> Option<Vec<u8>> {
        Some(std::fs::read(self.dir.join("db")).unwrap())
    }
}

/// The redb backend with a fault plan on its commits, injected inside redb (a failed write of
/// the file), so redb fails as on a real I/O error: it refuses every call until reopened.
struct FaultyRedb {
    inner: osis_store::RedbBackend,
    faults: Faults,
    trap: Arc<AtomicUsize>,
}

impl Backend for FaultyRedb {
    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, BackendError> {
        self.inner.get(key)
    }
    fn scan(&self, start: &[u8], end: Option<&[u8]>, limit: usize) -> Result<Vec<KeyValue>, BackendError> {
        self.inner.scan(start, end, limit)
    }
    fn commit(&mut self, batch: WriteBatch) -> Result<(), BackendError> {
        if let Err(e) = self.faults.check() {
            self.trap.store(1, Ordering::SeqCst);
            assert!(self.inner.commit(batch).is_err(), "the fault reaches redb");
            return Err(e);
        }
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

/// The redb file, failing the write `trap` counts down to and every write while the device is
/// crashed (each `write`, `set_len` and `sync_data` is a write).
#[derive(Debug)]
struct FaultyFile {
    file: FileBackend,
    faults: Faults,
    trap: Arc<AtomicUsize>,
}

impl FaultyFile {
    fn fault(&self) -> std::io::Result<()> {
        let n = self.trap.load(Ordering::SeqCst);
        self.trap.store(n.saturating_sub(1), Ordering::SeqCst);
        let hit = n == 1;
        if hit || self.faults.crashed() {
            return Err(std::io::Error::other("injected write fault"));
        }
        Ok(())
    }
}

impl StorageBackend for FaultyFile {
    fn len(&self) -> std::io::Result<u64> {
        self.file.len()
    }
    fn read(&self, offset: u64, len: usize) -> std::io::Result<Vec<u8>> {
        self.file.read(offset, len)
    }
    fn set_len(&self, len: u64) -> std::io::Result<()> {
        self.fault()?;
        self.file.set_len(len)
    }
    fn sync_data(&self, eventual: bool) -> std::io::Result<()> {
        self.fault()?;
        self.file.sync_data(eventual)
    }
    fn write(&self, offset: u64, data: &[u8]) -> std::io::Result<()> {
        self.fault()?;
        self.file.write(offset, data)
    }
}

/// Every device kind this build has, fresh.
pub fn devices(name: &str) -> Vec<Box<dyn Device>> {
    vec![Box::new(MemDevice::new()), Box::new(FileDevice::new(name))]
}

pub fn create(dev: &dyn Device, rng: &mut SeededRng) -> Store {
    Store::create(dev.backend(), dev.root(), cfg(), rng).unwrap()
}

pub fn reopen(dev: &dyn Device) -> Store {
    Store::open(dev.backend(), dev.root(), cfg()).unwrap()
}
