#![allow(dead_code)]
//! Shared test setup: a device (backend + root storage) per backend kind.

use osis_base::{Ak, BlobId, Tid};
use osis_crypto::SeededRng;
use osis_store::{Backend, BackendError, Faults, KeyValue, MemoryBackend, MemoryRoot, RootStorage, Store, StoreConfig, Synced, WriteBatch};
use redb::StorageBackend;
use redb::backends::FileBackend;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

/// Small pages and a small key tree so tests exercise splits and several tree levels.
pub fn cfg() -> StoreConfig {
    StoreConfig { arity: 8, page_max: 512, ..StoreConfig::default() }
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
    /// Power loss, with no store open: writes whose sync failed are dropped (`Fault::Unsynced`).
    fn power_cut(&self);
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
    /// The device as it stands, sharing its faults: a backup, or a copy to run beside it.
    pub fn copy(&self) -> MemDevice {
        MemDevice { backend: self.backend.copy(), root: self.root.copy(), faults: self.faults.clone() }
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
    fn power_cut(&self) {
        self.backend.power_cut();
        self.root.power_cut();
    }
}

pub struct FileDevice {
    pub dir: std::path::PathBuf,
    pub faults: Faults,
    /// `n > 0`: the `n`th write of the redb file from now fails (`FaultyFile`).
    pub trap: Arc<AtomicUsize>,
    /// The next sync of the redb file fails.
    pub sync_trap: Arc<AtomicBool>,
    disk: Arc<Mutex<Disk>>,
}

/// What a power cut leaves of the redb file: its bytes as last synced, and the writes since.
#[derive(Debug, Default)]
struct Disk {
    synced: Vec<u8>,
    pending: Vec<(u64, Option<Vec<u8>>)>,
}

impl Disk {
    /// A failed sync: the writes since the last sync never reach the disk, whatever later syncs
    /// do (Linux drops the failed pages from write-back and marks them clean).
    fn sync(&mut self, ok: bool) {
        for (at, w) in std::mem::take(&mut self.pending).into_iter().filter(|_| ok) {
            match w {
                None => self.synced.resize(at as usize, 0),
                Some(data) => {
                    let end = at as usize + data.len();
                    if self.synced.len() < end {
                        self.synced.resize(end, 0);
                    }
                    self.synced[at as usize..end].copy_from_slice(&data);
                }
            }
        }
    }
}

impl Disk {
    /// An open's cache drop: an fsync attempt, then the file reads its bytes on disk (Linux keeps
    /// pages whose sync failed in the cache, clean, until dropped).
    fn drop_cache(&mut self, path: &std::path::Path) {
        self.sync(true);
        if path.exists() {
            std::fs::write(path, &self.synced).unwrap();
        }
    }
}

impl FileDevice {
    /// A redb file and a file root in a fresh temp directory (default-test disk rule: own temp dir only).
    pub fn new(name: &str) -> FileDevice {
        let dir = std::env::temp_dir().join(format!("osis-store-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let faults = Faults::new();
        FileDevice { dir, faults, trap: Arc::default(), sync_trap: Arc::default(), disk: Arc::default() }
    }
}

impl Drop for FileDevice {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

impl Device for FileDevice {
    fn backend(&self) -> Box<dyn Backend> {
        let (path, faults, trap, sync_trap, disk) = (self.dir.join("db"), self.faults.clone(), self.trap.clone(), self.sync_trap.clone(), self.disk.clone());
        let inner = osis_store::RedbBackend::with_storage(move |_sync_failed| {
            // every open drops the cache, as `RedbBackend::open` does: after an fsync attempt,
            // the file reads what the disk holds
            disk.lock().unwrap().drop_cache(&path);
            let mut o = std::fs::OpenOptions::new();
            // created owner-only, as `RedbBackend::open` creates it
            #[cfg(unix)]
            std::os::unix::fs::OpenOptionsExt::mode(&mut o, 0o600);
            let file = o.read(true).write(true).create(true).truncate(false).open(&path)?;
            let file = FileBackend::new(file).map_err(std::io::Error::other)?;
            Ok(FaultyFile { file, faults: faults.clone(), trap: trap.clone(), sync_trap: sync_trap.clone(), disk: disk.clone() })
        })
        .unwrap();
        Box::new(FaultyRedb { inner, faults: self.faults.clone(), trap: self.trap.clone(), sync_trap: self.sync_trap.clone() })
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
    /// The redb file goes back to its synced bytes; the root file is written through (its
    /// failed syncs are not modelled).
    fn power_cut(&self) {
        let mut d = self.disk.lock().unwrap();
        d.pending.clear();
        std::fs::write(self.dir.join("db"), &d.synced).unwrap();
    }
}

/// The redb backend with a fault plan on its commits, injected inside redb (a failed write of
/// the file; for `Fault::Unsynced`, a failed sync), so redb fails as on a real I/O error: it
/// refuses every call until reopened.
struct FaultyRedb {
    inner: osis_store::RedbBackend,
    faults: Faults,
    trap: Arc<AtomicUsize>,
    sync_trap: Arc<AtomicBool>,
}

impl Backend for FaultyRedb {
    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, BackendError> {
        self.inner.get(key)
    }
    fn scan(&self, start: &[u8], end: Option<&[u8]>, limit: usize) -> Result<Vec<KeyValue>, BackendError> {
        self.inner.scan(start, end, limit)
    }
    fn commit(&mut self, batch: WriteBatch) -> Result<(), BackendError> {
        match self.faults.check() {
            Ok(Synced::Yes) => self.inner.commit(batch),
            Ok(Synced::No) => {
                self.sync_trap.store(true, Ordering::SeqCst);
                let r = self.inner.commit(batch);
                assert_eq!(r, Err(BackendError::Unsynced), "the fault reaches redb's sync");
                r
            }
            Err(e) => {
                self.trap.store(1, Ordering::SeqCst);
                assert!(self.inner.commit(batch).is_err(), "the fault reaches redb");
                Err(e)
            }
        }
    }
    fn read_blob(&self, id: &BlobId, offset: u64, len: usize) -> Result<Option<Vec<u8>>, BackendError> {
        self.inner.read_blob(id, offset, len)
    }
    fn blob_len(&self, id: &BlobId) -> Result<Option<u64>, BackendError> {
        self.inner.blob_len(id)
    }
}

/// The redb file, failing the write `trap` counts down to, the sync `sync_trap` arms, and every
/// write while the device is crashed (each `write`, `set_len` and `sync_data` is a write). A
/// failed write has no effect; a failed sync loses the writes since the last one at a power cut
/// (`Disk`).
#[derive(Debug)]
struct FaultyFile {
    file: FileBackend,
    faults: Faults,
    trap: Arc<AtomicUsize>,
    sync_trap: Arc<AtomicBool>,
    disk: Arc<Mutex<Disk>>,
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
        self.file.set_len(len)?;
        self.disk.lock().unwrap().pending.push((len, None));
        Ok(())
    }
    fn sync_data(&self, eventual: bool) -> std::io::Result<()> {
        let r = if self.sync_trap.swap(false, Ordering::SeqCst) { Err(std::io::Error::other("injected sync fault")) } else { self.fault() };
        let r = r.and_then(|()| self.file.sync_data(eventual));
        self.disk.lock().unwrap().sync(r.is_ok());
        r
    }
    fn write(&self, offset: u64, data: &[u8]) -> std::io::Result<()> {
        self.fault()?;
        self.file.write(offset, data)?;
        self.disk.lock().unwrap().pending.push((offset, Some(data.to_vec())));
        Ok(())
    }
}

/// Every device kind this build has, fresh.
pub fn devices(name: &str) -> Vec<Box<dyn Device>> {
    vec![Box::new(MemDevice::new()), Box::new(FileDevice::new(name))]
}

/// A store created on a fresh memory device, and the rng that made it.
pub fn fresh(cfg: StoreConfig) -> (MemDevice, SeededRng, Store) {
    let dev = MemDevice::new();
    let mut rng = SeededRng::from_u64(0);
    let s = Store::create(dev.backend(), dev.root(), cfg, &mut rng).unwrap();
    (dev, rng, s)
}

pub fn create(dev: &dyn Device, rng: &mut SeededRng) -> Store {
    Store::create(dev.backend(), dev.root(), cfg(), rng).unwrap()
}

pub fn reopen(dev: &dyn Device) -> Store {
    Store::open(dev.backend(), dev.root(), cfg()).unwrap()
}
