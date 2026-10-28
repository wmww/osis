#![allow(dead_code)]
//! Shared test setup: a device (backend + root storage) per backend kind.

use osis_base::{Ak, Tid};
use osis_crypto::SeededRng;
use osis_store::{Backend, Faults, MemoryBackend, MemoryRoot, RootStorage, Store, StoreConfig};

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

#[cfg(feature = "file-backend")]
pub struct FileDevice {
    pub dir: std::path::PathBuf,
    pub faults: Faults,
}

#[cfg(feature = "file-backend")]
impl FileDevice {
    /// A redb file and a file root in a fresh temp directory (tier-1 disk rule: own temp dir only).
    pub fn new(name: &str) -> FileDevice {
        let dir = std::env::temp_dir().join(format!("osis-store-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let faults = Faults::new();
        FileDevice { dir, faults }
    }
}

#[cfg(feature = "file-backend")]
impl Drop for FileDevice {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

#[cfg(feature = "file-backend")]
impl Device for FileDevice {
    fn backend(&self) -> Box<dyn Backend> {
        let b = osis_store::RedbBackend::open(&self.dir.join("db")).unwrap();
        Box::new(osis_store::FaultyBackend::new(b, self.faults.clone()))
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
}

/// Every device kind this build has, fresh.
pub fn devices(name: &str) -> Vec<Box<dyn Device>> {
    #[allow(unused_mut)]
    let mut v: Vec<Box<dyn Device>> = vec![Box::new(MemDevice::new())];
    #[cfg(feature = "file-backend")]
    v.push(Box::new(FileDevice::new(name)));
    let _ = name;
    v
}

pub fn create(dev: &dyn Device, rng: &mut SeededRng) -> Store {
    Store::create(dev.backend(), dev.root(), cfg(), rng).unwrap()
}

pub fn reopen(dev: &dyn Device) -> Store {
    Store::open(dev.backend(), dev.root(), cfg()).unwrap()
}
