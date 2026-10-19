//! `RootStorage`: the one place the platform can erase, holding the key tree's root key
//! (notes/local-store.md, Key tree). Replacing the record must destroy the previous one.

use crate::backend::BackendError;
use crate::memory::Faults;
use osis_crypto::Secret32;
use std::sync::{Arc, Mutex};

/// The root key and the rotation epoch it belongs to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RootRecord {
    pub epoch: u64,
    pub key: Secret32,
}

/// How trustworthy erasure of the previous root is (notes/local-store.md). Below `Hardware`,
/// diagnostics report best effort.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RootTier {
    /// Process memory: tests and the simulator.
    Memory,
    /// A small file overwritten in place with fsync: last resort.
    FileOverwrite,
    /// Hardware-backed keystore (not yet implemented).
    Hardware,
}

pub trait RootStorage: Send {
    fn load(&self) -> Result<Option<RootRecord>, BackendError>;
    /// Replaces the record durably, destroying the previous one, before returning `Ok`.
    fn store(&mut self, record: &RootRecord) -> Result<(), BackendError>;
    fn tier(&self) -> RootTier;
}

/// In-memory root. Clones share the slot (a test reopens the store over it); obeys the device's
/// `Faults` plan like `MemoryBackend`.
#[derive(Clone, Debug, Default)]
pub struct MemoryRoot {
    slot: Arc<Mutex<Option<RootRecord>>>,
    faults: Faults,
}

impl MemoryRoot {
    pub fn new() -> MemoryRoot {
        MemoryRoot::default()
    }
    pub fn with_faults(faults: Faults) -> MemoryRoot {
        MemoryRoot { slot: Arc::default(), faults }
    }
}

impl RootStorage for MemoryRoot {
    fn load(&self) -> Result<Option<RootRecord>, BackendError> {
        Ok(self.slot.lock().unwrap_or_else(std::sync::PoisonError::into_inner).clone())
    }
    fn store(&mut self, record: &RootRecord) -> Result<(), BackendError> {
        self.faults.check()?;
        *self.slot.lock().unwrap_or_else(std::sync::PoisonError::into_inner) = Some(record.clone());
        Ok(())
    }
    fn tier(&self) -> RootTier {
        RootTier::Memory
    }
}

#[cfg(feature = "file-backend")]
pub use file::FileRoot;

#[cfg(feature = "file-backend")]
mod file {
    use super::*;
    use std::fs::{File, OpenOptions};
    use std::io::{Read, Seek, SeekFrom, Write};
    use std::path::PathBuf;

    const MAGIC: &[u8; 8] = b"osisroot";
    /// magic, seq, epoch, key, check (first 8 bytes of BLAKE3 of the rest).
    const SLOT: usize = 8 + 8 + 8 + 32 + 8;

    fn io(e: std::io::Error) -> BackendError {
        BackendError::Io(e.to_string())
    }

    /// Root in a file of two fixed slots overwritten in place (never renamed, so no stale copy
    /// is left in a freed block by the file system's own doing): the new record goes to the slot
    /// not holding the newest, fsync, then over the other slot, fsync. A torn write leaves the
    /// other slot valid; after `store` returns, both slots hold the new record.
    pub struct FileRoot {
        path: PathBuf,
    }

    impl FileRoot {
        pub fn new(path: PathBuf) -> FileRoot {
            FileRoot { path }
        }

        fn encode(seq: u64, r: &RootRecord) -> [u8; SLOT] {
            let mut b = [0u8; SLOT];
            let mut body = osis_crypto::Zeroizing::new(Vec::with_capacity(SLOT));
            body.extend_from_slice(MAGIC);
            body.extend_from_slice(&seq.to_be_bytes());
            body.extend_from_slice(&r.epoch.to_be_bytes());
            body.extend_from_slice(r.key.expose());
            let check = osis_core::hash::hash(&body);
            body.extend_from_slice(check.get(..8).unwrap_or_default());
            b.copy_from_slice(&body);
            b
        }

        fn decode(b: &[u8]) -> Option<(u64, RootRecord)> {
            let (body, check) = b.split_at_checked(SLOT - 8)?;
            if osis_core::hash::hash(body).get(..8)? != check || body.get(..8)? != MAGIC {
                return None;
            }
            let seq = u64::from_be_bytes(body.get(8..16)?.try_into().ok()?);
            let epoch = u64::from_be_bytes(body.get(16..24)?.try_into().ok()?);
            let key: [u8; 32] = body.get(24..56)?.try_into().ok()?;
            Some((seq, RootRecord { epoch, key: Secret32::from_bytes(key) }))
        }

        /// The valid slots: (slot index, seq, record).
        fn slots(&self) -> Result<Vec<(u64, u64, RootRecord)>, BackendError> {
            let mut buf = osis_crypto::Zeroizing::new(Vec::new());
            match File::open(&self.path) {
                Ok(mut f) => {
                    f.read_to_end(&mut buf).map_err(io)?;
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
                Err(e) => return Err(io(e)),
            }
            Ok(buf.chunks(SLOT).take(2).enumerate().filter_map(|(i, c)| Self::decode(c).map(|(s, r)| (i as u64, s, r))).collect())
        }

        fn write_slot(f: &mut File, slot: u64, bytes: &[u8; SLOT]) -> Result<(), BackendError> {
            f.seek(SeekFrom::Start(slot * SLOT as u64)).map_err(io)?;
            f.write_all(bytes).map_err(io)?;
            f.sync_all().map_err(io)
        }
    }

    impl RootStorage for FileRoot {
        fn load(&self) -> Result<Option<RootRecord>, BackendError> {
            Ok(self.slots()?.into_iter().max_by_key(|(_, s, _)| *s).map(|(_, _, r)| r))
        }

        fn store(&mut self, record: &RootRecord) -> Result<(), BackendError> {
            let slots = self.slots()?;
            let newest = slots.iter().max_by_key(|(_, s, _)| *s);
            let seq = newest.map_or(1, |(_, s, _)| s.saturating_add(1));
            let first = match newest {
                Some((0, _, _)) => 1,
                _ => 0,
            };
            let created = !self.path.exists();
            let mut f = OpenOptions::new().read(true).write(true).create(true).truncate(false).open(&self.path).map_err(io)?;
            let bytes = osis_crypto::Zeroizing::new(Self::encode(seq, record));
            Self::write_slot(&mut f, first, &bytes)?;
            Self::write_slot(&mut f, 1 - first, &bytes)?;
            if created && let Some(dir) = self.path.parent() {
                File::open(dir).and_then(|d| d.sync_all()).map_err(io)?;
            }
            Ok(())
        }

        fn tier(&self) -> RootTier {
            RootTier::FileOverwrite
        }
    }
}
