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
    /// Completes a `store` a crash interrupted, so no copy of a replaced record remains.
    /// Called on open before `load`.
    fn repair(&mut self) -> Result<(), BackendError> {
        Ok(())
    }
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
        faults: Option<Faults>,
    }

    impl FileRoot {
        pub fn new(path: PathBuf) -> FileRoot {
            FileRoot { path, faults: None }
        }
        /// Each slot write counts as one write of `faults` (crash tests).
        pub fn with_faults(path: PathBuf, faults: Faults) -> FileRoot {
            FileRoot { path, faults: Some(faults) }
        }

        fn encode(seq: u64, r: &RootRecord) -> [u8; SLOT] {
            let mut b = [0u8; SLOT];
            let mut body = osis_crypto::Zeroizing::new(Vec::with_capacity(SLOT));
            body.extend_from_slice(MAGIC);
            body.extend_from_slice(&seq.to_be_bytes());
            body.extend_from_slice(&r.epoch.to_be_bytes());
            body.extend_from_slice(r.key.expose());
            let check = osis_base::hash::hash(&body);
            body.extend_from_slice(check.get(..8).unwrap_or_default());
            b.copy_from_slice(&body);
            b
        }

        fn decode(b: &[u8]) -> Option<(u64, RootRecord)> {
            let (body, check) = b.split_at_checked(SLOT - 8)?;
            if osis_base::hash::hash(body).get(..8)? != check || body.get(..8)? != MAGIC {
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
                    // a root file made before files were created owner-only becomes so
                    let _ = crate::backend::restrict_to_owner(&self.path);
                    f.read_to_end(&mut buf).map_err(io)?;
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
                Err(e) => return Err(io(e)),
            }
            Ok(buf.chunks(SLOT).take(2).enumerate().filter_map(|(i, c)| Self::decode(c).map(|(s, r)| (i as u64, s, r))).collect())
        }

        fn write_slot(&self, f: &mut File, slot: u64, bytes: &[u8; SLOT]) -> Result<(), BackendError> {
            if let Some(faults) = &self.faults {
                faults.check()?;
            }
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
            let mut f = crate::backend::owner_only().read(true).write(true).create(true).truncate(false).open(&self.path).map_err(io)?;
            let bytes = osis_crypto::Zeroizing::new(Self::encode(seq, record));
            self.write_slot(&mut f, first, &bytes)?;
            self.write_slot(&mut f, 1 - first, &bytes)?;
            if created && let Some(dir) = self.path.parent() {
                File::open(dir).and_then(|d| d.sync_all()).map_err(io)?;
            }
            Ok(())
        }

        fn tier(&self) -> RootTier {
            RootTier::FileOverwrite
        }

        /// A crash between the slot writes leaves the old record in one slot: overwrite it.
        fn repair(&mut self) -> Result<(), BackendError> {
            let slots = self.slots()?;
            let Some((_, seq, rec)) = slots.iter().max_by_key(|(_, s, _)| *s) else { return Ok(()) };
            if slots.len() == 2 && slots.iter().all(|(_, s, _)| s == seq) {
                return Ok(());
            }
            let bytes = osis_crypto::Zeroizing::new(Self::encode(*seq, rec));
            let mut f = OpenOptions::new().read(true).write(true).open(&self.path).map_err(io)?;
            self.write_slot(&mut f, 0, &bytes)?;
            self.write_slot(&mut f, 1, &bytes)
        }
    }
}

#[cfg(all(test, feature = "file-backend"))]
mod tests {
    use super::*;

    // spec/commits.md §5: dropping destroys every copy; notes/local-store.md, Key tree: the file
    // root survives a torn slot and keeps no copy of a replaced key.
    #[test]
    fn file_root() {
        let dir = std::env::temp_dir().join(format!("osis-store-root-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("root");
        let mut r = FileRoot::new(path.clone());
        assert_eq!(r.load().unwrap(), None);
        let rec = |e: u64, b: u8| RootRecord { epoch: e, key: Secret32::from_bytes([b; 32]) };
        r.store(&rec(1, 0xa1)).unwrap();
        r.store(&rec(2, 0xb2)).unwrap();
        assert_eq!(r.load().unwrap(), Some(rec(2, 0xb2)));
        let raw = std::fs::read(&path).unwrap();
        assert!(!raw.windows(32).any(|w| w == [0xa1; 32]), "old key left in the file");
        // The root key is readable by its owner only.
        #[cfg(unix)]
        assert_eq!(std::os::unix::fs::PermissionsExt::mode(&std::fs::metadata(&path).unwrap().permissions()) & 0o077, 0);
        // Torn write of one slot: the other still loads.
        let mut torn = raw.clone();
        torn[10] ^= 1;
        std::fs::write(&path, &torn).unwrap();
        assert_eq!(r.load().unwrap(), Some(rec(2, 0xb2)));
        r.store(&rec(3, 0xc3)).unwrap();
        assert_eq!(FileRoot::new(path.clone()).load().unwrap(), Some(rec(3, 0xc3)));
        assert_eq!(r.tier(), RootTier::FileOverwrite);
        // Crash between the slot writes: the old key stays until repair.
        let faults = Faults::new();
        let mut r = FileRoot::with_faults(path.clone(), faults.clone());
        faults.at(1, crate::Fault::Crash);
        assert!(r.store(&rec(4, 0xd4)).is_err());
        faults.revive();
        assert_eq!(r.load().unwrap(), Some(rec(4, 0xd4)));
        assert!(std::fs::read(&path).unwrap().windows(32).any(|w| w == [0xc3; 32]));
        r.repair().unwrap();
        assert!(!std::fs::read(&path).unwrap().windows(32).any(|w| w == [0xc3; 32]), "old key left after repair");
        assert_eq!(r.load().unwrap(), Some(rec(4, 0xd4)));
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
