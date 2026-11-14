//! `RootStorage`: the one place the platform can erase, holding the key tree's root key
//! (notes/local-store.md, Key tree). Replacing the record must destroy the previous one.

use crate::backend::{BackendError, lock};
use crate::memory::{Faults, Synced};
use osis_crypto::Secret32;
use std::sync::{Arc, Mutex};

/// The root key and the rotation epoch it belongs to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RootRecord {
    pub epoch: u64,
    pub key: Secret32,
}

pub trait RootStorage: Send {
    fn load(&self) -> Result<Option<RootRecord>, BackendError>;
    /// Replaces the record durably, destroying the previous one, before returning `Ok`.
    fn store(&mut self, record: &RootRecord) -> Result<(), BackendError>;
    /// Completes a `store` that failed or a crash interrupted: afterwards `load` reads a durable
    /// record and no copy of a replaced one remains (a record that reads as stored but whose
    /// sync failed is written again). Called on open, and on recovering in place, before `load`.
    fn repair(&mut self) -> Result<(), BackendError> {
        Ok(())
    }
    /// Destroys the record durably (crypto-shredding the store it keys) and whatever holds it.
    fn erase(&mut self) -> Result<(), BackendError>;
    /// Tests only: an exact copy sharing nothing with this root (`MemoryRoot::test_copy`), for a
    /// world copy (`Store::test_copy`); `None`: this root has none.
    #[doc(hidden)]
    fn test_copy_boxed(&self) -> Option<Box<dyn RootStorage>> {
        None
    }
}

/// The record a `MemoryRoot` reads, and what a power cut leaves where that differs (a store
/// whose sync failed).
#[derive(Clone, Debug, Default)]
struct Slot {
    live: Option<RootRecord>,
    disk: Option<Option<RootRecord>>,
}

impl Slot {
    fn write(&mut self, record: Option<RootRecord>, sync: Synced) {
        match sync {
            Synced::Yes => self.disk = None,
            Synced::No => {
                let old = self.live.clone();
                self.disk.get_or_insert(old);
            }
        }
        self.live = record;
    }
}

/// In-memory root. Clones share the slot (a test reopens the store over it); obeys the device's
/// `Faults` plan like `MemoryBackend`.
#[derive(Clone, Debug, Default)]
pub struct MemoryRoot {
    slot: Arc<Mutex<Slot>>,
    faults: Faults,
}

impl MemoryRoot {
    pub fn new() -> MemoryRoot {
        MemoryRoot::default()
    }
    pub fn with_faults(faults: Faults) -> MemoryRoot {
        MemoryRoot { slot: Arc::default(), faults }
    }
    /// An independent copy of the record, sharing the faults (`MemoryBackend::copy`).
    pub fn copy(&self) -> MemoryRoot {
        MemoryRoot { slot: Arc::new(Mutex::new(lock(&self.slot).clone())), faults: self.faults.clone() }
    }
    /// Power loss: a record whose sync failed is dropped (`MemoryBackend::power_cut`).
    pub fn power_cut(&self) {
        let mut s = lock(&self.slot);
        if let Some(disk) = s.disk.take() {
            s.live = disk;
        }
    }
    /// Tests only (world copies): an exact copy of the record and fault plan, sharing neither
    /// (`MemoryBackend::test_copy`).
    #[doc(hidden)]
    pub fn test_copy(&self) -> MemoryRoot {
        MemoryRoot { slot: osis_base::copying::remap(&self.slot, |m| Mutex::new(lock(m).clone())), faults: self.faults.test_copy() }
    }
    fn write(&mut self, record: Option<RootRecord>) -> Result<(), BackendError> {
        let sync = self.faults.check()?;
        lock(&self.slot).write(record, sync);
        if sync == Synced::No { Err(BackendError::Unsynced) } else { Ok(()) }
    }
}

impl RootStorage for MemoryRoot {
    fn test_copy_boxed(&self) -> Option<Box<dyn RootStorage>> {
        Some(Box::new(self.test_copy()))
    }
    fn load(&self) -> Result<Option<RootRecord>, BackendError> {
        Ok(lock(&self.slot).live.clone())
    }
    fn store(&mut self, record: &RootRecord) -> Result<(), BackendError> {
        self.write(Some(record.clone()))
    }
    /// Writes the record that reads again if its sync failed.
    fn repair(&mut self) -> Result<(), BackendError> {
        let live = {
            let s = lock(&self.slot);
            if s.disk.is_none() {
                return Ok(());
            }
            s.live.clone()
        };
        self.write(live)
    }
    fn erase(&mut self) -> Result<(), BackendError> {
        self.write(None)
    }
}

pub use file::FileRoot;

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
        /// A slot's sync failed since the last `repair`: the disk may hold an older record in
        /// either slot though both read the newest, so `repair` writes both again.
        unsynced: bool,
    }

    impl FileRoot {
        pub fn new(path: PathBuf) -> FileRoot {
            FileRoot { path, faults: None, unsynced: false }
        }
        /// Each slot write counts as one write of `faults` (crash tests).
        pub fn with_faults(path: PathBuf, faults: Faults) -> FileRoot {
            FileRoot { path, faults: Some(faults), unsynced: false }
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
                    // a root file open to group or others becomes owner-only
                    let _ = crate::backend::restrict_to_owner(&self.path);
                    f.read_to_end(&mut buf).map_err(io)?;
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
                Err(e) => return Err(io(e)),
            }
            Ok(buf.chunks(SLOT).take(2).enumerate().filter_map(|(i, c)| Self::decode(c).map(|(s, r)| (i as u64, s, r))).collect())
        }

        /// Writes and syncs one slot. A failed sync is `Unsynced`: `repair` writes the slot again.
        fn write_slot(&mut self, f: &mut File, slot: u64, bytes: &[u8; SLOT]) -> Result<(), BackendError> {
            let sync = match &self.faults {
                Some(faults) => faults.check()?,
                None => Synced::Yes,
            };
            f.seek(SeekFrom::Start(slot * SLOT as u64)).map_err(io)?;
            f.write_all(bytes).map_err(io)?;
            if sync == Synced::No || f.sync_all().is_err() {
                self.unsynced = true;
                return Err(BackendError::Unsynced);
            }
            Ok(())
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

        /// A crash between the slot writes leaves the old record in one slot, and a failed sync
        /// may leave it on disk though it reads as replaced: overwrite both slots.
        fn repair(&mut self) -> Result<(), BackendError> {
            let slots = self.slots()?;
            let Some((_, seq, rec)) = slots.iter().max_by_key(|(_, s, _)| *s) else { return Ok(()) };
            if !self.unsynced && slots.len() == 2 && slots.iter().all(|(_, s, _)| s == seq) {
                return Ok(());
            }
            let bytes = osis_crypto::Zeroizing::new(Self::encode(*seq, rec));
            let mut f = OpenOptions::new().read(true).write(true).open(&self.path).map_err(io)?;
            self.write_slot(&mut f, 0, &bytes)?;
            self.write_slot(&mut f, 1, &bytes)?;
            self.unsynced = false;
            Ok(())
        }

        /// Overwrites both slots in place (each synced), then removes the file and syncs its
        /// directory. A crash before the removal is durable leaves zeroed slots: no record.
        fn erase(&mut self) -> Result<(), BackendError> {
            let mut f = match OpenOptions::new().write(true).open(&self.path) {
                Ok(f) => f,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
                Err(e) => return Err(io(e)),
            };
            self.write_slot(&mut f, 0, &[0; SLOT])?;
            self.write_slot(&mut f, 1, &[0; SLOT])?;
            drop(f);
            std::fs::remove_file(&self.path).map_err(io)?;
            if let Some(dir) = self.path.parent().filter(|d| !d.as_os_str().is_empty()) {
                File::open(dir).and_then(|d| d.sync_all()).map_err(io)?;
            }
            Ok(())
        }
    }
}

#[cfg(test)]
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
        // A failed sync of the second slot: both read the new record, the disk may still hold
        // the old one, so repair writes both again.
        faults.at(1, crate::Fault::Unsynced);
        assert_eq!(r.store(&rec(5, 0xe5)), Err(BackendError::Unsynced));
        faults.at(0, crate::Fault::Crash);
        assert_eq!(r.repair(), Err(BackendError::Crashed), "repair writes again");
        faults.revive();
        let w = faults.writes();
        r.repair().unwrap();
        assert_eq!(faults.writes(), w + 2, "both slots");
        r.repair().unwrap();
        assert_eq!(faults.writes(), w + 2, "once");
        assert_eq!(r.load().unwrap(), Some(rec(5, 0xe5)));
        // Erase: no record, no file; a second erase finds nothing.
        r.erase().unwrap();
        assert!(!path.exists());
        assert_eq!(r.load().unwrap(), None);
        r.erase().unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
