//! File backend over redb (choice recorded in notes/local-store.md).

use crate::backend::{Backend, BackendError, KeyValue, Op, WriteBatch, blob_slice};
use osis_base::BlobId;
use redb::backends::FileBackend;
use redb::{Builder, Database, StorageBackend, TableDefinition};
use std::cell::RefCell;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

const KV: TableDefinition<&[u8], &[u8]> = TableDefinition::new("kv");
const BLOBS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("blobs");

fn io(e: impl std::fmt::Display) -> BackendError {
    BackendError::Io(e.to_string())
}

/// Opens the database, again after each failed call; given whether a sync of the file failed
/// since this backend first opened it.
type Opener = Box<dyn Fn(bool) -> Result<Database, BackendError> + Send>;

/// A redb database file. `commit` uses redb's immediate durability (fsync before returning).
/// redb refuses every call after an I/O error until opened again, so a failed call closes the
/// database and the next call opens it again (redb repairs on open): it reads the file as an open
/// would, and fails while the open does. A call during which a sync of the file failed fails
/// `Unsynced`: what the file reads may not be on disk. Every open first drops the file's cached
/// pages (`drop_cache`), so it reads what the disk holds, never pages whose sync failed; where
/// the platform cannot (all but Linux and Android), an open after a failed sync fails.
pub struct RedbBackend {
    open: Opener,
    db: RefCell<Option<Database>>,
    /// A sync of the file failed since the last call began.
    unsynced: Arc<AtomicBool>,
    /// A sync of the file failed since this backend opened it.
    sync_failed: std::cell::Cell<bool>,
}

/// Drops the file's cached pages, so what is read next comes from the disk: an fsync first (its
/// result does not matter: a failed one leaves its pages clean), as only clean pages are dropped.
#[cfg(any(target_os = "linux", target_os = "android"))]
fn drop_cache(file: &std::fs::File) -> std::io::Result<()> {
    let _ = file.sync_all();
    rustix::fs::fadvise(file, 0, None, rustix::fs::Advice::DontNeed).map_err(std::io::Error::from)
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
fn drop_cache(_file: &std::fs::File) -> std::io::Result<()> {
    Err(std::io::ErrorKind::Unsupported.into())
}

/// Storage that notes a failed sync.
#[derive(Debug)]
struct Watched<S> {
    inner: S,
    unsynced: Arc<AtomicBool>,
}

impl<S: StorageBackend> StorageBackend for Watched<S> {
    fn len(&self) -> std::io::Result<u64> {
        self.inner.len()
    }
    fn read(&self, offset: u64, len: usize) -> std::io::Result<Vec<u8>> {
        self.inner.read(offset, len)
    }
    fn set_len(&self, len: u64) -> std::io::Result<()> {
        self.inner.set_len(len)
    }
    fn sync_data(&self, eventual: bool) -> std::io::Result<()> {
        self.inner.sync_data(eventual).inspect_err(|_| self.unsynced.store(true, Ordering::SeqCst))
    }
    fn write(&self, offset: u64, data: &[u8]) -> std::io::Result<()> {
        self.inner.write(offset, data)
    }
}

impl RedbBackend {
    /// Opens or creates the database at `path` (owner-only, an existing file made so).
    pub fn open(path: &Path) -> Result<RedbBackend, BackendError> {
        crate::backend::owner_only().create(true).truncate(false).write(true).open(path).map_err(io)?;
        // best effort; the `osis` handle reports what it could not tighten
        let _ = crate::backend::restrict_to_owner(path);
        let path = path.to_owned();
        RedbBackend::with_storage(move |sync_failed| {
            let file = std::fs::OpenOptions::new().read(true).write(true).open(&path)?;
            // best effort, unless a sync failed: then reading the cache could see its pages
            drop_cache(&file).or_else(|e| if sync_failed { Err(e) } else { Ok(()) })?;
            FileBackend::new(file).map_err(std::io::Error::other)
        })
    }

    /// Opens or creates a database on the storage `open` gives, called again for each reopen
    /// with whether a sync failed since the first: it must then read what the disk holds, never
    /// pages whose sync failed (`drop_cache`), or fail. Tests inject faults through it.
    pub fn with_storage<S: StorageBackend>(open: impl Fn(bool) -> std::io::Result<S> + Send + 'static) -> Result<RedbBackend, BackendError> {
        let unsynced = Arc::new(AtomicBool::new(false));
        let watch = unsynced.clone();
        let open = move |sync_failed| Builder::new().create_with_backend(Watched { inner: open(sync_failed).map_err(io)?, unsynced: watch.clone() }).map_err(io);
        let b = RedbBackend { open: Box::new(open), db: RefCell::new(None), unsynced, sync_failed: std::cell::Cell::new(false) };
        b.call(|_| Ok(()))?;
        Ok(b)
    }

    fn open_db(&self) -> Result<Database, BackendError> {
        let db = (self.open)(self.sync_failed.get())?;
        let w = db.begin_write().map_err(io)?;
        w.open_table(KV).map_err(io)?;
        w.open_table(BLOBS).map_err(io)?;
        w.commit().map_err(io)?;
        Ok(db)
    }

    /// Runs `f` on the database, opening it first if it is closed. A failure closes it (releasing
    /// the file lock), so the next call opens it again.
    fn call<T>(&self, f: impl FnOnce(&Database) -> Result<T, BackendError>) -> Result<T, BackendError> {
        self.unsynced.store(false, Ordering::SeqCst);
        let mut slot = self.db.borrow_mut();
        let r = match slot.take() {
            Some(db) => Ok(db),
            None => self.open_db(),
        }
        .and_then(|db| f(&db).map(|v| (v, db)));
        match r {
            Ok((v, db)) => {
                *slot = Some(db);
                Ok(v)
            }
            Err(_) if self.unsynced.load(Ordering::SeqCst) => {
                self.sync_failed.set(true);
                Err(BackendError::Unsynced)
            }
            Err(e) => Err(e),
        }
    }

    fn read<T>(&self, def: TableDefinition<&[u8], &[u8]>, f: impl FnOnce(&redb::ReadOnlyTable<&[u8], &[u8]>) -> Result<T, redb::StorageError>) -> Result<T, BackendError> {
        self.call(|db| {
            let r = db.begin_read().map_err(io)?;
            let t = r.open_table(def).map_err(io)?;
            f(&t).map_err(io)
        })
    }
}

impl Backend for RedbBackend {
    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, BackendError> {
        self.read(KV, |t| Ok(t.get(key)?.map(|v| v.value().to_vec())))
    }

    fn scan(&self, start: &[u8], end: Option<&[u8]>, limit: usize) -> Result<Vec<KeyValue>, BackendError> {
        if end.is_some_and(|e| e <= start) {
            return Ok(Vec::new());
        }
        self.read(KV, |t| {
            let mut out = Vec::new();
            let iter = match end {
                Some(e) => t.range::<&[u8]>(start..e)?,
                None => t.range::<&[u8]>(start..)?,
            };
            for item in iter.take(limit) {
                let (k, v) = item?;
                out.push((k.value().to_vec(), v.value().to_vec()));
            }
            Ok(out)
        })
    }

    fn commit(&mut self, batch: WriteBatch) -> Result<(), BackendError> {
        self.call(|db| {
            let mut w = db.begin_write().map_err(io)?;
            w.set_durability(redb::Durability::Immediate);
            {
                let mut kv = w.open_table(KV).map_err(io)?;
                let mut blobs = w.open_table(BLOBS).map_err(io)?;
                for op in &batch.ops {
                    match op {
                        Op::Put(k, v) => {
                            kv.insert(k.as_slice(), v.as_slice()).map_err(io)?;
                        }
                        Op::Delete(k) => {
                            kv.remove(k.as_slice()).map_err(io)?;
                        }
                        Op::PutBlob(id, b) => {
                            blobs.insert(id.0.as_slice(), b.as_slice()).map_err(io)?;
                        }
                        Op::DeleteBlob(id) => {
                            blobs.remove(id.0.as_slice()).map_err(io)?;
                        }
                    }
                }
            }
            w.commit().map_err(io)
        })
    }

    /// redb reads the whole value (at most `MAX_BLOB`) before slicing.
    fn read_blob(&self, id: &BlobId, offset: u64, len: usize) -> Result<Option<Vec<u8>>, BackendError> {
        self.read(BLOBS, |t| Ok(t.get(id.0.as_slice())?.map(|v| blob_slice(v.value(), offset, len))))
    }

    fn blob_len(&self, id: &BlobId) -> Result<Option<u64>, BackendError> {
        self.read(BLOBS, |t| Ok(t.get(id.0.as_slice())?.map(|v| v.value().len() as u64)))
    }
}
