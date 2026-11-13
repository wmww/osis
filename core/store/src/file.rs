//! File backend over redb (choice recorded in notes/local-store.md).

use crate::backend::{Backend, BackendError, KeyValue, Op, WriteBatch, blob_slice};
use osis_base::BlobId;
use redb::backends::FileBackend;
use redb::{Builder, Database, StorageBackend, TableDefinition};
use std::cell::RefCell;
use std::path::Path;

const KV: TableDefinition<&[u8], &[u8]> = TableDefinition::new("kv");
const BLOBS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("blobs");

fn io(e: impl std::fmt::Display) -> BackendError {
    BackendError::Io(e.to_string())
}

/// Opens the database, again after each failed call.
type Opener = Box<dyn Fn() -> Result<Database, BackendError> + Send>;

/// A redb database file. `commit` uses redb's immediate durability (fsync before returning).
/// redb refuses every call after an I/O error until opened again, so a failed call closes the
/// database and the next call opens it again (redb repairs on open): it reads the file as an open
/// would, and fails while the open does.
pub struct RedbBackend {
    open: Opener,
    db: RefCell<Option<Database>>,
}

impl RedbBackend {
    /// Opens or creates the database at `path` (owner-only, an existing file made so).
    pub fn open(path: &Path) -> Result<RedbBackend, BackendError> {
        crate::backend::owner_only().create(true).truncate(false).write(true).open(path).map_err(io)?;
        // best effort; the `osis` handle reports what it could not tighten
        let _ = crate::backend::restrict_to_owner(path);
        let path = path.to_owned();
        RedbBackend::with_storage(move || {
            let file = std::fs::OpenOptions::new().read(true).write(true).open(&path)?;
            FileBackend::new(file).map_err(std::io::Error::other)
        })
    }

    /// Opens or creates a database on the storage `open` gives, called again for each reopen
    /// (tests inject faults through it).
    pub fn with_storage<S: StorageBackend>(open: impl Fn() -> std::io::Result<S> + Send + 'static) -> Result<RedbBackend, BackendError> {
        let b = RedbBackend { open: Box::new(move || Builder::new().create_with_backend(open().map_err(io)?).map_err(io)), db: RefCell::new(None) };
        b.call(|_| Ok(()))?;
        Ok(b)
    }

    fn open_db(&self) -> Result<Database, BackendError> {
        let db = (self.open)()?;
        let w = db.begin_write().map_err(io)?;
        w.open_table(KV).map_err(io)?;
        w.open_table(BLOBS).map_err(io)?;
        w.commit().map_err(io)?;
        Ok(db)
    }

    /// Runs `f` on the database, opening it first if it is closed. A failure closes it (releasing
    /// the file lock), so the next call opens it again.
    fn call<T>(&self, f: impl FnOnce(&Database) -> Result<T, BackendError>) -> Result<T, BackendError> {
        let mut slot = self.db.borrow_mut();
        let db = match slot.take() {
            Some(db) => db,
            None => self.open_db()?,
        };
        let r = f(&db);
        if r.is_ok() {
            *slot = Some(db);
        }
        r
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
