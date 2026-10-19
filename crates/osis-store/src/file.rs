//! File backend over redb (feature `file-backend`; choice recorded in notes/local-store.md).

use crate::backend::{Backend, BackendError, Op, WriteBatch, blob_slice};
use osis_core::BlobId;
use redb::{Database, TableDefinition};
use std::path::Path;

const KV: TableDefinition<&[u8], &[u8]> = TableDefinition::new("kv");
const BLOBS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("blobs");

fn io(e: impl std::fmt::Display) -> BackendError {
    BackendError::Io(e.to_string())
}

/// A redb database file. Commits use redb's immediate durability (fsync before returning).
pub struct RedbBackend {
    db: Database,
}

impl RedbBackend {
    /// Opens or creates the database at `path`.
    pub fn open(path: &Path) -> Result<RedbBackend, BackendError> {
        let db = Database::create(path).map_err(io)?;
        let w = db.begin_write().map_err(io)?;
        w.open_table(KV).map_err(io)?;
        w.open_table(BLOBS).map_err(io)?;
        w.commit().map_err(io)?;
        Ok(RedbBackend { db })
    }

    fn read<T>(&self, def: TableDefinition<&[u8], &[u8]>, f: impl FnOnce(&redb::ReadOnlyTable<&[u8], &[u8]>) -> Result<T, redb::StorageError>) -> Result<T, BackendError> {
        let r = self.db.begin_read().map_err(io)?;
        let t = r.open_table(def).map_err(io)?;
        f(&t).map_err(io)
    }
}

impl Backend for RedbBackend {
    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, BackendError> {
        self.read(KV, |t| Ok(t.get(key)?.map(|v| v.value().to_vec())))
    }

    fn scan(&self, start: &[u8], end: Option<&[u8]>, limit: usize) -> Result<Vec<(Vec<u8>, Vec<u8>)>, BackendError> {
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
        let w = self.db.begin_write().map_err(io)?;
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
    }

    fn get_blob(&self, id: &BlobId) -> Result<Option<Vec<u8>>, BackendError> {
        self.read(BLOBS, |t| Ok(t.get(id.0.as_slice())?.map(|v| v.value().to_vec())))
    }

    fn read_blob(&self, id: &BlobId, offset: u64, len: usize) -> Result<Option<Vec<u8>>, BackendError> {
        self.read(BLOBS, |t| Ok(t.get(id.0.as_slice())?.map(|v| blob_slice(v.value(), offset, len))))
    }

    fn blob_len(&self, id: &BlobId) -> Result<Option<u64>, BackendError> {
        self.read(BLOBS, |t| Ok(t.get(id.0.as_slice())?.map(|v| v.value().len() as u64)))
    }
}
