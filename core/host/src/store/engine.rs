//! The engine's blobs in the hub's store (`osis_store::CipherHost`, issues/net-one-peer.md step
//! 4): one blob area for what the node reads and what it keeps for others, so a blob read and
//! served is stored once. A `B` row marks a blob the engine holds; the hub deletes a blob only
//! once no entry references it (`R`) and the engine holds it no more, the engine's release only
//! once no `R` row is left. The engine's writes go into the store's open transaction, committed
//! by `commit` before the engine's own.

use super::{HostStore, Write, Writes, key};
use osis_base::BlobId;
use osis_store::{CipherHost, Error};
use std::sync::Arc;

fn mark(id: &BlobId) -> Vec<u8> {
    key(b'B', &[&id.0])
}

fn store_err(_: osis_proto::StoreError) -> Error {
    Error::Corrupt("hub store row")
}

impl CipherHost for HostStore {
    fn held(&mut self, id: &BlobId) -> Result<bool, Error> {
        if self.engine_mem.contains_key(id) {
            return Ok(true);
        }
        Ok(self.get(&mark(id)).map_err(store_err)?.is_some())
    }

    fn read(&mut self, id: &BlobId, offset: u64, len: usize) -> Result<Option<Vec<u8>>, Error> {
        if let Some(b) = self.engine_mem.get(id) {
            let start = usize::try_from(offset).unwrap_or(usize::MAX).min(b.len());
            return Ok(b.get(start..start.saturating_add(len).min(b.len())).map(<[u8]>::to_vec));
        }
        self.db.get_mut().run(|t, _| t.read_blob(id, offset, len))
    }

    fn hold(&mut self, id: &BlobId, blob: Vec<u8>, memory: bool) -> Result<bool, Error> {
        if self.held(id)? {
            return Ok(false);
        }
        if memory {
            self.engine_mem.insert(*id, blob);
            return Ok(true);
        }
        let mut w = Writes::default();
        w.put(mark(id), Vec::new());
        w.put_blob(*id, blob);
        self.db.get_mut().apply(w)?;
        Ok(true)
    }

    fn release(&mut self, id: &BlobId, memory: bool) -> Result<(), Error> {
        if self.engine_mem.remove(id).is_some() || memory || !self.held(id)? {
            return Ok(());
        }
        let (refs, _) = self.refs(id).map_err(store_err)?;
        let mut w = Writes::default();
        w.0.push(Write::Unmark(mark(id)));
        if refs == 0 {
            w.delete_blob(*id);
        }
        self.db.get_mut().apply(w)
    }

    fn commit(&mut self) -> Result<(), Error> {
        // a failed commit recovered the store in place: the outcome is unknown
        HostStore::commit(self).map_err(|_| Error::Broken)
    }

    fn abort(&mut self) {
        self.db.get_mut().open = None;
    }

    fn test_copy(&self, clock: Arc<dyn osis_base::Clock>) -> Result<HostStore, Error> {
        HostStore::test_copy(self, clock)
    }
}
