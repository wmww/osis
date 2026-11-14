//! The engine's ciphertext door (`osis_store::CipherHost`): the engine holds and releases blobs
//! in the node's one store, in a transaction of the store's that it commits before its own. A
//! blob's bytes stay while the engine or any entry of any sync ID holds them; bytes the engine
//! holds make every entry naming them servable (`entries::bytes_arrived`).

use super::entries::{bytes_arrived, unref};
use super::{Inner, rows};
use osis_base::BlobId;
use osis_store::{Error, Shred, Transaction};
use std::sync::Arc;

type Res<T> = std::result::Result<T, Error>;

fn store_err(e: crate::types::Error) -> Error {
    match e {
        crate::types::Error::Store(e) => e,
        _ => Error::Corrupt("sync store"),
    }
}

impl Inner {
    /// Runs `f` in the engine's open transaction (begun at its first use).
    fn engine_tx<R>(&mut self, f: impl FnOnce(&mut Transaction<'_>, &mut super::Env<'_>) -> crate::types::Result<R>) -> Res<R> {
        let Inner { store, rng, open, now, holdings, caps, policy, mem, total, .. } = self;
        let mut t = match open.take() {
            Some(s) => store.resume(s, &mut **rng),
            None => store.transaction(&mut **rng)?,
        };
        let mut env = super::Env { now: *now, holdings, caps, policy, mem, total: *total };
        let r = f(&mut t, &mut env);
        *open = Some(t.suspend()?);
        // an abort of the engine's transaction counts the total again (`abort`)
        *total = env.total;
        r.map_err(store_err)
    }
}

impl osis_store::CipherHost for Inner {
    fn held(&mut self, id: &BlobId) -> Res<bool> {
        if self.mem.engine.contains(id) {
            return Ok(true);
        }
        self.engine_tx(|t, _| Ok(t.get_local(&rows::engine_key(id))?.is_some()))
    }

    fn read(&mut self, id: &BlobId, offset: u64, len: usize) -> Res<Option<Vec<u8>>> {
        if let Some(b) = self.mem.blobs.get(id) {
            let start = usize::try_from(offset).unwrap_or(usize::MAX).min(b.len());
            return Ok(b.get(start..start.saturating_add(len).min(b.len())).map(<[u8]>::to_vec));
        }
        self.engine_tx(|t, _| Ok(t.read_blob(id, offset, len)?))
    }

    fn len(&mut self, id: &BlobId) -> Res<Option<u64>> {
        if let Some(b) = self.mem.blobs.get(id) {
            return Ok(Some(b.len() as u64));
        }
        self.engine_tx(|t, _| Ok(t.blob_len(id)?))
    }

    fn hold(&mut self, id: &BlobId, blob: Vec<u8>, memory: bool) -> Res<bool> {
        if self.held(id)? {
            return Ok(false);
        }
        if memory {
            self.mem.engine.insert(*id);
            self.mem.blobs.entry(*id).or_insert(blob);
            return Ok(true);
        }
        self.engine_tx(|t, env| {
            if t.blob_len(id)?.is_none() {
                t.put_blob(id, blob)?;
            }
            t.put_local(&rows::engine_key(id), &[], Shred::No)?;
            bytes_arrived(t, env, id)
        })?;
        Ok(true)
    }

    fn release(&mut self, id: &BlobId, memory: bool) -> Res<()> {
        if self.mem.engine.remove(id) {
            if !self.mem.by_blob.contains_key(id) {
                self.mem.blobs.remove(id);
            }
            return Ok(());
        }
        if memory {
            return Ok(());
        }
        self.engine_tx(|t, env| {
            t.remove_local(&rows::engine_key(id), Shred::No)?;
            unref(t, env, id)
        })
    }

    fn local(&mut self, f: &mut dyn FnMut(&mut Transaction<'_>) -> Res<()>) -> Res<()> {
        self.engine_tx(|t, _| Ok(f(t)?))
    }

    fn commit(&mut self) -> Res<()> {
        let Inner { store, rng, open, .. } = self;
        let Some(s) = open.take() else { return Ok(()) };
        store.resume(s, &mut **rng).commit()
    }

    fn abort(&mut self) {
        // a suspended transaction dropped aborts; the total is counted again
        self.open = None;
        self.total = None;
    }

    fn forensic_keys(&mut self) -> Res<Vec<[u8; 32]>> {
        self.commit()?;
        self.store.forensic_keys()
    }

    fn test_copy(&self, _clock: Arc<dyn osis_base::Clock>) -> Res<Inner> {
        Ok(Inner {
            store: self.store.test_copy()?,
            rng: self.rng.test_copy(),
            open: self.open.as_ref().map(osis_store::Suspended::test_copy),
            now: self.now,
            holdings: self.holdings.clone(),
            caps: self.caps.clone(),
            policy: self.policy.clone(),
            mem: self.mem.clone(),
            total: self.total,
            past_cap: self.past_cap.clone(),
        })
    }
}
