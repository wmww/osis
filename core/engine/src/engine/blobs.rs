//! Blob ciphertexts in the node's one store (`osis_store::Ciphertext`), behind the traits of
//! osis-label (pages, chunks) and osis-commit (header-list chunk trees).

use osis_base::{Ak, BlobId, CommitId, Link, Tid, WallMs};
use osis_crypto::{CryptoRngCore, Secret32};
use osis_store::{CipherTx, Ciphertext};

/// One engine transaction's blobs: the ciphertext store locked at the first use, committed
/// before the engine's store (`Engine::run`). What it newly held is journaled, so a step rolled
/// back (`Tx::step`) or a transaction dropped releases it again.
pub struct Cipher<'a> {
    src: &'a dyn Ciphertext,
    tx: Option<Box<dyn CipherTx + 'a>>,
    /// Blobs this transaction newly held, with whether in memory, in order.
    held: Vec<(BlobId, bool)>,
    done: bool,
}

impl<'a> Cipher<'a> {
    pub fn new(src: &'a dyn Ciphertext) -> Cipher<'a> {
        Cipher { src, tx: None, held: Vec::new(), done: false }
    }

    fn tx(&mut self) -> &mut (dyn CipherTx + 'a) {
        let src = self.src;
        &mut **self.tx.get_or_insert_with(|| src.begin())
    }

    /// The store itself (node sync: the hub's store), locked for this transaction.
    pub fn store(&mut self) -> &mut dyn std::any::Any {
        self.tx().any()
    }

    /// Whether the engine holds blob `id`.
    pub fn held(&mut self, id: &BlobId) -> crate::error::Result<bool> {
        Ok(self.tx().held(id)?)
    }

    /// Blob `id`'s bytes, held by the engine or kept by the store for others.
    pub fn get(&mut self, id: &BlobId) -> crate::error::Result<Option<Vec<u8>>> {
        self.read(id, 0, usize::MAX)
    }

    /// Bytes `offset..offset+len` of blob `id`.
    pub fn read(&mut self, id: &BlobId, offset: u64, len: usize) -> crate::error::Result<Option<Vec<u8>>> {
        Ok(self.tx().read(id, offset, len)?)
    }

    /// The engine holds `id` (`memory`: in memory only); whether it did not before.
    pub fn hold(&mut self, id: &BlobId, blob: Vec<u8>, memory: bool) -> crate::error::Result<bool> {
        let new = self.tx().hold(id, blob, memory)?;
        if new {
            self.held.push((*id, memory));
        }
        Ok(new)
    }

    /// The engine holds `id` no more (`memory`: memory data's work, a durable blob stays).
    pub fn release(&mut self, id: &BlobId, memory: bool) -> crate::error::Result<()> {
        Ok(self.tx().release(id, memory)?)
    }

    /// A point `rollback_to` releases back to.
    pub fn mark(&self) -> usize {
        self.held.len()
    }

    /// Releases what was newly held since `m`.
    pub fn rollback_to(&mut self, m: usize) {
        let undo: Vec<_> = self.held.drain(m.min(self.held.len())..).rev().collect();
        if let Some(t) = self.tx.as_mut() {
            for (id, memory) in undo {
                // a failure leaves a blob nothing names: space only
                let _ = t.release(&id, memory);
            }
        }
    }

    /// Commits the ciphertext store's writes (the engine's store commits after).
    pub fn commit(&mut self) -> crate::error::Result<()> {
        self.done = true;
        match self.tx.as_mut() {
            Some(t) => Ok(t.commit()?),
            None => Ok(()),
        }
    }
}

impl Drop for Cipher<'_> {
    fn drop(&mut self) {
        if !self.done {
            self.rollback_to(0);
        }
    }
}

/// Blobs of one transaction; records what it wrote.
pub struct TxBlobs<'t, 'a> {
    pub blobs: &'t mut Cipher<'a>,
    memory: bool,
    pub written: Vec<BlobId>,
}

impl<'t, 'a> TxBlobs<'t, 'a> {
    /// `memory`: the transaction works on memory data (`Transaction::is_memory`).
    pub fn new(blobs: &'t mut Cipher<'a>, memory: bool) -> TxBlobs<'t, 'a> {
        TxBlobs { blobs, memory, written: Vec::new() }
    }
}

impl osis_label::BlobSink for TxBlobs<'_, '_> {
    fn put(&mut self, id: BlobId, blob: Vec<u8>) -> Result<(), osis_label::Error> {
        self.blobs.hold(&id, blob, self.memory).map_err(|_| osis_label::Error::Missing)?;
        self.written.push(id);
        Ok(())
    }
}

impl osis_label::BlobFetch for TxBlobs<'_, '_> {
    fn fetch(&mut self, id: &BlobId) -> Result<Vec<u8>, osis_label::Error> {
        self.blobs.get(id).ok().flatten().ok_or(osis_label::Error::Missing)
    }
}

/// Header-list chunk trees (osis-commit's traits): frames under the given prefix.
pub struct ListBlobs<'t, 'a, 'r> {
    pub blobs: TxBlobs<'t, 'a>,
    pub rng: &'r mut dyn CryptoRngCore,
}

impl osis_commit::BlobSink for ListBlobs<'_, '_, '_> {
    fn put(&mut self, prefix: &osis_commit::Prefix, plaintext: &[u8]) -> Result<(BlobId, [u8; 32]), osis_commit::Error> {
        let p = osis_label::Prefix::for_delete_keys(prefix.salt, &prefix.blind, prefix.expiry.map(WallMs), std::slice::from_ref(&prefix.keys)).map_err(|_| osis_commit::Error::Storage("prefix"))?;
        let (key, blob) = osis_label::frame(&p, plaintext, self.rng).map_err(|_| osis_commit::Error::Storage("frame"))?;
        let id = osis_label::blob_id(&blob);
        osis_label::BlobSink::put(&mut self.blobs, id, blob).map_err(|_| osis_commit::Error::Storage("blob"))?;
        Ok((id, *key.expose()))
    }
}

impl osis_commit::BlobSource for TxBlobs<'_, '_> {
    fn get(&mut self, link: &Link) -> Result<Vec<u8>, osis_commit::Error> {
        let blob = self.blobs.get(&link.blob).map_err(|_| osis_commit::Error::Storage("blob"))?.ok_or(osis_commit::Error::Missing)?;
        if osis_label::blob_id(&blob) != link.blob {
            return Err(osis_commit::Error::Corrupt);
        }
        let (_, pt) = osis_label::open(&blob, &Secret32::from_bytes(link.key)).map_err(|_| osis_commit::Error::Corrupt)?;
        Ok(pt)
    }
}

impl crate::engine::Engine {
    /// Stores blob ciphertexts (pages, chunks, commit blobs) by ID.
    pub fn put_blobs(&mut self, blobs: Vec<(BlobId, Vec<u8>)>) -> crate::error::Result<()> {
        if blobs.is_empty() {
            return Ok(());
        }
        if !self.run(|tx| tx.store_blobs(blobs))?.is_empty() {
            self.blobs_stored();
        }
        Ok(())
    }

    /// `put_blobs` of blobs of memory commits: kept in the store's memory overlay, never on disk
    /// (spec/sync.md §9).
    pub fn put_memory_blobs(&mut self, blobs: Vec<(BlobId, Vec<u8>)>) -> crate::error::Result<()> {
        if blobs.is_empty() {
            return Ok(());
        }
        self.run(|tx| {
            tx.set_memory();
            tx.store_blobs(blobs)
        })?;
        Ok(())
    }

    /// After a transaction that stored a new blob (`Tx::store_blobs`) committed: what reads
    /// noted missing was re-delivered, and a node blob may complete a tree walk that lacked it.
    pub fn blobs_stored(&mut self) {
        self.core.missed.clear();
        self.core.live_trees.retain(|_, t| t.missing.is_empty());
    }

    /// A read of `tid`'s `ak` (its state, or with `entry` that commit's part) found a
    /// link whose blob is not held: the next blob stored re-delivers it to watches (`put_blobs`).
    pub fn missed_blob(&mut self, tid: Tid, ak: Ak, entry: Option<CommitId>) {
        self.core.missed.insert((tid, ak, entry));
    }

    pub fn has_blob(&mut self, id: &BlobId) -> bool {
        let id = *id;
        self.run(|tx| tx.blobs.held(&id)).unwrap_or(false)
    }
}

impl crate::engine::Tx<'_> {
    /// Stores blob ciphertexts by ID (one not matching its ID, or held already, is skipped);
    /// those it stored. A new one re-delivers what reads noted missing (`Core::missed`):
    /// aspects as `Cause::Fetched`, history entries as `Event::Commits`; a read still missing
    /// a blob notes it again. The notes stay until `Engine::blobs_stored` clears them after the
    /// commit, so a rolled back transaction (its events discarded) loses none.
    pub fn store_blobs(&mut self, blobs: Vec<(BlobId, Vec<u8>)>) -> crate::error::Result<Vec<BlobId>> {
        let mut stored = Vec::new();
        let memory = self.txn.is_memory();
        for (id, b) in blobs {
            if osis_label::blob_id(&b) == id && self.blobs.hold(&id, b, memory)? {
                stored.push(id);
            }
        }
        if !stored.is_empty() && !self.core.missed.is_empty() {
            let (mut changed, mut entries) = (Vec::new(), Vec::new());
            for (tid, ak, entry) in &self.core.missed {
                match entry {
                    None => changed.push((*tid, ak.clone())),
                    Some(c) => entries.push((*tid, ak.clone(), *c)),
                }
            }
            if !changed.is_empty() {
                self.core.events.queue(crate::events::Event::Changed { cause: crate::events::Cause::Fetched, changed });
            }
            self.core.commits_touched(entries);
        }
        Ok(stored)
    }
}
