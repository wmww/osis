//! Blob ciphertexts in the store, behind the traits of osis-label (pages, chunks) and
//! osis-commit (header-list chunk trees).

use crate::events::BatchId;
use osis_base::{Ak, BlobId, Link, Tid, WallMs};
use osis_crypto::{CryptoRngCore, Secret32};
use osis_store::Transaction;

/// Blobs of one transaction; records what it wrote.
pub struct TxBlobs<'t, 'a> {
    pub txn: &'t mut Transaction<'a>,
    pub written: Vec<BlobId>,
}

impl<'t, 'a> TxBlobs<'t, 'a> {
    pub fn new(txn: &'t mut Transaction<'a>) -> TxBlobs<'t, 'a> {
        TxBlobs { txn, written: Vec::new() }
    }
}

fn store_err(e: osis_store::Error) -> osis_label::Error {
    let _ = e;
    osis_label::Error::Missing
}

impl osis_label::BlobSink for TxBlobs<'_, '_> {
    fn put(&mut self, id: BlobId, blob: Vec<u8>) -> Result<(), osis_label::Error> {
        self.txn.put_blob(&id, blob).map_err(store_err)?;
        self.written.push(id);
        Ok(())
    }
}

impl osis_label::BlobFetch for TxBlobs<'_, '_> {
    fn fetch(&mut self, id: &BlobId) -> Result<Vec<u8>, osis_label::Error> {
        self.txn.get_blob(id).ok().flatten().ok_or(osis_label::Error::Missing)
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
        let blob = self.txn.get_blob(&link.blob).map_err(|_| osis_commit::Error::Storage("blob"))?.ok_or(osis_commit::Error::Missing)?;
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
        if self.run(|tx| tx.store_blobs(blobs))? {
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
    pub(crate) fn blobs_stored(&mut self) {
        self.core.missed.clear();
        self.core.live_trees.retain(|_, t| t.missing.is_empty());
    }

    /// A read of `tid`'s `ak` (its state, or with `entry` that change's history entry) found a
    /// link whose blob is not held: the next blob stored re-delivers it to watches (`put_blobs`).
    pub fn missed_blob(&mut self, tid: Tid, ak: Ak, entry: Option<BatchId>) {
        self.core.missed.insert((tid, ak, entry));
    }

    pub fn has_blob(&mut self, id: &BlobId) -> bool {
        let id = *id;
        self.run(|tx| Ok(tx.txn.read_blob(&id, 0, 0)?.is_some())).unwrap_or(false)
    }
}

impl crate::engine::Tx<'_> {
    /// Stores blob ciphertexts by ID (one not matching its ID, or held already, is skipped);
    /// whether one was new. A new one re-delivers what reads noted missing (`Core::missed`):
    /// aspects as `Cause::Fetched`, history entries as `Event::History`; a read still missing
    /// a blob notes it again. The notes stay until `Engine::blobs_stored` clears them after the
    /// commit, so a rolled back transaction (its events discarded) loses none.
    pub(crate) fn store_blobs(&mut self, blobs: Vec<(BlobId, Vec<u8>)>) -> crate::error::Result<bool> {
        let mut fresh = false;
        for (id, b) in blobs {
            if osis_label::blob_id(&b) == id && self.txn.read_blob(&id, 0, 0)?.is_none() {
                self.txn.put_blob(&id, b)?;
                fresh = true;
            }
        }
        if fresh && !self.core.missed.is_empty() {
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
            self.core.history_touched(entries);
        }
        Ok(fresh)
    }
}
