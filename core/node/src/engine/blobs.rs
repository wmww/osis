//! Blob ciphertexts in the store, behind the traits of osis-label (pages, chunks) and
//! osis-commit (header-list chunk trees).

use osis_core::{BlobId, Link, WallMs};
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
        let p = osis_label::Prefix::new(prefix.salt, prefix.expiry.map(WallMs), prefix.commitments.clone()).map_err(|_| osis_commit::Error::Storage("prefix"))?;
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
