//! Sealed fires (spec/sync-inbox.md §2): a fire of an open signal, a commit by the sender's own
//! account sealed to the thing's public key, delivered as a deposit. Filled by lane (c) of
//! issues/reference-graph.md.

use crate::Error;
use osis_crypto::{CryptoRngCore, KemPublicKey, KemSecret};

/// Seals `commit` (a `CommitBlobPlaintext`'s bytes) to the thing's read KEM key `kem`
/// (spec/sync-inbox.md §2): the blob a deposit carries.
pub fn seal_fire(kem: &KemPublicKey, commit: &[u8], rng: &mut dyn CryptoRngCore) -> Result<Vec<u8>, Error> {
    let _ = (kem, commit, rng);
    todo!("refgraph: (c) sealing a fire")
}

/// Opens a sealed fire with the thing's read KEM secret: the commit's bytes.
pub fn open_fire(blob: &[u8], kem: &KemSecret) -> Result<Vec<u8>, Error> {
    let _ = (blob, kem);
    todo!("refgraph: (c) opening a fire")
}
