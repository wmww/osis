//! osis-crypto: suite 1 primitives and every derivation, box, wrap and delete key of spec/crypto.md
//! (layouts: spec/wire.md §3, §5, §7, §8). Pure functions; randomness is injected
//! (`&mut dyn CryptoRngCore`), secrets are zeroized on drop and never printed.
//! Layer 1 (notes/architecture.md). Notes: notes/crypto.md.
#![forbid(unsafe_code)]

pub mod aead;
mod blob;
mod boxes;
mod delete;
mod error;
pub mod kdf;
mod kem;
mod keys;
mod sync_id;
mod rng;
mod secret;
mod sign;

pub use blob::{BlobKey, SECTION_WRAP_LEN, Trial, WRAP_LEN, blob_id, blob_len, decrypt_blob, encrypt_blob, filler_wrap, open_fire, open_section, pad, padme, reseal_section, seal_fire, seal_section, unpad, unwrap, unwrap_order, unwrap_section, wrap, wrap_section};
pub use delete::{DeleteSecret, blind, commitment, link_blind, thing_blind, verify_delete};
pub use boxes::{BoxForm, BoxItem, BoxSlot, Epoch, HistoryEntry, open_box, open_form_box, read_open_box, open_history, open_joint_box, open_symmetric_box, roles_secret, seal_box, seal_history, seal_joint_box, wrap_symmetric_box};
pub use error::Error;
pub use kem::{KEM_PUBLIC_LEN, KemPublicKey, KemSecret, MLKEM_CT_LEN, SEALED_OVERHEAD, X25519Secret, open_sealed, seal, seal_with};
pub use keys::{creation_nonce, dedup_secret, delta_hash, link_hash, link_key_role_secret, link_tree_hash, RoleSecret, role_kem, signing_key, thing_role_secret};
pub use sync_id::{RoleKey, claim_key, deposit_key, genesis_seed, role_key, role_key_seed, open_digest, proof_digest, sign_open, sync_id, verify_open};
pub use rng::{NodeRng, SeededRng};
pub use secret::Secret32;
pub use sign::{Domain, Signature, SigningSecret, VerifyingKey};

pub use rand_core::OsRng;
pub use rand_core::{CryptoRng, CryptoRngCore, Error as RngError, RngCore};
pub use zeroize::Zeroizing;

/// The only suite (spec/crypto.md §8): suite byte of wraps and links, suite ID of epochs.
pub const SUITE_1: u8 = 1;

/// Agility enum case of every suite 1 key, signature and sealed box (spec/wire.md §3).
const CASE_1: u64 = 1;

/// Bytes of a case 1 agility enum value `1617([1, h'..'])`, of length `len`; another case parks
/// (spec/crypto.md §8).
fn agility_bytes(v: &osis_base::Value, len: usize) -> Result<&[u8], Error> {
    use osis_base::Value;
    let Value::Enum(case, payload) = v else { return Err(Error::Malformed("not an enum")) };
    if *case != CASE_1 {
        return Err(Error::UnknownCase(*case));
    }
    match payload.as_deref() {
        Some(Value::Bytes(b)) if b.len() == len => Ok(b),
        _ => Err(Error::Malformed("agility payload")),
    }
}

fn agility_value(bytes: &[u8]) -> osis_base::Value {
    osis_base::Value::Enum(CASE_1, Some(Box::new(osis_base::Value::Bytes(bytes.to_vec()))))
}
