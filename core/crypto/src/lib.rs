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
mod label;
mod rng;
mod secret;
mod sign;

pub use aead::WRAP_LEN;
pub use blob::{blob_id, blob_len, decrypt_blob, encrypt_blob, filler_wrap, open_inbox, pad, padme, seal_inbox, unpad, unwrap, wrap};
pub use delete::{DeleteSecret, blind, commitment, verify_delete};
pub use boxes::{BoxForm, BoxItem, BoxSlot, Epoch, open_box, open_history, open_symmetric_box, seal_box, seal_history, wrap_symmetric_box};
pub use error::Error;
pub use kem::{KEM_PUBLIC_LEN, KemPublicKey, KemSecret, MLKEM_CT_LEN, SEALED_OVERHEAD, X25519Secret, open_sealed, seal, seal_with, sealed_from_value, sealed_to_value};
pub use keys::{KeyActorKeys, creation_nonce, dedup_secret, delta_hash, key_actor_role_secret, lan_digest, lan_keystream, lan_tag, link_hash, open_lan_sig, seal_lan_sig, link_tree_hash, role_kem, thing_role_secret};
pub use label::{LabelRole, claim_key, deposit_key, label_id, label_role_key, open_digest, sign_open, static_entry, verify_open};
pub use rng::SeededRng;
pub use secret::Secret32;
pub use sign::{Domain, Signature, SigningSecret, VerifyingKey};

pub use rand_core::OsRng;
pub use rand_core::{CryptoRng, CryptoRngCore, Error as RngError, RngCore};
pub use zeroize::Zeroizing;

/// The only suite (spec/crypto.md §8): suite byte of wraps and links, suite ID of epochs.
pub const SUITE_1: u8 = 1;

/// Agility enum case of every suite 1 key, signature and sealed box (spec/wire.md §3).
const CASE_1: u64 = 1;

/// Bytes of a case 1 agility enum value `1617([1, h'..'])`, of length `len` if given;
/// another case parks (spec/crypto.md §8).
fn agility_bytes(v: &osis_base::Value, len: Option<usize>) -> Result<&[u8], Error> {
    use osis_base::Value;
    let Value::Enum(case, payload) = v else { return Err(Error::Malformed("not an enum")) };
    if *case != CASE_1 {
        return Err(Error::UnknownCase(*case));
    }
    match payload.as_deref() {
        Some(Value::Bytes(b)) if len.is_none_or(|l| l == b.len()) => Ok(b),
        _ => Err(Error::Malformed("agility payload")),
    }
}

fn agility_value(bytes: &[u8]) -> osis_base::Value {
    osis_base::Value::Enum(CASE_1, Some(Box::new(osis_base::Value::Bytes(bytes.to_vec()))))
}
