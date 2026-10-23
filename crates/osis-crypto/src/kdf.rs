//! `kdf` (spec/crypto.md §1) and every domain string the spec uses: kdf purposes, BLAKE3
//! derive_key contexts and hash prefixes. Signature domains: `Domain`.

use crate::Secret32;
use osis_core::Role;
use zeroize::{Zeroize, Zeroizing};

/// `kdf(purpose, secret, input) = keyed_hash(derive_key("osis v1 " + purpose, secret), input)`.
/// Callers deriving a public value (a hash, a nonce) copy it out of the `Secret32`.
pub fn kdf(purpose: &str, secret: &[u8], input: &[u8]) -> Secret32 {
    Secret32::from_bytes(blake3::keyed_hash(&kdf_key(purpose, secret), input).into())
}

/// The XOF form of `kdf`, filling `out` (spec/crypto.md §1: where more than 32 bytes are needed).
pub fn kdf_xof(purpose: &str, secret: &[u8], input: &[u8], out: &mut [u8]) {
    let mut h = blake3::Hasher::new_keyed(&kdf_key(purpose, secret));
    h.update(input);
    let mut reader = h.finalize_xof();
    reader.fill(out);
    reader.zeroize();
    h.zeroize();
}

fn kdf_key(purpose: &str, secret: &[u8]) -> Zeroizing<[u8; 32]> {
    let mut h = blake3::Hasher::new_derive_key(&format!("{PREFIX}{purpose}"));
    h.update(secret);
    let k = Zeroizing::new(h.finalize().into());
    h.zeroize();
    k
}

/// Prefix of every derive_key context.
pub const PREFIX: &str = "osis v1 ";

// kdf purposes (without `PREFIX`).
/// Plain thing role secrets from the owner's (spec/crypto.md §3); `thing_purpose` picks one.
pub const THING_READ: &str = "thing read";
pub const THING_WRITE: &str = "thing write";
pub const THING_ADMIN: &str = "thing admin";
/// Key actor role secrets from its seed (spec/crypto.md §3); `role_purpose` picks one.
pub const ROLE_READ: &str = "role read";
pub const ROLE_WRITE: &str = "role write";
pub const ROLE_ADMIN: &str = "role admin";
/// Key actor signing key from its seed.
pub const SIGN: &str = "sign";
/// KEM key pair from a seed or role secret.
pub const KEM: &str = "kem";
/// Link and recovery key creation nonce from the seed (spec/wire.md §3).
pub const CREATION_NONCE: &str = "creation nonce";
/// Symmetric box key (spec/wire.md §7).
pub const BOX: &str = "box";
/// History box key.
pub const HISTORY: &str = "history";
/// Wrap key from a label read secret (spec/crypto.md §5).
pub const WRAP: &str = "wrap";
/// Keyed content hashes (spec/crypto.md §6).
pub const DELTA: &str = "delta";
pub const LINK: &str = "link";
pub const LINK_TREE: &str = "link tree";
/// Delete keys, their blinding factor and blinded signing nonce (spec/crypto.md §7).
pub const DELETE_KEY: &str = "delete key";
pub const DELETE_BLIND: &str = "delete blind";
pub const DELETE_NONCE: &str = "delete nonce";
/// Label role keys (spec/sync.md §2).
pub const LABEL_SYNC: &str = "label sync";
pub const LABEL_WRITE: &str = "label write";
pub const LABEL_DELETE: &str = "label delete";
pub const LABEL_DEPOSIT: &str = "label deposit";
pub const LABEL_CLAIM: &str = "label claim";
/// LAN discovery tag and the announcement signature's keystream (spec/sync.md §10).
pub const LAN_TAG: &str = "lan tag";
pub const LAN_SIG: &str = "lan sig";

/// Every kdf purpose, for distinctness checks and vectors.
pub const PURPOSES: [&str; 25] = [
    THING_READ, THING_WRITE, THING_ADMIN, ROLE_READ, ROLE_WRITE, ROLE_ADMIN, SIGN, KEM, CREATION_NONCE, BOX, HISTORY, WRAP,
    DELTA, LINK, LINK_TREE, DELETE_KEY, DELETE_BLIND, DELETE_NONCE, LABEL_SYNC, LABEL_WRITE, LABEL_DELETE, LABEL_DEPOSIT, LABEL_CLAIM, LAN_TAG, LAN_SIG,
];

// Full derive_key contexts used directly (not through `kdf`).
/// Dedup secret from the creation nonce (spec/crypto.md §3).
pub const DEDUP: &str = "osis v1 dedup";
/// Hybrid KEM combiner (spec/crypto.md §1).
pub const HYBRID_KEM: &str = "osis v1 hybrid kem";

// Unkeyed hash prefixes.
/// Label ID = BLAKE3(LABEL_ID || genesis delete key)[..16] (spec/wire.md §8).
pub const LABEL_ID: &str = "osis v1 label id";
/// Static entry = BLAKE3(STATIC_CLAIM || label ID || signing key) (spec/wire.md §8).
pub const STATIC_CLAIM: &str = "osis v1 static claim";

pub fn thing_purpose(role: Role) -> &'static str {
    match role {
        Role::Read => THING_READ,
        Role::Write => THING_WRITE,
        Role::Admin => THING_ADMIN,
    }
}

pub fn role_purpose(role: Role) -> &'static str {
    match role {
        Role::Read => ROLE_READ,
        Role::Write => ROLE_WRITE,
        Role::Admin => ROLE_ADMIN,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Domain;
    use std::collections::BTreeSet;

    // spec/crypto.md §1, §2: every context, prefix and signature domain is distinct.
    #[test]
    fn strings_distinct() {
        let mut all: Vec<String> = PURPOSES.iter().map(|p| format!("{PREFIX}{p}")).collect();
        all.extend([DEDUP, HYBRID_KEM, LABEL_ID, STATIC_CLAIM, "osis v1 gear table"].map(String::from));
        all.extend(Domain::ALL.iter().map(|d| d.as_str().to_string()));
        let set: BTreeSet<&String> = all.iter().collect();
        assert_eq!(set.len(), all.len());
        assert_eq!(all.len(), 25 + 5 + 10);
    }

    // spec/crypto.md §1: kdf = keyed_hash(derive_key("osis v1 " + purpose, secret), input).
    #[test]
    fn kdf_definition() {
        let secret = [0x11; 32];
        let k = blake3::derive_key("osis v1 wrap", &secret);
        assert_eq!(kdf(WRAP, &secret, b"in").expose(), blake3::keyed_hash(&k, b"in").as_bytes());
        let mut out = [0u8; 96];
        kdf_xof(KEM, &secret, b"", &mut out);
        assert_eq!(out[..32], kdf(KEM, &secret, b"").expose()[..]);
        assert_ne!(kdf(LINK, &secret, b"x"), kdf(LINK_TREE, &secret, b"x"));
    }
}
