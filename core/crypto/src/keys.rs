//! Key derivations per actor kind (spec/crypto.md §3) and keyed content hashes (§6).

use crate::kdf::{self, DEDUP, kdf};
use crate::{KemSecret, Secret32, SigningSecret};
use osis_base::{Role, Tid};

/// A key actor's keys (node, link key), all from its 32-byte seed, derived once and held with
/// it: zeroized on drop with it; `Debug` shows public keys only.
#[derive(Clone, Debug)]
pub struct KeyActorKeys {
    seed: Secret32,
    /// From `kdf("sign", seed)`; the creation record commits to its public key.
    pub signing: SigningSecret,
    /// From `kdf("kem", seed)`; its X25519 half is the claim key.
    pub kem: KemSecret,
}

impl KeyActorKeys {
    pub fn from_seed(seed: &Secret32) -> KeyActorKeys {
        KeyActorKeys { seed: seed.clone(), signing: KeyActorKeys::signing_of(seed), kem: KemSecret::derive(seed) }
    }
    /// The signing key alone (what its creation record names), without the KEM key pair.
    pub fn signing_of(seed: &Secret32) -> SigningSecret {
        SigningSecret::from_seed(&kdf(kdf::SIGN, seed.expose(), b""))
    }
    /// The seed the keys derive from (its role secrets, `key_actor_role_secret`).
    pub fn seed(&self) -> &Secret32 {
        &self.seed
    }
}

/// A key actor's role secret `kdf("role <role>", seed)`, never rotated.
pub fn key_actor_role_secret(seed: &Secret32, role: Role) -> Secret32 {
    kdf(kdf::role_purpose(role), seed.expose(), b"")
}

/// A dependent thing's role secret `kdf("thing <role>", mint admin's secret, tid)`.
pub fn thing_role_secret(base_secret: &Secret32, role: Role, tid: &Tid) -> Secret32 {
    kdf(kdf::thing_purpose(role), base_secret.expose(), tid.as_bytes())
}

/// A role's KEM key pair of one epoch, `kdf("kem", role secret)` (actors other than key actors).
pub fn role_kem(role_secret: &Secret32) -> KemSecret {
    KemSecret::derive(role_secret)
}

/// Creation nonce of a link key, `kdf("creation nonce", seed, "")` (spec/wire.md §3).
pub fn creation_nonce(seed: &Secret32) -> [u8; 32] {
    *kdf(kdf::CREATION_NONCE, seed.expose(), b"").expose()
}

/// Dedup secret of a thing, `derive_key("osis v1 dedup", creation nonce)`.
pub fn dedup_secret(creation_nonce: &[u8; 32]) -> Secret32 {
    Secret32::from_bytes(blake3::derive_key(DEDUP, creation_nonce))
}

/// Delta hash `kdf("delta", dedup secret, delta bytes)` (spec/crypto.md §6).
pub fn delta_hash(dedup: &Secret32, delta: &[u8]) -> [u8; 32] {
    *kdf(kdf::DELTA, dedup.expose(), delta).expose()
}

/// Link content hash of a chunk, page or link page: `kdf("link", d, bytes)` (spec/wire.md §6).
pub fn link_hash(dedup: &Secret32, bytes: &[u8]) -> [u8; 32] {
    *kdf(kdf::LINK, dedup.expose(), bytes).expose()
}

/// Link content hash of a tree node: `kdf("link tree", d, le64(level) || for each child:
/// hash || le64(len))`, `len` the plaintext length under the child (spec/wire.md §6).
pub fn link_tree_hash(dedup: &Secret32, level: u64, children: &[([u8; 32], u64)]) -> [u8; 32] {
    let mut input = Vec::with_capacity(8 + 40 * children.len());
    input.extend_from_slice(&level.to_le_bytes());
    for (h, len) in children {
        input.extend_from_slice(h);
        input.extend_from_slice(&len.to_le_bytes());
    }
    *kdf(kdf::LINK_TREE, dedup.expose(), &input).expose()
}

#[cfg(test)]
mod tests {
    use super::*;

    // spec/crypto.md §3: a key actor's keys follow from its seed alone; role secrets differ per
    // role; a dependent thing's secrets differ per tid and role.
    #[test]
    fn key_actor_and_thing() {
        let seed = Secret32::from_bytes([5; 32]);
        let a = KeyActorKeys::from_seed(&seed);
        let b = KeyActorKeys::from_seed(&seed);
        assert_eq!(a.signing.verifying_key(), b.signing.verifying_key());
        assert_eq!(a.kem.public(), b.kem.public());
        let expect = SigningSecret::from_seed(&kdf("sign", &[5; 32], b""));
        assert_eq!(a.signing.verifying_key(), expect.verifying_key());
        let r = [Role::Read, Role::Write, Role::Admin].map(|role| key_actor_role_secret(&seed, role));
        assert!(r[0] != r[1] && r[1] != r[2] && r[0] != r[2]);
        let sync = key_actor_role_secret(&seed, Role::Sync);
        assert!(r.iter().all(|x| *x != sync));
        let (t1, t2) = (Tid::from_bytes([1; 15]), Tid::from_bytes([2; 15]));
        assert_ne!(thing_role_secret(&r[0], Role::Read, &t1), thing_role_secret(&r[0], Role::Read, &t2));
        assert_ne!(thing_role_secret(&r[0], Role::Read, &t1), thing_role_secret(&r[0], Role::Write, &t1));
        assert_eq!(*thing_role_secret(&r[0], Role::Read, &t1).expose(), *kdf("thing read", r[0].expose(), &[1; 15]).expose());
        assert_ne!(role_kem(&r[0]).public(), role_kem(&r[1]).public());
        assert_ne!(creation_nonce(&seed), *dedup_secret(&creation_nonce(&seed)).expose());
    }

    // spec/wire.md §6: tree-node hashes cover the level and the children's hashes and lengths
    // in order.
    #[test]
    fn content_hashes() {
        let d = Secret32::from_bytes([7; 32]);
        let (a, b) = ((link_hash(&d, b"a"), 1), (link_hash(&d, b"b"), 1));
        assert_ne!(link_tree_hash(&d, 1, &[a, b]), link_tree_hash(&d, 1, &[b, a]));
        assert_ne!(link_tree_hash(&d, 1, &[a, b]), link_tree_hash(&d, 2, &[a, b]));
        assert_ne!(link_tree_hash(&d, 1, &[a, b]), link_tree_hash(&d, 1, &[(a.0, 2), (b.0, 0)]));
        assert_ne!(link_hash(&d, b"a"), delta_hash(&d, b"a"));
        assert_ne!(link_hash(&d, b"a"), link_hash(&Secret32::from_bytes([8; 32]), b"a"));
    }
}
