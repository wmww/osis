//! Key derivations per actor kind (spec/crypto.md §3) and keyed content hashes (§6).

use crate::kdf::{self, DEDUP, kdf};
use crate::{Domain, KemSecret, Secret32, Signature, SigningSecret, VerifyingKey};
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

/// One epoch of an account's signing chain, all from its 32-byte seed (spec/crypto.md §3),
/// derived once and held with it: signing and KEM keys as a key actor's, its inner secret and
/// (through the seed) its role secrets.
#[derive(Clone, Debug)]
pub struct AccountEpochKeys {
    seed: Secret32,
    pub signing: SigningSecret,
    pub kem: KemSecret,
    /// `kdf("inner secret", seed)`: keys the inner signatures of commits signed at this epoch.
    pub inner: Secret32,
}

impl AccountEpochKeys {
    pub fn from_seed(seed: &Secret32) -> AccountEpochKeys {
        let KeyActorKeys { seed, signing, kem } = KeyActorKeys::from_seed(seed);
        let inner = kdf(kdf::INNER_SECRET, seed.expose(), b"");
        AccountEpochKeys { seed, signing, kem, inner }
    }
    /// The epoch's seed (its role secrets, `key_actor_role_secret`; stored in `account.0`).
    pub fn seed(&self) -> &Secret32 {
        &self.seed
    }
}

/// Bytes of a sealed inner signature: the node's tid (15) and its signature (64), plus the tag.
pub const INNER_LEN: usize = osis_base::format::TID_LEN + 64 + crate::aead::TAG_LEN;

/// A node's inner signature on an account's commit (spec/crypto.md §3, spec/wire.md §4): the
/// node's tid and its signature under `"osis v1 inner"` over the commit ID, sealed under
/// `kdf("inner key", inner secret, commit ID)` with a zero nonce (one plaintext per key).
pub fn seal_inner(inner: &Secret32, commit: &[u8; 32], node: &Tid, key: &SigningSecret) -> [u8; INNER_LEN] {
    let sig = key.sign(Domain::Inner, commit);
    let k = kdf(kdf::INNER, inner.expose(), commit);
    let plain = [node.as_bytes().as_slice(), &sig.0].concat();
    let mut out = [0u8; INNER_LEN];
    // XChaCha20-Poly1305 of 79 bytes under a 32-byte key cannot fail
    if let Ok(c) = crate::aead::seal(k.expose(), &[0; crate::aead::NONCE_LEN], &[], &plain) {
        out.copy_from_slice(&c);
    }
    out
}

/// Opens an inner signature with the epoch's inner secret: the node's tid and signature, not yet
/// checked against the node's key (`verify_inner`). `None` when it does not open.
pub fn open_inner(inner: &Secret32, commit: &[u8; 32], sealed: &[u8; INNER_LEN]) -> Option<(Tid, Signature)> {
    let k = kdf(kdf::INNER, inner.expose(), commit);
    let plain = crate::aead::open(k.expose(), &[0; crate::aead::NONCE_LEN], &[], sealed).ok()?;
    let (t, s) = plain.split_at_checked(osis_base::format::TID_LEN)?;
    Some((Tid::from_bytes(t.try_into().ok()?), Signature(s.try_into().ok()?)))
}

/// Whether an opened inner signature is `node`'s over the commit.
pub fn verify_inner(node: &VerifyingKey, commit: &[u8; 32], sig: &Signature) -> bool {
    node.verify(Domain::Inner, commit, sig).is_ok()
}

/// Bytes of a seed box's tag (spec/crypto.md §9, Custody).
pub const SEED_TAG_LEN: usize = 16;

/// The tag of a seed box of the epoch with seed `seed` to device `device`: the first 16 bytes of
/// `kdf("seed box", seed, device tid)`, so a holder of the seed reads whom the epoch is boxed to
/// and no one else does (spec/crypto.md §9, Custody).
pub fn seed_tag(seed: &Secret32, device: &Tid) -> [u8; SEED_TAG_LEN] {
    let k = kdf(kdf::SEED_BOX, seed.expose(), device.as_bytes());
    let mut t = [0u8; SEED_TAG_LEN];
    t.copy_from_slice(&k.expose()[..SEED_TAG_LEN]);
    t
}

fn seeds_ad(account: &Tid, epoch: &VerifyingKey) -> Vec<u8> {
    [b"osis v1 seeds".as_slice(), account.as_bytes(), &epoch.to_bytes()].concat()
}

/// A seed box (spec/crypto.md §9, Custody): `seeds` (the epoch's own first, then earlier ones
/// its writer hands a device it adds) sealed to device KEM key `kem`, AD naming the account and
/// the epoch by its signing key.
pub fn seal_seeds(kem: &crate::KemPublicKey, account: &Tid, epoch: &VerifyingKey, seeds: &[&Secret32], rng: &mut dyn rand_core::CryptoRngCore) -> Result<Vec<u8>, crate::Error> {
    let payload: zeroize::Zeroizing<Vec<u8>> = zeroize::Zeroizing::new(seeds.iter().flat_map(|s| s.expose().iter().copied()).collect());
    crate::seal(kem, &seeds_ad(account, epoch), &payload, rng)
}

/// Opens a seed box with this device's KEM key: its seeds, the epoch's own first. `None` when it
/// is not to this device, or its first seed is not that epoch's.
pub fn open_seeds(kem: &KemSecret, account: &Tid, epoch: &VerifyingKey, sealed: &[u8]) -> Option<Vec<Secret32>> {
    let plain = crate::open_sealed(kem, &seeds_ad(account, epoch), sealed).ok()?;
    if plain.is_empty() || plain.len() % 32 != 0 {
        return None;
    }
    let seeds: Vec<Secret32> = plain.as_chunks::<32>().0.iter().map(|c| Secret32::from_bytes(*c)).collect();
    (AccountEpochKeys::from_seed(seeds.first()?).signing.verifying_key() == *epoch).then_some(seeds)
}

/// A rotation's membership changes (spec/crypto.md §9, Roster): the devices it adds, then those
/// it removes, sealed under `kdf("devices", inner secret, new epoch's signing key)` of the epoch
/// it is signed at, zero nonce (one plaintext per key: the new key is fresh).
pub fn seal_devices(inner: &Secret32, new_epoch: &VerifyingKey, adds: &[Tid], removes: &[Tid]) -> Vec<u8> {
    let k = kdf(kdf::DEVICES, inner.expose(), &new_epoch.to_bytes());
    let mut plain = Vec::with_capacity(2 + (adds.len() + removes.len()) * osis_base::format::TID_LEN);
    plain.extend_from_slice(&u16::try_from(adds.len()).unwrap_or(u16::MAX).to_le_bytes());
    for t in adds.iter().chain(removes) {
        plain.extend_from_slice(t.as_bytes());
    }
    crate::aead::seal(k.expose(), &[0; crate::aead::NONCE_LEN], &[], &plain).unwrap_or_default()
}

/// Opens a rotation's sealed membership changes with the inner secret of the epoch it is signed
/// at: (adds, removes). `None` when the secret is not that epoch's or the bytes are malformed.
pub fn open_devices(inner: &Secret32, new_epoch: &VerifyingKey, sealed: &[u8]) -> Option<(Vec<Tid>, Vec<Tid>)> {
    let k = kdf(kdf::DEVICES, inner.expose(), &new_epoch.to_bytes());
    let plain = crate::aead::open(k.expose(), &[0; crate::aead::NONCE_LEN], &[], sealed).ok()?;
    let (n, rest) = plain.split_at_checked(2)?;
    let n = usize::from(u16::from_le_bytes(n.try_into().ok()?));
    let (tids, extra) = rest.as_chunks::<{ osis_base::format::TID_LEN }>();
    if !extra.is_empty() {
        return None;
    }
    let (adds, removes) = tids.split_at_checked(n)?;
    let tid = |t: &[u8; osis_base::format::TID_LEN]| Tid::from_bytes(*t);
    Some((adds.iter().map(tid).collect(), removes.iter().map(tid).collect()))
}

/// An account's creation nonce (spec/crypto.md §3): `kdf("first device", first seed, creation
/// device's tid)`, so its tid fixes the device that created it, read only with the first seed.
pub fn first_device_nonce(first_seed: &Secret32, device: &Tid) -> [u8; 32] {
    *kdf(kdf::FIRST_DEVICE, first_seed.expose(), device.as_bytes()).expose()
}

/// A merge epoch's seed: `kdf("merge seed", its tips' seeds concatenated)`, the tips in ascending
/// order of their epoch IDs (spec/crypto.md §9, Merges): a function of the tips alone, so every
/// holder of their seeds derives it and every certificate of the merge mints one epoch.
pub fn merge_seed(tips: &[&Secret32]) -> Secret32 {
    let mut cat = zeroize::Zeroizing::new(Vec::with_capacity(32 * tips.len()));
    for t in tips {
        cat.extend_from_slice(t.expose());
    }
    kdf(kdf::MERGE_SEED, &cat, b"")
}

/// A key actor's role secret `kdf("role <role>", seed)`, never rotated.
pub fn key_actor_role_secret(seed: &Secret32, role: Role) -> Secret32 {
    kdf(kdf::role_purpose(role), seed.expose(), b"")
}

/// A plain thing's role secret `kdf("thing <role>", base actor's secret, tid)`.
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

/// Keyed state digest of an aspect: the first 16 bytes of `kdf("state", dedup secret, AK || 0 ||
/// state bytes)` (spec/permissions.md §4).
pub fn state_digest(dedup: &Secret32, ak: &str, state: &[u8]) -> [u8; 16] {
    let h = kdf(kdf::STATE, dedup.expose(), &[ak.as_bytes(), &[0], state].concat());
    let mut out = [0u8; 16];
    out.copy_from_slice(&h.expose()[..16]);
    out
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
    // role; a plain thing's secrets differ per tid and role.
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

    // spec/crypto.md §3: an inner signature opens only under its epoch's inner secret and
    // commit, and verifies only under its node's key.
    #[test]
    fn inner_signature_spec_crypto_3() {
        let e = AccountEpochKeys::from_seed(&Secret32::from_bytes([3; 32]));
        let node = KeyActorKeys::from_seed(&Secret32::from_bytes([4; 32]));
        let (t, c) = (Tid::from_bytes([9; 15]), [6u8; 32]);
        let sealed = seal_inner(&e.inner, &c, &t, &node.signing);
        assert_eq!(sealed.len(), 95);
        let (got, sig) = open_inner(&e.inner, &c, &sealed).expect("opens");
        assert_eq!(got, t);
        assert!(verify_inner(&node.signing.verifying_key(), &c, &sig));
        assert!(!verify_inner(&e.signing.verifying_key(), &c, &sig), "another key");
        assert!(open_inner(&e.inner, &[7; 32], &sealed).is_none(), "another commit");
        let other = AccountEpochKeys::from_seed(&Secret32::from_bytes([5; 32]));
        assert!(open_inner(&other.inner, &c, &sealed).is_none(), "another epoch");
        assert_eq!(e.signing.verifying_key(), KeyActorKeys::from_seed(&Secret32::from_bytes([3; 32])).signing.verifying_key());
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
