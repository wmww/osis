//! Key derivations per actor kind (spec/crypto.md §3) and keyed content hashes (§6).

use crate::kdf::{self, DEDUP, kdf};
use crate::{Domain, KemSecret, Secret32, Signature, SigningSecret, VerifyingKey};
use osis_core::{Role, Tid};

/// A key actor's keys (node, recovery key, link key), all from its 32-byte seed.
#[derive(Clone, Debug)]
pub struct KeyActorKeys {
    /// From `kdf("sign", seed)`; the creation record commits to its public key.
    pub signing: SigningSecret,
    /// From `kdf("kem", seed)`; its X25519 half is the claim key.
    pub kem: KemSecret,
}

impl KeyActorKeys {
    pub fn from_seed(seed: &Secret32) -> KeyActorKeys {
        let signing = SigningSecret::from_seed(&kdf(kdf::SIGN, seed.expose(), b""));
        KeyActorKeys { signing, kem: KemSecret::derive(seed) }
    }
}

/// A key actor's role secret `kdf("role <role>", seed)`, never rotated.
pub fn key_actor_role_secret(seed: &Secret32, role: Role) -> Secret32 {
    kdf(kdf::role_purpose(role), seed.expose(), b"")
}

/// A plain thing's role secret `kdf("thing <role>", owner's secret, tid)`.
pub fn thing_role_secret(owner_secret: &Secret32, role: Role, tid: &Tid) -> Secret32 {
    kdf(kdf::thing_purpose(role), owner_secret.expose(), tid.as_bytes())
}

/// A role's KEM key pair of one epoch, `kdf("kem", role secret)` (actors other than key actors).
pub fn role_kem(role_secret: &Secret32) -> KemSecret {
    KemSecret::derive(role_secret)
}

/// Creation nonce of a link or recovery key, `kdf("creation nonce", seed, "")` (spec/wire.md §3).
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

/// LAN discovery tag: first 16 bytes of `kdf("lan tag", lan secret, le64(window))`, window =
/// floor(unix ms / 600000) (spec/sync.md §10).
pub fn lan_tag(lan_secret: &Secret32, unix_ms: u64) -> [u8; 16] {
    let full = kdf(kdf::LAN_TAG, lan_secret.expose(), &(unix_ms / 600_000).to_le_bytes());
    let mut t = [0u8; 16];
    t.copy_from_slice(full.expose().get(..16).unwrap_or(&[0; 16]));
    t
}

/// What a LAN announcement's signature covers: BLAKE3(tag (16) || key (32) || be16(port))
/// (spec/sync.md §10).
pub fn lan_digest(tag: &[u8; 16], key: &[u8; 32], port: u16) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(tag);
    h.update(key);
    h.update(&port.to_be_bytes());
    h.finalize().into()
}

/// The 64-byte keystream hiding a LAN announcement's signature: `kdf("lan sig", lan secret,
/// le64(window) || digest)` in the XOF form, `digest` = `lan_digest` (spec/sync.md §10), so
/// another key or port in the same window never reuses it.
pub fn lan_keystream(lan_secret: &Secret32, window: u64, digest: &[u8; 32]) -> [u8; 64] {
    let mut input = [0u8; 40];
    let (w, d) = input.split_at_mut(8);
    w.copy_from_slice(&window.to_le_bytes());
    d.copy_from_slice(digest);
    let mut k = [0u8; 64];
    crate::kdf::kdf_xof(kdf::LAN_SIG, lan_secret.expose(), &input, &mut k);
    k
}

fn xor64(a: &[u8; 64], b: &[u8; 64]) -> [u8; 64] {
    let mut out = [0u8; 64];
    for ((o, x), y) in out.iter_mut().zip(a).zip(b) {
        *o = x ^ y;
    }
    out
}

/// A LAN announcement's sealed signature (spec/sync.md §10): the Ed25519 signature under the
/// dialable key over `"osis v1 lan announce"` and `lan_digest`, XORed with the window's
/// keystream, so checking it needs both the lan secret and the dialable key.
pub fn seal_lan_sig(dialable: &SigningSecret, lan_secret: &Secret32, window: u64, tag: &[u8; 16], key: &[u8; 32], port: u16) -> [u8; 64] {
    let digest = lan_digest(tag, key, port);
    let sig = dialable.sign(Domain::LanAnnounce, &digest);
    xor64(&sig.0, &lan_keystream(lan_secret, window, &digest))
}

/// Whether `sealed` is `seal_lan_sig` of these inputs under `dialable`'s key.
pub fn open_lan_sig(dialable: &VerifyingKey, lan_secret: &Secret32, window: u64, tag: &[u8; 16], key: &[u8; 32], port: u16, sealed: &[u8; 64]) -> bool {
    let digest = lan_digest(tag, key, port);
    let sig = Signature(xor64(sealed, &lan_keystream(lan_secret, window, &digest)));
    dialable.verify(Domain::LanAnnounce, &digest, &sig).is_ok()
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
        let s = Secret32::from_bytes([1; 32]);
        assert_eq!(lan_tag(&s, 0), lan_tag(&s, 599_999));
        assert_ne!(lan_tag(&s, 0), lan_tag(&s, 600_000));
    }

    // spec/sync.md §10: a sealed announcement signature opens only with the same lan secret,
    // window, dialable key and signed fields.
    #[test]
    fn lan_sig_sealed_spec_sync_10() {
        let d = SigningSecret::from_seed(&Secret32::from_bytes([8; 32]));
        let lan = Secret32::from_bytes([12; 32]);
        let (tag, key) = ([1u8; 16], [2u8; 32]);
        let sealed = seal_lan_sig(&d, &lan, 7, &tag, &key, 9);
        let vk = d.verifying_key();
        assert!(open_lan_sig(&vk, &lan, 7, &tag, &key, 9, &sealed));
        assert!(!open_lan_sig(&vk, &Secret32::from_bytes([13; 32]), 7, &tag, &key, 9, &sealed), "other lan secret");
        assert!(!open_lan_sig(&vk, &lan, 8, &tag, &key, 9, &sealed), "other window");
        assert!(!open_lan_sig(&vk, &lan, 7, &tag, &key, 10, &sealed), "other port");
        let other = SigningSecret::from_seed(&Secret32::from_bytes([9; 32])).verifying_key();
        assert!(!open_lan_sig(&other, &lan, 7, &tag, &key, 9, &sealed), "other dialable key");
        let plain = d.sign(Domain::LanAnnounce, &lan_digest(&tag, &key, 9));
        assert!(!open_lan_sig(&vk, &lan, 7, &tag, &key, 9, &plain.0), "unsealed");
    }
}
