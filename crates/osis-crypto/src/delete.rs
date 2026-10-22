//! Delete keys and their blinded prefix commitments (spec/crypto.md §7).

use crate::kdf::{self, kdf, kdf_xof};
use crate::{Domain, Secret32, Signature, VerifyingKey};
use curve25519_dalek::Scalar;
use ed25519_dalek::hazmat::{ExpandedSecretKey, raw_sign};
use ed25519_dalek::Sha512;

/// A delete key: the Ed25519 key seeded by `kdf("delete key", secret)` of a role secret, or a key
/// actor's signing key. Signs only under a blob's blinded key. Zeroized on drop; `Debug` redacted.
pub struct DeleteSecret {
    seed: Secret32,
    esk: ExpandedSecretKey,
}

impl DeleteSecret {
    pub fn derive(secret: &Secret32) -> DeleteSecret {
        DeleteSecret::from_seed(kdf(kdf::DELETE_KEY, secret.expose(), b""))
    }

    /// From an Ed25519 seed (a key actor's signing seed `kdf("sign", seed)`, spec/crypto.md §3).
    pub fn from_seed(seed: Secret32) -> DeleteSecret {
        let esk = ExpandedSecretKey::from(seed.expose());
        DeleteSecret { seed, esk }
    }

    /// The Ed25519 seed.
    pub fn seed(&self) -> &Secret32 {
        &self.seed
    }

    /// The delete verification key, listed in headers and published in `/keys`.
    pub fn verifying_key(&self) -> VerifyingKey {
        VerifyingKey(ed25519_dalek::VerifyingKey::from(&self.esk))
    }

    /// Signs `"osis v1 delete" || digest` under the key blinded by the prefix `salt` and the
    /// header's `hb` (the commitment's key, [`blind`]): scalar `h·a mod ℓ`, nonce prefix
    /// `kdf("delete nonce", seed, salt || hb)`.
    pub fn sign(&self, salt: &[u8; 16], hb: &[u8; 16], digest: &[u8; 32]) -> Signature {
        let h = factor(&self.verifying_key(), salt, hb);
        let blinded = ExpandedSecretKey { scalar: h * self.esk.scalar, hash_prefix: *kdf(kdf::DELETE_NONCE, self.seed.expose(), &cat(salt, hb)).expose() };
        let vk = ed25519_dalek::VerifyingKey::from(&blinded);
        let mut m = Vec::with_capacity(Domain::Delete.as_str().len() + 32);
        m.extend_from_slice(Domain::Delete.as_str().as_bytes());
        m.extend_from_slice(digest);
        Signature(raw_sign::<Sha512>(&blinded, &m, &vk).to_bytes())
    }
}

impl std::fmt::Debug for DeleteSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "DeleteSecret({:?})", self.verifying_key())
    }
}

fn cat(salt: &[u8; 16], hb: &[u8; 16]) -> [u8; 32] {
    let mut x = [0u8; 32];
    x[..16].copy_from_slice(salt);
    x[16..].copy_from_slice(hb);
    x
}

/// Blinding factor h = `kdf("delete blind", vk, salt || hb)` read as 64 XOF bytes,
/// little-endian, mod ℓ.
fn factor(vk: &VerifyingKey, salt: &[u8; 16], hb: &[u8; 16]) -> Scalar {
    let mut wide = [0u8; 64];
    kdf_xof(kdf::DELETE_BLIND, &vk.to_bytes(), &cat(salt, hb), &mut wide);
    Scalar::from_bytes_mod_order_wide(&wide)
}

/// The blinded key `h·A` a blob prefix commits to for delete key `vk` under prefix `salt` and
/// the header's blind `hb`: computable only by readers of the header (who hold `vk` and `hb`),
/// unlinkable to `vk` without `hb`.
pub fn blind(vk: &VerifyingKey, salt: &[u8; 16], hb: &[u8; 16]) -> VerifyingKey {
    let p = factor(vk, salt, hb) * vk.0.to_edwards();
    VerifyingKey(ed25519_dalek::VerifyingKey::from(p))
}

/// Prefix commitment `level || blind(vk, salt, hb)`; level 1..=3.
pub fn commitment(level: u8, vk: &VerifyingKey, salt: &[u8; 16], hb: &[u8; 16]) -> Result<[u8; 33], crate::Error> {
    if !(1..=3).contains(&level) {
        return Err(crate::Error::Malformed("delete level"));
    }
    let mut c = [level; 33];
    if let Some(dst) = c.get_mut(1..) {
        dst.copy_from_slice(&blind(vk, salt, hb).to_bytes());
    }
    Ok(c)
}

/// Checks a delete signature against a commitment's 32-byte key (strict verification; an
/// invalid key fails).
pub fn verify_delete(key: &[u8; 32], digest: &[u8; 32], sig: &Signature) -> Result<(), crate::Error> {
    VerifyingKey::from_bytes(key)?.verify(Domain::Delete, digest, sig)
}

#[cfg(test)]
mod tests {
    use super::*;

    // spec/crypto.md §7: a delete signature verifies only under its blob's blinded key; blinded
    // keys of one key under two salts or two header blinds differ and differ from the key.
    #[test]
    fn blinded_signatures() {
        let k = DeleteSecret::derive(&Secret32::from_bytes([1; 32]));
        let vk = k.verifying_key();
        let (s1, s2, hb, hb2) = ([2u8; 16], [3u8; 16], [5u8; 16], [6u8; 16]);
        let (b1, b2, b3) = (blind(&vk, &s1, &hb), blind(&vk, &s2, &hb), blind(&vk, &s1, &hb2));
        assert!(b1 != b2 && b1 != b3 && b1 != vk);
        let d = [9u8; 32];
        let sig = k.sign(&s1, &hb, &d);
        verify_delete(&b1.to_bytes(), &d, &sig).unwrap();
        assert!(verify_delete(&b2.to_bytes(), &d, &sig).is_err());
        assert!(verify_delete(&b3.to_bytes(), &d, &sig).is_err());
        assert!(verify_delete(&vk.to_bytes(), &d, &sig).is_err());
        assert!(verify_delete(&b1.to_bytes(), &[8; 32], &sig).is_err());
        // another key's signature fails
        let other = DeleteSecret::derive(&Secret32::from_bytes([4; 32]));
        assert!(verify_delete(&b1.to_bytes(), &d, &other.sign(&s1, &hb, &d)).is_err());
        // deterministic; another salt or blind gives another nonce
        assert_eq!(k.sign(&s1, &hb, &d), sig);
        assert_ne!(k.sign(&s2, &hb, &d).0[..32], sig.0[..32]);
        assert_ne!(k.sign(&s1, &hb2, &d).0[..32], sig.0[..32]);
        // a plain signature by the unblinded key does not verify as a delete
        let c = commitment(2, &vk, &s1, &hb).unwrap();
        assert_eq!((c[0], &c[1..]), (2, &b1.to_bytes()[..]));
        assert!(commitment(0, &vk, &s1, &hb).is_err() && commitment(4, &vk, &s1, &hb).is_err());
        assert_eq!(format!("{k:?}"), format!("DeleteSecret({vk:?})"));
    }
}
