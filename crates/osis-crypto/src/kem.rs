//! X25519, ML-KEM-768 (FIPS 203, libcrux-ml-kem) and their hybrid key pair (spec/crypto.md §1, §3).

use crate::kdf::{KEM, kdf_xof};
use crate::{Error, Secret32, agility_bytes, agility_value};
use libcrux_ml_kem::mlkem768;
use osis_core::Value;
use rand_core::CryptoRngCore;
use std::fmt;
use zeroize::Zeroize;

const MLKEM_PK_LEN: usize = 1184;
const MLKEM_SK_LEN: usize = 2400;
/// ML-KEM-768 ciphertext.
pub const MLKEM_CT_LEN: usize = 1088;
/// `pk_x || pk_m` (spec/crypto.md §1).
pub const KEM_PUBLIC_LEN: usize = 32 + MLKEM_PK_LEN;

/// X25519 private key. Zeroized on drop; `Debug` redacted.
#[derive(Clone)]
pub struct X25519Secret(x25519_dalek::StaticSecret);

impl X25519Secret {
    pub fn from_secret(s: &Secret32) -> X25519Secret {
        X25519Secret(x25519_dalek::StaticSecret::from(*s.expose()))
    }
    /// A fresh key (a step key, an ephemeral key).
    pub fn random(rng: &mut dyn CryptoRngCore) -> X25519Secret {
        X25519Secret::from_secret(&Secret32::random(rng))
    }
    pub fn public(&self) -> [u8; 32] {
        x25519_dalek::PublicKey::from(&self.0).to_bytes()
    }
    /// Shared secret; a non-contributory (all-zero) result is rejected (spec/crypto.md §1).
    pub fn dh(&self, their: &[u8; 32]) -> Result<Secret32, Error> {
        let ss = self.0.diffie_hellman(&x25519_dalek::PublicKey::from(*their));
        if !ss.was_contributory() {
            return Err(Error::NonContributory);
        }
        Ok(Secret32::from_bytes(*ss.as_bytes()))
    }
}

impl fmt::Debug for X25519Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("X25519Secret(..)")
    }
}

/// Hybrid public key `pk_x || pk_m`, 1216 bytes, validated: the agility enum `kem_key` case 1.
#[derive(Clone, PartialEq, Eq)]
pub struct KemPublicKey(Box<[u8; KEM_PUBLIC_LEN]>);

impl KemPublicKey {
    /// Rejects a wrong length, a low-order X25519 half and an ML-KEM key failing the FIPS 203
    /// modulus check.
    pub fn from_slice(b: &[u8]) -> Result<KemPublicKey, Error> {
        let arr: [u8; KEM_PUBLIC_LEN] = b.try_into().map_err(|_| Error::BadKey)?;
        let k = KemPublicKey(Box::new(arr));
        // Any scalar exposes a low-order point: the clamped scalar is a multiple of the cofactor.
        X25519Secret::from_secret(&Secret32::from_bytes([1; 32])).dh(&k.x25519()).map_err(|_| Error::BadKey)?;
        if !mlkem768::validate_public_key(&k.mlkem()) {
            return Err(Error::BadKey);
        }
        Ok(k)
    }
    pub fn as_bytes(&self) -> &[u8; KEM_PUBLIC_LEN] {
        &self.0
    }
    /// The X25519 half: a key actor's or read role's claim key (spec/sync.md §2).
    pub fn x25519(&self) -> [u8; 32] {
        let mut x = [0u8; 32];
        x.copy_from_slice(self.0.get(..32).unwrap_or(&[0; 32]));
        x
    }
    pub(crate) fn mlkem(&self) -> mlkem768::MlKem768PublicKey {
        let mut m = [0u8; MLKEM_PK_LEN];
        m.copy_from_slice(self.0.get(32..).unwrap_or(&[0; MLKEM_PK_LEN]));
        m.into()
    }
    pub fn to_value(&self) -> Value {
        agility_value(&self.0[..])
    }
    pub fn from_value(v: &Value) -> Result<KemPublicKey, Error> {
        KemPublicKey::from_slice(agility_bytes(v, Some(KEM_PUBLIC_LEN))?)
    }
}

impl fmt::Debug for KemPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "KemPublicKey(")?;
        for b in self.0.iter().take(8) {
            write!(f, "{b:02x}")?;
        }
        write!(f, "..)")
    }
}

/// Hybrid KEM private key. Zeroized on drop; `Debug` shows the public key only.
#[derive(Clone)]
pub struct KemSecret {
    x: X25519Secret,
    m: MlKemSk,
    public: KemPublicKey,
}

#[derive(Clone)]
struct MlKemSk(Box<[u8; MLKEM_SK_LEN]>);

impl Drop for MlKemSk {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl KemSecret {
    /// Key pair from a seed or role secret: `kdf("kem", secret, "")` as 96 XOF bytes, the first
    /// 64 the ML-KEM-768 keygen seed `d || z`, the last 32 the X25519 private key (spec/crypto.md §3).
    pub fn derive(secret: &Secret32) -> KemSecret {
        let mut out = [0u8; 96];
        kdf_xof(KEM, secret.expose(), b"", &mut out);
        let (mut seed, mut x) = ([0u8; 64], [0u8; 32]);
        seed.copy_from_slice(out.get(..64).unwrap_or(&[0; 64]));
        x.copy_from_slice(out.get(64..).unwrap_or(&[0; 32]));
        out.zeroize();
        let k = KemSecret::from_parts(seed, &Secret32::from_bytes(x));
        seed.zeroize();
        x.zeroize();
        k
    }

    /// From the ML-KEM keygen seed `d || z` and the X25519 private key.
    pub fn from_parts(mlkem_seed: [u8; 64], x25519: &Secret32) -> KemSecret {
        let (sk, pk) = mlkem768::generate_key_pair(mlkem_seed).into_parts();
        let x = X25519Secret::from_secret(x25519);
        let mut public = Box::new([0u8; KEM_PUBLIC_LEN]);
        if let Some(dst) = public.get_mut(..32) {
            dst.copy_from_slice(&x.public());
        }
        if let Some(dst) = public.get_mut(32..) {
            dst.copy_from_slice(pk.as_slice());
        }
        let mut skb: [u8; MLKEM_SK_LEN] = sk.into();
        let m = MlKemSk(Box::new(skb));
        skb.zeroize();
        KemSecret { x, m, public: KemPublicKey(public) }
    }

    pub fn public(&self) -> &KemPublicKey {
        &self.public
    }
    /// The X25519 half: claim key DH (spec/sync.md §2).
    pub fn x25519(&self) -> &X25519Secret {
        &self.x
    }
    pub(crate) fn decapsulate(&self, ct: &[u8; MLKEM_CT_LEN]) -> Secret32 {
        let sk = mlkem768::MlKem768PrivateKey::from(&*self.m.0);
        let ss = mlkem768::decapsulate(&sk, &(*ct).into());
        let mut back: [u8; MLKEM_SK_LEN] = sk.into();
        back.zeroize();
        Secret32::from_bytes(ss)
    }
}

impl fmt::Debug for KemSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "KemSecret({:?})", self.public)
    }
}

/// ML-KEM encapsulation with explicit randomness: `(ct_m, ss_m)`.
pub(crate) fn encapsulate(pk: &KemPublicKey, m: &[u8; 32]) -> ([u8; MLKEM_CT_LEN], Secret32) {
    let (ct, ss) = mlkem768::encapsulate(&pk.mlkem(), *m);
    (*ct.as_slice(), Secret32::from_bytes(ss))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex<const N: usize>(s: &str) -> [u8; N] {
        let v: Vec<u8> = (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect();
        v.try_into().unwrap()
    }

    // spec/crypto.md §1: X25519 is RFC 7748 (§6.1 Diffie-Hellman example).
    #[test]
    fn rfc7748_known_answer() {
        let a = X25519Secret::from_secret(&Secret32::from_bytes(hex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")));
        let b = X25519Secret::from_secret(&Secret32::from_bytes(hex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")));
        assert_eq!(a.public(), hex::<32>("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"));
        assert_eq!(b.public(), hex::<32>("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"));
        let shared: [u8; 32] = hex("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");
        assert_eq!(*a.dh(&b.public()).unwrap().expose(), shared);
        assert_eq!(*b.dh(&a.public()).unwrap().expose(), shared);
    }

    // spec/crypto.md §1: a non-contributory X25519 result is rejected.
    #[test]
    fn non_contributory_rejected() {
        let a = X25519Secret::from_secret(&Secret32::from_bytes([7; 32]));
        assert_eq!(a.dh(&[0; 32]), Err(Error::NonContributory));
        let one: [u8; 32] = hex("0100000000000000000000000000000000000000000000000000000000000000");
        assert_eq!(a.dh(&one), Err(Error::NonContributory));
    }

    // spec/crypto.md §3: deterministic ML-KEM keygen from d || z. Cross-checked against the
    // RustCrypto ml-kem 0.3.2 crate (from_seed, encapsulate_deterministic) when the crate was chosen.
    #[test]
    fn mlkem_keygen_known_answer() {
        let k = KemSecret::from_parts([0x42; 64], &Secret32::from_bytes([0x43; 32]));
        let pk_m = &k.public().as_bytes()[32..];
        assert_eq!(pk_m.len(), MLKEM_PK_LEN);
        assert_eq!(blake3::hash(pk_m).to_hex().as_str(), MLKEM_PK_HASH);
        let (ct, ss) = encapsulate(k.public(), &[0x44; 32]);
        assert_eq!(blake3::hash(&ct).to_hex().as_str(), "ad1edbb53598d1667d505bf2f5b12ff058f932a60487ce4dd752ae29e7f79a62");
        assert_eq!(blake3::hash(ss.expose()).to_hex().as_str(), "f60dbed41561aab49b81770d266860aefa52ac4dab9e9b4e7c0935705ae8b521");
        assert_eq!(k.decapsulate(&ct), ss);
        assert_eq!(KemPublicKey::from_slice(k.public().as_bytes()), Ok(k.public().clone()));
    }
    const MLKEM_PK_HASH: &str = "fa88246c20b3b266f6dd762098c644f8758af78f1214964c87e50ac969082eb3";

    // spec/crypto.md §1, §3: keys that fail validation are rejected at parse.
    #[test]
    fn kem_public_rejections() {
        let k = KemSecret::derive(&Secret32::from_bytes([1; 32]));
        let good = k.public().as_bytes().to_vec();
        assert!(KemPublicKey::from_slice(&good[..100]).is_err());
        let mut low = good.clone();
        low[..32].copy_from_slice(&[0; 32]);
        assert_eq!(KemPublicKey::from_slice(&low), Err(Error::BadKey));
        let mut big = good.clone();
        big[32] = 0xff;
        big[33] |= 0x0f; // first 12-bit coefficient = 4095 >= q
        assert_eq!(KemPublicKey::from_slice(&big), Err(Error::BadKey));
        assert_eq!(KemPublicKey::from_value(&k.public().to_value()), Ok(k.public().clone()));
    }

    // notes/architecture.md §3: Debug of secrets redacted.
    #[test]
    fn debug_redacted() {
        let k = KemSecret::derive(&Secret32::from_bytes([1; 32]));
        let d = format!("{k:?} {:?}", k.x25519());
        assert!(d.starts_with("KemSecret(KemPublicKey(") && d.ends_with("X25519Secret(..)"), "{d}");
    }
}
