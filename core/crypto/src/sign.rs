//! Ed25519 with strict verification over `domain || digest` (spec/crypto.md §1, §2).
//! No batch verification: single verification is the only one, so the two trivially agree.

use crate::{Error, Secret32, agility_bytes, agility_value};
use osis_base::Value;
use std::fmt;

/// Signature domains, one per signed object (spec/crypto.md §2).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Domain {
    Commit,
    Signal,
    SignalPublish,
    LabelRegister,
    LabelOpen,
    Upload,
    Deposit,
    Delete,
    /// A LAN announcement, by a dialable key (spec/sync.md §10).
    LanAnnounce,
    /// A member node's open at a member peer, by its dialable key (spec/sync.md §5).
    MemberOpen,
}

impl Domain {
    pub const ALL: [Domain; 10] = [
        Domain::Commit,
        Domain::Signal,
        Domain::SignalPublish,
        Domain::LabelRegister,
        Domain::LabelOpen,
        Domain::Upload,
        Domain::Deposit,
        Domain::Delete,
        Domain::LanAnnounce,
        Domain::MemberOpen,
    ];
    pub const fn as_str(self) -> &'static str {
        match self {
            Domain::Commit => "osis v1 commit",
            Domain::Signal => "osis v1 signal",
            Domain::SignalPublish => "osis v1 signal publish",
            Domain::LabelRegister => "osis v1 label register",
            Domain::LabelOpen => "osis v1 label open",
            Domain::Upload => "osis v1 upload",
            Domain::Deposit => "osis v1 deposit",
            Domain::Delete => "osis v1 delete",
            Domain::LanAnnounce => "osis v1 lan announce",
            Domain::MemberOpen => "osis v1 member open",
        }
    }
    fn message(self, digest: &[u8; 32]) -> Vec<u8> {
        let mut m = Vec::with_capacity(self.as_str().len() + 32);
        m.extend_from_slice(self.as_str().as_bytes());
        m.extend_from_slice(digest);
        m
    }
}

/// Ed25519 private key from a 32-byte seed. Zeroized on drop; `Debug` redacted.
#[derive(Clone)]
pub struct SigningSecret(ed25519_dalek::SigningKey);

impl SigningSecret {
    /// RFC 8032 key from its 32-byte seed (spec/wire.md §8: role keys are seeded by a kdf output).
    pub fn from_seed(seed: &Secret32) -> SigningSecret {
        SigningSecret(ed25519_dalek::SigningKey::from_bytes(seed.expose()))
    }
    pub fn verifying_key(&self) -> VerifyingKey {
        VerifyingKey(self.0.verifying_key())
    }
    /// Signs `domain || digest`.
    pub fn sign(&self, domain: Domain, digest: &[u8; 32]) -> Signature {
        use ed25519_dalek::Signer;
        Signature(self.0.sign(&domain.message(digest)).to_bytes())
    }
}

impl fmt::Debug for SigningSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SigningSecret({:?})", self.verifying_key())
    }
}

/// Ed25519 public key, canonically encoded and not of small order. The agility enum
/// `signing_key` case 1 (spec/wire.md §3).
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct VerifyingKey(pub(crate) ed25519_dalek::VerifyingKey);

impl VerifyingKey {
    /// Rejects non-canonical encodings and small-order points (spec/crypto.md §1).
    pub fn from_bytes(b: &[u8; 32]) -> Result<VerifyingKey, Error> {
        let k = ed25519_dalek::VerifyingKey::from_bytes(b).map_err(|_| Error::BadKey)?;
        if k.is_weak() || k.to_edwards().compress().to_bytes() != *b {
            return Err(Error::BadKey);
        }
        Ok(VerifyingKey(k))
    }
    pub fn from_slice(b: &[u8]) -> Result<VerifyingKey, Error> {
        VerifyingKey::from_bytes(b.try_into().map_err(|_| Error::BadKey)?)
    }
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }
    /// Strict verification of `sig` over `domain || digest`.
    pub fn verify(&self, domain: Domain, digest: &[u8; 32], sig: &Signature) -> Result<(), Error> {
        let s = ed25519_dalek::Signature::from_bytes(&sig.0);
        self.0.verify_strict(&domain.message(digest), &s).map_err(|_| Error::BadSignature)
    }
    /// `1617([1, h'pk'])`.
    pub fn to_value(&self) -> Value {
        agility_value(&self.to_bytes())
    }
    pub fn from_value(v: &Value) -> Result<VerifyingKey, Error> {
        VerifyingKey::from_slice(agility_bytes(v, Some(32))?)
    }
}

impl fmt::Debug for VerifyingKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "VerifyingKey(")?;
        for b in self.0.as_bytes().iter().take(8) {
            write!(f, "{b:02x}")?;
        }
        write!(f, "..)")
    }
}

/// Raw 64-byte Ed25519 signature; the agility enum `signature` case 1 (spec/wire.md §3).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Signature(pub [u8; 64]);

impl Signature {
    pub fn from_slice(b: &[u8]) -> Result<Signature, Error> {
        Ok(Signature(b.try_into().map_err(|_| Error::Malformed("signature length"))?))
    }
    pub fn to_value(&self) -> Value {
        agility_value(&self.0)
    }
    pub fn from_value(v: &Value) -> Result<Signature, Error> {
        Signature::from_slice(agility_bytes(v, Some(64))?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use osis_base::Classified;

    fn hex<const N: usize>(s: &str) -> [u8; N] {
        osis_base::hex::decode(s).unwrap().try_into().unwrap()
    }

    // spec/crypto.md §1: Ed25519 is RFC 8032 (test 1 of §7.1: empty message).
    #[test]
    fn rfc8032_known_answer() {
        use ed25519_dalek::Signer;
        let seed: [u8; 32] = hex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
        let sk = SigningSecret::from_seed(&Secret32::from_bytes(seed));
        let pk: [u8; 32] = hex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
        assert_eq!(sk.verifying_key().to_bytes(), pk);
        let sig: [u8; 64] = hex(concat!(
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155",
            "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
        ));
        assert_eq!(sk.0.sign(b"").to_bytes(), sig);
    }

    // spec/crypto.md §2: a signature verifies under its own domain only.
    #[test]
    fn domain_separation() {
        let sk = SigningSecret::from_seed(&Secret32::from_bytes([5; 32]));
        let pk = sk.verifying_key();
        let digest = [9u8; 32];
        for d in Domain::ALL {
            let sig = sk.sign(d, &digest);
            for e in Domain::ALL {
                assert_eq!(pk.verify(e, &digest, &sig).is_ok(), d == e, "{d:?} {e:?}");
            }
            assert_eq!(pk.verify(d, &[8; 32], &sig), Err(Error::BadSignature));
        }
    }

    // spec/crypto.md §1: strict verification rejects small-order and non-canonical keys and a
    // non-canonical s.
    #[test]
    fn strict_rejections() {
        let identity: [u8; 32] = hex("0100000000000000000000000000000000000000000000000000000000000000");
        assert_eq!(VerifyingKey::from_bytes(&identity), Err(Error::BadKey));
        // y = p + k encodes y = k non-canonically; reject those dalek alone would accept.
        let mut seen = 0;
        for k in 2u8..=18 {
            let mut b = [0xffu8; 32];
            b[0] = 0xed + k;
            b[31] = 0x7f;
            if let Ok(d) = ed25519_dalek::VerifyingKey::from_bytes(&b)
                && !d.is_weak()
            {
                seen += 1;
                assert_eq!(VerifyingKey::from_bytes(&b), Err(Error::BadKey));
            }
        }
        assert!(seen > 0);
        let sk = SigningSecret::from_seed(&Secret32::from_bytes([5; 32]));
        let pk = sk.verifying_key();
        let digest = [1u8; 32];
        let mut sig = sk.sign(Domain::Commit, &digest);
        // s + l is a non-canonical scalar for the same signature.
        let l: [u8; 32] = hex("edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010");
        let mut carry = 0u16;
        for (i, li) in l.iter().enumerate() {
            let v = u16::from(sig.0[32 + i]) + u16::from(*li) + carry;
            sig.0[32 + i] = v as u8;
            carry = v >> 8;
        }
        assert_eq!(pk.verify(Domain::Commit, &digest, &sig), Err(Error::BadSignature));
    }

    // spec/wire.md §3: signing_key and signature are enum values; another case parks.
    #[test]
    fn agility_values() {
        let sk = SigningSecret::from_seed(&Secret32::from_bytes([5; 32]));
        let pk = sk.verifying_key();
        let [_, _, _, _, _, _, hi, lo] = osis_base::format::TAG_ENUM.to_be_bytes();
        assert_eq!(osis_base::encode(&pk.to_value())[..5], [0xd9, hi, lo, 0x82, 0x01]);
        assert_eq!(VerifyingKey::from_value(&pk.to_value()), Ok(pk));
        let sig = sk.sign(Domain::Upload, &[0; 32]);
        assert_eq!(Signature::from_value(&sig.to_value()), Ok(sig));
        let other = Value::Enum(2, Some(Box::new(Value::Bytes(vec![0; 32]))));
        let e = VerifyingKey::from_value(&other).unwrap_err();
        assert_eq!((e, e.class()), (Error::UnknownCase(2), osis_base::ErrorClass::Parked));
        assert!(Signature::from_value(&pk.to_value()).is_err());
    }

    // spec: none (notes/architecture.md §3: Debug of a private key shows only the public half)
    #[test]
    fn debug_redacted() {
        let sk = SigningSecret::from_seed(&Secret32::from_bytes([0xab; 32]));
        assert!(!format!("{sk:?}").contains("abab"));
    }
}
