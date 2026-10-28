//! Label keys, label ID, claim keys, static entries and the open signature (spec/sync.md §2, §5,
//! spec/wire.md §8, §11.2).

use crate::kdf::{self, LABEL_ID, STATIC_CLAIM, kdf};
use crate::{Domain, Error, Secret32, Signature, SigningSecret, VerifyingKey, X25519Secret};
use osis_base::{LabelId, Value, encode};

/// A label role key and the group role secret it derives from.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum LabelRole {
    /// From the read secret.
    Sync,
    /// From the write secret.
    Write,
    /// From the admin secret.
    Delete,
}

/// `kdf("label <role>", secret, le64(index))` as an Ed25519 seed.
pub fn label_role_key(role: LabelRole, secret: &Secret32, index: u64) -> SigningSecret {
    let purpose = match role {
        LabelRole::Sync => kdf::LABEL_SYNC,
        LabelRole::Write => kdf::LABEL_WRITE,
        LabelRole::Delete => kdf::LABEL_DELETE,
    };
    SigningSecret::from_seed(&kdf(purpose, secret.expose(), &index.to_le_bytes()))
}

/// Deposit key `kdf("label deposit", deposit seed, label ID)`.
pub fn deposit_key(deposit_seed: &Secret32, label: &LabelId) -> SigningSecret {
    SigningSecret::from_seed(&kdf(kdf::LABEL_DEPOSIT, deposit_seed.expose(), &label.0))
}

/// Label ID = BLAKE3("osis v1 label id" || genesis delete key)[..16].
pub fn label_id(genesis_delete: &VerifyingKey) -> LabelId {
    let mut h = blake3::Hasher::new();
    h.update(LABEL_ID.as_bytes()).update(&genesis_delete.to_bytes());
    let mut id = [0u8; 16];
    id.copy_from_slice(h.finalize().as_bytes().get(..16).unwrap_or(&[0; 16]));
    LabelId(id)
}

/// Claim key pair: seed `kdf("label claim", DH(own, their), label_id || step_key)`. The registrar
/// passes the step private key and M's X25519 key; M passes its private key and the step key.
/// A non-contributory DH omits M.
pub fn claim_key(own: &X25519Secret, their: &[u8; 32], label: &LabelId, step_key: &[u8; 32]) -> Result<SigningSecret, Error> {
    let dh = own.dh(their)?;
    let mut input = Vec::with_capacity(48);
    input.extend_from_slice(&label.0);
    input.extend_from_slice(step_key);
    Ok(SigningSecret::from_seed(&kdf(kdf::LABEL_CLAIM, dh.expose(), &input)))
}

/// Static entry of a key actor: BLAKE3("osis v1 static claim" || label ID || signing key).
pub fn static_entry(label: &LabelId, signing: &VerifyingKey) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(STATIC_CLAIM.as_bytes()).update(&label.0).update(&signing.to_bytes());
    *h.finalize().as_bytes()
}

/// Digest of an open: BLAKE3(canonical `[label_id, challenge, static_key]`) (spec/wire.md §11.2).
pub fn open_digest(label: &LabelId, challenge: &[u8; 32], static_key: &[u8; 32]) -> [u8; 32] {
    let v = Value::List(vec![Value::Bytes(label.0.to_vec()), Value::Bytes(challenge.to_vec()), Value::Bytes(static_key.to_vec())]);
    *blake3::hash(&encode(&v)).as_bytes()
}

/// Open signature under `"osis v1 label open"` with the opened side's challenge and static key.
pub fn sign_open(key: &SigningSecret, label: &LabelId, challenge: &[u8; 32], static_key: &[u8; 32]) -> Signature {
    key.sign(Domain::LabelOpen, &open_digest(label, challenge, static_key))
}

pub fn verify_open(key: &VerifyingKey, label: &LabelId, challenge: &[u8; 32], static_key: &[u8; 32], sig: &Signature) -> Result<(), Error> {
    key.verify(Domain::LabelOpen, &open_digest(label, challenge, static_key), sig)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{KeyActorKeys, SeededRng};

    // spec/sync.md §2: role keys differ per role, secret and index; deposit keys per label.
    #[test]
    fn role_keys() {
        let s = Secret32::from_bytes([9; 32]);
        let pk = |r, i| label_role_key(r, &s, i).verifying_key();
        assert_ne!(pk(LabelRole::Sync, 0), pk(LabelRole::Sync, 1));
        assert_ne!(pk(LabelRole::Sync, 0), pk(LabelRole::Write, 0));
        assert_ne!(pk(LabelRole::Delete, 0), pk(LabelRole::Write, 0));
        let expect = SigningSecret::from_seed(&kdf("label delete", &[9; 32], &1u64.to_le_bytes()));
        assert_eq!(pk(LabelRole::Delete, 1), expect.verifying_key());
        let seed = Secret32::from_bytes([1; 32]);
        assert_ne!(deposit_key(&seed, &LabelId([1; 16])).verifying_key(), deposit_key(&seed, &LabelId([2; 16])).verifying_key());
        let id = label_id(&pk(LabelRole::Delete, 0));
        let mut h = blake3::Hasher::new();
        h.update(b"osis v1 label id").update(&pk(LabelRole::Delete, 0).to_bytes());
        assert_eq!(id.0, h.finalize().as_bytes()[..16]);
    }

    // spec/sync.md §2: registrar and member derive the same claim key; non-contributory omits.
    #[test]
    fn claim_keys() {
        let mut rng = SeededRng::from_u64(5);
        let step = X25519Secret::random(&mut rng);
        let m = KeyActorKeys::from_seed(&Secret32::from_bytes([6; 32]));
        let label = LabelId([7; 16]);
        let by_registrar = claim_key(&step, &m.kem.public().x25519(), &label, &step.public()).unwrap();
        let by_member = claim_key(m.kem.x25519(), &step.public(), &label, &step.public()).unwrap();
        assert_eq!(by_registrar.verifying_key(), by_member.verifying_key());
        let other = claim_key(&step, &m.kem.public().x25519(), &LabelId([8; 16]), &step.public()).unwrap();
        assert_ne!(other.verifying_key(), by_member.verifying_key());
        assert_eq!(claim_key(&step, &[0; 32], &label, &step.public()).err(), Some(Error::NonContributory));
        let e = static_entry(&label, &m.signing.verifying_key());
        assert_ne!(e, static_entry(&LabelId([8; 16]), &m.signing.verifying_key()));
    }

    // spec/wire.md §11.2: an open signature binds label, challenge and static key.
    #[test]
    fn open_signature() {
        let k = label_role_key(LabelRole::Sync, &Secret32::from_bytes([1; 32]), 0);
        let (l, c, s) = (LabelId([1; 16]), [2; 32], [3; 32]);
        let sig = sign_open(&k, &l, &c, &s);
        let pk = k.verifying_key();
        assert_eq!(verify_open(&pk, &l, &c, &s, &sig), Ok(()));
        assert!(verify_open(&pk, &LabelId([9; 16]), &c, &s, &sig).is_err());
        assert!(verify_open(&pk, &l, &[9; 32], &s, &sig).is_err());
        assert!(verify_open(&pk, &l, &c, &[9; 32], &sig).is_err());
        assert!(pk.verify(Domain::Upload, &open_digest(&l, &c, &s), &sig).is_err());
    }
}
