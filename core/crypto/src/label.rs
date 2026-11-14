//! Label keys, label ID, claim keys, static entries and the open signature (spec/sync-ids.md §2, §3, spec/sync-opens.md §4,
//! spec/wire.md §8, §11.2).

use crate::kdf::{self, LABEL_ID, STATIC_CLAIM, kdf};
use crate::{Domain, Error, Secret32, Signature, SigningSecret, VerifyingKey, X25519Secret};
use osis_base::{LabelId, Role, Value, encode};

/// A label role key and the group role secret it derives from (`role`).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum LabelRole {
    /// From the sync secret.
    Sync,
    /// From the write secret.
    Write,
    /// From the admin secret.
    Delete,
}

impl LabelRole {
    pub const ALL: [LabelRole; 3] = [LabelRole::Sync, LabelRole::Write, LabelRole::Delete];

    /// The group role whose secret derives the key.
    pub fn role(self) -> Role {
        match self {
            LabelRole::Sync => Role::Sync,
            LabelRole::Write => Role::Write,
            LabelRole::Delete => Role::Admin,
        }
    }
}

/// `kdf("label <role>", secret, "")` as an Ed25519 seed.
pub fn label_role_key(role: LabelRole, secret: &Secret32) -> SigningSecret {
    SigningSecret::from_seed(&label_role_seed(role, secret))
}

/// The seed of `label_role_key`: `kdf("label <role>", secret, "")`. A sync key's seed is what its
/// proof derives from (`kdf::sync_proof`).
pub fn label_role_seed(role: LabelRole, secret: &Secret32) -> Secret32 {
    let purpose = match role {
        LabelRole::Sync => kdf::LABEL_SYNC,
        LabelRole::Write => kdf::LABEL_WRITE,
        LabelRole::Delete => kdf::LABEL_DELETE,
    };
    kdf(purpose, secret.expose(), &[])
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

/// Digest of an open: BLAKE3(canonical `[side, label_id, challenge, static_key]`) (spec/wire.md
/// §11.2), `side` the signer's (`by_listener`: 0 the dialer, 1 the listener), `challenge` the
/// other side's Hello challenge. Invariant, as for `proof_digest`: an open signature made as one
/// side verifies as no other, so a peer that copies this side's challenge into its own Hello
/// cannot offer a signature it was sent back as its own (model `ON_side`).
pub fn open_digest(by_listener: bool, label: &LabelId, challenge: &[u8; 32], static_key: &[u8; 32]) -> [u8; 32] {
    let v = Value::List(vec![Value::uint(u64::from(by_listener)), Value::Bytes(label.0.to_vec()), Value::Bytes(challenge.to_vec()), Value::Bytes(static_key.to_vec())]);
    *blake3::hash(&encode(&v)).as_bytes()
}

/// Digest of a connection proof (spec/wire.md §11.2): the prover's role, the verifier's Hello
/// challenge and the listener's static key. Invariant: a proof made as one role cannot be accepted
/// in the other, and is bound to one challenge and one listener; so a peer that chooses or echoes
/// a challenge gets no proof it can present as anyone but the prover, on any other connection.
pub fn proof_digest(by_listener: bool, challenge: &[u8; 32], listener_key: &[u8; 32]) -> [u8; 32] {
    let v = Value::List(vec![Value::uint(u64::from(by_listener)), Value::Bytes(challenge.to_vec()), Value::Bytes(listener_key.to_vec())]);
    *blake3::hash(&encode(&v)).as_bytes()
}

/// Open signature under `"osis v1 label open"` by the side `by_listener`, over the other side's
/// Hello challenge and the listener's static key.
pub fn sign_open(key: &SigningSecret, by_listener: bool, label: &LabelId, challenge: &[u8; 32], static_key: &[u8; 32]) -> Signature {
    key.sign(Domain::LabelOpen, &open_digest(by_listener, label, challenge, static_key))
}

/// Verifies an open signature as made by the side `by_listener` (the peer's, at the verifier).
pub fn verify_open(key: &VerifyingKey, by_listener: bool, label: &LabelId, challenge: &[u8; 32], static_key: &[u8; 32], sig: &Signature) -> Result<(), Error> {
    key.verify(Domain::LabelOpen, &open_digest(by_listener, label, challenge, static_key), sig)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{KeyActorKeys, SeededRng};

    // spec/sync-ids.md §2: role keys differ per role and secret; deposit keys per label.
    #[test]
    fn role_keys() {
        let s = Secret32::from_bytes([9; 32]);
        let pk = |r| label_role_key(r, &s).verifying_key();
        assert_ne!(pk(LabelRole::Sync), label_role_key(LabelRole::Sync, &Secret32::from_bytes([8; 32])).verifying_key());
        assert_ne!(pk(LabelRole::Sync), pk(LabelRole::Write));
        assert_ne!(pk(LabelRole::Delete), pk(LabelRole::Write));
        let expect = SigningSecret::from_seed(&kdf("label delete", &[9; 32], &[]));
        assert_eq!(pk(LabelRole::Delete), expect.verifying_key());
        let seed = Secret32::from_bytes([1; 32]);
        assert_ne!(deposit_key(&seed, &LabelId([1; 16])).verifying_key(), deposit_key(&seed, &LabelId([2; 16])).verifying_key());
        let id = label_id(&pk(LabelRole::Delete));
        let mut h = blake3::Hasher::new();
        h.update(b"osis v1 label id").update(&pk(LabelRole::Delete).to_bytes());
        assert_eq!(id.0, h.finalize().as_bytes()[..16]);
    }

    // spec/sync-ids.md §3: registrar and holder derive the same claim key; non-contributory omits.
    #[test]
    fn claim_keys() {
        let mut rng = SeededRng::from_u64(0);
        let step = X25519Secret::random(&mut rng);
        let m = KeyActorKeys::from_seed(&Secret32::from_bytes([6; 32]));
        let label = LabelId([7; 16]);
        let by_registrar = claim_key(&step, &m.kem.public().x25519(), &label, &step.public()).unwrap();
        let by_holder = claim_key(m.kem.x25519(), &step.public(), &label, &step.public()).unwrap();
        assert_eq!(by_registrar.verifying_key(), by_holder.verifying_key());
        let other = claim_key(&step, &m.kem.public().x25519(), &LabelId([8; 16]), &step.public()).unwrap();
        assert_ne!(other.verifying_key(), by_holder.verifying_key());
        assert_eq!(claim_key(&step, &[0; 32], &label, &step.public()).err(), Some(Error::NonContributory));
        let e = static_entry(&label, &m.signing.verifying_key());
        assert_ne!(e, static_entry(&LabelId([8; 16]), &m.signing.verifying_key()));
    }

    // spec/wire.md §11.2: an open signature binds label, challenge and static key.
    #[test]
    fn open_signature() {
        let k = label_role_key(LabelRole::Sync, &Secret32::from_bytes([1; 32]));
        let (l, c, s) = (LabelId([1; 16]), [2; 32], [3; 32]);
        let sig = sign_open(&k, false, &l, &c, &s);
        let pk = k.verifying_key();
        assert_eq!(verify_open(&pk, false, &l, &c, &s, &sig), Ok(()));
        assert!(verify_open(&pk, false, &LabelId([9; 16]), &c, &s, &sig).is_err());
        assert!(verify_open(&pk, false, &l, &[9; 32], &s, &sig).is_err());
        assert!(verify_open(&pk, false, &l, &c, &[9; 32], &sig).is_err());
        assert!(pk.verify(Domain::Stamp, &open_digest(false, &l, &c, &s), &sig).is_err());
        assert_eq!(label_role_key(LabelRole::Sync, &Secret32::from_bytes([1; 32])).verifying_key(), SigningSecret::from_seed(&label_role_seed(LabelRole::Sync, &Secret32::from_bytes([1; 32]))).verifying_key());
    }

    // spec/wire.md §11.2: an open signature binds its signer's side; one made by either side
    // verifies only as that side's, so a signature sent to a peer is no signature of the peer's
    // (on a connection whose challenges the peer copied, model `ON_side`).
    #[test]
    fn an_open_signature_binds_its_signers_side_spec_wire_11_2() {
        let k = label_role_key(LabelRole::Sync, &Secret32::from_bytes([1; 32]));
        let pk = k.verifying_key();
        let (l, c, s) = (LabelId([1; 16]), [2; 32], [3; 32]);
        for side in [false, true] {
            let sig = sign_open(&k, side, &l, &c, &s);
            assert_eq!(verify_open(&pk, side, &l, &c, &s, &sig), Ok(()));
            assert!(verify_open(&pk, !side, &l, &c, &s, &sig).is_err(), "side {side}");
        }
        assert_ne!(open_digest(false, &l, &c, &s), open_digest(true, &l, &c, &s));
    }
}
