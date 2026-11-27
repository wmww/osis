//! Role keys, the sync ID, claim keys, static entries and the open signature (spec/sync-ids.md §2, §3, spec/sync-opens.md §4,
//! spec/wire.md §8, §11.2).

use crate::kdf::{self, SYNC_ID, kdf};
use crate::{Domain, Error, Secret32, Signature, SigningSecret, VerifyingKey, X25519Secret};
use osis_base::{SyncId, Role, Value, encode};

/// A role key and the role secret of the sync ID's thing it derives from (`role`).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RoleKey {
    /// From the sync secret.
    Sync,
    /// From the write secret.
    Write,
    /// From the admin secret.
    Delete,
}

impl RoleKey {
    pub const ALL: [RoleKey; 3] = [RoleKey::Sync, RoleKey::Write, RoleKey::Delete];

    /// The role whose secret derives the key.
    pub fn role(self) -> Role {
        match self {
            RoleKey::Sync => Role::Sync,
            RoleKey::Write => Role::Write,
            RoleKey::Delete => Role::Admin,
        }
    }
}

/// `kdf("sync <role>", secret, "")` as an Ed25519 seed.
pub fn role_key(role: RoleKey, secret: &Secret32) -> SigningSecret {
    SigningSecret::from_seed(&role_key_seed(role, secret))
}

/// The seed of `role_key`: `kdf("sync <role>", secret, "")`. A sync key's seed is what its
/// proof derives from (`kdf::sync_proof`).
pub fn role_key_seed(role: RoleKey, secret: &Secret32) -> Secret32 {
    let purpose = match role {
        RoleKey::Sync => kdf::SYNC_KEY,
        RoleKey::Write => kdf::SYNC_WRITE,
        RoleKey::Delete => kdf::SYNC_DELETE,
    };
    kdf(purpose, secret.expose(), &[])
}

/// Deposit key `kdf("sync deposit", deposit seed, sync_id ID)`.
pub fn deposit_key(deposit_seed: &Secret32, sync_id: &SyncId) -> SigningSecret {
    SigningSecret::from_seed(&kdf(kdf::SYNC_DEPOSIT, deposit_seed.expose(), &sync_id.0))
}

/// The genesis seed of thing `tid` minted by a thing whose genesis seed is `mint_admin` (spec/crypto.md §3 Genesis seed): `kdf("sync genesis", g, tid)`.
pub fn genesis_seed(mint_admin: &Secret32, tid: &osis_base::Tid) -> Secret32 {
    kdf(kdf::SYNC_GENESIS, mint_admin.expose(), tid.as_bytes())
}

/// Sync ID = BLAKE3("osis v1 sync id" || genesis delete key)[..16].
pub fn sync_id(genesis_delete: &VerifyingKey) -> SyncId {
    let mut h = blake3::Hasher::new();
    h.update(SYNC_ID.as_bytes()).update(&genesis_delete.to_bytes());
    let mut id = [0u8; 16];
    id.copy_from_slice(h.finalize().as_bytes().get(..16).unwrap_or(&[0; 16]));
    SyncId(id)
}

/// Claim key pair: seed `kdf("sync claim", DH(own, their), sync_id || step_key)`. The registrar
/// passes the step private key and M's X25519 key; M passes its private key and the step key.
/// A non-contributory DH omits M.
pub fn claim_key(own: &X25519Secret, their: &[u8; 32], sync_id: &SyncId, step_key: &[u8; 32]) -> Result<SigningSecret, Error> {
    let dh = own.dh(their)?;
    let mut input = Vec::with_capacity(48);
    input.extend_from_slice(&sync_id.0);
    input.extend_from_slice(step_key);
    Ok(SigningSecret::from_seed(&kdf(kdf::SYNC_CLAIM, dh.expose(), &input)))
}

/// Digest of an open: BLAKE3(canonical `[side, sync_id, challenge, static_key]`) (spec/wire.md
/// §11.2), `side` the signer's (`by_listener`: 0 the dialer, 1 the listener), `challenge` the
/// other side's Hello challenge. Invariant, as for `proof_digest`: an open signature made as one
/// side verifies as no other, so a peer that copies this side's challenge into its own Hello
/// cannot offer a signature it was sent back as its own (model `ON_side`).
pub fn open_digest(by_listener: bool, sync_id: &SyncId, challenge: &[u8; 32], static_key: &[u8; 32]) -> [u8; 32] {
    let v = Value::List(vec![Value::uint(u64::from(by_listener)), Value::Bytes(sync_id.0.to_vec()), Value::Bytes(challenge.to_vec()), Value::Bytes(static_key.to_vec())]);
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

/// Open signature under `"osis v1 sync open"` by the side `by_listener`, over the other side's
/// Hello challenge and the listener's static key.
pub fn sign_open(key: &SigningSecret, by_listener: bool, sync_id: &SyncId, challenge: &[u8; 32], static_key: &[u8; 32]) -> Signature {
    key.sign(Domain::SyncOpen, &open_digest(by_listener, sync_id, challenge, static_key))
}

/// Verifies an open signature as made by the side `by_listener` (the peer's, at the verifier).
pub fn verify_open(key: &VerifyingKey, by_listener: bool, sync_id: &SyncId, challenge: &[u8; 32], static_key: &[u8; 32], sig: &Signature) -> Result<(), Error> {
    key.verify(Domain::SyncOpen, &open_digest(by_listener, sync_id, challenge, static_key), sig)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{KemSecret, SeededRng};

    // spec/sync-ids.md §2: role keys differ per role and secret; deposit keys per sync ID.
    #[test]
    fn role_keys() {
        let s = Secret32::from_bytes([9; 32]);
        let pk = |r| role_key(r, &s).verifying_key();
        assert_ne!(pk(RoleKey::Sync), role_key(RoleKey::Sync, &Secret32::from_bytes([8; 32])).verifying_key());
        assert_ne!(pk(RoleKey::Sync), pk(RoleKey::Write));
        assert_ne!(pk(RoleKey::Delete), pk(RoleKey::Write));
        let expect = SigningSecret::from_seed(&kdf("sync delete", &[9; 32], &[]));
        assert_eq!(pk(RoleKey::Delete), expect.verifying_key());
        let seed = Secret32::from_bytes([1; 32]);
        assert_ne!(deposit_key(&seed, &SyncId([1; 16])).verifying_key(), deposit_key(&seed, &SyncId([2; 16])).verifying_key());
        let id = sync_id(&pk(RoleKey::Delete));
        let mut h = blake3::Hasher::new();
        h.update(b"osis v1 sync id").update(&pk(RoleKey::Delete).to_bytes());
        assert_eq!(id.0, h.finalize().as_bytes()[..16]);
    }

    // spec/sync-ids.md §3: registrar and holder derive the same claim key; non-contributory omits.
    #[test]
    fn claim_keys() {
        let mut rng = SeededRng::from_u64(0);
        let step = X25519Secret::random(&mut rng);
        let kem = KemSecret::derive(&Secret32::from_bytes([6; 32]));
        let sync_id = SyncId([7; 16]);
        let by_registrar = claim_key(&step, &kem.public().x25519(), &sync_id, &step.public()).unwrap();
        let by_holder = claim_key(kem.x25519(), &step.public(), &sync_id, &step.public()).unwrap();
        assert_eq!(by_registrar.verifying_key(), by_holder.verifying_key());
        let other = claim_key(&step, &kem.public().x25519(), &SyncId([8; 16]), &step.public()).unwrap();
        assert_ne!(other.verifying_key(), by_holder.verifying_key());
        assert_eq!(claim_key(&step, &[0; 32], &sync_id, &step.public()).err(), Some(Error::NonContributory));
    }

    // spec/wire.md §11.2: an open signature binds sync ID, challenge and static key.
    #[test]
    fn open_signature() {
        let k = role_key(RoleKey::Sync, &Secret32::from_bytes([1; 32]));
        let (l, c, s) = (SyncId([1; 16]), [2; 32], [3; 32]);
        let sig = sign_open(&k, false, &l, &c, &s);
        let pk = k.verifying_key();
        assert_eq!(verify_open(&pk, false, &l, &c, &s, &sig), Ok(()));
        assert!(verify_open(&pk, false, &SyncId([9; 16]), &c, &s, &sig).is_err());
        assert!(verify_open(&pk, false, &l, &[9; 32], &s, &sig).is_err());
        assert!(verify_open(&pk, false, &l, &c, &[9; 32], &sig).is_err());
        assert!(pk.verify(Domain::Stamp, &open_digest(false, &l, &c, &s), &sig).is_err());
        assert_eq!(role_key(RoleKey::Sync, &Secret32::from_bytes([1; 32])).verifying_key(), SigningSecret::from_seed(&role_key_seed(RoleKey::Sync, &Secret32::from_bytes([1; 32]))).verifying_key());
    }

    // spec/wire.md §11.2: an open signature binds its signer's side; one made by either side
    // verifies only as that side's, so a signature sent to a peer is no signature of the peer's
    // (on a connection whose challenges the peer copied, model `ON_side`).
    #[test]
    fn an_open_signature_binds_its_signers_side_spec_wire_11_2() {
        let k = role_key(RoleKey::Sync, &Secret32::from_bytes([1; 32]));
        let pk = k.verifying_key();
        let (l, c, s) = (SyncId([1; 16]), [2; 32], [3; 32]);
        for side in [false, true] {
            let sig = sign_open(&k, side, &l, &c, &s);
            assert_eq!(verify_open(&pk, side, &l, &c, &s, &sig), Ok(()));
            assert!(verify_open(&pk, !side, &l, &c, &s, &sig).is_err(), "side {side}");
        }
        assert_ne!(open_digest(false, &l, &c, &s), open_digest(true, &l, &c, &s));
    }
}
