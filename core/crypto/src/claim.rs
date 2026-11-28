//! Step secrets, claim keys and claims' W (spec/sync-ids.md §3, spec/wire.md §5 Claim blocks, §8).

use crate::kdf::{self, kdf};
use crate::{Domain, Error, KemPublicKey, KemSecret, SEALED_OVERHEAD, Secret32, Signature, SigningSecret, VerifyingKey, X25519Secret, open_sealed, seal};
use osis_base::SyncId;
use rand_core::CryptoRngCore;
use zeroize::Zeroizing;

/// A claim's W payload: 65 bytes (spec/wire.md §5).
pub const W_PAYLOAD_LEN: usize = 65;
/// A claim's W: a sealed box of the payload, the public's payload padded alike, or a dummy's
/// random bytes.
pub const W_LEN: usize = SEALED_OVERHEAD + W_PAYLOAD_LEN;
/// AD prefix of a W (spec/wire.md §5).
const CLAIM_AD: &[u8] = b"osis v1 claim";

/// What a claim hands its holder (spec/sync-ids.md §3 Claims).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WPayload {
    /// A read holder: the blob key and the key of the section holding the commit's role parts on
    /// the claim's thing.
    Read { blob_key: Secret32, section_key: Secret32 },
    /// A sync holder: the sync secret at n of the epoch the block is bound to.
    Sync { n: u64, secret: Secret32 },
}

impl WPayload {
    fn to_bytes(&self) -> Zeroizing<[u8; W_PAYLOAD_LEN]> {
        let mut b = Zeroizing::new([0u8; W_PAYLOAD_LEN]);
        let (tag, rest) = b.split_at_mut(1);
        match self {
            WPayload::Read { blob_key, section_key } => {
                let (k, s) = rest.split_at_mut(32);
                k.copy_from_slice(blob_key.expose());
                s.copy_from_slice(section_key.expose());
            }
            WPayload::Sync { n, secret } => {
                tag.fill(1);
                let (nb, rest) = rest.split_at_mut(8);
                nb.copy_from_slice(&n.to_le_bytes());
                if let Some(s) = rest.get_mut(..32) {
                    s.copy_from_slice(secret.expose());
                }
            }
        }
        b
    }

    /// Any payload but these two forms opens nothing (spec/wire.md §5).
    fn from_bytes(b: &[u8]) -> Option<WPayload> {
        let (tag, rest) = b.split_first()?;
        if rest.len() != W_PAYLOAD_LEN - 1 {
            return None;
        }
        let k32 = |b: &[u8]| -> Option<Secret32> { Some(Secret32::from_bytes(b.try_into().ok()?)) };
        match tag {
            0 => Some(WPayload::Read { blob_key: k32(rest.get(..32)?)?, section_key: k32(rest.get(32..)?)? }),
            1 if rest.get(40..)?.iter().all(|x| *x == 0) => Some(WPayload::Sync { n: u64::from_le_bytes(rest.get(..8)?.try_into().ok()?), secret: k32(rest.get(8..40)?)? }),
            _ => None,
        }
    }
}

/// The step secret of a sync epoch: X25519 private key `kdf("step key", sync secret, roles secret)`,
/// the roles secret that of the sync keyset's claim epoch (spec/wire.md §8).
pub fn step_secret(sync_secret: &Secret32, roles_secret: &Secret32) -> X25519Secret {
    X25519Secret::from_secret(&kdf(kdf::STEP_KEY, sync_secret.expose(), roles_secret.expose()))
}

/// A holder's claim key: seed `kdf("claim key", DH(own, their), sync_id || step_key)`. A writer passes
/// the step secret and the holder's X25519 key; the holder its X25519 private key and the step key.
/// A non-contributory DH gives none.
pub fn claim_key(own: &X25519Secret, their: &[u8; 32], sync_id: &SyncId, step_key: &[u8; 32]) -> Result<SigningSecret, Error> {
    let dh = own.dh(their)?;
    let mut input = Vec::with_capacity(48);
    input.extend_from_slice(&sync_id.0);
    input.extend_from_slice(step_key);
    Ok(SigningSecret::from_seed(&kdf(kdf::CLAIM_KEY, dh.expose(), &input)))
}

/// The public's claim key: seed `kdf("public claim key", sync_id, step_key)`: anyone holding a step of the
/// epoch computes it.
pub fn public_claim_key(sync_id: &SyncId, step_key: &[u8; 32]) -> SigningSecret {
    SigningSecret::from_seed(&kdf(kdf::PUBLIC_CLAIM_KEY, &sync_id.0, step_key))
}

fn claim_ad(sync_id: &SyncId, claim_key: &[u8; 32]) -> Vec<u8> {
    let mut ad = Vec::with_capacity(CLAIM_AD.len() + 48);
    ad.extend_from_slice(CLAIM_AD);
    ad.extend_from_slice(&sync_id.0);
    ad.extend_from_slice(claim_key);
    ad
}

/// W for a holder: `keys` sealed to its read KEM key, bound to the sync ID and its claim key.
pub fn seal_w(pk: &KemPublicKey, sync_id: &SyncId, claim_key: &[u8; 32], keys: &WPayload, rng: &mut dyn CryptoRngCore) -> Result<Vec<u8>, Error> {
    seal(pk, &claim_ad(sync_id, claim_key), &keys.to_bytes()[..], rng)
}

/// Opens a holder's W; `None` when it does not open or holds another payload.
pub fn open_w(sk: &KemSecret, sync_id: &SyncId, claim_key: &[u8; 32], w: &[u8]) -> Option<WPayload> {
    WPayload::from_bytes(&open_sealed(sk, &claim_ad(sync_id, claim_key), w).ok()?)
}

/// The public's W: the payload in clear, then zeros to `W_LEN`.
pub fn public_w(keys: &WPayload) -> Vec<u8> {
    let mut w = keys.to_bytes().to_vec();
    w.resize(W_LEN, 0);
    w
}

/// Reads the public's W; `None` unless it is a payload followed by zeros.
pub fn read_public_w(w: &[u8]) -> Option<WPayload> {
    let (payload, pad) = (w.get(..W_PAYLOAD_LEN)?, w.get(W_PAYLOAD_LEN..)?);
    (w.len() == W_LEN && pad.iter().all(|x| *x == 0)).then_some(())?;
    WPayload::from_bytes(payload)
}

/// The digest a claim block's signature covers: BLAKE3(sync_id || salt || the block's bytes
/// before its signature) (spec/wire.md §5).
pub fn claim_block_digest(sync_id: &SyncId, salt: &[u8; 16], unsigned: &[u8]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(&sync_id.0).update(salt).update(unsigned);
    *h.finalize().as_bytes()
}

/// Signs a claim block by its sync key.
pub fn sign_claim_block(sync_key: &SigningSecret, sync_id: &SyncId, salt: &[u8; 16], unsigned: &[u8]) -> Signature {
    sync_key.sign(Domain::ClaimBlock, &claim_block_digest(sync_id, salt, unsigned))
}

/// Verifies a claim block's signature under the sync key it names, for the sync ID it is read
/// under.
pub fn verify_claim_block(sync_pk: &VerifyingKey, sync_id: &SyncId, salt: &[u8; 16], unsigned: &[u8], sig: &Signature) -> Result<(), Error> {
    sync_pk.verify(Domain::ClaimBlock, &claim_block_digest(sync_id, salt, unsigned), sig)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{SeededRng, roles_secret};

    // spec/sync-ids.md §3: a writer holding the step secret and the holder holding its KEM key derive
    // the same claim key; another sync ID, step key or holder another; a non-contributory DH none
    #[test]
    fn a_claim_key_agrees_at_both_sides_spec_sync_ids_3() {
        let ss = step_secret(&Secret32::from_bytes([1; 32]), &roles_secret(&Secret32::from_bytes([2; 32])));
        let step_key = ss.public();
        let m = KemSecret::derive(&Secret32::from_bytes([6; 32]));
        let s = SyncId([7; 16]);
        let by_writer = claim_key(&ss, &m.public().x25519(), &s, &step_key).unwrap().verifying_key();
        let by_holder = claim_key(m.x25519(), &step_key, &s, &step_key).unwrap().verifying_key();
        assert_eq!(by_writer, by_holder);
        assert_ne!(claim_key(&ss, &m.public().x25519(), &SyncId([8; 16]), &step_key).unwrap().verifying_key(), by_holder);
        let other = KemSecret::derive(&Secret32::from_bytes([5; 32]));
        assert_ne!(claim_key(&ss, &other.public().x25519(), &s, &step_key).unwrap().verifying_key(), by_holder);
        // the step secret takes the roles secret: the sync secret alone (a store's) gives another
        let store = step_secret(&Secret32::from_bytes([1; 32]), &Secret32::from_bytes([0; 32]));
        assert_ne!(store.public(), step_key);
        assert_eq!(claim_key(&ss, &[0; 32], &s, &step_key).err(), Some(Error::NonContributory));
        assert_ne!(public_claim_key(&s, &step_key).verifying_key(), public_claim_key(&SyncId([8; 16]), &step_key).verifying_key());
    }

    // spec/wire.md §5: W opens only for its holder, under its sync ID and claim key, to either payload
    #[test]
    fn w_opens_only_for_its_holder_spec_wire_5() {
        let mut rng = SeededRng::from_u64(0);
        let m = KemSecret::derive(&Secret32::from_bytes([6; 32]));
        let (s, c) = (SyncId([7; 16]), [3; 32]);
        for keys in [WPayload::Read { blob_key: Secret32::from_bytes([1; 32]), section_key: Secret32::from_bytes([2; 32]) }, WPayload::Sync { n: 9, secret: Secret32::from_bytes([4; 32]) }] {
            let w = seal_w(m.public(), &s, &c, &keys, &mut rng).unwrap();
            assert_eq!(w.len(), W_LEN);
            assert_eq!(open_w(&m, &s, &c, &w), Some(keys.clone()));
            assert_eq!(open_w(&KemSecret::derive(&Secret32::from_bytes([5; 32])), &s, &c, &w), None);
            assert_eq!(open_w(&m, &SyncId([8; 16]), &c, &w), None);
            assert_eq!(open_w(&m, &s, &[4; 32], &w), None);
            let p = public_w(&keys);
            assert_eq!(p.len(), W_LEN);
            assert_eq!(read_public_w(&p), Some(keys));
        }
        // another payload opens nothing
        let mut bad = public_w(&WPayload::Sync { n: 1, secret: Secret32::from_bytes([4; 32]) });
        bad[60] = 1;
        assert_eq!(read_public_w(&bad), None);
        bad[60] = 0;
        bad[0] = 2;
        assert_eq!(read_public_w(&bad), None);
    }

    // spec/wire.md §5: a claim block verifies only under its sync ID, salt and sync key
    #[test]
    fn a_block_verifies_only_under_its_sync_id_and_key_spec_wire_5() {
        let k = SigningSecret::from_seed(&Secret32::from_bytes([1; 32]));
        let (s, salt, bytes) = (SyncId([7; 16]), [2; 16], b"block".as_slice());
        let sig = sign_claim_block(&k, &s, &salt, bytes);
        assert!(verify_claim_block(&k.verifying_key(), &s, &salt, bytes, &sig).is_ok());
        assert!(verify_claim_block(&k.verifying_key(), &SyncId([8; 16]), &salt, bytes, &sig).is_err());
        assert!(verify_claim_block(&k.verifying_key(), &s, &[3; 16], bytes, &sig).is_err());
        assert!(verify_claim_block(&SigningSecret::from_seed(&Secret32::from_bytes([2; 32])).verifying_key(), &s, &salt, bytes, &sig).is_err());
        assert!(k.verifying_key().verify(Domain::SyncOpen, &claim_block_digest(&s, &salt, bytes), &sig).is_err());
    }
}
