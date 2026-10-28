//! Node identity (spec/permissions.md §1, spec/crypto.md §3): a seed that never leaves the
//! device gives the node's signing and KEM keys, its creation record and tid. Creation records
//! of new things (spec/data-model.md §1).

use osis_base::{CreationRecord, Tid};
use osis_crypto::{CryptoRngCore, KeyActorKeys, Secret32, creation_nonce};
use osis_keys::ActorEpochs;

/// `signing_key` case ed25519 (spec/wire.md §3).
const SIGNING_KEY_ED25519: u64 = 1;

/// A key actor this node signs as: the node itself.
pub struct Identity {
    seed: Secret32,
    keys: KeyActorKeys,
    record: CreationRecord,
    tid: Tid,
}

impl Identity {
    pub fn from_seed(seed: Secret32) -> Identity {
        let keys = KeyActorKeys::from_seed(&seed);
        let record = key_actor_record(&keys, &seed);
        let tid = record.tid();
        Identity { seed, keys, record, tid }
    }

    pub fn generate(rng: &mut dyn CryptoRngCore) -> Identity {
        Identity::from_seed(Secret32::random(rng))
    }

    pub fn tid(&self) -> Tid {
        self.tid
    }
    pub fn record(&self) -> &CreationRecord {
        &self.record
    }
    pub fn keys(&self) -> &KeyActorKeys {
        &self.keys
    }
    pub(crate) fn seed(&self) -> &Secret32 {
        &self.seed
    }
    /// The node's own role secrets (never rotated).
    pub fn epochs(&self) -> ActorEpochs {
        ActorEpochs::key_actor(&self.seed)
    }
}

/// The creation record of a key actor with these keys (spec/wire.md §3).
pub fn key_actor_record(keys: &KeyActorKeys, seed: &Secret32) -> CreationRecord {
    CreationRecord::KeyActor { alg: SIGNING_KEY_ED25519, public_key: keys.signing.verifying_key().to_bytes().to_vec(), nonce: creation_nonce(seed) }
}

/// A fresh record for a thing owned by `owner` (32 random nonce bytes).
pub fn thing_record(owner: Tid, rng: &mut dyn CryptoRngCore) -> CreationRecord {
    let mut nonce = [0u8; 32];
    rng.fill_bytes(&mut nonce);
    CreationRecord::Thing { owner, nonce }
}
