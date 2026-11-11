//! Node identity (spec/permissions.md §1, spec/crypto.md §3): a seed that never leaves the
//! device gives the node's signing and KEM keys, its creation record and tid. Creation records
//! of new things (spec/data-model.md §1).

use osis_base::{CreationRecord, SIGNING_KEY_ED25519, Tid};
use osis_crypto::{CryptoRngCore, KeyActorKeys, Secret32, VerifyingKey, creation_nonce};
use osis_keys::ActorEpochs;

/// A key actor this node signs as: the node itself.
#[derive(Clone)]
pub struct Identity {
    keys: KeyActorKeys,
    record: CreationRecord,
    tid: Tid,
}

impl Identity {
    pub fn from_seed(seed: Secret32) -> Identity {
        let keys = KeyActorKeys::from_seed(&seed);
        let record = key_actor_record(&keys.signing.verifying_key(), keys.seed());
        let tid = record.tid();
        Identity { keys, record, tid }
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
    #[doc(hidden)]
    pub fn seed(&self) -> &Secret32 {
        self.keys.seed()
    }
    /// The node's own role secrets (never rotated).
    pub fn epochs(&self) -> ActorEpochs {
        ActorEpochs::key_actor(self.keys.seed())
    }
}

/// The creation record of the key actor of `seed`, whose signing key is `signing` (spec/wire.md §3).
pub fn key_actor_record(signing: &VerifyingKey, seed: &Secret32) -> CreationRecord {
    CreationRecord::KeyActor { alg: SIGNING_KEY_ED25519, public_key: signing.to_bytes().to_vec(), nonce: creation_nonce(seed), account: false }
}

/// The tid of the key actor of `seed`, without deriving its KEM key pair.
pub fn key_actor_tid(seed: &Secret32) -> Tid {
    key_actor_record(&KeyActorKeys::signing_of(seed).verifying_key(), seed).tid()
}

/// A fresh record for a link's actor K of `admin`, made for `target` (spec/permissions.md §7).
pub fn link_record(admin: Tid, target: Tid, rng: &mut dyn CryptoRngCore) -> CreationRecord {
    let CreationRecord::Thing { nonce, .. } = thing_record(admin, rng) else { unreachable!() };
    CreationRecord::Thing { admin, nonce, link: Some(target) }
}

/// A fresh record for a thing whose first admin is `admin` (32 random nonce bytes).
pub fn thing_record(admin: Tid, rng: &mut dyn CryptoRngCore) -> CreationRecord {
    let mut nonce = [0u8; 32];
    rng.fill_bytes(&mut nonce);
    CreationRecord::Thing { admin, nonce, link: None }
}
