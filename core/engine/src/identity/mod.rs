//! Signing identities (spec/permissions.md §1, spec/crypto.md §3): a 32-byte seed that never
//! leaves the node gives a signing key, and the thing minted with that key is what it signs as:
//! the node thing (its nonce random, its secrets random from its minting, kept in the node's own
//! store like every secret it holds) or a link key (its nonce and secrets from the link's seed).
//! Creation records of new things (spec/data-model.md §1).

use osis_base::{CreationRecord, SignKey, Tid};
use osis_crypto::{CryptoRngCore, Secret32, SigningSecret, creation_nonce, signing_key};
use osis_keys::ActorEpochs;

/// A signing key and the thing minted with it, which this node signs as.
#[derive(Clone)]
pub struct Identity {
    seed: Secret32,
    signing: SigningSecret,
    record: CreationRecord,
    tid: Tid,
    /// A link key's secrets, from its seed (none for a node thing): held here, so each KEM key
    /// pair is derived once.
    link: Option<ActorEpochs>,
}

impl Identity {
    /// The node thing of signing seed `seed`, minted with creation nonce `nonce`.
    pub fn node(seed: Secret32, nonce: [u8; 32]) -> Identity {
        let signing = signing_key(&seed);
        let record = CreationRecord::with_key(SignKey(signing.verifying_key().to_bytes()), nonce);
        Identity::of(seed, signing, record)
    }

    /// A fresh node thing: a random seed and nonce.
    pub fn generate(rng: &mut dyn CryptoRngCore) -> Identity {
        let seed = Secret32::random(rng);
        let mut nonce = [0u8; 32];
        rng.fill_bytes(&mut nonce);
        Identity::node(seed, nonce)
    }

    /// The link key of a link's seed `seed`, holding a grant on the link's thing `k`
    /// (spec/permissions.md §7).
    pub fn link_key(seed: Secret32, k: Tid) -> Identity {
        let signing = signing_key(&seed);
        let record = link_key_record(&seed, k);
        Identity::of(seed, signing, record)
    }

    fn of(seed: Secret32, signing: SigningSecret, record: CreationRecord) -> Identity {
        let tid = record.tid();
        let link = record.link_key_of().map(|_| ActorEpochs::link_key(&tid, &seed));
        Identity { seed, signing, record, tid, link }
    }

    pub fn tid(&self) -> Tid {
        self.tid
    }
    pub fn record(&self) -> &CreationRecord {
        &self.record
    }
    /// The signing key, the record's key.
    pub fn signing(&self) -> &SigningSecret {
        &self.signing
    }
    #[doc(hidden)]
    pub fn seed(&self) -> &Secret32 {
        &self.seed
    }
    /// A link key's secrets, from its seed alone (spec/crypto.md §3); none for a node thing,
    /// whose random secrets its minting gave the node's store.
    pub fn link_epochs(&self) -> Option<ActorEpochs> {
        self.link.clone()
    }
    /// A link key's first read keyset's KEM key, which its entry boxes are sealed to
    /// (spec/sync-ids.md §3).
    pub fn link_read_kem(&self) -> Option<&osis_crypto::KemSecret> {
        self.link.as_ref()?.read.held().next().map(|(_, s)| s.kem())
    }
}

/// The creation record of the link key of `seed` holding a grant on link's thing `k`
/// (spec/wire.md §3): its key, its nonce from the seed, K in `link`.
pub fn link_key_record(seed: &Secret32, k: Tid) -> CreationRecord {
    let key = SignKey(signing_key(seed).verifying_key().to_bytes());
    CreationRecord { link: Some(k), ..CreationRecord::with_key(key, creation_nonce(seed)) }
}

/// The tid of the link key of `seed` on `k`.
pub fn link_key_tid(seed: &Secret32, k: Tid) -> Tid {
    link_key_record(seed, k).tid()
}

/// A fresh record for a link's thing K of `admin`, made for `target` (spec/permissions.md §7).
pub fn link_record(admin: Tid, target: Tid, rng: &mut dyn CryptoRngCore) -> CreationRecord {
    CreationRecord { link: Some(target), ..thing_record(admin, None, rng) }
}

/// A fresh record for a thing whose mint admin is `admin` (32 random nonce bytes), ending at
/// `expires` (wall ms; `None`: never).
pub fn thing_record(admin: Tid, expires: Option<u64>, rng: &mut dyn CryptoRngCore) -> CreationRecord {
    let mut nonce = [0u8; 32];
    rng.fill_bytes(&mut nonce);
    CreationRecord { expires, ..CreationRecord::with_admin(admin, nonce) }
}
