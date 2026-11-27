//! Steps: role keys, registration steps, step IDs and paths (spec/sync-ids.md §2, §3,
//! spec/wire.md §8).

use crate::cbor::{get_bytes, get_key};
use crate::Error;
use osis_base::cbor::{Limits, decode, encode};
use osis_base::format::{MAX_MESSAGE, MAX_OBJECT_DEPTH};
use osis_base::SyncId;
use osis_base::Value;
use osis_crypto::{Domain, RoleKey, Secret32, Signature, SigningSecret, VerifyingKey, X25519Secret, deposit_key, role_key, sync_id};

/// BLAKE3 of a step's canonical bytes.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct StepId(pub [u8; 32]);

/// A registration step (spec/wire.md §8).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Step {
    pub sync_id: SyncId,
    pub prev: Option<StepId>,
    pub keys: StepKeys,
    /// Raw X25519 public key: the public half of the claim key of the sync epoch whose sync key
    /// the step bears.
    pub step_key: [u8; 32],
    /// By the parent's delete key (the genesis step: its own).
    pub sig: Signature,
}

/// The four public keys a step registers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StepKeys {
    pub sync: VerifyingKey,
    pub write: VerifyingKey,
    pub delete: VerifyingKey,
    pub deposit: VerifyingKey,
}

impl StepKeys {
    /// Role public keys from the role secrets of the sync ID's thing, deposit key from the actor's
    /// deposit seed (spec/sync-ids.md §2).
    pub fn derive(sync: &Secret32, write: &Secret32, admin: &Secret32, deposit_seed: &Secret32, sync_id: &SyncId) -> StepKeys {
        StepKeys {
            sync: role_key(RoleKey::Sync, sync).verifying_key(),
            write: role_key(RoleKey::Write, write).verifying_key(),
            delete: role_key(RoleKey::Delete, admin).verifying_key(),
            deposit: deposit_key(deposit_seed, sync_id).verifying_key(),
        }
    }

    pub fn get(&self, role: RoleKey) -> &VerifyingKey {
        match role {
            RoleKey::Sync => &self.sync,
            RoleKey::Write => &self.write,
            RoleKey::Delete => &self.delete,
        }
    }
}

/// The sync ID of a thing whose genesis seed is `g` (spec/sync-ids.md §2): its genesis step's
/// (`genesis`).
pub fn genesis_sync_id(g: &Secret32) -> SyncId {
    sync_id(&role_key(RoleKey::Delete, g).verifying_key())
}

/// Limits for steps and the structures holding them (spec/wire.md §12).
pub(crate) const OBJECT_LIMITS: Limits = Limits::new(MAX_OBJECT_DEPTH, MAX_MESSAGE);

impl Step {
    fn unsigned(&self) -> Vec<Value> {
        let k = &self.keys;
        vec![
            Value::bytes(&self.sync_id.0),
            Value::List(self.prev.iter().map(|p| Value::bytes(&p.0)).collect()),
            Value::bytes(&k.sync.to_bytes()),
            Value::bytes(&k.write.to_bytes()),
            Value::bytes(&k.delete.to_bytes()),
            Value::bytes(&k.deposit.to_bytes()),
            Value::bytes(&self.step_key),
        ]
    }

    /// Digest the signature covers: BLAKE3 of the canonical array of the first seven items.
    pub fn digest(&self) -> [u8; 32] {
        osis_base::hash::hash(&encode(&Value::List(self.unsigned())))
    }

    pub fn to_value(&self) -> Value {
        let mut items = self.unsigned();
        items.push(Value::bytes(&self.sig.0));
        Value::List(items)
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        encode(&self.to_value())
    }

    pub fn id(&self) -> StepId {
        StepId(osis_base::hash::hash(&self.to_bytes()))
    }

    pub fn parse(b: &[u8]) -> Result<Step, Error> {
        Step::from_value(&decode(b, &OBJECT_LIMITS)?)
    }

    pub fn from_value(v: &Value) -> Result<Step, Error> {
        let Value::List(items) = v else { return Err(Error::Malformed("step")) };
        let [sync_id, prev, sync, write, delete, deposit, step_key, sig] = items.as_slice() else {
            return Err(Error::Malformed("step"));
        };
        let prev = match prev {
            Value::List(p) => match p.as_slice() {
                [] => None,
                [id] => Some(StepId(get_bytes(id, "step prev")?)),
                _ => return Err(Error::Malformed("step prev")),
            },
            _ => return Err(Error::Malformed("step prev")),
        };
        Ok(Step {
            sync_id: SyncId(get_bytes(sync_id, "step sync ID")?),
            prev,
            keys: StepKeys {
                sync: get_key(sync, "step sync key")?,
                write: get_key(write, "step write key")?,
                delete: get_key(delete, "step delete key")?,
                deposit: get_key(deposit, "step deposit key")?,
            },
            step_key: get_bytes(step_key, "step key")?,
            sig: Signature(get_bytes(sig, "step signature")?),
        })
    }

    /// A genesis step: no `prev`, signed by its own delete key, which hashes to the sync ID.
    pub fn verify_genesis(&self) -> Result<(), Error> {
        if self.prev.is_some() {
            return Err(Error::Verify("genesis step has prev"));
        }
        if sync_id(&self.keys.delete) != self.sync_id {
            return Err(Error::Verify("genesis delete key does not hash to the sync ID"));
        }
        self.keys.delete.verify(Domain::SyncStep, &self.digest(), &self.sig).map_err(|_| Error::Verify("step signature"))
    }

    /// A child of `parent`: same sync ID, `prev` its ID, signed by its delete key.
    pub fn verify_child(&self, parent: &Step) -> Result<(), Error> {
        if self.sync_id != parent.sync_id || self.prev != Some(parent.id()) {
            return Err(Error::Verify("step is not a child"));
        }
        parent.keys.delete.verify(Domain::SyncStep, &self.digest(), &self.sig).map_err(|_| Error::Verify("step signature"))
    }

    /// An endorsement of this step by delete key `delete` (spec/sync-ids.md §6 Register, spec/wire.md
    /// §8): a store whose head bears that key may take a branch ending at this step.
    pub fn endorse(&self, delete: &SigningSecret) -> Signature {
        delete.sign(Domain::SyncEndorse, &self.id().0)
    }

    /// Whether `sig` endorses this step under delete key `delete` (`endorse`).
    pub fn endorsed_by(&self, delete: &VerifyingKey, sig: &Signature) -> bool {
        delete.verify(Domain::SyncEndorse, &self.id().0, sig).is_ok()
    }
}

/// Verifies a registration path: the genesis step of `sync_id`, then each step a child of the one
/// before (spec/sync-ids.md §3).
pub fn verify_path(sync_id: &SyncId, path: &[Step]) -> Result<(), Error> {
    let (first, rest) = path.split_first().ok_or(Error::Verify("empty path"))?;
    if first.sync_id != *sync_id {
        return Err(Error::Verify("path of another sync ID"));
    }
    first.verify_genesis()?;
    let mut parent = first;
    for s in rest {
        s.verify_child(parent)?;
        parent = s;
    }
    Ok(())
}

/// The genesis step of the sync ID of a thing whose genesis seed is `g` (spec/sync-ids.md §2,
/// spec/wire.md §8): every key from `g` (its role keys as if `g` were every role's secret, its
/// step key from `kdf("genesis step", g)`). Deterministic: every holder of `g` builds these bytes.
pub fn genesis(g: &Secret32) -> Step {
    let delete = role_key(RoleKey::Delete, g);
    let sync_id = sync_id(&delete.verifying_key());
    let keys = StepKeys { sync: role_key(RoleKey::Sync, g).verifying_key(), write: role_key(RoleKey::Write, g).verifying_key(), delete: delete.verifying_key(), deposit: deposit_key(g, &sync_id).verifying_key() };
    let step_key = X25519Secret::from_secret(&osis_crypto::kdf::kdf(osis_crypto::kdf::GENESIS_STEP, g.expose(), b"")).public();
    let mut step = Step { sync_id, prev: None, keys, step_key, sig: Signature([0; 64]) };
    step.sig = delete.sign(Domain::SyncStep, &step.digest());
    step
}

/// Issues a child of `parent` registering `keys` and `step_key`, signed by the parent's delete key
/// `delete` (spec/sync-ids.md §3).
pub fn register(parent: &Step, delete: &SigningSecret, keys: StepKeys, step_key: [u8; 32]) -> Result<Step, Error> {
    if delete.verifying_key() != parent.keys.delete {
        return Err(Error::Verify("signer is not the parent's delete key"));
    }
    let mut step = Step { sync_id: parent.sync_id, prev: Some(parent.id()), keys, step_key, sig: Signature([0; 64]) };
    step.sig = delete.sign(Domain::SyncStep, &step.digest());
    Ok(step)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub(crate) struct Secrets {
        pub read: Secret32,
        pub write: Secret32,
        pub admin: Secret32,
        pub deposit: Secret32,
        pub sync: Secret32,
    }

    impl Secrets {
        pub fn new(b: u8) -> Secrets {
            Secrets { read: Secret32::from_bytes([b; 32]), write: Secret32::from_bytes([b + 1; 32]), admin: Secret32::from_bytes([b + 2; 32]), deposit: Secret32::from_bytes([b + 3; 32]), sync: Secret32::from_bytes([b + 4; 32]) }
        }
        pub fn keys(&self) -> StepKeys {
            StepKeys::derive(&self.sync, &self.write, &self.admin, &self.deposit, &genesis_sync_id(&self.admin))
        }
        pub fn delete(&self) -> SigningSecret {
            role_key(RoleKey::Delete, &self.admin)
        }
    }

    // spec/wire.md §8, spec/sync-ids.md §3: genesis step bytes round trip; the ID is BLAKE3 of the
    // bytes; the sync ID hashes the genesis delete key; a child verifies under the parent's
    // delete key only; paths verify step by step.
    #[test]
    fn steps_and_paths() {
        let g = Secrets::new(10);
        let s0 = genesis(&g.admin);
        assert_eq!(s0.sync_id, genesis_sync_id(&g.admin));
        assert_eq!(genesis(&g.admin), s0, "deterministic");
        assert_ne!(genesis(&g.read).sync_id, s0.sync_id);
        assert_eq!(Step::parse(&s0.to_bytes()).unwrap(), s0);
        assert_eq!(s0.id().0, osis_base::hash::hash(&s0.to_bytes()));
        s0.verify_genesis().unwrap();
        // Rotation: new admin secret, step signed by the old delete key.
        let g2 = Secrets::new(20);
        let k1 = StepKeys::derive(&g2.sync, &g2.write, &g2.admin, &g.deposit, &s0.sync_id);
        let s1 = register(&s0, &g.delete(), k1, [1; 32]).unwrap();
        s1.verify_child(&s0).unwrap();
        assert!(s1.verify_genesis().is_err());
        let g3 = Secrets::new(30);
        let s2 = register(&s1, &g2.delete(), StepKeys::derive(&g3.sync, &g3.write, &g3.admin, &g.deposit, &s0.sync_id), [2; 32]).unwrap();
        verify_path(&s0.sync_id, &[s0.clone(), s1.clone(), s2.clone()]).unwrap();
        assert!(verify_path(&s0.sync_id, &[s0.clone(), s2.clone()]).is_err());
        assert!(verify_path(&s0.sync_id, std::slice::from_ref(&s1)).is_err());
        assert!(verify_path(&SyncId([0; 16]), std::slice::from_ref(&s0)).is_err());
        // Signer checks.
        assert!(register(&s1, &g.delete(), s1.keys, [3; 32]).is_err());
        // A tampered field fails the signature.
        let mut t = s1.clone();
        t.step_key[0] ^= 1;
        assert!(t.verify_child(&s0).is_err());
    }

    // spec/wire.md §8, §1: step decoder rejections: wrong length, bad prev, bad key.
    #[test]
    fn step_rejections() {
        let g = Secrets::new(30);
        let s0 = genesis(&g.admin);
        let Value::List(items) = s0.to_value() else { panic!() };
        let mut short = items.clone();
        short.pop();
        assert!(Step::from_value(&Value::List(short)).is_err());
        let mut two_prev = items.clone();
        two_prev[1] = Value::List(vec![Value::bytes(&[0; 32]), Value::bytes(&[0; 32])]);
        assert!(Step::from_value(&Value::List(two_prev)).is_err());
        let mut bad_key = items.clone();
        bad_key[2] = Value::bytes(&[0; 32]);
        assert!(Step::from_value(&Value::List(bad_key)).is_err());
        let mut short_key = items;
        short_key[6] = Value::bytes(&[0; 31]);
        assert!(Step::from_value(&Value::List(short_key)).is_err());
        assert!(Step::parse(&[0x80]).is_err());
    }
}
