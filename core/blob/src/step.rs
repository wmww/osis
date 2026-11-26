//! Steps: role keys, registration steps, step IDs and paths, claim sets with claim keys and
//! static entries, entry boxes (spec/sync-ids.md §2, §3, spec/wire.md §8, §7).

use crate::cbor::{get_bytes, get_key};
use crate::Error;
use osis_base::cbor::{Limits, decode, encode};
use osis_base::format::{MAX_CLAIMS, MAX_MESSAGE, MAX_OBJECT_DEPTH};
use osis_base::{SyncId, Tid, Value};
use osis_crypto::{
    BoxForm, BoxSlot, CryptoRngCore, Domain, EntryItem, EntryRead, Epoch, KemPublicKey, KemSecret, RoleKey, Secret32, Signature, SigningSecret,
    VerifyingKey, X25519Secret, claim_key, deposit_key, role_key, open_entry, open_form_entry, public_entry, read_open_entry, seal_entry, static_entry, sync_id,
};
use osis_schema::Codec;
use osis_schema::core_types::{SealedBox, SecretBox, Sealed};
use std::collections::{BTreeMap, BTreeSet};

/// BLAKE3 of a step's canonical bytes.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct StepId(pub [u8; 32]);

/// A registration step (spec/wire.md §8).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Step {
    pub sync_id: SyncId,
    pub prev: Option<StepId>,
    pub keys: StepKeys,
    /// Raw X25519 public key.
    pub step_key: [u8; 32],
    pub claims_hash: [u8; 32],
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

/// Sync ID of the sync ID whose genesis derives from `admin` (spec/sync-ids.md §2).
pub fn genesis_sync_id(admin: &Secret32) -> SyncId {
    sync_id(&role_key(RoleKey::Delete, admin).verifying_key())
}

/// Limits for steps, claim sets and the structures holding them (spec/wire.md §12).
pub(crate) const OBJECT_LIMITS: Limits = Limits::new(MAX_OBJECT_DEPTH, MAX_MESSAGE);

/// Largest encoded claim set with its entry boxes, so a step and its set fit one message
/// (spec/wire.md §12).
pub const MAX_CLAIM_SET: usize = MAX_MESSAGE - 64 * 1024;

fn check_claim_set_size(len: usize) -> Result<(), Error> {
    if len > MAX_CLAIM_SET {
        return Err(Error::TooLarge("claim set above MAX_CLAIM_SET"));
    }
    Ok(())
}

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
            Value::bytes(&self.claims_hash),
        ]
    }

    /// Digest the signature covers: BLAKE3 of the canonical array of the first eight items.
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
        let [sync_id, prev, sync, write, delete, deposit, step_key, claims_hash, sig] = items.as_slice() else {
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
            claims_hash: get_bytes(claims_hash, "claims hash")?,
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

    /// The claim key a reader derives from its X25519 private key (spec/sync-ids.md §3); try each
    /// keyset epoch held.
    pub fn claim_key(&self, own: &X25519Secret) -> Result<SigningSecret, Error> {
        Ok(claim_key(own, &self.step_key, &self.sync_id, &self.step_key)?)
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

/// A step's claim set: claims (claim keys and static entries, power-of-two count) and the entry
/// boxes keyed by static entry (spec/wire.md §8).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClaimSet {
    pub claims: Vec<[u8; 32]>,
    pub entries: BTreeMap<[u8; 32], SecretBox>,
}

impl ClaimSet {
    pub fn to_value(&self) -> Value {
        Value::List(vec![
            Value::List(self.claims.iter().map(|c| Value::bytes(c)).collect()),
            Value::Map(self.entries.iter().map(|(k, b)| (Value::bytes(k), b.to_value())).collect()),
        ])
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        encode(&self.to_value())
    }

    /// `claims_hash` = BLAKE3 of the canonical bytes.
    pub fn hash(&self) -> [u8; 32] {
        osis_base::hash::hash(&self.to_bytes())
    }

    /// `Malformed` above `MAX_CLAIM_SET` bytes.
    pub fn parse(b: &[u8]) -> Result<ClaimSet, Error> {
        if b.len() > MAX_CLAIM_SET {
            return Err(Error::Malformed("claim set above MAX_CLAIM_SET"));
        }
        ClaimSet::from_value(&decode(b, &OBJECT_LIMITS)?)
    }

    /// Count a power of two in 1..=MAX_CLAIMS; every entry key among the claims; boxes typed as
    /// `box` values (an unknown case parks).
    pub fn from_value(v: &Value) -> Result<ClaimSet, Error> {
        let Value::List(items) = v else { return Err(Error::Malformed("claim set")) };
        let [Value::List(claims), Value::Map(entries)] = items.as_slice() else { return Err(Error::Malformed("claim set")) };
        if !claims.len().is_power_of_two() || claims.len() > MAX_CLAIMS {
            return Err(Error::Malformed("claim count"));
        }
        let claims: Vec<[u8; 32]> = claims.iter().map(|c| get_bytes(c, "claim")).collect::<Result<_, _>>()?;
        let set: BTreeSet<&[u8; 32]> = claims.iter().collect();
        let mut out = BTreeMap::new();
        for (k, b) in entries {
            let k: [u8; 32] = get_bytes(k, "entry key")?;
            if !set.contains(&k) {
                return Err(Error::Malformed("entry box key not in the claims"));
            }
            out.insert(k, entry_box_from_value(b)?);
        }
        Ok(ClaimSet { claims, entries: out })
    }

    pub fn contains(&self, key: &[u8; 32]) -> bool {
        self.claims.contains(key)
    }

    /// The entry box of a link key's static entry.
    pub fn entry_box(&self, sync_id: &SyncId, signing: &VerifyingKey) -> Option<&SecretBox> {
        self.entries.get(&static_entry(sync_id, signing))
    }

    /// Whether the set lists the public (spec/sync-ids.md §3): its public entry.
    pub fn lists_public(&self, sync_id: &SyncId) -> bool {
        self.contains(&public_entry(sync_id))
    }

    /// Whether the set fits sync ID `sync_id` (spec/wire.md §7 Entry box): an open-form box only
    /// under its public entry, a sealed one under any other. A set that does not is malformed.
    pub fn fits(&self, sync_id: &SyncId) -> bool {
        let public = public_entry(sync_id);
        self.entries.iter().all(|(k, b)| matches!(b, SecretBox::Open(_)) == (*k == public))
    }
}

/// An entry box (spec/wire.md §7): a canonical `box` value in the sealed or (the public entry's)
/// open form (an unknown case parks). Which entry may hold which form: `ClaimSet::fits`.
pub fn entry_box_from_value(v: &Value) -> Result<SecretBox, Error> {
    let b = SecretBox::from_value(v).map_err(|e| match e.kind {
        osis_schema::PathErrorKind::UnknownCase(c) => Error::Crypto(osis_crypto::Error::UnknownCase(c)),
        _ => Error::Malformed("entry box"),
    })?;
    if b.to_value() != *v || !matches!(&b, SecretBox::Sealed(_) | SecretBox::Open(_)) {
        return Err(Error::Malformed("entry box"));
    }
    Ok(b)
}

/// A reader of the registered read epoch (spec/sync-ids.md §3).
pub enum Reader<'a> {
    /// Listed by claim key: the X25519 half of its read-role KEM key (a node: its KEM key).
    Dh([u8; 32]),
    /// A link key, by static entry, with an entry box sealed to its first read keyset's KEM key.
    Static { signing: VerifyingKey, kem: &'a KemPublicKey },
    /// The public, by its public entry, with an open-form entry box: the read secrets and the
    /// sync secret where it reads (`reads`), the sync secret alone where it holds only sync.
    Public { reads: bool },
}

/// Who signs a new step.
pub enum Parent<'a> {
    /// A genesis step, signed by its own delete key (whose public key `keys.delete` must be).
    Genesis(&'a SigningSecret),
    /// A child of `step`, signed by that step's delete key.
    Child { step: &'a Step, delete: &'a SigningSecret },
}

/// Issues a step with a fresh step key, its claim set and entry boxes (spec/sync-ids.md §3): one
/// claim key per DH reader (a non-contributory result omits it), one static entry and entry box
/// per static reader, padded with random public keys to a power of two, shuffled. `read` is the
/// sync ID's thing, the registered read epoch and its secret; `sync` the sync epoch and
/// secret its sync key derives from. The step private key is dropped (zeroized) on return.
/// A step without rotation passes the parent's keys. Randomness in draw order: the step key
/// (32 bytes), per sealed entry box the seal's ephemeral key and ML-KEM randomness (32 + 32), 32
/// per padding key, 8 per shuffle swap.
pub fn register(parent: Parent, keys: StepKeys, readers: &[Reader], read: (&Tid, Epoch, &Secret32), sync: (Epoch, &Secret32), rng: &mut dyn CryptoRngCore) -> Result<(Step, ClaimSet), Error> {
    register_with(parent, keys, readers, read, sync, None, rng)
}

/// `register` with the entry boxes also carrying `earlier`, the read epoch the registered one's
/// rotation commit is wrapped under (spec/sync-ids.md §3).
pub fn register_with(parent: Parent, keys: StepKeys, readers: &[Reader], read: (&Tid, Epoch, &Secret32), sync: (Epoch, &Secret32), earlier: Option<(Epoch, &Secret32)>, rng: &mut dyn CryptoRngCore) -> Result<(Step, ClaimSet), Error> {
    let (sync_id, prev, signer) = match parent {
        Parent::Genesis(own) => {
            if own.verifying_key() != keys.delete {
                return Err(Error::Verify("genesis signer is not the step's delete key"));
            }
            (sync_id(&keys.delete), None, own)
        }
        Parent::Child { step, delete } => {
            if delete.verifying_key() != step.keys.delete {
                return Err(Error::Verify("signer is not the parent's delete key"));
            }
            (step.sync_id, Some(step.id()), delete)
        }
    };
    let step_secret = X25519Secret::random(rng);
    let step_key = step_secret.public();
    let slot = BoxSlot::Entry { sync_id, step_key, actor: *read.0 };
    let item = EntryItem { read: Some(EntryRead { epoch: read.1, secret: read.2.clone(), earlier: earlier.map(|(e, s)| (e, s.clone())) }), sync: (sync.0, sync.1.clone()) };
    let mut claims = Vec::new();
    let mut entries = BTreeMap::new();
    for r in readers {
        match r {
            Reader::Dh(pk) => {
                if let Ok(k) = claim_key(&step_secret, pk, &sync_id, &step_key) {
                    claims.push(k.verifying_key().to_bytes());
                }
            }
            Reader::Static { signing, kem } => {
                let e = static_entry(&sync_id, signing);
                claims.push(e);
                entries.insert(e, seal_entry_box(&slot, kem, &item, rng)?);
            }
            Reader::Public { reads } => {
                let e = public_entry(&sync_id);
                claims.push(e);
                let alone = EntryItem { read: None, sync: item.sync.clone() };
                entries.insert(e, SecretBox::Open(open_form_entry(&slot, if *reads { &item } else { &alone })?));
            }
        }
    }
    drop(step_secret);
    let total = claims.len().max(1).next_power_of_two();
    if total > MAX_CLAIMS {
        return Err(Error::TooLarge("claim set"));
    }
    while claims.len() < total {
        claims.push(SigningSecret::from_seed(&Secret32::random(rng)).verifying_key().to_bytes());
    }
    shuffle(&mut claims, rng);
    let set = ClaimSet { claims, entries };
    check_claim_set_size(set.to_bytes().len())?;
    let mut step = Step { sync_id, prev, keys, step_key, claims_hash: set.hash(), sig: Signature([0; 64]) };
    step.sig = signer.sign(Domain::SyncStep, &step.digest());
    Ok((step, set))
}

/// Fisher-Yates from the end; each draw is 8 bytes read as le64, reduced mod `i + 1`.
fn shuffle<T>(v: &mut [T], rng: &mut dyn CryptoRngCore) {
    for i in (1..v.len()).rev() {
        let mut b = [0u8; 8];
        rng.fill_bytes(&mut b);
        let bound = u64::try_from(i + 1).unwrap_or(u64::MAX);
        let j = usize::try_from(u64::from_le_bytes(b) % bound).unwrap_or(0);
        v.swap(i, j);
    }
}

fn seal_entry_box(slot: &BoxSlot, kem: &KemPublicKey, item: &EntryItem, rng: &mut dyn CryptoRngCore) -> Result<SecretBox, Error> {
    let sealed = seal_entry(kem, slot, item, rng)?;
    Ok(SecretBox::Sealed(SealedBox { keyset: None, suite: u64::from(osis_crypto::SUITE_1), sealed: Sealed::X25519MlKem768(sealed) }))
}

/// Opens an entry box of `step` of `t`'s sync ID with the link key's read KEM key: the read
/// secrets it carries, with the epochs of `t` they name (spec/sync-ids.md §3).
pub fn open_entry_box(b: &SecretBox, step: &Step, kem: &KemSecret, t: &Tid) -> Result<EntryItem, Error> {
    let slot = BoxSlot::Entry { sync_id: step.sync_id, step_key: step.step_key, actor: *t };
    let SecretBox::Sealed(sb) = b else { return Err(Error::Malformed("entry box form")) };
    let keyset = sb.keyset.as_ref().map(|e| Epoch::new(e.n, e.nonce)).transpose()?;
    let Sealed::X25519MlKem768(sealed) = &sb.sealed;
    Ok(open_entry(kem, &slot, BoxForm::Sealed { keyset, suite: sb.suite }, sealed)?)
}

/// Reads the public entry's box of `step` of `t`'s sync ID (open form, spec/sync-ids.md §3):
/// the secrets of the public's role it carries (read and sync, or only sync), with the epochs of
/// `t` they name. Anyone reads it.
pub fn read_public_entry_box(b: &SecretBox, step: &Step, t: &Tid) -> Result<EntryItem, Error> {
    let slot = BoxSlot::Entry { sync_id: step.sync_id, step_key: step.step_key, actor: *t };
    let SecretBox::Open(payload) = b else { return Err(Error::Malformed("entry box form")) };
    Ok(read_open_entry(&slot, payload)?)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use osis_base::Role;
    use osis_crypto::{KemSecret, SeededRng, SigningSecret, signing_key};
    use proptest::prelude::*;

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
        /// The sync epoch (n 0) of the test sync IDs' thing and its secret.
        pub fn sync_at(&self) -> (Epoch, &Secret32) {
            (Epoch::derive(&THING, osis_base::Role::Sync, 0, &self.sync).unwrap_or(Epoch::ZERO), &self.sync)
        }
        pub fn delete(&self) -> SigningSecret {
            role_key(RoleKey::Delete, &self.admin)
        }
    }

    /// The thing of test sync IDs.
    pub(crate) const THING: Tid = Tid::from_bytes([0x47; 15]);

    fn epoch(n: u64) -> Epoch {
        Epoch::new(n, [n as u8; 32]).unwrap()
    }

    // spec/wire.md §8, spec/sync-ids.md §3: genesis step bytes round trip; the ID is BLAKE3 of the
    // bytes; the sync ID hashes the genesis delete key; a child verifies under the parent's
    // delete key only; paths verify step by step.
    #[test]
    fn steps_and_paths() {
        let mut rng = SeededRng::from_u64(0);
        let g = Secrets::new(10);
        let (s0, c0) = register(Parent::Genesis(&g.delete()), g.keys(), &[], (&THING, epoch(0), &g.read), g.sync_at(), &mut rng).unwrap();
        assert_eq!(s0.sync_id, genesis_sync_id(&g.admin));
        assert_eq!(Step::parse(&s0.to_bytes()).unwrap(), s0);
        assert_eq!(s0.id().0, osis_base::hash::hash(&s0.to_bytes()));
        assert_eq!(s0.claims_hash, c0.hash());
        assert_eq!(c0.claims.len(), 1);
        s0.verify_genesis().unwrap();
        // Rotation: new admin secret, step signed by the old delete key.
        let g2 = Secrets::new(20);
        let k1 = StepKeys::derive(&g2.sync, &g2.write, &g2.admin, &g.deposit, &s0.sync_id);
        let (s1, _) = register(Parent::Child { step: &s0, delete: &g.delete() }, k1, &[], (&THING, epoch(1), &g2.read), g2.sync_at(), &mut rng).unwrap();
        s1.verify_child(&s0).unwrap();
        assert!(s1.verify_genesis().is_err());
        // Step without rotation: same keys, fresh step key.
        let (s2, _) = register(Parent::Child { step: &s1, delete: &g2.delete() }, s1.keys, &[], (&THING, epoch(1), &g2.read), g2.sync_at(), &mut rng).unwrap();
        assert_eq!(s2.keys, s1.keys);
        assert_ne!(s2.step_key, s1.step_key);
        verify_path(&s0.sync_id, &[s0.clone(), s1.clone(), s2.clone()]).unwrap();
        assert!(verify_path(&s0.sync_id, &[s0.clone(), s2.clone()]).is_err());
        assert!(verify_path(&s0.sync_id, std::slice::from_ref(&s1)).is_err());
        assert!(verify_path(&SyncId([0; 16]), std::slice::from_ref(&s0)).is_err());
        // Signer checks.
        assert!(register(Parent::Child { step: &s1, delete: &g.delete() }, s1.keys, &[], (&THING, epoch(1), &g2.read), g2.sync_at(), &mut rng).is_err());
        assert!(register(Parent::Genesis(&g2.delete()), g.keys(), &[], (&THING, epoch(0), &g.read), g.sync_at(), &mut rng).is_err());
        // A tampered field fails the signature.
        let mut t = s1.clone();
        t.claims_hash[0] ^= 1;
        assert!(t.verify_child(&s0).is_err());
    }

    // spec/wire.md §8, §1: step decoder rejections: wrong length, bad prev, bad key.
    #[test]
    fn step_rejections() {
        let mut rng = SeededRng::from_u64(0);
        let g = Secrets::new(30);
        let (s0, _) = register(Parent::Genesis(&g.delete()), g.keys(), &[], (&THING, epoch(0), &g.read), g.sync_at(), &mut rng).unwrap();
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
        let mut short_hash = items;
        short_hash[7] = Value::bytes(&[0; 31]);
        assert!(Step::from_value(&Value::List(short_hash)).is_err());
        assert!(Step::parse(&[0x80]).is_err());
    }

    // spec/sync-ids.md §3, spec/wire.md §8: DH readers derive their claim key from the step key;
    // static entries carry entry boxes that open to the read secret; non-contributory keys are
    // omitted; the set hashes into the step.
    #[test]
    fn claims_and_entry_boxes() {
        let mut rng = SeededRng::from_u64(0);
        let g = Secrets::new(40);
        // two link keys: a signing key, and their first read keyset's KEM key
        struct Link {
            signing: SigningSecret,
            kem: KemSecret,
        }
        let link_key = |b: u8| Link { signing: signing_key(&Secret32::from_bytes([b; 32])), kem: KemSecret::derive(&Secret32::from_bytes([b + 0x10; 32])) };
        let (m1, m2) = (KemSecret::derive(&Secret32::from_bytes([1; 32])), KemSecret::derive(&Secret32::from_bytes([2; 32])));
        let (link, card) = (link_key(3), link_key(4));
        let readers = [
            Reader::Dh(m1.public().x25519()),
            Reader::Dh(m2.public().x25519()),
            Reader::Dh([0; 32]),
            Reader::Static { signing: card.signing.verifying_key(), kem: card.kem.public() },
            Reader::Static { signing: link.signing.verifying_key(), kem: link.kem.public() },
        ];
        let e3 = Epoch::derive(&THING, Role::Read, 3, &g.read).unwrap();
        let (s0, c0) = register(Parent::Genesis(&g.delete()), g.keys(), &readers, (&THING, e3, &g.read), g.sync_at(), &mut rng).unwrap();
        assert_eq!(c0.claims.len(), 4);
        assert_eq!(ClaimSet::parse(&c0.to_bytes()).unwrap(), c0);
        assert_eq!(s0.claims_hash, c0.hash());
        for m in [&m1, &m2] {
            let k = s0.claim_key(m.x25519()).unwrap();
            assert!(c0.contains(&k.verifying_key().to_bytes()));
        }
        let outsider = KemSecret::derive(&Secret32::from_bytes([6; 32]));
        assert!(!c0.contains(&s0.claim_key(outsider.x25519()).unwrap().verifying_key().to_bytes()));
        let b = c0.entry_box(&s0.sync_id, &card.signing.verifying_key()).unwrap();
        let r3 = EntryRead { epoch: e3, secret: g.read.clone(), earlier: None };
        let want = EntryItem { read: Some(r3.clone()), sync: (g.sync_at().0, g.sync.clone()) };
        assert_eq!(open_entry_box(b, &s0, &card.kem, &THING).unwrap(), want);
        // read as another thing's, the secret names that thing's epoch (spec/crypto.md §4)
        let other = Tid::from_bytes([1; 15]);
        assert_ne!(open_entry_box(b, &s0, &card.kem, &other).unwrap().read.unwrap().epoch, e3);
        // a registrar naming an epoch the secret does not name boxes nothing
        assert!(register(Parent::Genesis(&g.delete()), g.keys(), &readers, (&THING, epoch(3), &g.read), g.sync_at(), &mut rng).is_err());
        let b = c0.entry_box(&s0.sync_id, &link.signing.verifying_key()).unwrap();
        assert_eq!(open_entry_box(b, &s0, &link.kem, &THING).unwrap(), want);
        assert!(open_entry_box(b, &s0, &card.kem, &THING).is_err());
        // Another step's slot does not open it.
        let (s1, _) = register(Parent::Child { step: &s0, delete: &g.delete() }, s0.keys, &[], (&THING, e3, &g.read), g.sync_at(), &mut rng).unwrap();
        let b = c0.entry_box(&s0.sync_id, &card.signing.verifying_key()).unwrap();
        assert!(open_entry_box(b, &s1, &card.kem, &THING).is_err());
        // the earlier read secret travels with it (spec/sync-ids.md §3)
        let e2 = Epoch::derive(&THING, osis_base::Role::Read, 2, &g.write).unwrap();
        let (s2, c2) = register_with(Parent::Child { step: &s0, delete: &g.delete() }, s0.keys, &readers, (&THING, e3, &g.read), g.sync_at(), Some((e2, &g.write)), &mut rng).unwrap();
        let b = c2.entry_box(&s2.sync_id, &card.signing.verifying_key()).unwrap();
        assert_eq!(open_entry_box(b, &s2, &card.kem, &THING).unwrap(), EntryItem { read: Some(EntryRead { earlier: Some((e2, g.write.clone())), ..r3 }), ..want });
    }

    // spec/sync-ids.md §3 (Entry boxes), spec/wire.md §7: the public listed by its public entry
    // with an open entry box, which anyone reads, carrying its role's secrets: the read secrets
    // and the sync secret where it reads, the sync secret alone where it holds only sync; the set
    // fits its sync ID only with the open box under that sync ID's public entry.
    #[test]
    fn the_public_entry_box_is_open() {
        let mut rng = SeededRng::from_u64(0);
        let g = Secrets::new(40);
        let e = Epoch::derive(&THING, Role::Read, 0, &g.read).unwrap();
        for reads in [true, false] {
            let (s0, c0) = register(Parent::Genesis(&g.delete()), g.keys(), &[Reader::Public { reads }], (&THING, e, &g.read), g.sync_at(), &mut rng).unwrap();
            assert!(c0.lists_public(&s0.sync_id) && c0.fits(&s0.sync_id));
            assert!(!c0.fits(&SyncId([1; 16])), "the open box under another sync ID's entry");
            assert_eq!(ClaimSet::parse(&c0.to_bytes()).unwrap(), c0);
            let b = c0.entries.get(&public_entry(&s0.sync_id)).unwrap();
            let read = reads.then(|| EntryRead { epoch: e, secret: g.read.clone(), earlier: None });
            assert_eq!(read_public_entry_box(b, &s0, &THING).unwrap(), EntryItem { read, sync: (g.sync_at().0, g.sync.clone()) });
        }
    }

    // spec/wire.md §8: claim set rejections: count not a power of two, entry key not among the
    // claims, wrong claim length, a box that is not a sealed `box` value.
    #[test]
    fn claim_set_rejections() {
        let c = |n: usize| Value::List((0..n).map(|i| Value::bytes(&[i as u8; 32])).collect());
        let set = |claims: Value, entries: Vec<(Value, Value)>| Value::List(vec![claims, Value::Map(entries.into_iter().collect())]);
        assert!(ClaimSet::from_value(&set(c(4), vec![])).is_ok());
        for n in [0, 3, 5] {
            assert!(ClaimSet::from_value(&set(c(n), vec![])).is_err(), "{n}");
        }
        let sealed = SecretBox::Sealed(SealedBox { keyset: None, suite: 1, sealed: Sealed::X25519MlKem768(vec![0; 1200]) }).to_value();
        assert!(ClaimSet::from_value(&set(c(2), vec![(Value::bytes(&[1; 32]), sealed.clone())])).is_ok());
        assert!(ClaimSet::from_value(&set(c(2), vec![(Value::bytes(&[9; 32]), sealed)])).is_err());
        // an entry box is sealed (spec/wire.md §7)
        let sym = SecretBox::Symmetric(osis_schema::core_types::SymmetricBox { epoch: osis_schema::core_types::Epoch { n: 1, nonce: [0; 32] }, wrap: vec![0; 49] }).to_value();
        assert!(ClaimSet::from_value(&set(c(2), vec![(Value::bytes(&[1; 32]), sym)])).is_err());
        assert!(ClaimSet::from_value(&set(c(2), vec![(Value::bytes(&[1; 32]), Value::Int(0))])).is_err());
        assert!(ClaimSet::from_value(&set(Value::List(vec![Value::bytes(&[0; 31])]), vec![])).is_err());
        let parked = Value::Enum(7, None);
        assert_eq!(ClaimSet::from_value(&set(c(1), vec![(Value::bytes(&[0; 32]), parked)])), Err(Error::Crypto(osis_crypto::Error::UnknownCase(7))));
    }

    // spec/wire.md §12: a claim set with its entry boxes is at most MAX_MESSAGE − 64 KiB, on
    // read and when registering.
    #[test]
    fn claim_set_size_cap() {
        let big = SecretBox::Sealed(SealedBox { keyset: None, suite: 1, sealed: Sealed::X25519MlKem768(vec![0; MAX_CLAIM_SET]) });
        let set = ClaimSet { claims: vec![[1; 32]], entries: [([1; 32], big)].into_iter().collect() };
        let b = set.to_bytes();
        assert!(b.len() > MAX_CLAIM_SET && b.len() < MAX_MESSAGE);
        assert_eq!(ClaimSet::parse(&b), Err(Error::Malformed("claim set above MAX_CLAIM_SET")));
        assert!(check_claim_set_size(MAX_CLAIM_SET).is_ok());
        assert!(matches!(check_claim_set_size(MAX_CLAIM_SET + 1), Err(Error::TooLarge(_))));
    }

    proptest! {
        // spec/sync-ids.md §3: the claim set size is the next power of two of the reader count, so
        // counts within one bucket give equal sizes; every slot is a valid Ed25519 key.
        #[test]
        fn claim_set_hides_count(n in 0usize..40, seed in any::<u64>()) {
            let mut rng = SeededRng::from_u64(seed);
            let g = Secrets::new(50);
            let ms: Vec<[u8; 32]> = (0..n).map(|_| X25519Secret::random(&mut rng).public()).collect();
            let readers: Vec<Reader> = ms.iter().map(|m| Reader::Dh(*m)).collect();
            let (_, c) = register(Parent::Genesis(&g.delete()), g.keys(), &readers, (&THING, epoch(0), &g.read), g.sync_at(), &mut rng).unwrap();
            prop_assert_eq!(c.claims.len(), n.max(1).next_power_of_two());
            prop_assert!(c.claims.iter().all(|k| VerifyingKey::from_bytes(k).is_ok()));
        }
    }

    // spec/sync-ids.md §3: a claim key verifies at its own step only (fresh step key per step).
    #[test]
    fn claim_key_per_step() {
        let mut rng = SeededRng::from_u64(0);
        let g = Secrets::new(60);
        let m = X25519Secret::random(&mut rng);
        let r = [Reader::Dh(m.public())];
        let (s0, c0) = register(Parent::Genesis(&g.delete()), g.keys(), &r, (&THING, epoch(0), &g.read), g.sync_at(), &mut rng).unwrap();
        let (s1, c1) = register(Parent::Child { step: &s0, delete: &g.delete() }, s0.keys, &r, (&THING, epoch(0), &g.read), g.sync_at(), &mut rng).unwrap();
        let k0 = s0.claim_key(&m).unwrap().verifying_key().to_bytes();
        let k1 = s1.claim_key(&m).unwrap().verifying_key().to_bytes();
        assert!(c0.contains(&k0) && c1.contains(&k1));
        assert!(!c1.contains(&k0) && !c0.contains(&k1));
    }
}
