//! Labels: role keys, registration steps, step IDs and paths, claim sets with claim keys and
//! static entries, entry boxes (spec/sync.md §2, §5, spec/wire.md §8, §7).

use crate::cbor::{get_bytes, get_key};
use crate::Error;
use osis_base::cbor::{Limits, decode, encode};
use osis_base::format::{MAX_CLAIMS, MAX_MESSAGE, MAX_OBJECT_DEPTH};
use osis_base::{LabelId, Role, Value};
use osis_crypto::{
    BoxForm, BoxItem, BoxSlot, CryptoRngCore, Domain, Epoch, KemPublicKey, KemSecret, LabelRole, Secret32, Signature, SigningSecret,
    VerifyingKey, X25519Secret, claim_key, deposit_key, label_id, label_role_key, open_box, open_symmetric_box, seal_box, static_entry,
    wrap_symmetric_box,
};
use osis_schema::Codec;
use osis_schema::core_types::{Epoch as EpochValue, SealedBox, SecretBox, Sealed, SymmetricBox};
use std::collections::{BTreeMap, BTreeSet};

/// BLAKE3 of a step's canonical bytes.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct StepId(pub [u8; 32]);

/// A registration step (spec/wire.md §8).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Step {
    pub label: LabelId,
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
    /// Role public keys at `index` from the group's role secrets, deposit key from the actor's
    /// deposit seed (spec/sync.md §2).
    pub fn derive(read: &Secret32, write: &Secret32, admin: &Secret32, index: u64, deposit_seed: &Secret32, label: &LabelId) -> StepKeys {
        StepKeys {
            sync: label_role_key(LabelRole::Sync, read, index).verifying_key(),
            write: label_role_key(LabelRole::Write, write, index).verifying_key(),
            delete: label_role_key(LabelRole::Delete, admin, index).verifying_key(),
            deposit: deposit_key(deposit_seed, label).verifying_key(),
        }
    }

    pub fn get(&self, role: LabelRole) -> &VerifyingKey {
        match role {
            LabelRole::Sync => &self.sync,
            LabelRole::Write => &self.write,
            LabelRole::Delete => &self.delete,
        }
    }
}

/// Label ID of the label at `index` whose genesis derives from `admin` (spec/sync.md §2).
pub fn genesis_label(admin: &Secret32, index: u64) -> LabelId {
    label_id(&label_role_key(LabelRole::Delete, admin, index).verifying_key())
}

/// Index into `candidates` of the role secret whose label key at `index` is `pk`: which held
/// epoch a server's head registers (spec/sync.md §2).
pub fn match_secret<'a>(pk: &VerifyingKey, role: LabelRole, index: u64, candidates: impl IntoIterator<Item = &'a Secret32>) -> Option<usize> {
    candidates.into_iter().position(|s| label_role_key(role, s, index).verifying_key() == *pk)
}

/// Limits for steps, claim sets and the structures holding them (spec/wire.md §13).
pub(crate) const OBJECT_LIMITS: Limits = Limits { max_depth: MAX_OBJECT_DEPTH, max_bytes: MAX_MESSAGE };

/// Largest encoded claim set with its entry boxes, so a step and its set fit one message
/// (spec/wire.md §13).
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
            Value::bytes(&self.label.0),
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
        let [label, prev, sync, write, delete, deposit, step_key, claims_hash, sig] = items.as_slice() else {
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
            label: LabelId(get_bytes(label, "step label")?),
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

    /// A genesis step: no `prev`, signed by its own delete key, which hashes to the label ID.
    pub fn verify_genesis(&self) -> Result<(), Error> {
        if self.prev.is_some() {
            return Err(Error::Verify("genesis step has prev"));
        }
        if label_id(&self.keys.delete) != self.label {
            return Err(Error::Verify("genesis delete key does not hash to the label ID"));
        }
        self.keys.delete.verify(Domain::LabelRegister, &self.digest(), &self.sig).map_err(|_| Error::Verify("step signature"))
    }

    /// A child of `parent`: same label, `prev` its ID, signed by its delete key.
    pub fn verify_child(&self, parent: &Step) -> Result<(), Error> {
        if self.label != parent.label || self.prev != Some(parent.id()) {
            return Err(Error::Verify("step is not a child"));
        }
        parent.keys.delete.verify(Domain::LabelRegister, &self.digest(), &self.sig).map_err(|_| Error::Verify("step signature"))
    }

    /// The claim key a reader derives from its X25519 private key (spec/sync.md §2); try each
    /// keyset epoch held.
    pub fn claim_key(&self, own: &X25519Secret) -> Result<SigningSecret, Error> {
        Ok(claim_key(own, &self.step_key, &self.label, &self.step_key)?)
    }
}

/// Verifies a registration path: the genesis step of `label`, then each step a child of the one
/// before (spec/sync.md §5).
pub fn verify_path(label: &LabelId, path: &[Step]) -> Result<(), Error> {
    let (first, rest) = path.split_first().ok_or(Error::Verify("empty path"))?;
    if first.label != *label {
        return Err(Error::Verify("path of another label"));
    }
    first.verify_genesis()?;
    let mut parent = first;
    for s in rest {
        s.verify_child(parent)?;
        parent = s;
    }
    Ok(())
}

/// The verified path from the genesis step to `head` through a set of steps (the tree by
/// `prev`, as `/label` holds it).
pub fn path_to(steps: &BTreeMap<StepId, Step>, head: &StepId) -> Result<Vec<Step>, Error> {
    let mut path = Vec::new();
    let mut at = Some(*head);
    while let Some(id) = at {
        if path.len() > steps.len() {
            return Err(Error::Verify("step cycle"));
        }
        let s = steps.get(&id).ok_or(Error::Verify("step missing on the path"))?;
        if s.id() != id {
            return Err(Error::Verify("step ID"));
        }
        at = s.prev;
        path.push(s.clone());
    }
    path.reverse();
    let label = path.first().map(|s| s.label).ok_or(Error::Verify("empty path"))?;
    verify_path(&label, &path)?;
    Ok(path)
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
            out.insert(k, parse_box(b)?);
        }
        Ok(ClaimSet { claims, entries: out })
    }

    pub fn contains(&self, key: &[u8; 32]) -> bool {
        self.claims.contains(key)
    }

    /// The entry box of a key actor's static entry.
    pub fn entry_box(&self, label: &LabelId, signing: &VerifyingKey) -> Option<&SecretBox> {
        self.entries.get(&static_entry(label, signing))
    }
}

/// A `box` value, strictly: it must re-encode to itself.
fn parse_box(v: &Value) -> Result<SecretBox, Error> {
    let b = SecretBox::from_value(v).map_err(|e| match e.kind {
        osis_schema::PathErrorKind::UnknownCase(c) => Error::Crypto(osis_crypto::Error::UnknownCase(c)),
        _ => Error::Malformed("entry box"),
    })?;
    if b.to_value() != *v {
        return Err(Error::Malformed("entry box"));
    }
    Ok(b)
}

/// A reader of the registered read epoch (spec/sync.md §2).
pub enum Reader<'a> {
    /// Listed by claim key: the X25519 half of its read-role KEM key (a node: its KEM key).
    Dh([u8; 32]),
    /// A key actor other than a node, by static entry, with an entry box.
    Static { signing: VerifyingKey, entry: EntryTo<'a> },
}

/// How an entry box reaches its key actor (spec/crypto.md §4 forms).
pub enum EntryTo<'a> {
    /// Sealed to its KEM key.
    Sealed(&'a KemPublicKey),
    /// Wrapped under `kdf("box", s)`, s its own read secret of epoch `epoch_s`, when the
    /// registrar holds s (a link key's seed holder).
    Symmetric { s: &'a Secret32, epoch_s: Epoch },
}

/// Who signs a new step.
pub enum Parent<'a> {
    /// A genesis step, signed by its own delete key (whose public key `keys.delete` must be).
    Genesis(&'a SigningSecret),
    /// A child of `step`, signed by that step's delete key.
    Child { step: &'a Step, delete: &'a SigningSecret },
}

/// Issues a step with a fresh step key, its claim set and entry boxes (spec/sync.md §2): one
/// claim key per DH reader (a non-contributory result omits it), one static entry and entry box
/// per key actor, padded with random public keys to a power of two, shuffled. `read` is the
/// registered read epoch and its secret. The step private key is dropped (zeroized) on return.
/// A step without rotation passes the parent's keys. Randomness in draw order: the step key
/// (32 bytes), per sealed entry box the seal's ephemeral key and ML-KEM randomness (32 + 32), 32
/// per padding key, 8 per shuffle swap.
pub fn register(parent: Parent, keys: StepKeys, readers: &[Reader], read: (Epoch, &Secret32), rng: &mut dyn CryptoRngCore) -> Result<(Step, ClaimSet), Error> {
    let (label, prev, signer) = match parent {
        Parent::Genesis(own) => {
            if own.verifying_key() != keys.delete {
                return Err(Error::Verify("genesis signer is not the step's delete key"));
            }
            (label_id(&keys.delete), None, own)
        }
        Parent::Child { step, delete } => {
            if delete.verifying_key() != step.keys.delete {
                return Err(Error::Verify("signer is not the parent's delete key"));
            }
            (step.label, Some(step.id()), delete)
        }
    };
    let step_secret = X25519Secret::random(rng);
    let step_key = step_secret.public();
    let slot = BoxSlot::Entry { label, step_key };
    let mut claims = Vec::new();
    let mut entries = BTreeMap::new();
    for r in readers {
        match r {
            Reader::Dh(pk) => {
                if let Ok(k) = claim_key(&step_secret, pk, &label, &step_key) {
                    claims.push(k.verifying_key().to_bytes());
                }
            }
            Reader::Static { signing, entry } => {
                let e = static_entry(&label, signing);
                claims.push(e);
                entries.insert(e, seal_entry(&slot, entry, read.0, read.1, rng)?);
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
    let mut step = Step { label, prev, keys, step_key, claims_hash: set.hash(), sig: Signature([0; 64]) };
    step.sig = signer.sign(Domain::LabelRegister, &step.digest());
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

fn epoch_value(e: &Epoch) -> EpochValue {
    EpochValue { n: e.n(), nonce: *e.nonce() }
}

fn seal_entry(slot: &BoxSlot, to: &EntryTo, epoch: Epoch, secret: &Secret32, rng: &mut dyn CryptoRngCore) -> Result<SecretBox, Error> {
    Ok(match to {
        EntryTo::Sealed(pk) => {
            let item = BoxItem { role: Role::Read, epoch, secret: secret.clone() };
            let sealed = seal_box(pk, slot, None, &[item], rng)?;
            SecretBox::Sealed(SealedBox { keyset: None, suite: u64::from(osis_crypto::SUITE_1), sealed: Sealed::X25519MlKem768(sealed) })
        }
        EntryTo::Symmetric { s, epoch_s } => {
            let wrap = wrap_symmetric_box(s, slot, *epoch_s, secret)?;
            SecretBox::Symmetric(SymmetricBox { epoch: epoch_value(epoch_s), wrap: wrap.to_vec() })
        }
    })
}

/// A key actor's key for its entry box.
pub enum EntryKey<'a> {
    Kem(&'a KemSecret),
    /// Its own read secret s (the symmetric form names the epoch of s).
    Symmetric(&'a Secret32),
}

/// Opens an entry box of `step`: the read secret, with its epoch for the sealed form.
pub fn open_entry_box(b: &SecretBox, step: &Step, key: EntryKey) -> Result<(Option<Epoch>, Secret32), Error> {
    let slot = BoxSlot::Entry { label: step.label, step_key: step.step_key };
    match (b, key) {
        (SecretBox::Sealed(sb), EntryKey::Kem(kem)) => {
            let keyset = sb.keyset.as_ref().map(|e| Epoch::new(e.n, e.nonce)).transpose()?;
            let Sealed::X25519MlKem768(sealed) = &sb.sealed;
            let items = open_box(kem, &slot, BoxForm::Sealed { keyset, suite: sb.suite }, sealed)?;
            match items.as_slice() {
                [BoxItem { role: Role::Read, epoch, secret }] => Ok((Some(*epoch), secret.clone())),
                _ => Err(Error::Malformed("entry box carries other than the read secret")),
            }
        }
        (SecretBox::Symmetric(sb), EntryKey::Symmetric(s)) => {
            let epoch_s = Epoch::new(sb.epoch.n, sb.epoch.nonce)?;
            Ok((None, open_symmetric_box(s, &slot, epoch_s, &sb.wrap)?))
        }
        _ => Err(Error::Malformed("entry box form")),
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use osis_crypto::{KeyActorKeys, SeededRng};
    use proptest::prelude::*;

    pub(crate) struct Group {
        pub read: Secret32,
        pub write: Secret32,
        pub admin: Secret32,
        pub deposit: Secret32,
    }

    impl Group {
        pub fn new(b: u8) -> Group {
            Group { read: Secret32::from_bytes([b; 32]), write: Secret32::from_bytes([b + 1; 32]), admin: Secret32::from_bytes([b + 2; 32]), deposit: Secret32::from_bytes([b + 3; 32]) }
        }
        pub fn keys(&self, index: u64) -> StepKeys {
            StepKeys::derive(&self.read, &self.write, &self.admin, index, &self.deposit, &genesis_label(&self.admin, index))
        }
        pub fn delete(&self, index: u64) -> SigningSecret {
            label_role_key(LabelRole::Delete, &self.admin, index)
        }
    }

    fn epoch(n: u64) -> Epoch {
        Epoch::new(n, [n as u8; 16]).unwrap()
    }

    // spec/wire.md §8, spec/sync.md §2: genesis step bytes round trip; the ID is BLAKE3 of the
    // bytes; the label ID hashes the genesis delete key; a child verifies under the parent's
    // delete key only; paths verify step by step.
    #[test]
    fn steps_and_paths() {
        let mut rng = SeededRng::from_u64(1);
        let g = Group::new(10);
        let (s0, c0) = register(Parent::Genesis(&g.delete(0)), g.keys(0), &[], (epoch(0), &g.read), &mut rng).unwrap();
        assert_eq!(s0.label, genesis_label(&g.admin, 0));
        assert_eq!(Step::parse(&s0.to_bytes()).unwrap(), s0);
        assert_eq!(s0.id().0, osis_base::hash::hash(&s0.to_bytes()));
        assert_eq!(s0.claims_hash, c0.hash());
        assert_eq!(c0.claims.len(), 1);
        s0.verify_genesis().unwrap();
        // Rotation: new admin secret, step signed by the old delete key.
        let g2 = Group::new(20);
        let k1 = StepKeys::derive(&g2.read, &g2.write, &g2.admin, 0, &g.deposit, &s0.label);
        let (s1, _) = register(Parent::Child { step: &s0, delete: &g.delete(0) }, k1, &[], (epoch(1), &g2.read), &mut rng).unwrap();
        s1.verify_child(&s0).unwrap();
        assert!(s1.verify_genesis().is_err());
        // Step without rotation: same keys, fresh step key.
        let (s2, _) = register(Parent::Child { step: &s1, delete: &g2.delete(0) }, s1.keys, &[], (epoch(1), &g2.read), &mut rng).unwrap();
        assert_eq!(s2.keys, s1.keys);
        assert_ne!(s2.step_key, s1.step_key);
        verify_path(&s0.label, &[s0.clone(), s1.clone(), s2.clone()]).unwrap();
        assert!(verify_path(&s0.label, &[s0.clone(), s2.clone()]).is_err());
        assert!(verify_path(&s0.label, std::slice::from_ref(&s1)).is_err());
        assert!(verify_path(&LabelId([0; 16]), std::slice::from_ref(&s0)).is_err());
        let map: BTreeMap<StepId, Step> = [&s0, &s1, &s2].into_iter().map(|s| (s.id(), s.clone())).collect();
        assert_eq!(path_to(&map, &s2.id()).unwrap(), vec![s0.clone(), s1.clone(), s2.clone()]);
        // Signer checks.
        assert!(register(Parent::Child { step: &s1, delete: &g.delete(0) }, s1.keys, &[], (epoch(1), &g2.read), &mut rng).is_err());
        assert!(register(Parent::Genesis(&g.delete(1)), g.keys(0), &[], (epoch(0), &g.read), &mut rng).is_err());
        // A tampered field fails the signature.
        let mut t = s1.clone();
        t.claims_hash[0] ^= 1;
        assert!(t.verify_child(&s0).is_err());
        // Role key matching.
        assert_eq!(match_secret(&s1.keys.sync, LabelRole::Sync, 0, [&g.read, &g2.read]), Some(1));
    }

    // spec/wire.md §8, §1: step decoder rejections: wrong length, bad prev, bad key.
    #[test]
    fn step_rejections() {
        let mut rng = SeededRng::from_u64(2);
        let g = Group::new(30);
        let (s0, _) = register(Parent::Genesis(&g.delete(0)), g.keys(0), &[], (epoch(0), &g.read), &mut rng).unwrap();
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

    // spec/sync.md §2, spec/wire.md §8: DH readers derive their claim key from the step key;
    // static entries carry entry boxes that open to the read secret; non-contributory keys are
    // omitted; the set hashes into the step.
    #[test]
    fn claims_and_entry_boxes() {
        let mut rng = SeededRng::from_u64(3);
        let g = Group::new(40);
        let m1 = KeyActorKeys::from_seed(&Secret32::from_bytes([1; 32]));
        let m2 = KeyActorKeys::from_seed(&Secret32::from_bytes([2; 32]));
        let link = KeyActorKeys::from_seed(&Secret32::from_bytes([3; 32]));
        let card = KeyActorKeys::from_seed(&Secret32::from_bytes([4; 32]));
        let s_link = Secret32::from_bytes([5; 32]);
        let readers = [
            Reader::Dh(m1.kem.public().x25519()),
            Reader::Dh(m2.kem.public().x25519()),
            Reader::Dh([0; 32]),
            Reader::Static { signing: card.signing.verifying_key(), entry: EntryTo::Sealed(card.kem.public()) },
            Reader::Static { signing: link.signing.verifying_key(), entry: EntryTo::Symmetric { s: &s_link, epoch_s: epoch(9) } },
        ];
        let (s0, c0) = register(Parent::Genesis(&g.delete(0)), g.keys(0), &readers, (epoch(3), &g.read), &mut rng).unwrap();
        assert_eq!(c0.claims.len(), 4);
        assert_eq!(ClaimSet::parse(&c0.to_bytes()).unwrap(), c0);
        assert_eq!(s0.claims_hash, c0.hash());
        for m in [&m1, &m2] {
            let k = s0.claim_key(m.kem.x25519()).unwrap();
            assert!(c0.contains(&k.verifying_key().to_bytes()));
        }
        let outsider = KeyActorKeys::from_seed(&Secret32::from_bytes([6; 32]));
        assert!(!c0.contains(&s0.claim_key(outsider.kem.x25519()).unwrap().verifying_key().to_bytes()));
        let b = c0.entry_box(&s0.label, &card.signing.verifying_key()).unwrap();
        let (e, s) = open_entry_box(b, &s0, EntryKey::Kem(&card.kem)).unwrap();
        assert_eq!((e, s), (Some(epoch(3)), g.read.clone()));
        let b = c0.entry_box(&s0.label, &link.signing.verifying_key()).unwrap();
        assert_eq!(open_entry_box(b, &s0, EntryKey::Symmetric(&s_link)).unwrap(), (None, g.read.clone()));
        assert!(open_entry_box(b, &s0, EntryKey::Symmetric(&g.read)).is_err());
        assert!(open_entry_box(b, &s0, EntryKey::Kem(&card.kem)).is_err());
        // Another step's slot does not open it.
        let (s1, _) = register(Parent::Child { step: &s0, delete: &g.delete(0) }, s0.keys, &[], (epoch(3), &g.read), &mut rng).unwrap();
        let b = c0.entry_box(&s0.label, &card.signing.verifying_key()).unwrap();
        assert!(open_entry_box(b, &s1, EntryKey::Kem(&card.kem)).is_err());
    }

    // spec/wire.md §8: claim set rejections: count not a power of two, entry key not among the
    // claims, wrong claim length, a box that is not a `box` value.
    #[test]
    fn claim_set_rejections() {
        let c = |n: usize| Value::List((0..n).map(|i| Value::bytes(&[i as u8; 32])).collect());
        let set = |claims: Value, entries: Vec<(Value, Value)>| Value::List(vec![claims, Value::Map(entries.into_iter().collect())]);
        assert!(ClaimSet::from_value(&set(c(4), vec![])).is_ok());
        for n in [0, 3, 5] {
            assert!(ClaimSet::from_value(&set(c(n), vec![])).is_err(), "{n}");
        }
        let sym = SecretBox::Symmetric(SymmetricBox { epoch: EpochValue { n: 1, nonce: [0; 16] }, wrap: vec![0; 49] }).to_value();
        assert!(ClaimSet::from_value(&set(c(2), vec![(Value::bytes(&[1; 32]), sym.clone())])).is_ok());
        assert!(ClaimSet::from_value(&set(c(2), vec![(Value::bytes(&[9; 32]), sym)])).is_err());
        assert!(ClaimSet::from_value(&set(c(2), vec![(Value::bytes(&[1; 32]), Value::Int(0))])).is_err());
        assert!(ClaimSet::from_value(&set(Value::List(vec![Value::bytes(&[0; 31])]), vec![])).is_err());
        let parked = Value::Enum(7, None);
        assert_eq!(ClaimSet::from_value(&set(c(1), vec![(Value::bytes(&[0; 32]), parked)])), Err(Error::Crypto(osis_crypto::Error::UnknownCase(7))));
    }

    // spec/wire.md §13: a claim set with its entry boxes is at most MAX_MESSAGE − 64 KiB, on
    // read and when registering.
    #[test]
    fn claim_set_size_cap() {
        let big = SecretBox::Symmetric(SymmetricBox { epoch: EpochValue { n: 1, nonce: [0; 16] }, wrap: vec![0; MAX_CLAIM_SET] });
        let set = ClaimSet { claims: vec![[1; 32]], entries: [([1; 32], big)].into_iter().collect() };
        let b = set.to_bytes();
        assert!(b.len() > MAX_CLAIM_SET && b.len() < MAX_MESSAGE);
        assert_eq!(ClaimSet::parse(&b), Err(Error::Malformed("claim set above MAX_CLAIM_SET")));
        assert!(check_claim_set_size(MAX_CLAIM_SET).is_ok());
        assert!(matches!(check_claim_set_size(MAX_CLAIM_SET + 1), Err(Error::TooLarge(_))));
    }

    proptest! {
        // spec/sync.md §2: the claim set size is the next power of two of the reader count, so
        // counts within one bucket give equal sizes; every slot is a valid Ed25519 key.
        #[test]
        fn claim_set_hides_count(n in 0usize..40, seed in any::<u64>()) {
            let mut rng = SeededRng::from_u64(seed);
            let g = Group::new(50);
            let ms: Vec<[u8; 32]> = (0..n).map(|_| X25519Secret::random(&mut rng).public()).collect();
            let readers: Vec<Reader> = ms.iter().map(|m| Reader::Dh(*m)).collect();
            let (_, c) = register(Parent::Genesis(&g.delete(0)), g.keys(0), &readers, (epoch(0), &g.read), &mut rng).unwrap();
            prop_assert_eq!(c.claims.len(), n.max(1).next_power_of_two());
            prop_assert!(c.claims.iter().all(|k| VerifyingKey::from_bytes(k).is_ok()));
        }

        // spec/sync.md §2: a claim key verifies at its own step only (fresh step key per step).
        #[test]
        fn claim_key_per_step(seed in any::<u64>()) {
            let mut rng = SeededRng::from_u64(seed);
            let g = Group::new(60);
            let m = X25519Secret::random(&mut rng);
            let r = [Reader::Dh(m.public())];
            let (s0, c0) = register(Parent::Genesis(&g.delete(0)), g.keys(0), &r, (epoch(0), &g.read), &mut rng).unwrap();
            let (s1, c1) = register(Parent::Child { step: &s0, delete: &g.delete(0) }, s0.keys, &r, (epoch(0), &g.read), &mut rng).unwrap();
            let k0 = s0.claim_key(&m).unwrap().verifying_key().to_bytes();
            let k1 = s1.claim_key(&m).unwrap().verifying_key().to_bytes();
            prop_assert!(c0.contains(&k0) && c1.contains(&k1));
            prop_assert!(!c1.contains(&k0) && !c0.contains(&k1));
        }
    }
}
