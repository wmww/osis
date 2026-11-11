//! Signatures of label operations and their checks at a host (spec/sync.md §5, spec/wire.md
//! §9, §11.2): open proofs and their evaluation against a registration path, stamps, deposits,
//! deletes by the label delete key or by a delete-key signature.

use crate::blob::{Level, Prefix};
use crate::cbor::{get_bytes, get_key, get_uint};
use crate::step::{Step, StepId};
use crate::Error;
use osis_base::cbor::encode;
use osis_base::format::{DELETE_ADMIN, DELETE_WRITER};
use osis_base::{BlobId, LabelId, Value};
use osis_crypto::{DeleteSecret, Domain, LabelRole, Signature, SigningSecret, VerifyingKey, sign_open, static_entry, verify_delete, verify_open};
use osis_schema::core_types::SecretBox;

/// Open proof (spec/wire.md §11.2): `[0, Opt(step_id), sync_pk, sig] | [1, step_id, claim_pk,
/// sig] | [2, signing_pk, sig] | [3]`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Proof {
    /// A sync key, at the step it is for when the opener holds one (a hint's holds none).
    Sync { step: Option<StepId>, pk: VerifyingKey, sig: Signature },
    Claim { step: StepId, pk: VerifyingKey, sig: Signature },
    Static { signing: VerifyingKey, sig: Signature },
}

impl Proof {
    pub fn sync(step: Option<StepId>, key: &SigningSecret, label: &LabelId, challenge: &[u8; 32], static_key: &[u8; 32]) -> Proof {
        Proof::Sync { step, pk: key.verifying_key(), sig: sign_open(key, label, challenge, static_key) }
    }
    pub fn claim(step: StepId, key: &SigningSecret, label: &LabelId, challenge: &[u8; 32], static_key: &[u8; 32]) -> Proof {
        Proof::Claim { step, pk: key.verifying_key(), sig: sign_open(key, label, challenge, static_key) }
    }
    /// By a key actor's signing key (its static entry).
    pub fn static_entry(signing: &SigningSecret, label: &LabelId, challenge: &[u8; 32], static_key: &[u8; 32]) -> Proof {
        Proof::Static { signing: signing.verifying_key(), sig: sign_open(signing, label, challenge, static_key) }
    }

    pub fn to_value(&self) -> Value {
        Value::List(match self {
            Proof::Sync { step, pk, sig } => vec![Value::Int(0), Value::List(step.iter().map(|s| Value::bytes(&s.0)).collect()), Value::bytes(&pk.to_bytes()), Value::bytes(&sig.0)],
            Proof::Claim { step, pk, sig } => vec![Value::Int(1), Value::bytes(&step.0), Value::bytes(&pk.to_bytes()), Value::bytes(&sig.0)],
            Proof::Static { signing, sig } => vec![Value::Int(2), Value::bytes(&signing.to_bytes()), Value::bytes(&sig.0)],
        })
    }

    pub fn from_value(v: &Value) -> Result<Proof, Error> {
        let Value::List(items) = v else { return Err(Error::Malformed("proof")) };
        let key = |v: &Value| get_key(v, "proof key");
        let sig = |v: &Value| get_bytes(v, "proof signature").map(Signature);
        Ok(match items.as_slice() {
            [Value::Int(0), Value::List(step), pk, s] => {
                let step = match step.as_slice() {
                    [] => None,
                    [id] => Some(StepId(get_bytes(id, "proof step")?)),
                    _ => return Err(Error::Malformed("proof step")),
                };
                Proof::Sync { step, pk: key(pk)?, sig: sig(s)? }
            }
            [Value::Int(1), step, pk, s] => Proof::Claim { step: StepId(get_bytes(step, "proof step")?), pk: key(pk)?, sig: sig(s)? },
            [Value::Int(2), pk, s] => Proof::Static { signing: key(pk)?, sig: sig(s)? },
            _ => return Err(Error::Malformed("proof")),
        })
    }

    /// The signature over (label ID, challenge, static key) of the opened side.
    pub fn verify_sig(&self, label: &LabelId, challenge: &[u8; 32], static_key: &[u8; 32]) -> Result<(), Error> {
        let (Proof::Sync { pk, sig, .. } | Proof::Claim { pk, sig, .. } | Proof::Static { signing: pk, sig }) = self;
        verify_open(pk, label, challenge, static_key, sig).map_err(|_| Error::Verify("open signature"))
    }
}

/// What a host answers an open with (spec/sync.md §5).
#[derive(Clone, Debug, PartialEq, Eq)]
#[allow(clippy::large_enum_variant)] // one per Open, consumed at once
pub enum OpenOutcome {
    /// The label is open on the connection; for a static proof, with the head's entry box.
    Opened(Option<SecretBox>),
    /// A match at a superseded step: its child on the path (sent without its claim set).
    Child(Step),
    /// Refused like an unknown key.
    Refused,
}

/// What `evaluate_open` reads of a host's path besides its head: indexes the store keeps as
/// steps are added, so an open costs a constant number of lookups however long the path.
pub trait PathIndex {
    type Error;
    /// The newest step on the path registering sync key `pk`.
    fn step_with_sync(&self, pk: &VerifyingKey) -> Result<Option<StepId>, Self::Error>;
    /// Step `step` when it is on the path.
    fn step(&self, step: &StepId) -> Result<Option<Step>, Self::Error>;
    /// Whether `key` (a claim key or a static entry) is in the held claim set of step `step` on
    /// the path, with its entry box if it has one; none if not, or the set is not held. A
    /// lookup, never a whole set: a stranger's Open must not cost a claim set's size.
    fn claim(&self, step: &StepId, key: &[u8; 32]) -> Result<Option<Option<SecretBox>>, Self::Error>;
    /// The child on the path of a step on it; none past the head.
    fn child(&self, step: &StepId) -> Result<Option<Step>, Self::Error>;
}

/// Evaluates an open against a host's head and its path indexes. The signature is checked
/// first. A sync key matches the head, else the superseded step it names when it bears that
/// key (steps without a rotation share it, so only the step says which child the opener can
/// verify), else, naming none, the newest superseded step bearing it; a claim at
/// step j needs V in j's set (head: open; on the path: its child); a static proof needs the
/// key's static entry in the head's set. At most three lookups.
pub fn evaluate_open<I: PathIndex>(head: &Step, index: &I, proof: &Proof, challenge: &[u8; 32], static_key: &[u8; 32]) -> Result<OpenOutcome, I::Error> {
    if proof.verify_sig(&head.label, challenge, static_key).is_err() {
        return Ok(OpenOutcome::Refused);
    }
    let child_of = |s: &StepId| Ok(index.child(s)?.map_or(OpenOutcome::Refused, OpenOutcome::Child));
    match proof {
        Proof::Sync { pk, .. } if head.keys.sync == *pk => Ok(OpenOutcome::Opened(None)),
        Proof::Sync { step: Some(step), pk, .. } => match index.step(step)? {
            Some(s) if s.keys.sync == *pk => child_of(step),
            _ => Ok(OpenOutcome::Refused),
        },
        Proof::Sync { step: None, pk, .. } => match index.step_with_sync(pk)? {
            Some(s) => child_of(&s),
            None => Ok(OpenOutcome::Refused),
        },
        Proof::Claim { step, pk, .. } => {
            if index.claim(step, &pk.to_bytes())?.is_none() {
                return Ok(OpenOutcome::Refused);
            }
            if *step == head.id() { Ok(OpenOutcome::Opened(None)) } else { child_of(step) }
        }
        Proof::Static { signing, .. } => {
            let e = static_entry(&head.label, signing);
            Ok(match index.claim(&head.id(), &e)? {
                Some(entry_box) => OpenOutcome::Opened(entry_box),
                None => OpenOutcome::Refused,
            })
        }
    }
}

/// Digest of a stamp, deposit or publish authorization: BLAKE3 of canonical
/// `[label_id, blob_id, wrap]`.
pub fn entry_digest(label: &LabelId, blob: &BlobId, wrap: &[u8]) -> [u8; 32] {
    osis_base::hash::hash(&encode(&Value::List(vec![Value::bytes(&label.0), Value::bytes(&blob.0), Value::bytes(wrap)])))
}

/// A stamp: the label write key's signature under `"osis v1 upload"`.
pub fn sign_stamp(write: &SigningSecret, label: &LabelId, blob: &BlobId, wrap: &[u8]) -> Signature {
    write.sign(Domain::Upload, &entry_digest(label, blob, wrap))
}

/// Checks a stamp against the head's write key; an altered wrap fails.
pub fn verify_stamp(head_write: &VerifyingKey, label: &LabelId, blob: &BlobId, wrap: &[u8], stamp: &Signature) -> Result<(), Error> {
    head_write.verify(Domain::Upload, &entry_digest(label, blob, wrap), stamp).map_err(|_| Error::Verify("stamp"))
}

/// A deposit signature by the deposit key under `"osis v1 deposit"`.
pub fn sign_deposit(deposit: &SigningSecret, label: &LabelId, blob: &BlobId, wrap: &[u8]) -> Signature {
    deposit.sign(Domain::Deposit, &entry_digest(label, blob, wrap))
}

/// Checks a deposit's signature against the head's deposit key; an altered wrap fails.
pub fn verify_deposit(head_deposit: &VerifyingKey, label: &LabelId, blob: &BlobId, wrap: &[u8], sig: &Signature) -> Result<(), Error> {
    head_deposit.verify(Domain::Deposit, &entry_digest(label, blob, wrap), sig).map_err(|_| Error::Verify("deposit"))
}

/// The label key a delete by delete keys at `levels` needs beside them (spec/sync.md §5): the
/// write key when any is level 3, else the sync key; the delete key with no level.
pub fn key_for_levels(levels: &[Level]) -> Result<LabelRole, Error> {
    if levels.iter().any(|l| !(DELETE_ADMIN..=DELETE_WRITER).contains(l)) {
        return Err(Error::Malformed("delete level"));
    }
    Ok(if levels.is_empty() {
        LabelRole::Delete
    } else if levels.contains(&DELETE_WRITER) {
        LabelRole::Write
    } else {
        LabelRole::Sync
    })
}

/// A delete item `[blob_id, [[level, dsig]*], sig]` (spec/wire.md §11.2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeleteItem {
    pub blob: BlobId,
    /// Signatures by delete keys, each under the blob's blinded key at its level in a commitment
    /// group (spec/crypto.md §7); levels ascending, distinct. Empty: by the label delete key.
    pub by: Vec<(Level, Signature)>,
    pub sig: Signature,
}

/// Digest of a delete: BLAKE3 of canonical `[label_id, blob_id, [level*]]`.
pub fn delete_digest(label: &LabelId, blob: &BlobId, levels: &[Level]) -> Result<[u8; 32], Error> {
    let v = Value::List(vec![Value::bytes(&label.0), Value::bytes(&blob.0), Value::List(levels.iter().map(|l| Value::Int(i64::from(*l))).collect())]);
    Ok(osis_base::hash::hash(&encode(&v)))
}

impl DeleteItem {
    /// Signed by the head's delete key alone.
    pub fn sign(delete: &SigningSecret, label: &LabelId, blob: BlobId) -> Result<DeleteItem, Error> {
        let sig = delete.sign(Domain::Delete, &delete_digest(label, &blob, &[])?);
        Ok(DeleteItem { blob, by: Vec::new(), sig })
    }

    /// Signed by the delete keys `dks` (one per level used, levels distinct) under the blob's
    /// prefix `salt` and its header's blind `hb`, and by the label key `key_for_levels` names.
    #[allow(clippy::too_many_arguments)]
    pub fn sign_by(key: &SigningSecret, dks: &[(Level, &DeleteSecret)], salt: &[u8; 16], hb: &[u8; 16], label: &LabelId, blob: BlobId) -> Result<DeleteItem, Error> {
        let mut dks: Vec<(Level, &DeleteSecret)> = dks.to_vec();
        dks.sort_by_key(|(l, _)| *l);
        let levels: Vec<Level> = dks.iter().map(|(l, _)| *l).collect();
        if !levels.is_sorted_by(|a, b| a < b) || levels.is_empty() {
            return Err(Error::Malformed("delete levels"));
        }
        let d = delete_digest(label, &blob, &levels)?;
        let by = dks.iter().map(|(l, dk)| (*l, dk.sign(salt, hb, &d))).collect();
        Ok(DeleteItem { blob, by, sig: key.sign(Domain::Delete, &d) })
    }

    /// The levels signed, ascending.
    pub fn levels(&self) -> Vec<Level> {
        self.by.iter().map(|(l, _)| *l).collect()
    }

    /// The same delete signed again by label key `key` (a later head's, the delete-key
    /// signatures kept: they do not depend on the head).
    pub fn resign(&self, key: &SigningSecret, label: &LabelId) -> Result<DeleteItem, Error> {
        let d = delete_digest(label, &self.blob, &self.levels())?;
        Ok(DeleteItem { sig: key.sign(Domain::Delete, &d), ..self.clone() })
    }

    /// Host check against its head and the entry's blob prefix (none: unknown framing, no
    /// commitments): without levels the delete key; with them, each delete-key signature under
    /// a group's commitment at its level, every group covered by one (`every`: a Delete) or at
    /// least one group (a Replace), and the label key the levels need (spec/sync.md §5).
    pub fn verify(&self, head: &Step, prefix: Option<&Prefix>, every: bool) -> Result<(), Error> {
        let levels = self.levels();
        let d = delete_digest(&head.label, &self.blob, &levels)?;
        let role = key_for_levels(&levels)?;
        if !self.by.is_empty() {
            if !levels.is_sorted_by(|a, b| a < b) {
                return Err(Error::Malformed("delete levels"));
            }
            let prefix = prefix.ok_or(Error::Verify("no commitments"))?;
            let groups = prefix.groups();
            let mut covered = vec![false; groups.len()];
            for (level, dsig) in &self.by {
                let mut any = false;
                for (gi, c) in covered.iter_mut().enumerate() {
                    if prefix.key_at(gi, *level).is_some_and(|k| verify_delete(&k, &d, dsig).is_ok()) {
                        *c = true;
                        any = true;
                    }
                }
                if !any {
                    return Err(Error::Verify("delete-key signature"));
                }
            }
            if every && !covered.iter().all(|c| *c) {
                return Err(Error::Verify("a commitment group without a signature"));
            }
            if covered.is_empty() {
                return Err(Error::Verify("no commitment group"));
            }
        }
        head.keys.get(role).verify(Domain::Delete, &d, &self.sig).map_err(|_| Error::Verify("delete signature"))
    }

    pub fn to_value(&self) -> Result<Value, Error> {
        let by = Value::List(self.by.iter().map(|(l, s)| Value::List(vec![Value::Int(i64::from(*l)), Value::bytes(&s.0)])).collect());
        Ok(Value::List(vec![Value::bytes(&self.blob.0), by, Value::bytes(&self.sig.0)]))
    }

    pub fn from_value(v: &Value) -> Result<DeleteItem, Error> {
        let Value::List(items) = v else { return Err(Error::Malformed("delete item")) };
        let [blob, by, sig] = items.as_slice() else { return Err(Error::Malformed("delete item")) };
        let by = by_from_value(by)?;
        Ok(DeleteItem {
            blob: BlobId(get_bytes(blob, "delete blob")?),
            by,
            sig: Signature(get_bytes(sig, "delete signature")?),
        })
    }
}

/// `[[level, dsig]*]`: levels ascending and distinct, within 1..=3.
pub fn by_from_value(v: &Value) -> Result<Vec<(Level, Signature)>, Error> {
    let Value::List(xs) = v else { return Err(Error::Malformed("delete levels")) };
    let mut out: Vec<(Level, Signature)> = Vec::with_capacity(xs.len());
    for x in xs {
        let Value::List(p) = x else { return Err(Error::Malformed("delete level")) };
        let [l, s] = p.as_slice() else { return Err(Error::Malformed("delete level")) };
        let l = u8::try_from(get_uint(l, "delete level")?).ok().filter(|l| (DELETE_ADMIN..=DELETE_WRITER).contains(l)).ok_or(Error::Malformed("delete level"))?;
        if out.last().is_some_and(|(p, _)| *p >= l) {
            return Err(Error::Malformed("delete levels not ascending"));
        }
        out.push((l, Signature(get_bytes(s, "delete-key signature")?)));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::step::tests::{Group, TG};
    use crate::step::{ClaimSet, Parent, Reader, register};
    use std::sync::Arc;
    use osis_crypto::{Epoch, KeyActorKeys, SeededRng, Secret32, X25519Secret, label_role_key};
    use proptest::prelude::*;

    /// A path and its held claim sets, indexed by scanning (`PathIndex` for tests).
    struct Slice<'a> {
        path: &'a [Step],
        sets: Vec<(StepId, Arc<ClaimSet>)>,
    }

    impl PathIndex for Slice<'_> {
        type Error = std::convert::Infallible;
        fn step_with_sync(&self, pk: &VerifyingKey) -> Result<Option<StepId>, Self::Error> {
            Ok(self.path.iter().rev().find(|s| s.keys.sync == *pk).map(|s| s.id()))
        }
        fn step(&self, step: &StepId) -> Result<Option<Step>, Self::Error> {
            Ok(self.path.iter().find(|s| s.id() == *step).cloned())
        }
        fn claim(&self, step: &StepId, key: &[u8; 32]) -> Result<Option<Option<SecretBox>>, Self::Error> {
            Ok(self.sets.iter().find(|(id, _)| id == step).and_then(|(_, c)| c.contains(key).then(|| c.entries.get(key).cloned())))
        }
        fn child(&self, step: &StepId) -> Result<Option<Step>, Self::Error> {
            Ok(self.path.iter().position(|s| s.id() == *step).and_then(|i| self.path.get(i + 1)).cloned())
        }
    }

    fn epoch(n: u64) -> Epoch {
        Epoch::new(n, [n as u8; 32]).unwrap()
    }

    // spec/sync.md §5, spec/wire.md §11.2: opens by sync key (head or superseded: child), by
    // claim (head, path, dropped set, unknown key), by static entry (with the entry box); the
    // signature binds challenge and static key.
    #[test]
    fn open_evaluation() {
        let mut rng = SeededRng::from_u64(0);
        let (g, g2) = (Group::new(10), Group::new(20));
        let m = X25519Secret::random(&mut rng);
        let card = KeyActorKeys::from_seed(&Secret32::from_bytes([4; 32]));
        let readers = [Reader::Dh(m.public()), Reader::Static { signing: card.signing.verifying_key(), kem: card.kem.public() }];
        let (s0, c0) = register(Parent::Genesis(&g.delete(0)), g.keys(0), &readers, (&TG, Epoch::derive(&TG, osis_base::Role::Read, 0, &g.read).unwrap(), &g.read), &mut rng).unwrap();
        let k1 = crate::StepKeys::derive(&g2.read, &g2.write, &g2.admin, 0, &g.deposit, &s0.label);
        let (s1, c1) = register(Parent::Child { step: &s0, delete: &g.delete(0) }, k1, &readers, (&TG, Epoch::derive(&TG, osis_base::Role::Read, 1, &g2.read).unwrap(), &g2.read), &mut rng).unwrap();
        let path = vec![s0.clone(), s1.clone()];
        let sets = Slice { path: &path, sets: vec![(s0.id(), Arc::new(c0.clone())), (s1.id(), Arc::new(c1.clone()))] };
        let evaluate_open = |p: &[Step], ix: &Slice<'_>, pr: &Proof, ch: &[u8; 32], sk: &[u8; 32]| evaluate_open(p.last().unwrap(), ix, pr, ch, sk).unwrap();
        let (ch, sk) = ([1; 32], [2; 32]);
        let l = s0.label;
        let sync1 = label_role_key(LabelRole::Sync, &g2.read, 0);
        let sync0 = label_role_key(LabelRole::Sync, &g.read, 0);
        assert_eq!(evaluate_open(&path, &sets, &Proof::sync(None, &sync1, &l, &ch, &sk), &ch, &sk), OpenOutcome::Opened(None));
        assert_eq!(evaluate_open(&path, &sets, &Proof::sync(None, &sync0, &l, &ch, &sk), &ch, &sk), OpenOutcome::Child(s1.clone()));
        assert_eq!(evaluate_open(&path, &sets, &Proof::sync(None, &sync1, &l, &[9; 32], &sk), &ch, &sk), OpenOutcome::Refused);
        assert_eq!(evaluate_open(&path, &sets, &Proof::sync(None, &sync1, &l, &ch, &[9; 32]), &ch, &sk), OpenOutcome::Refused);
        let cl0 = s0.claim_key(&m).unwrap();
        let cl1 = s1.claim_key(&m).unwrap();
        assert_eq!(evaluate_open(&path, &sets, &Proof::claim(s0.id(), &cl0, &l, &ch, &sk), &ch, &sk), OpenOutcome::Child(s1.clone()));
        assert_eq!(evaluate_open(&path, &sets, &Proof::claim(s1.id(), &cl1, &l, &ch, &sk), &ch, &sk), OpenOutcome::Opened(None));
        assert_eq!(evaluate_open(&path, &sets, &Proof::claim(s1.id(), &cl0, &l, &ch, &sk), &ch, &sk), OpenOutcome::Refused);
        let dropped = Slice { path: &path, sets: vec![(s1.id(), Arc::new(c1.clone()))] };
        assert_eq!(evaluate_open(&path, &dropped, &Proof::claim(s0.id(), &cl0, &l, &ch, &sk), &ch, &sk), OpenOutcome::Refused);
        let p = Proof::static_entry(&card.signing, &l, &ch, &sk);
        assert_eq!(evaluate_open(&path, &sets, &p, &ch, &sk), OpenOutcome::Opened(c1.entry_box(&l, &card.signing.verifying_key()).cloned()));
        let stranger = KeyActorKeys::from_seed(&Secret32::from_bytes([5; 32]));
        assert_eq!(evaluate_open(&path, &sets, &Proof::static_entry(&stranger.signing, &l, &ch, &sk), &ch, &sk), OpenOutcome::Refused);
        for pr in [Proof::sync(None, &sync0, &l, &ch, &sk), Proof::claim(s0.id(), &cl0, &l, &ch, &sk), p] {
            assert_eq!(Proof::from_value(&pr.to_value()).unwrap(), pr);
        }
        assert!(Proof::from_value(&Value::List(vec![Value::Int(3)])).is_err(), "no proof 3");
    }

    // spec/sync.md §5, spec/wire.md §11.2: a sync key at a superseded step it bears is answered
    // with that step's child, which verifies under it, also where a later step without a rotation
    // bears the key too; a step that does not bear the key, or one off the path, is refused;
    // naming no step, the newest step bearing the key answers
    #[test]
    fn sync_key_open_at_its_step_spec_sync_5() {
        let mut rng = SeededRng::from_u64(0);
        let (g, g2) = (Group::new(40), Group::new(50));
        let rd = |n: u64, s: &Secret32| Epoch::derive(&TG, osis_base::Role::Read, n, s).unwrap();
        let (s0, _) = register(Parent::Genesis(&g.delete(0)), g.keys(0), &[], (&TG, rd(0, &g.read), &g.read), &mut rng).unwrap();
        // a step without a rotation (a reader listed since), then a rotation
        let (s1, _) = register(Parent::Child { step: &s0, delete: &g.delete(0) }, g.keys(0), &[], (&TG, rd(0, &g.read), &g.read), &mut rng).unwrap();
        let k2 = crate::StepKeys::derive(&g2.read, &g2.write, &g2.admin, 0, &g.deposit, &s0.label);
        let (s2, _) = register(Parent::Child { step: &s1, delete: &g.delete(0) }, k2, &[], (&TG, rd(1, &g2.read), &g2.read), &mut rng).unwrap();
        let path = vec![s0.clone(), s1.clone(), s2.clone()];
        let ix = Slice { path: &path, sets: Vec::new() };
        let (ch, sk) = ([1; 32], [2; 32]);
        let l = s0.label;
        let sync0 = label_role_key(LabelRole::Sync, &g.read, 0);
        let open = |step: Option<StepId>| evaluate_open(&s2, &ix, &Proof::sync(step, &sync0, &l, &ch, &sk), &ch, &sk).unwrap();
        assert_eq!(open(Some(s0.id())), OpenOutcome::Child(s1.clone()));
        s1.verify_child(&s0).unwrap();
        assert_eq!(open(Some(s1.id())), OpenOutcome::Child(s2.clone()));
        assert_eq!(open(None), OpenOutcome::Child(s2.clone()), "no step named: the newest bearing the key");
        assert_eq!(open(Some(s2.id())), OpenOutcome::Refused, "the head does not bear it");
        assert_eq!(open(Some(StepId([7; 32]))), OpenOutcome::Refused, "off the path");
        let at = Proof::sync(Some(s1.id()), &sync0, &l, &ch, &sk);
        assert_eq!(Proof::from_value(&at.to_value()).unwrap(), at);
    }

    // spec/sync.md §5, spec/wire.md §11.2: stamps and deposits verify
    // under their own key and domain only.
    #[test]
    fn entry_signatures() {
        let g = Group::new(30);
        let mut rng = SeededRng::from_u64(0);
        let (s0, _) = register(Parent::Genesis(&g.delete(0)), g.keys(0), &[], (&TG, epoch(0), &g.read), &mut rng).unwrap();
        let (l, b, w) = (s0.label, BlobId([1; 32]), [2u8; 49]);
        let write = label_role_key(LabelRole::Write, &g.write, 0);
        let stamp = sign_stamp(&write, &l, &b, &w);
        verify_stamp(&s0.keys.write, &l, &b, &w, &stamp).unwrap();
        assert!(verify_stamp(&s0.keys.sync, &l, &b, &w, &stamp).is_err());
        let digest = entry_digest(&l, &b, &w);
        assert!(s0.keys.write.verify(Domain::Deposit, &digest, &stamp).is_err());
        let dep = osis_crypto::deposit_key(&g.deposit, &l);
        s0.keys.deposit.verify(Domain::Deposit, &digest, &sign_deposit(&dep, &l, &b, &w)).unwrap();
    }

    // spec/sync.md §5, spec/crypto.md §7: delete by the label delete key; by a level's delete
    // key with the label key the level needs; a wrong level, a forged or unblinded key, a
    // missing commitment fail; layouts round trip.
    #[test]
    fn deletes() {
        let g = Group::new(40);
        let mut rng = SeededRng::from_u64(0);
        let (s0, _) = register(Parent::Genesis(&g.delete(0)), g.keys(0), &[], (&TG, epoch(0), &g.read), &mut rng).unwrap();
        let l = s0.label;
        let (sync, write) = (label_role_key(LabelRole::Sync, &g.read, 0), label_role_key(LabelRole::Write, &g.write, 0));
        let salt = [5u8; 16];
        let (d2, d3) = (DeleteSecret::derive(&Secret32::from_bytes([1; 32])), DeleteSecret::derive(&Secret32::from_bytes([2; 32])));
        let hb = [7u8; 16];
        let prefix = Prefix::for_keys(salt, &hb, None, &[(2, d2.verifying_key()), (3, d3.verifying_key())]).unwrap();
        let b = BlobId([9; 32]);
        let by = |key: &SigningSecret, dks: &[(Level, &DeleteSecret)], salt: &[u8; 16], hb: &[u8; 16]| DeleteItem::sign_by(key, dks, salt, hb, &l, b).unwrap();
        DeleteItem::sign(&g.delete(0), &l, b).unwrap().verify(&s0, None, true).unwrap();
        by(&sync, &[(2, &d2)], &salt, &hb).verify(&s0, Some(&prefix), true).unwrap();
        by(&write, &[(3, &d3)], &salt, &hb).verify(&s0, Some(&prefix), true).unwrap();
        // level 3 needs the write key, level 2 the sync key; both levels at once the write key
        assert!(by(&sync, &[(3, &d3)], &salt, &hb).verify(&s0, Some(&prefix), true).is_err());
        assert!(by(&write, &[(2, &d2)], &salt, &hb).verify(&s0, Some(&prefix), true).is_err());
        by(&write, &[(2, &d2), (3, &d3)], &salt, &hb).verify(&s0, Some(&prefix), true).unwrap();
        assert!(by(&sync, &[(2, &d2), (3, &d3)], &salt, &hb).verify(&s0, Some(&prefix), true).is_err());
        // a key at another level, a forged key, another salt, no prefix
        assert!(by(&sync, &[(2, &d3)], &salt, &hb).verify(&s0, Some(&prefix), true).is_err());
        assert!(by(&sync, &[(1, &d2)], &salt, &hb).verify(&s0, Some(&prefix), true).is_err());
        let forged = DeleteSecret::derive(&Secret32::from_bytes([3; 32]));
        assert!(by(&sync, &[(2, &forged)], &salt, &hb).verify(&s0, Some(&prefix), true).is_err());
        assert!(by(&sync, &[(2, &d2)], &[6; 16], &hb).verify(&s0, Some(&prefix), true).is_err());
        assert!(by(&sync, &[(2, &d2)], &salt, &[9; 16]).verify(&s0, Some(&prefix), true).is_err(), "another header's blind");
        assert!(by(&sync, &[(2, &d2)], &salt, &hb).verify(&s0, None, true).is_err());
        // a signature that verifies under no group, beside one that does, refuses the item
        let mut extra = by(&sync, &[(2, &d2)], &salt, &hb);
        extra.by.push((3, forged.sign(&salt, &hb, &[0; 32])));
        assert!(extra.verify(&s0, Some(&prefix), true).is_err());
        // the label-key signature binds the levels: moved to level 3 it fails
        let mut moved = by(&sync, &[(2, &d2)], &salt, &hb);
        moved.by = moved.by.iter().map(|(_, s)| (3, *s)).collect();
        assert!(moved.verify(&s0, Some(&prefix), true).is_err());
        assert!(DeleteItem::sign(&sync, &l, b).unwrap().verify(&s0, None, true).is_err());
        // groups (spec/sync.md §5): a Delete needs a signature under every group, a Replace one
        // under any; an empty group blocks a Delete by level; the author key shared by both
        // groups covers both with one signature
        let d1 = DeleteSecret::derive(&Secret32::from_bytes([4; 32]));
        let two = Prefix::for_groups(salt, &hb, None, &[vec![(2, d2.verifying_key()), (3, d3.verifying_key())], vec![(1, d1.verifying_key()), (2, d2.verifying_key())]]).unwrap();
        assert!(by(&write, &[(3, &d3)], &salt, &hb).verify(&s0, Some(&two), true).is_err());
        by(&write, &[(3, &d3)], &salt, &hb).verify(&s0, Some(&two), false).unwrap();
        by(&write, &[(1, &d1), (3, &d3)], &salt, &hb).verify(&s0, Some(&two), true).unwrap();
        by(&sync, &[(2, &d2)], &salt, &hb).verify(&s0, Some(&two), true).unwrap();
        let nobody = Prefix::for_groups(salt, &hb, None, &[vec![(2, d2.verifying_key())], vec![]]).unwrap();
        assert!(by(&sync, &[(2, &d2)], &salt, &hb).verify(&s0, Some(&nobody), true).is_err());
        by(&sync, &[(2, &d2)], &salt, &hb).verify(&s0, Some(&nobody), false).unwrap();
        let none = Prefix::new(salt, None, vec![]).unwrap();
        assert!(by(&sync, &[(2, &d2)], &salt, &hb).verify(&s0, Some(&none), false).is_err());
        let item = by(&sync, &[(2, &d2)], &salt, &hb);
        assert_eq!(DeleteItem::from_value(&item.to_value().unwrap()).unwrap(), item);
        let mut v = item.to_value().unwrap();
        if let Value::List(x) = &mut v {
            x[2] = Value::List(vec![Value::List(vec![Value::Int(4), Value::bytes(&[0; 64])])]);
        }
        assert!(DeleteItem::from_value(&v).is_err());
        let mut v = item.to_value().unwrap();
        if let Value::List(x) = &mut v {
            x[2] = Value::List(vec![Value::List(vec![Value::Int(3), Value::bytes(&[0; 64])]), Value::List(vec![Value::Int(2), Value::bytes(&[0; 64])])]);
        }
        assert!(DeleteItem::from_value(&v).is_err(), "levels not ascending");
        assert!(key_for_levels(&[0]).is_err());
    }

    proptest! {
        // spec/sync.md §5: a stamp binds the wrap: any altered wrap byte fails.
        #[test]
        fn stamp_binds_wrap(i in 0usize..49, x in 1u8..=255) {
            let write = label_role_key(LabelRole::Write, &Secret32::from_bytes([1; 32]), 0);
            let (l, b, w) = (LabelId([1; 16]), BlobId([2; 32]), [3u8; 49]);
            let stamp = sign_stamp(&write, &l, &b, &w);
            let mut w2 = w;
            w2[i] ^= x;
            prop_assert!(verify_stamp(&write.verifying_key(), &l, &b, &w2, &stamp).is_err());
            prop_assert!(verify_stamp(&write.verifying_key(), &l, &b, &w, &stamp).is_ok());
        }
    }
}
