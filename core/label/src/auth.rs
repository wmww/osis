//! Signatures of label operations and their server-side checks (spec/sync.md §5, spec/wire.md
//! §9, §11.2): open proofs and their evaluation against a registration path, stamps, deposits,
//! deletes by the label delete key or by a delete-key signature.

use crate::blob::{Level, Prefix};
use crate::cbor::{get_bytes, get_key, get_opt, get_uint, uint};
use crate::step::{Step, StepId};
use crate::Error;
use osis_base::cbor::encode;
use osis_base::format::{DELETE_ADMIN, DELETE_AUTHOR, DELETE_WRITER};
use osis_base::{BlobId, LabelId, Value, WallMs};
use osis_crypto::{DeleteSecret, Domain, LabelRole, Signature, SigningSecret, VerifyingKey, open_digest, sign_open, static_entry, verify_delete, verify_open};
use osis_schema::core_types::SecretBox;

/// Open proof (spec/wire.md §11.2): `[0, sync_pk, sig] | [1, step_id, claim_pk, sig] |
/// [2, signing_pk, sig] | [3, dialable_pk, sig]`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Proof {
    Sync { pk: VerifyingKey, sig: Signature },
    Claim { step: StepId, pk: VerifyingKey, sig: Signature },
    Static { signing: VerifyingKey, sig: Signature },
    /// A node's dialable key, to a member peer (spec/sync.md §5): signed under
    /// `"osis v1 member open"`; blind nodes refuse it.
    Member { dialable: VerifyingKey, sig: Signature },
}

impl Proof {
    pub fn sync(key: &SigningSecret, label: &LabelId, challenge: &[u8; 32], static_key: &[u8; 32]) -> Proof {
        Proof::Sync { pk: key.verifying_key(), sig: sign_open(key, label, challenge, static_key) }
    }
    pub fn claim(step: StepId, key: &SigningSecret, label: &LabelId, challenge: &[u8; 32], static_key: &[u8; 32]) -> Proof {
        Proof::Claim { step, pk: key.verifying_key(), sig: sign_open(key, label, challenge, static_key) }
    }
    /// By a key actor's signing key (its static entry).
    pub fn static_entry(signing: &SigningSecret, label: &LabelId, challenge: &[u8; 32], static_key: &[u8; 32]) -> Proof {
        Proof::Static { signing: signing.verifying_key(), sig: sign_open(signing, label, challenge, static_key) }
    }

    /// By a node's dialable key (a member node at a member peer).
    pub fn member(dialable: &SigningSecret, label: &LabelId, challenge: &[u8; 32], static_key: &[u8; 32]) -> Proof {
        Proof::Member { dialable: dialable.verifying_key(), sig: dialable.sign(Domain::MemberOpen, &open_digest(label, challenge, static_key)) }
    }

    pub fn to_value(&self) -> Value {
        Value::List(match self {
            Proof::Sync { pk, sig } => vec![Value::Int(0), Value::bytes(&pk.to_bytes()), Value::bytes(&sig.0)],
            Proof::Claim { step, pk, sig } => vec![Value::Int(1), Value::bytes(&step.0), Value::bytes(&pk.to_bytes()), Value::bytes(&sig.0)],
            Proof::Static { signing, sig } => vec![Value::Int(2), Value::bytes(&signing.to_bytes()), Value::bytes(&sig.0)],
            Proof::Member { dialable, sig } => vec![Value::Int(3), Value::bytes(&dialable.to_bytes()), Value::bytes(&sig.0)],
        })
    }

    pub fn from_value(v: &Value) -> Result<Proof, Error> {
        let Value::List(items) = v else { return Err(Error::Malformed("proof")) };
        let key = |v: &Value| get_key(v, "proof key");
        let sig = |v: &Value| get_bytes(v, "proof signature").map(Signature);
        Ok(match items.as_slice() {
            [Value::Int(0), pk, s] => Proof::Sync { pk: key(pk)?, sig: sig(s)? },
            [Value::Int(1), step, pk, s] => Proof::Claim { step: StepId(get_bytes(step, "proof step")?), pk: key(pk)?, sig: sig(s)? },
            [Value::Int(2), pk, s] => Proof::Static { signing: key(pk)?, sig: sig(s)? },
            [Value::Int(3), pk, s] => Proof::Member { dialable: key(pk)?, sig: sig(s)? },
            _ => return Err(Error::Malformed("proof")),
        })
    }

    /// The signature over (label ID, challenge, static key) of the opened side.
    pub fn verify_sig(&self, label: &LabelId, challenge: &[u8; 32], static_key: &[u8; 32]) -> Result<(), Error> {
        let (pk, sig) = match self {
            Proof::Sync { pk, sig } | Proof::Claim { pk, sig, .. } | Proof::Static { signing: pk, sig } => (pk, sig),
            Proof::Member { dialable, sig } => return dialable.verify(Domain::MemberOpen, &open_digest(label, challenge, static_key), sig).map_err(|_| Error::Verify("open signature")),
        };
        verify_open(pk, label, challenge, static_key, sig).map_err(|_| Error::Verify("open signature"))
    }
}

/// What a server answers an open with (spec/sync.md §5).
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

/// What `evaluate_open` reads of a server's path besides its head: indexes the store keeps as
/// steps are added, so an open costs a constant number of lookups however long the path.
pub trait PathIndex {
    type Error;
    /// The newest step on the path registering sync key `pk`.
    fn step_with_sync(&self, pk: &VerifyingKey) -> Result<Option<StepId>, Self::Error>;
    /// Whether `key` (a claim key or a static entry) is in the held claim set of step `step` on
    /// the path, with its entry box if it has one; none if not, or the set is not held. A
    /// lookup, never a whole set: a stranger's Open must not cost a claim set's size.
    fn claim(&self, step: &StepId, key: &[u8; 32]) -> Result<Option<Option<SecretBox>>, Self::Error>;
    /// The child on the path of a step on it; none past the head.
    fn child(&self, step: &StepId) -> Result<Option<Step>, Self::Error>;
}

/// Evaluates an open against a server's head and its path indexes. The signature is checked
/// first. A sync key matches the head, else the newest superseded step bearing it; a claim at
/// step j needs V in j's set (head: open; on the path: its child); a static proof needs the
/// key's static entry in the head's set. At most three lookups.
pub fn evaluate_open<I: PathIndex>(head: &Step, index: &I, proof: &Proof, challenge: &[u8; 32], static_key: &[u8; 32]) -> Result<OpenOutcome, I::Error> {
    if proof.verify_sig(&head.label, challenge, static_key).is_err() {
        return Ok(OpenOutcome::Refused);
    }
    let child_of = |s: &StepId| Ok(index.child(s)?.map_or(OpenOutcome::Refused, OpenOutcome::Child));
    match proof {
        Proof::Sync { pk, .. } if head.keys.sync == *pk => Ok(OpenOutcome::Opened(None)),
        Proof::Sync { pk, .. } => match index.step_with_sync(pk)? {
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
        // only a member peer that knows the key's node opens it (`ServerConnection`)
        Proof::Member { .. } => Ok(OpenOutcome::Refused),
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

/// The label key a delete by a level's delete key needs beside it (spec/sync.md §5): the write
/// key for level 3, the sync key for level 1 or 2.
pub fn key_for_level(level: Level) -> Result<LabelRole, Error> {
    match level {
        DELETE_WRITER => Ok(LabelRole::Write),
        DELETE_ADMIN | DELETE_AUTHOR => Ok(LabelRole::Sync),
        _ => Err(Error::Malformed("delete level")),
    }
}

/// A delete item `[blob_id, Opt(at), Opt([level, dsig]), sig]` (spec/wire.md §11.2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeleteItem {
    pub blob: BlobId,
    /// A timed delete.
    pub at: Option<WallMs>,
    /// A signature by the delete key of a level, under the blob's blinded key at that level
    /// (spec/crypto.md §7).
    pub by: Option<(Level, Signature)>,
    pub sig: Signature,
}

/// Digest of a delete: BLAKE3 of canonical `[label_id, blob_id, Opt(at), Opt(level)]`.
pub fn delete_digest(label: &LabelId, blob: &BlobId, at: Option<WallMs>, level: Option<Level>) -> Result<[u8; 32], Error> {
    let at = at.map(|t| uint(t.0)).transpose()?;
    let v = Value::List(vec![Value::bytes(&label.0), Value::bytes(&blob.0), Value::opt(at), Value::opt(level.map(|l| Value::Int(i64::from(l))))]);
    Ok(osis_base::hash::hash(&encode(&v)))
}

impl DeleteItem {
    /// Signed by the head's delete key alone.
    pub fn sign(delete: &SigningSecret, label: &LabelId, blob: BlobId, at: Option<WallMs>) -> Result<DeleteItem, Error> {
        let sig = delete.sign(Domain::Delete, &delete_digest(label, &blob, at, None)?);
        Ok(DeleteItem { blob, at, by: None, sig })
    }

    /// Signed by the delete key of `level` under the blob's prefix `salt` and its header's blind
    /// `hb`, and by the label key `key_for_level` names.
    #[allow(clippy::too_many_arguments)]
    pub fn sign_by(key: &SigningSecret, dk: &DeleteSecret, level: Level, salt: &[u8; 16], hb: &[u8; 16], label: &LabelId, blob: BlobId, at: Option<WallMs>) -> Result<DeleteItem, Error> {
        let d = delete_digest(label, &blob, at, Some(level))?;
        Ok(DeleteItem { blob, at, by: Some((level, dk.sign(salt, hb, &d))), sig: key.sign(Domain::Delete, &d) })
    }

    /// The same delete signed again by label key `key` (a later head's, the delete-key
    /// signature kept: it does not depend on the head).
    pub fn resign(&self, key: &SigningSecret, label: &LabelId) -> Result<DeleteItem, Error> {
        let d = delete_digest(label, &self.blob, self.at, self.by.map(|b| b.0))?;
        Ok(DeleteItem { sig: key.sign(Domain::Delete, &d), ..self.clone() })
    }

    /// Server check against its head and the entry's blob prefix (none: unknown framing, no
    /// commitments): without a level the delete key; with one, the delete-key signature under
    /// the prefix's commitment at that level and the label key the level needs.
    pub fn verify(&self, head: &Step, prefix: Option<&Prefix>) -> Result<(), Error> {
        let d = delete_digest(&head.label, &self.blob, self.at, self.by.map(|b| b.0))?;
        let role = match &self.by {
            None => LabelRole::Delete,
            Some((level, dsig)) => {
                let key = prefix.and_then(|p| p.key_at(*level)).ok_or(Error::Verify("no commitment at the level"))?;
                verify_delete(&key, &d, dsig).map_err(|_| Error::Verify("delete-key signature"))?;
                key_for_level(*level)?
            }
        };
        head.keys.get(role).verify(Domain::Delete, &d, &self.sig).map_err(|_| Error::Verify("delete signature"))
    }

    pub fn to_value(&self) -> Result<Value, Error> {
        let at = self.at.map(|t| uint(t.0)).transpose()?;
        let by = self.by.map(|(l, s)| Value::List(vec![Value::Int(i64::from(l)), Value::bytes(&s.0)]));
        Ok(Value::List(vec![Value::bytes(&self.blob.0), Value::opt(at), Value::opt(by), Value::bytes(&self.sig.0)]))
    }

    pub fn from_value(v: &Value) -> Result<DeleteItem, Error> {
        let Value::List(items) = v else { return Err(Error::Malformed("delete item")) };
        let [blob, at, by, sig] = items.as_slice() else { return Err(Error::Malformed("delete item")) };
        let by = match get_opt(by, "delete level")? {
            None => None,
            Some(Value::List(x)) => match x.as_slice() {
                [l, s] => {
                    let l = u8::try_from(get_uint(l, "delete level")?).ok().filter(|l| (DELETE_ADMIN..=DELETE_WRITER).contains(l)).ok_or(Error::Malformed("delete level"))?;
                    Some((l, Signature(get_bytes(s, "delete-key signature")?)))
                }
                _ => return Err(Error::Malformed("delete level")),
            },
            Some(_) => return Err(Error::Malformed("delete level")),
        };
        Ok(DeleteItem {
            blob: BlobId(get_bytes(blob, "delete blob")?),
            at: get_opt(at, "delete at")?.map(|t| get_uint(t, "delete at").map(WallMs)).transpose()?,
            by,
            sig: Signature(get_bytes(sig, "delete signature")?),
        })
    }
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
        let mut rng = SeededRng::from_u64(1);
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
        assert_eq!(evaluate_open(&path, &sets, &Proof::sync(&sync1, &l, &ch, &sk), &ch, &sk), OpenOutcome::Opened(None));
        assert_eq!(evaluate_open(&path, &sets, &Proof::sync(&sync0, &l, &ch, &sk), &ch, &sk), OpenOutcome::Child(s1.clone()));
        assert_eq!(evaluate_open(&path, &sets, &Proof::sync(&sync1, &l, &[9; 32], &sk), &ch, &sk), OpenOutcome::Refused);
        assert_eq!(evaluate_open(&path, &sets, &Proof::sync(&sync1, &l, &ch, &[9; 32]), &ch, &sk), OpenOutcome::Refused);
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
        for pr in [Proof::sync(&sync0, &l, &ch, &sk), Proof::claim(s0.id(), &cl0, &l, &ch, &sk), p] {
            assert_eq!(Proof::from_value(&pr.to_value()).unwrap(), pr);
        }
        assert!(Proof::from_value(&Value::List(vec![Value::Int(3)])).is_err());
    }

    // spec/sync.md §5, spec/wire.md §11.2: stamps and deposits verify
    // under their own key and domain only.
    #[test]
    fn entry_signatures() {
        let g = Group::new(30);
        let mut rng = SeededRng::from_u64(2);
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
        let mut rng = SeededRng::from_u64(3);
        let (s0, _) = register(Parent::Genesis(&g.delete(0)), g.keys(0), &[], (&TG, epoch(0), &g.read), &mut rng).unwrap();
        let l = s0.label;
        let (sync, write) = (label_role_key(LabelRole::Sync, &g.read, 0), label_role_key(LabelRole::Write, &g.write, 0));
        let salt = [5u8; 16];
        let (d2, d3) = (DeleteSecret::derive(&Secret32::from_bytes([1; 32])), DeleteSecret::derive(&Secret32::from_bytes([2; 32])));
        let hb = [7u8; 16];
        let prefix = Prefix::for_keys(salt, &hb, None, &[(2, d2.verifying_key()), (3, d3.verifying_key())]).unwrap();
        let b = BlobId([9; 32]);
        DeleteItem::sign(&g.delete(0), &l, b, None).unwrap().verify(&s0, None).unwrap();
        DeleteItem::sign_by(&sync, &d2, 2, &salt, &hb, &l, b, Some(WallMs(5))).unwrap().verify(&s0, Some(&prefix)).unwrap();
        DeleteItem::sign_by(&write, &d3, 3, &salt, &hb, &l, b, None).unwrap().verify(&s0, Some(&prefix)).unwrap();
        // level 3 needs the write key, level 2 the sync key
        assert!(DeleteItem::sign_by(&sync, &d3, 3, &salt, &hb, &l, b, None).unwrap().verify(&s0, Some(&prefix)).is_err());
        assert!(DeleteItem::sign_by(&write, &d2, 2, &salt, &hb, &l, b, None).unwrap().verify(&s0, Some(&prefix)).is_err());
        // a key at another level, a forged key, another salt, no prefix
        assert!(DeleteItem::sign_by(&sync, &d3, 2, &salt, &hb, &l, b, None).unwrap().verify(&s0, Some(&prefix)).is_err());
        assert!(DeleteItem::sign_by(&sync, &d2, 1, &salt, &hb, &l, b, None).unwrap().verify(&s0, Some(&prefix)).is_err());
        let forged = DeleteSecret::derive(&Secret32::from_bytes([3; 32]));
        assert!(DeleteItem::sign_by(&sync, &forged, 2, &salt, &hb, &l, b, None).unwrap().verify(&s0, Some(&prefix)).is_err());
        assert!(DeleteItem::sign_by(&sync, &d2, 2, &[6; 16], &hb, &l, b, None).unwrap().verify(&s0, Some(&prefix)).is_err());
        assert!(DeleteItem::sign_by(&sync, &d2, 2, &salt, &[9; 16], &l, b, None).unwrap().verify(&s0, Some(&prefix)).is_err(), "another header's blind");
        assert!(DeleteItem::sign_by(&sync, &d2, 2, &salt, &hb, &l, b, None).unwrap().verify(&s0, None).is_err());
        // the label-key signature binds the level: moved to level 3 it fails
        let mut moved = DeleteItem::sign_by(&sync, &d2, 2, &salt, &hb, &l, b, None).unwrap();
        moved.by = moved.by.map(|(_, s)| (3, s));
        assert!(moved.verify(&s0, Some(&prefix)).is_err());
        assert!(DeleteItem::sign(&sync, &l, b, None).unwrap().verify(&s0, None).is_err());
        let item = DeleteItem::sign_by(&sync, &d2, 2, &salt, &hb, &l, b, Some(WallMs(5))).unwrap();
        assert_eq!(DeleteItem::from_value(&item.to_value().unwrap()).unwrap(), item);
        let mut v = item.to_value().unwrap();
        if let Value::List(x) = &mut v {
            x[2] = Value::opt(Some(Value::List(vec![Value::Int(4), Value::bytes(&[0; 64])])));
        }
        assert!(DeleteItem::from_value(&v).is_err());
        assert!(key_for_level(0).is_err());
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
