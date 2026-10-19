//! Signatures of label operations and their server-side checks (spec/sync.md §5, spec/wire.md
//! §9, §11.2): open proofs and their evaluation against a registration path, stamps, deposits,
//! signal publish authorization, deletes with or without a presented token.

use crate::blob::{Level, Prefix};
use crate::step::{ClaimSet, Step, StepId};
use crate::Error;
use osis_core::cbor::encode;
use osis_core::{BlobId, LabelId, Value, WallMs};
use osis_crypto::{Domain, LabelRole, Secret32, Signature, SigningSecret, VerifyingKey, sign_open, static_entry, verify_open};
use osis_schema::core_types::SecretBox;

fn bytes(b: &[u8]) -> Value {
    Value::Bytes(b.to_vec())
}

pub(crate) fn get_bytes<const N: usize>(v: &Value, what: &'static str) -> Result<[u8; N], Error> {
    match v {
        Value::Bytes(b) => b.as_slice().try_into().map_err(|_| Error::Malformed(what)),
        _ => Err(Error::Malformed(what)),
    }
}

pub(crate) fn get_uint(v: &Value, what: &'static str) -> Result<u64, Error> {
    match v {
        Value::Int(n) => u64::try_from(*n).map_err(|_| Error::Malformed(what)),
        _ => Err(Error::Malformed(what)),
    }
}

pub(crate) fn uint(n: u64) -> Result<Value, Error> {
    Ok(Value::Int(i64::try_from(n).map_err(|_| Error::TooLarge("int"))?))
}

/// `Opt(X)` as a list of zero or one item.
pub(crate) fn get_opt<'a>(v: &'a Value, what: &'static str) -> Result<Option<&'a Value>, Error> {
    match v {
        Value::List(l) => match l.as_slice() {
            [] => Ok(None),
            [x] => Ok(Some(x)),
            _ => Err(Error::Malformed(what)),
        },
        _ => Err(Error::Malformed(what)),
    }
}

pub(crate) fn opt(v: Option<Value>) -> Value {
    Value::List(v.into_iter().collect())
}

/// Open proof (spec/wire.md §11.2): `[0, sync_pk, sig] | [1, step_id, claim_pk, sig] |
/// [2, signing_pk, sig]`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Proof {
    Sync { pk: VerifyingKey, sig: Signature },
    Claim { step: StepId, pk: VerifyingKey, sig: Signature },
    Static { signing: VerifyingKey, sig: Signature },
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

    pub fn to_value(&self) -> Value {
        Value::List(match self {
            Proof::Sync { pk, sig } => vec![Value::Int(0), bytes(&pk.to_bytes()), bytes(&sig.0)],
            Proof::Claim { step, pk, sig } => vec![Value::Int(1), bytes(&step.0), bytes(&pk.to_bytes()), bytes(&sig.0)],
            Proof::Static { signing, sig } => vec![Value::Int(2), bytes(&signing.to_bytes()), bytes(&sig.0)],
        })
    }

    pub fn from_value(v: &Value) -> Result<Proof, Error> {
        let Value::List(items) = v else { return Err(Error::Malformed("proof")) };
        let key = |v: &Value| VerifyingKey::from_bytes(&get_bytes(v, "proof key")?).map_err(|_| Error::Malformed("proof key"));
        let sig = |v: &Value| get_bytes(v, "proof signature").map(Signature);
        Ok(match items.as_slice() {
            [Value::Int(0), pk, s] => Proof::Sync { pk: key(pk)?, sig: sig(s)? },
            [Value::Int(1), step, pk, s] => Proof::Claim { step: StepId(get_bytes(step, "proof step")?), pk: key(pk)?, sig: sig(s)? },
            [Value::Int(2), pk, s] => Proof::Static { signing: key(pk)?, sig: sig(s)? },
            _ => return Err(Error::Malformed("proof")),
        })
    }

    /// The signature over (label ID, challenge, static key) of the opened side.
    pub fn verify_sig(&self, label: &LabelId, challenge: &[u8; 32], static_key: &[u8; 32]) -> Result<(), Error> {
        let (pk, sig) = match self {
            Proof::Sync { pk, sig } | Proof::Claim { pk, sig, .. } | Proof::Static { signing: pk, sig } => (pk, sig),
        };
        verify_open(pk, label, challenge, static_key, sig).map_err(|_| Error::Verify("open signature"))
    }
}

/// What a server answers an open with (spec/sync.md §5).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OpenOutcome<'a> {
    /// The label is open on the connection; for a static proof, with the head's entry box.
    Opened(Option<&'a SecretBox>),
    /// A match at a superseded step: its child on the path (sent without its claim set).
    Child(&'a Step),
    /// Refused like an unknown key.
    Refused,
}

/// Evaluates an open against a server's path (genesis first, head last) and the claim sets it
/// still holds. The signature is checked first. A sync key matches the head, else the newest
/// superseded step bearing it; a claim at step j needs V in j's set (head: open; on the path:
/// its child); a static proof needs the key's static entry in the head's set.
pub fn evaluate_open<'a>(
    path: &'a [Step],
    claims: &dyn Fn(&StepId) -> Option<&'a ClaimSet>,
    proof: &Proof,
    challenge: &[u8; 32],
    static_key: &[u8; 32],
) -> OpenOutcome<'a> {
    let Some(head) = path.last() else { return OpenOutcome::Refused };
    if proof.verify_sig(&head.label, challenge, static_key).is_err() {
        return OpenOutcome::Refused;
    }
    let child_of = |i: usize| path.get(i + 1).map_or(OpenOutcome::Refused, OpenOutcome::Child);
    match proof {
        Proof::Sync { pk, .. } => match path.iter().rposition(|s| s.keys.sync == *pk) {
            Some(i) if i + 1 == path.len() => OpenOutcome::Opened(None),
            Some(i) => child_of(i),
            None => OpenOutcome::Refused,
        },
        Proof::Claim { step, pk, .. } => {
            let Some(i) = path.iter().position(|s| s.id() == *step) else { return OpenOutcome::Refused };
            if !claims(step).is_some_and(|c| c.contains(&pk.to_bytes())) {
                return OpenOutcome::Refused;
            }
            if i + 1 == path.len() { OpenOutcome::Opened(None) } else { child_of(i) }
        }
        Proof::Static { signing, .. } => {
            let e = static_entry(&head.label, signing);
            match claims(&head.id()) {
                Some(c) if c.contains(&e) => OpenOutcome::Opened(c.entries.get(&e)),
                _ => OpenOutcome::Refused,
            }
        }
    }
}

/// Digest of a stamp, deposit or publish authorization: BLAKE3 of canonical
/// `[label_id, blob_id, wrap]`.
pub fn entry_digest(label: &LabelId, blob: &BlobId, wrap: &[u8]) -> [u8; 32] {
    osis_core::hash::hash(&encode(&Value::List(vec![bytes(&label.0), bytes(&blob.0), bytes(wrap)])))
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

pub fn verify_deposit(head_deposit: &VerifyingKey, label: &LabelId, blob: &BlobId, wrap: &[u8], sig: &Signature) -> Result<(), Error> {
    head_deposit.verify(Domain::Deposit, &entry_digest(label, blob, wrap), sig).map_err(|_| Error::Verify("deposit signature"))
}

/// Which key authorizes a signal publish: 0 the label's write key, 1 its deposit key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PublishKey {
    Write,
    Deposit,
}

/// Signal publish authorization `[key, sig]` under `"osis v1 signal publish"` (spec/wire.md §9).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublishAuth {
    pub key: PublishKey,
    pub sig: Signature,
}

impl PublishAuth {
    pub fn sign(key: PublishKey, secret: &SigningSecret, label: &LabelId, blob: &BlobId, wrap: &[u8]) -> PublishAuth {
        PublishAuth { key, sig: secret.sign(Domain::SignalPublish, &entry_digest(label, blob, wrap)) }
    }

    /// Against the head's write or deposit key.
    pub fn verify(&self, head: &Step, blob: &BlobId, wrap: &[u8]) -> Result<(), Error> {
        let pk = match self.key {
            PublishKey::Write => &head.keys.write,
            PublishKey::Deposit => &head.keys.deposit,
        };
        pk.verify(Domain::SignalPublish, &entry_digest(&head.label, blob, wrap), &self.sig).map_err(|_| Error::Verify("publish signature"))
    }

    pub fn to_value(&self) -> Value {
        let k = match self.key {
            PublishKey::Write => 0,
            PublishKey::Deposit => 1,
        };
        Value::List(vec![Value::Int(k), bytes(&self.sig.0)])
    }

    pub fn from_value(v: &Value) -> Result<PublishAuth, Error> {
        let Value::List(items) = v else { return Err(Error::Malformed("publish auth")) };
        let (key, sig) = match items.as_slice() {
            [Value::Int(0), s] => (PublishKey::Write, s),
            [Value::Int(1), s] => (PublishKey::Deposit, s),
            _ => return Err(Error::Malformed("publish auth")),
        };
        Ok(PublishAuth { key, sig: Signature(get_bytes(sig, "publish signature")?) })
    }
}

/// The label key a presented token of `level` needs beside it (spec/sync.md §5): the write key
/// for a level-3 commitment, the sync key for level 1 or 2.
pub fn key_for_level(level: Level) -> Result<LabelRole, Error> {
    match level {
        3 => Ok(LabelRole::Write),
        1 | 2 => Ok(LabelRole::Sync),
        _ => Err(Error::Malformed("token level")),
    }
}

/// A delete item `[blob_id, Opt(at), Opt(token), sig]` (spec/wire.md §11.2).
#[derive(Clone, PartialEq, Eq)]
pub struct DeleteItem {
    pub blob: BlobId,
    /// A timed delete.
    pub at: Option<WallMs>,
    /// A presented delete token (spec/crypto.md §7).
    pub token: Option<[u8; 32]>,
    pub sig: Signature,
}

impl std::fmt::Debug for DeleteItem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "DeleteItem({:?}, at {:?}, token {})", self.blob, self.at, if self.token.is_some() { "presented" } else { "none" })
    }
}

/// Digest of a delete: BLAKE3 of canonical `[label_id, blob_id, Opt(at), Opt(token)]`.
pub fn delete_digest(label: &LabelId, blob: &BlobId, at: Option<WallMs>, token: Option<&[u8; 32]>) -> Result<[u8; 32], Error> {
    let at = at.map(|t| uint(t.0)).transpose()?;
    let v = Value::List(vec![bytes(&label.0), bytes(&blob.0), opt(at), opt(token.map(|t| bytes(t)))]);
    Ok(osis_core::hash::hash(&encode(&v)))
}

impl DeleteItem {
    /// Signs with the head's delete key (no token), or with the key `key_for_level` names for the
    /// token's commitment level.
    pub fn sign(key: &SigningSecret, label: &LabelId, blob: BlobId, at: Option<WallMs>, token: Option<&Secret32>) -> Result<DeleteItem, Error> {
        let token = token.map(|t| *t.expose());
        let sig = key.sign(Domain::Delete, &delete_digest(label, &blob, at, token.as_ref())?);
        Ok(DeleteItem { blob, at, token, sig })
    }

    /// Server check against its head and the entry's blob prefix (none: unknown framing, no
    /// commitments): without a token the delete key; with one, a matching commitment and the
    /// key its level needs.
    pub fn verify(&self, head: &Step, prefix: Option<&Prefix>) -> Result<(), Error> {
        let role = match &self.token {
            None => LabelRole::Delete,
            Some(t) => key_for_level(prefix.and_then(|p| p.match_token(t)).ok_or(Error::Verify("token matches no commitment"))?)?,
        };
        let d = delete_digest(&head.label, &self.blob, self.at, self.token.as_ref())?;
        head.keys.get(role).verify(Domain::Delete, &d, &self.sig).map_err(|_| Error::Verify("delete signature"))
    }

    pub fn to_value(&self) -> Result<Value, Error> {
        let at = self.at.map(|t| uint(t.0)).transpose()?;
        Ok(Value::List(vec![bytes(&self.blob.0), opt(at), opt(self.token.map(|t| bytes(&t))), bytes(&self.sig.0)]))
    }

    pub fn from_value(v: &Value) -> Result<DeleteItem, Error> {
        let Value::List(items) = v else { return Err(Error::Malformed("delete item")) };
        let [blob, at, token, sig] = items.as_slice() else { return Err(Error::Malformed("delete item")) };
        Ok(DeleteItem {
            blob: BlobId(get_bytes(blob, "delete blob")?),
            at: get_opt(at, "delete at")?.map(|t| get_uint(t, "delete at").map(WallMs)).transpose()?,
            token: get_opt(token, "delete token")?.map(|t| get_bytes(t, "delete token")).transpose()?,
            sig: Signature(get_bytes(sig, "delete signature")?),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::step::tests::Group;
    use crate::step::{Parent, Reader, register};
    use osis_crypto::{Epoch, KeyActorKeys, SeededRng, X25519Secret, delete_token, label_role_key, token_hash};
    use proptest::prelude::*;

    fn epoch(n: u64) -> Epoch {
        Epoch::new(n, [n as u8; 16]).unwrap()
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
        let readers = [Reader::Dh(m.public()), Reader::Static { signing: card.signing.verifying_key(), entry: crate::EntryTo::Sealed(card.kem.public()) }];
        let (s0, c0) = register(Parent::Genesis(&g.delete(0)), g.keys(0), &readers, (epoch(0), &g.read), &mut rng).unwrap();
        let k1 = crate::StepKeys::derive(&g2.read, &g2.write, &g2.admin, 0, &g.deposit, &s0.label);
        let (s1, c1) = register(Parent::Child { step: &s0, delete: &g.delete(0) }, k1, &readers, (epoch(1), &g2.read), &mut rng).unwrap();
        let path = vec![s0.clone(), s1.clone()];
        let sets = |id: &StepId| if *id == s0.id() { Some(&c0) } else if *id == s1.id() { Some(&c1) } else { None };
        let (ch, sk) = ([1; 32], [2; 32]);
        let l = s0.label;
        let sync1 = label_role_key(LabelRole::Sync, &g2.read, 0);
        let sync0 = label_role_key(LabelRole::Sync, &g.read, 0);
        assert_eq!(evaluate_open(&path, &sets, &Proof::sync(&sync1, &l, &ch, &sk), &ch, &sk), OpenOutcome::Opened(None));
        assert_eq!(evaluate_open(&path, &sets, &Proof::sync(&sync0, &l, &ch, &sk), &ch, &sk), OpenOutcome::Child(&s1));
        assert_eq!(evaluate_open(&path, &sets, &Proof::sync(&sync1, &l, &[9; 32], &sk), &ch, &sk), OpenOutcome::Refused);
        assert_eq!(evaluate_open(&path, &sets, &Proof::sync(&sync1, &l, &ch, &[9; 32]), &ch, &sk), OpenOutcome::Refused);
        let cl0 = s0.claim_key(&m).unwrap();
        let cl1 = s1.claim_key(&m).unwrap();
        assert_eq!(evaluate_open(&path, &sets, &Proof::claim(s0.id(), &cl0, &l, &ch, &sk), &ch, &sk), OpenOutcome::Child(&s1));
        assert_eq!(evaluate_open(&path, &sets, &Proof::claim(s1.id(), &cl1, &l, &ch, &sk), &ch, &sk), OpenOutcome::Opened(None));
        assert_eq!(evaluate_open(&path, &sets, &Proof::claim(s1.id(), &cl0, &l, &ch, &sk), &ch, &sk), OpenOutcome::Refused);
        let dropped = |id: &StepId| if *id == s1.id() { Some(&c1) } else { None };
        assert_eq!(evaluate_open(&path, &dropped, &Proof::claim(s0.id(), &cl0, &l, &ch, &sk), &ch, &sk), OpenOutcome::Refused);
        let p = Proof::static_entry(&card.signing, &l, &ch, &sk);
        assert_eq!(evaluate_open(&path, &sets, &p, &ch, &sk), OpenOutcome::Opened(c1.entry_box(&l, &card.signing.verifying_key())));
        let stranger = KeyActorKeys::from_seed(&Secret32::from_bytes([5; 32]));
        assert_eq!(evaluate_open(&path, &sets, &Proof::static_entry(&stranger.signing, &l, &ch, &sk), &ch, &sk), OpenOutcome::Refused);
        for pr in [Proof::sync(&sync0, &l, &ch, &sk), Proof::claim(s0.id(), &cl0, &l, &ch, &sk), p] {
            assert_eq!(Proof::from_value(&pr.to_value()).unwrap(), pr);
        }
        assert!(Proof::from_value(&Value::List(vec![Value::Int(3)])).is_err());
    }

    // spec/sync.md §5, spec/wire.md §11.2: stamps, deposits and publish authorizations verify
    // under their own key and domain only.
    #[test]
    fn entry_signatures() {
        let g = Group::new(30);
        let mut rng = SeededRng::from_u64(2);
        let (s0, _) = register(Parent::Genesis(&g.delete(0)), g.keys(0), &[], (epoch(0), &g.read), &mut rng).unwrap();
        let (l, b, w) = (s0.label, BlobId([1; 32]), [2u8; 49]);
        let write = label_role_key(LabelRole::Write, &g.write, 0);
        let stamp = sign_stamp(&write, &l, &b, &w);
        verify_stamp(&s0.keys.write, &l, &b, &w, &stamp).unwrap();
        assert!(verify_stamp(&s0.keys.sync, &l, &b, &w, &stamp).is_err());
        assert!(verify_deposit(&s0.keys.write, &l, &b, &w, &stamp).is_err());
        let dep = osis_crypto::deposit_key(&g.deposit, &l);
        verify_deposit(&s0.keys.deposit, &l, &b, &w, &sign_deposit(&dep, &l, &b, &w)).unwrap();
        let a = PublishAuth::sign(PublishKey::Deposit, &dep, &l, &b, &w);
        a.verify(&s0, &b, &w).unwrap();
        assert_eq!(PublishAuth::from_value(&a.to_value()).unwrap(), a);
        let wrong = PublishAuth { key: PublishKey::Write, sig: a.sig };
        assert!(wrong.verify(&s0, &b, &w).is_err());
    }

    // spec/sync.md §5, spec/crypto.md §7: delete by delete key; by token with the key its level
    // needs; a token matching no commitment fails; layouts round trip.
    #[test]
    fn deletes() {
        let g = Group::new(40);
        let mut rng = SeededRng::from_u64(3);
        let (s0, _) = register(Parent::Genesis(&g.delete(0)), g.keys(0), &[], (epoch(0), &g.read), &mut rng).unwrap();
        let l = s0.label;
        let (sync, write) = (label_role_key(LabelRole::Sync, &g.read, 0), label_role_key(LabelRole::Write, &g.write, 0));
        let salt = [5u8; 16];
        let (t2, t3) = (delete_token(&Secret32::from_bytes([1; 32]), &[7; 16]), delete_token(&Secret32::from_bytes([2; 32]), &[7; 16]));
        let prefix = Prefix::for_tokens(salt, None, &[(2, token_hash(t2.expose())), (3, token_hash(t3.expose()))]).unwrap();
        let b = BlobId([9; 32]);
        DeleteItem::sign(&g.delete(0), &l, b, None, None).unwrap().verify(&s0, None).unwrap();
        DeleteItem::sign(&sync, &l, b, Some(WallMs(5)), Some(&t2)).unwrap().verify(&s0, Some(&prefix)).unwrap();
        DeleteItem::sign(&write, &l, b, None, Some(&t3)).unwrap().verify(&s0, Some(&prefix)).unwrap();
        assert!(DeleteItem::sign(&sync, &l, b, None, Some(&t3)).unwrap().verify(&s0, Some(&prefix)).is_err());
        assert!(DeleteItem::sign(&sync, &l, b, None, Some(&t2)).unwrap().verify(&s0, None).is_err());
        assert!(DeleteItem::sign(&sync, &l, b, None, None).unwrap().verify(&s0, None).is_err());
        let item = DeleteItem::sign(&sync, &l, b, Some(WallMs(5)), Some(&t2)).unwrap();
        assert_eq!(DeleteItem::from_value(&item.to_value().unwrap()).unwrap(), item);
        assert!(!format!("{item:?}").contains("token: ["));
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
