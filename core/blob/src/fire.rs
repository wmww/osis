//! Sealed fires and sealed copies (spec/sync-inbox.md §2, spec/wire.md §9): a fire of an external
//! signal (a commit by the sender's own account) or a certificate copy, sealed to the receiving
//! thing's read KEM key, delivered as a deposit. The commit travels as its `CommitBlobPlaintext`
//! value; osis-commit parses it.

use crate::blob::Prefix;
use crate::cbor::{records_from, records_value};
use crate::step::OBJECT_LIMITS;
use crate::Error;
use osis_base::cbor::{decode, encode};
use osis_base::{CreationRecord, Tid, Value};
use osis_crypto::{CryptoRngCore, Epoch, KemPublicKey, KemSecret};

/// A sealed payload (spec/wire.md §9 `Sealed`): a fire or certificate copy with what it rests on,
/// or (form 2) a sync copy alone, `[2, SyncCopyPlaintext]`: no evidence, records or blobs
/// (spec/wire.md §4; osis-commit parses its bytes).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Sealed {
    Fire(SealedFire),
    SyncCopy(Vec<u8>),
}

impl Sealed {
    pub fn to_value(&self) -> Result<Value, Error> {
        Ok(match self {
            Sealed::Fire(f) => f.to_value(),
            Sealed::SyncCopy(b) => Value::List(vec![Value::Int(2), decode(b, &OBJECT_LIMITS)?]),
        })
    }

    pub fn from_value(v: Value) -> Result<Sealed, Error> {
        match v {
            Value::List(items) if matches!(items.first(), Some(Value::Int(2))) => {
                let Ok::<[Value; 2], _>([_, c @ Value::List(_)]) = items.try_into() else { return Err(Error::Malformed("sealed sync copy")) };
                Ok(Sealed::SyncCopy(encode(&c)))
            }
            v => Ok(Sealed::Fire(SealedFire::from_value(v)?)),
        }
    }
}

/// `Sealed := [form, CommitBlobPlaintext, [CommitBlobPlaintext*], [creation*], [blob*]]`
/// (spec/wire.md §9): `form` 0 a sealed fire, 1 a sealed copy (`copy`); the fire's commit or the
/// certificate copy; its evidence as certificate copies; their creation records, ascending by
/// tid, distinct; the blobs its commit's deltas link (their pages), whole.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SealedFire {
    pub copy: bool,
    pub commit: Value,
    pub evidence: Vec<Value>,
    pub records: Vec<CreationRecord>,
    pub pages: Vec<Vec<u8>>,
}

impl SealedFire {
    pub fn to_value(&self) -> Value {
        let pages = Value::List(self.pages.iter().map(|b| Value::Bytes(b.clone())).collect());
        Value::List(vec![Value::Int(i64::from(self.copy)), self.commit.clone(), Value::List(self.evidence.clone()), records_value(&self.records), pages])
    }

    pub fn from_value(v: Value) -> Result<SealedFire, Error> {
        let bad = || Error::Malformed("sealed fire");
        let Value::List(items) = v else { return Err(bad()) };
        let Ok::<[Value; 5], _>([Value::Int(form @ (0 | 1)), commit @ Value::List(_), Value::List(evidence), Value::List(records), Value::List(pages)]) = items.try_into() else { return Err(bad()) };
        if !evidence.iter().all(|c| matches!(c, Value::List(_))) {
            return Err(bad());
        }
        let pages = pages.into_iter().map(|b| if let Value::Bytes(b) = b { Ok(b) } else { Err(bad()) }).collect::<Result<_, _>>()?;
        Ok(SealedFire { copy: form == 1, commit, evidence, records: records_from(&records)?, pages })
    }
}

/// Seals `fire` behind `prefix` (its commit's encryption prefix, spec/wire.md §5) to `thing`'s
/// read KEM key `kem` of read epoch `epoch`: the blob a deposit carries.
pub fn seal_fire(prefix: &Prefix, thing: &Tid, epoch: &Epoch, kem: &KemPublicKey, fire: &Sealed, rng: &mut dyn CryptoRngCore) -> Result<Vec<u8>, Error> {
    osis_crypto::seal_fire(&prefix.to_bytes(), thing, epoch, kem, &encode(&fire.to_value()?), rng).map_err(|e| match e {
        osis_crypto::Error::TooLarge => Error::TooLarge("sealed fire above MAX_BLOB"),
        e => Error::Crypto(e),
    })
}

/// Opens a sealed fire on `thing` with the read KEM secret of its keyset at `epoch`.
pub fn open_fire(blob: &[u8], thing: &Tid, epoch: &Epoch, kem: &KemSecret) -> Result<(Prefix, Sealed), Error> {
    crate::blob::check_size(blob)?;
    let prefix = Prefix::parse(blob)?;
    let pt = osis_crypto::open_fire(blob, prefix.len(), thing, epoch, kem)?;
    Ok((prefix, Sealed::from_value(decode(&pt, &OBJECT_LIMITS)?)?))
}

/// A notice's payload (spec/wire.md §9 `Notice := [holder, n, nonce, Sealed]`): the holder and
/// its read keyset's epoch the notice's key is sealed to, and the sealed copy it carries.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NoticeBody {
    pub holder: Tid,
    pub epoch: Epoch,
    pub copy: SealedFire,
}

impl NoticeBody {
    fn to_value(&self) -> Value {
        let n = i64::try_from(self.epoch.n()).unwrap_or(i64::MAX);
        Value::List(vec![Value::Bytes(self.holder.as_bytes().to_vec()), Value::Int(n), Value::Bytes(self.epoch.nonce().to_vec()), self.copy.to_value()])
    }

    fn from_value(v: Value) -> Result<NoticeBody, Error> {
        let bad = || Error::Malformed("notice");
        let Value::List(items) = v else { return Err(bad()) };
        let Ok::<[Value; 4], _>([Value::Bytes(h), Value::Int(n), Value::Bytes(nonce), copy]) = items.try_into() else { return Err(bad()) };
        let holder = Tid::from_bytes(h.as_slice().try_into().map_err(|_| bad())?);
        let epoch = Epoch::new(u64::try_from(n).map_err(|_| bad())?, nonce.as_slice().try_into().map_err(|_| bad())?).map_err(|_| bad())?;
        let copy = SealedFire::from_value(copy)?;
        if !copy.copy {
            return Err(bad());
        }
        Ok(NoticeBody { holder, epoch, copy })
    }
}

/// Seals notice `body` behind `prefix` (its copy's encryption prefix) under blob key `key`, the
/// key sealed to `kem`, the read KEM key of `body.holder`'s keyset at `body.epoch`
/// (`osis_crypto::seal_notice`).
pub fn seal_notice(prefix: &Prefix, kem: &KemPublicKey, key: &osis_crypto::Secret32, body: &NoticeBody) -> Result<Vec<u8>, Error> {
    osis_crypto::seal_notice(&prefix.to_bytes(), &body.holder, &body.epoch, kem, key, &encode(&body.to_value())).map_err(|e| match e {
        osis_crypto::Error::TooLarge => Error::TooLarge("notice above MAX_BLOB"),
        e => Error::Crypto(e),
    })
}

/// The blob key of notice `blob` opened by `holder`'s read KEM secret of its keyset at `epoch`.
pub fn notice_key(blob: &[u8], holder: &Tid, epoch: &Epoch, kem: &KemSecret) -> Result<osis_crypto::Secret32, Error> {
    crate::blob::check_size(blob)?;
    let prefix = Prefix::parse(blob)?;
    Ok(osis_crypto::notice_key(blob, prefix.len(), holder, epoch, kem)?)
}

/// Opens notice `blob` under its blob key `key`: its prefix and payload, its box checked against
/// the holder and epoch the payload names, at `kem_of` (that keyset's read KEM key, `None` where
/// not held): `Ok(None)` where the box cannot be checked here, an error where it is no such box.
pub fn open_notice(blob: &[u8], key: &osis_crypto::Secret32, kem_of: impl FnOnce(&Tid, &Epoch) -> Option<KemPublicKey>) -> Result<Option<(Prefix, NoticeBody)>, Error> {
    crate::blob::check_size(blob)?;
    let prefix = Prefix::parse(blob)?;
    let pt = osis_crypto::open_notice(blob, prefix.len(), key)?;
    let body = NoticeBody::from_value(decode(&pt, &OBJECT_LIMITS)?)?;
    let Some(kem) = kem_of(&body.holder, &body.epoch) else { return Ok(None) };
    if !osis_crypto::notice_box_is(blob, prefix.len(), &body.holder, &body.epoch, &kem, key) {
        return Err(Error::Malformed("notice box"));
    }
    Ok(Some((prefix, body)))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use osis_crypto::{SeededRng, Secret32};

    // spec/wire.md §9: a sealed fire's payload round-trips; another key opens nothing (the AD
    // binding: osis-crypto's `sealed_fire`).
    #[test]
    fn sealed_fire_round_trip_spec_wire_9() {
        let mut rng = SeededRng::from_seed([0; 32]);
        let kem = KemSecret::derive(&Secret32::from_bytes([1; 32]));
        let (t, e) = (Tid::from_bytes([2; 15]), Epoch::new(3, [4; 32]).unwrap());
        let prefix = Prefix::new(Prefix::random_salt(&mut rng), None, vec![]).unwrap();
        let fire = Sealed::Fire(SealedFire { copy: false, commit: Value::List(vec![Value::Int(1)]), evidence: vec![], records: vec![], pages: vec![] });
        let blob = seal_fire(&prefix, &t, &e, kem.public(), &fire, &mut rng).unwrap();
        assert_eq!(open_fire(&blob, &t, &e, &kem).unwrap(), (prefix.clone(), fire));
        // form 2: a sync copy alone
        let sync = Sealed::SyncCopy(encode(&Value::List(vec![Value::Bytes(vec![1; 32]), Value::Bytes(vec![2; 15]), Value::List(vec![]), Value::List(vec![Value::List(vec![])])])));
        let blob = seal_fire(&prefix, &t, &e, kem.public(), &sync, &mut rng).unwrap();
        assert_eq!(open_fire(&blob, &t, &e, &kem).unwrap().1, sync);
        assert!(open_fire(&blob, &t, &e, &KemSecret::derive(&Secret32::from_bytes([9; 32]))).is_err(), "another key");
    }
}
