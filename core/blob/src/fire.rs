//! Sealed fires (spec/sync-inbox.md §2, spec/wire.md §9): a fire of an external signal (a commit
//! by the sender's own account), sealed to the receiving thing's read KEM key and delivered as a
//! deposit. The commit travels as its `CommitBlobPlaintext` value; osis-commit parses it.

use crate::blob::Prefix;
use crate::cbor::{records_from, records_value};
use crate::step::OBJECT_LIMITS;
use crate::Error;
use osis_base::cbor::{decode, encode};
use osis_base::{CreationRecord, Tid, Value};
use osis_crypto::{CryptoRngCore, Epoch, KemPublicKey, KemSecret};

/// `Sealed := [CommitBlobPlaintext, [CommitBlobPlaintext*], [creation*], [blob*]]` (spec/wire.md
/// §9): the fire's commit; its evidence as certificate copies; their creation records, ascending
/// by tid, distinct; the blobs its commit's deltas link (their pages), whole.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Sealed {
    pub commit: Value,
    pub evidence: Vec<Value>,
    pub records: Vec<CreationRecord>,
    pub pages: Vec<Vec<u8>>,
}

impl Sealed {
    pub fn to_value(&self) -> Value {
        let pages = Value::List(self.pages.iter().map(|b| Value::Bytes(b.clone())).collect());
        Value::List(vec![self.commit.clone(), Value::List(self.evidence.clone()), records_value(&self.records), pages])
    }

    pub fn from_value(v: Value) -> Result<Sealed, Error> {
        let bad = || Error::Malformed("sealed fire");
        let Value::List(items) = v else { return Err(bad()) };
        let Ok::<[Value; 4], _>([commit @ Value::List(_), Value::List(evidence), Value::List(records), Value::List(pages)]) = items.try_into() else { return Err(bad()) };
        if !evidence.iter().all(|c| matches!(c, Value::List(_))) {
            return Err(bad());
        }
        let pages = pages.into_iter().map(|b| if let Value::Bytes(b) = b { Ok(b) } else { Err(bad()) }).collect::<Result<_, _>>()?;
        Ok(Sealed { commit, evidence, records: records_from(&records)?, pages })
    }
}

/// Seals `fire` behind `prefix` (its commit's encryption prefix, spec/wire.md §5) to `thing`'s
/// read KEM key `kem` of read epoch `epoch`: the blob a deposit carries.
pub fn seal_fire(prefix: &Prefix, thing: &Tid, epoch: &Epoch, kem: &KemPublicKey, fire: &Sealed, rng: &mut dyn CryptoRngCore) -> Result<Vec<u8>, Error> {
    osis_crypto::seal_fire(&prefix.to_bytes(), thing, epoch, kem, &encode(&fire.to_value()), rng).map_err(|e| match e {
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
        let fire = Sealed { commit: Value::List(vec![Value::Int(1)]), evidence: vec![], records: vec![], pages: vec![] };
        let blob = seal_fire(&prefix, &t, &e, kem.public(), &fire, &mut rng).unwrap();
        assert_eq!(open_fire(&blob, &t, &e, &kem).unwrap(), (prefix.clone(), fire));
        assert!(open_fire(&blob, &t, &e, &KemSecret::derive(&Secret32::from_bytes([9; 32]))).is_err(), "another key");
    }
}
