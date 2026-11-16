//! Sealed fires (spec/sync-inbox.md §2, spec/wire.md §9): a fire of an open signal, a commit by
//! the sender's own account sealed to the fired thing's read KEM key, delivered as a deposit.
//! The commit travels as its `CommitBlobPlaintext` value; osis-commit parses it.

use crate::blob::Prefix;
use crate::step::OBJECT_LIMITS;
use crate::Error;
use osis_base::cbor::{decode, encode};
use osis_base::{CreationRecord, Tid, Value};
use osis_crypto::{CryptoRngCore, Epoch, KemPublicKey, KemSecret};

/// `SealedFire := [CommitBlobPlaintext, [CommitBlobPlaintext*], [creation*]]` (spec/wire.md §9):
/// the fire's commit, its author's chain certificates for its actor (each projected to its chain
/// deltas), and their creation records, ascending by tid, distinct.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SealedFire {
    pub commit: Value,
    pub chain: Vec<Value>,
    pub records: Vec<CreationRecord>,
}

impl SealedFire {
    pub fn to_value(&self) -> Value {
        let mut records: Vec<&CreationRecord> = self.records.iter().collect();
        records.sort_by_key(|r| r.tid());
        records.dedup_by_key(|r| r.tid());
        Value::List(vec![self.commit.clone(), Value::List(self.chain.clone()), Value::List(records.into_iter().map(CreationRecord::to_value).collect())])
    }

    pub fn from_value(v: Value) -> Result<SealedFire, Error> {
        let bad = || Error::Malformed("sealed fire");
        let Value::List(items) = v else { return Err(bad()) };
        let Ok::<[Value; 3], _>([commit @ Value::List(_), Value::List(chain), Value::List(records)]) = items.try_into() else { return Err(bad()) };
        if !chain.iter().all(|c| matches!(c, Value::List(_))) {
            return Err(bad());
        }
        let records = records.iter().map(|r| CreationRecord::from_value(r).ok_or(Error::Malformed("creation record"))).collect::<Result<Vec<_>, _>>()?;
        if !records.windows(2).all(|w| matches!(w, [x, y] if x.tid() < y.tid())) {
            return Err(Error::Malformed("creation records not sorted by tid"));
        }
        Ok(SealedFire { commit, chain, records })
    }
}

/// Seals `fire` behind `prefix` (its commit's encryption prefix, spec/wire.md §5) to `thing`'s
/// read KEM key `kem` of read epoch `epoch`: the blob a deposit carries.
pub fn seal_fire(prefix: &Prefix, thing: &Tid, epoch: &Epoch, kem: &KemPublicKey, fire: &SealedFire, rng: &mut dyn CryptoRngCore) -> Result<Vec<u8>, Error> {
    osis_crypto::seal_fire(&prefix.to_bytes(), thing, epoch, kem, &encode(&fire.to_value()), rng).map_err(|e| match e {
        osis_crypto::Error::TooLarge => Error::TooLarge("sealed fire above MAX_BLOB"),
        e => Error::Crypto(e),
    })
}

/// Opens a sealed fire on `thing` with the read KEM secret of its keyset at `epoch`.
pub fn open_fire(blob: &[u8], thing: &Tid, epoch: &Epoch, kem: &KemSecret) -> Result<(Prefix, SealedFire), Error> {
    crate::blob::check_size(blob)?;
    let prefix = Prefix::parse(blob)?;
    let pt = osis_crypto::open_fire(blob, prefix.len(), thing, epoch, kem)?;
    Ok((prefix, SealedFire::from_value(decode(&pt, &OBJECT_LIMITS)?)?))
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
        let fire = SealedFire { commit: Value::List(vec![Value::Int(1)]), chain: vec![], records: vec![] };
        let blob = seal_fire(&prefix, &t, &e, kem.public(), &fire, &mut rng).unwrap();
        assert_eq!(open_fire(&blob, &t, &e, &kem).unwrap(), (prefix, fire));
        assert!(open_fire(&blob, &t, &e, &KemSecret::derive(&Secret32::from_bytes([9; 32]))).is_err(), "another key");
    }
}
