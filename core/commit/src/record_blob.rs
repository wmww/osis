//! Record blobs (spec/wire.md §3, spec/permissions.md §4): `RecordBlobPlaintext := ["records",
//! [creation+]]`, raw creation records a dependent's chain needs. A record proves itself by its
//! hash (its tid), so a record blob carries no header, signature or commitments.

use crate::cbor::as_list;
use crate::header::LIMITS;
use crate::Error;
use osis_base::{CreationRecord, Value};

const RECORDS_TAG: &str = "records";

/// A record blob's plaintext: `records` ascending by tid, distinct, at least one.
pub fn encode_record_blob(records: &[CreationRecord]) -> Vec<u8> {
    let mut rs: Vec<&CreationRecord> = records.iter().collect();
    rs.sort_by_key(|r| r.tid());
    rs.dedup_by_key(|r| r.tid());
    osis_base::encode(&Value::List(vec![Value::Str(RECORDS_TAG.into()), Value::List(rs.iter().map(|r| r.to_value()).collect())]))
}

/// Whether a blob plaintext is a record blob's (by its first item), not a commit's.
pub fn is_record_blob(plain: &[u8]) -> bool {
    osis_base::decode(plain, &LIMITS).ok().and_then(|v| v.as_list().and_then(|l| l.first().cloned())) == Some(Value::Str(RECORDS_TAG.into()))
}

/// Reads a record blob's plaintext: canonical, at least one record, each a valid creation record,
/// ascending by tid and distinct.
pub fn decode_record_blob(plain: &[u8]) -> Result<Vec<CreationRecord>, Error> {
    let v = osis_base::decode(plain, &LIMITS)?;
    let [tag, records] = as_list(&v)? else { return Err(Error::Malformed("record blob arity")) };
    if *tag != Value::Str(RECORDS_TAG.into()) {
        return Err(Error::Malformed("record blob tag"));
    }
    let records = as_list(records)?.iter().map(|r| CreationRecord::from_value(r).ok_or(Error::Malformed("record blob record"))).collect::<Result<Vec<_>, _>>()?;
    if records.is_empty() || !records.windows(2).all(|w| matches!(w, [x, y] if x.tid() < y.tid())) || osis_base::encode(&v) != plain {
        return Err(Error::Malformed("record blob empty, unsorted or not canonical"));
    }
    Ok(records)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use osis_base::Tid;

    fn rec(n: u8) -> CreationRecord {
        CreationRecord::Thing { admin: Tid::from_bytes([n; 15]), nonce: [n; 32], link: None }
    }

    // spec/wire.md §3 (Record blobs): records round-trip sorted and distinct; an empty blob, a
    // record out of order or twice, or a malformed record is bad input
    #[test]
    fn record_blob_round_trips_spec_wire_3() {
        let (a, b) = (rec(1), rec(2));
        let blob = encode_record_blob(&[b.clone(), a.clone(), b.clone()]);
        assert!(is_record_blob(&blob));
        let mut want = vec![a.clone(), b.clone()];
        want.sort_by_key(|r| r.tid());
        assert_eq!(decode_record_blob(&blob).unwrap(), want);
        assert!(decode_record_blob(&encode_record_blob(&[])).is_err());
        let mut bad = want.clone();
        bad.reverse();
        let unsorted = osis_base::encode(&Value::List(vec![Value::Str(RECORDS_TAG.into()), Value::List(bad.iter().map(|r| r.to_value()).collect())]));
        assert!(decode_record_blob(&unsorted).is_err());
        let junk = osis_base::encode(&Value::List(vec![Value::Str(RECORDS_TAG.into()), Value::List(vec![Value::Int(1)])]));
        assert!(decode_record_blob(&junk).is_err());
    }
}
