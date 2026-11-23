//! Value helpers for the layouts of this crate (spec/wire.md §1): `what` names the field in
//! `Malformed` errors.

use crate::Error;
use osis_base::{CreationRecord, Tid, Value};
use osis_crypto::VerifyingKey;

pub(crate) fn tid(t: &Tid) -> Value {
    Value::bytes(t.as_bytes())
}

pub(crate) fn get_bytes<const N: usize>(v: &Value, what: &'static str) -> Result<[u8; N], Error> {
    v.as_array().ok_or(Error::Malformed(what))
}

pub(crate) fn get_tid(v: &Value, what: &'static str) -> Result<Tid, Error> {
    Ok(Tid::from_bytes(get_bytes(v, what)?))
}

pub(crate) fn get_key(v: &Value, what: &'static str) -> Result<VerifyingKey, Error> {
    VerifyingKey::from_bytes(&get_bytes(v, what)?).map_err(|_| Error::Malformed(what))
}

pub(crate) fn get_uint(v: &Value, what: &'static str) -> Result<u64, Error> {
    v.as_uint().ok_or(Error::Malformed(what))
}

/// Creation records ascending by tid, distinct.
pub(crate) fn records_value(records: &[CreationRecord]) -> Value {
    let mut records: Vec<&CreationRecord> = records.iter().collect();
    records.sort_by_key(|r| r.tid());
    records.dedup_by_key(|r| r.tid());
    Value::List(records.into_iter().map(CreationRecord::to_value).collect())
}

/// Creation records, which must be ascending by tid and distinct.
pub(crate) fn records_from(records: &[Value]) -> Result<Vec<CreationRecord>, Error> {
    let records = records.iter().map(|r| CreationRecord::from_value(r).ok_or(Error::Malformed("creation record"))).collect::<Result<Vec<_>, _>>()?;
    if !records.windows(2).all(|w| matches!(w, [x, y] if x.tid() < y.tid())) {
        return Err(Error::Malformed("creation records not sorted by tid"));
    }
    Ok(records)
}
