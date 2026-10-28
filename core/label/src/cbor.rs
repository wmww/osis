//! Value helpers for the layouts of this crate (spec/wire.md §1): `what` names the field in
//! `Malformed` errors.

use crate::Error;
use osis_base::{Tid, Value};
use osis_crypto::VerifyingKey;

pub(crate) fn bytes(b: &[u8]) -> Value {
    Value::Bytes(b.to_vec())
}

pub(crate) fn tid(t: &Tid) -> Value {
    bytes(t.as_bytes())
}

/// A uint; `TooLarge` above i64.
pub(crate) fn uint(n: u64) -> Result<Value, Error> {
    Ok(Value::Int(i64::try_from(n).map_err(|_| Error::TooLarge("int"))?))
}

/// `Opt(X)` as a list of zero or one item.
pub(crate) fn opt(v: Option<Value>) -> Value {
    Value::List(v.into_iter().collect())
}

pub(crate) fn get_bytes<const N: usize>(v: &Value, what: &'static str) -> Result<[u8; N], Error> {
    match v {
        Value::Bytes(b) => b.as_slice().try_into().map_err(|_| Error::Malformed(what)),
        _ => Err(Error::Malformed(what)),
    }
}

pub(crate) fn get_tid(v: &Value, what: &'static str) -> Result<Tid, Error> {
    Ok(Tid::from_bytes(get_bytes(v, what)?))
}

pub(crate) fn get_key(v: &Value, what: &'static str) -> Result<VerifyingKey, Error> {
    VerifyingKey::from_bytes(&get_bytes(v, what)?).map_err(|_| Error::Malformed(what))
}

pub(crate) fn get_uint(v: &Value, what: &'static str) -> Result<u64, Error> {
    match v {
        Value::Int(n) => u64::try_from(*n).map_err(|_| Error::Malformed(what)),
        _ => Err(Error::Malformed(what)),
    }
}

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
