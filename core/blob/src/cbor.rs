//! Value helpers for the layouts of this crate (spec/wire.md §1): `what` names the field in
//! `Malformed` errors.

use crate::Error;
use osis_base::{Tid, Value};
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

