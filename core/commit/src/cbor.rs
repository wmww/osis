//! Structure encoding helpers (spec/wire.md §1).

use crate::Error;
use osis_base::format::TID_LEN;
use osis_base::{Ak, Tid, Value};

/// A uint in a structure. Every uint we write is below 2^63 (times, counters, indices).
pub(crate) fn uint(n: u64) -> Value {
    debug_assert!(i64::try_from(n).is_ok());
    Value::uint(n)
}

pub(crate) fn uidx(n: usize) -> Value {
    uint(n as u64)
}

pub(crate) fn as_uint(v: &Value) -> Result<u64, Error> {
    v.as_uint().ok_or(Error::Malformed("expected an unsigned integer"))
}

pub(crate) fn as_idx(v: &Value) -> Result<usize, Error> {
    usize::try_from(as_uint(v)?).map_err(|_| Error::Malformed("index too large"))
}

pub(crate) fn as_list(v: &Value) -> Result<&[Value], Error> {
    v.as_list().ok_or(Error::Malformed("expected an array"))
}

pub(crate) fn as_bytes<const N: usize>(v: &Value) -> Result<[u8; N], Error> {
    v.as_array().ok_or(Error::Malformed("expected a byte string of its length"))
}

pub(crate) fn tid(t: &Tid) -> Value {
    Value::bytes(t.as_bytes())
}

pub(crate) fn as_tid(v: &Value) -> Result<Tid, Error> {
    Ok(Tid::from_bytes(as_bytes::<TID_LEN>(v)?))
}

pub(crate) fn ak(a: &Ak) -> Value {
    Value::Str(a.as_str().to_owned())
}

pub(crate) fn as_ak(v: &Value) -> Result<Ak, Error> {
    match v {
        Value::Str(s) => Ak::new(s.clone()).map_err(|_| Error::Malformed("aspect key")),
        _ => Err(Error::Malformed("expected an aspect key")),
    }
}

pub(crate) fn as_opt(v: &Value) -> Result<Option<&Value>, Error> {
    v.as_opt().ok_or(Error::Malformed("expected an option"))
}

/// Strictly ascending (sorted, distinct) by a key.
pub(crate) fn strictly_ascending<T, K: Ord>(items: &[T], key: impl Fn(&T) -> K) -> bool {
    items.windows(2).all(|w| match w {
        [a, b] => key(a) < key(b),
        _ => true,
    })
}
