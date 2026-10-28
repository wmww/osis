//! Typed reads of decoded CBOR arrays (spec/wire.md §1: exact positions, stated sizes).

use crate::Error;
use osis_core::Value;

/// Positions of one array, read front to back. `end` checks nothing is left.
pub(crate) struct Fields {
    items: std::vec::IntoIter<Value>,
    what: &'static str,
}

impl Fields {
    /// An array of exactly `n` items, or between `min` and `max` items with `fields_range`.
    pub(crate) fn exact(v: Value, n: usize, what: &'static str) -> Result<Fields, Error> {
        Fields::range(v, n, n, what)
    }

    pub(crate) fn range(v: Value, min: usize, max: usize, what: &'static str) -> Result<Fields, Error> {
        let items = list_of(v, what)?;
        if items.len() < min || items.len() > max {
            return Err(Error::Malformed(what));
        }
        Ok(Fields { items: items.into_iter(), what })
    }

    pub(crate) fn remaining(&self) -> usize {
        self.items.len()
    }

    pub(crate) fn next(&mut self) -> Result<Value, Error> {
        self.items.next().ok_or(Error::Malformed(self.what))
    }

    pub(crate) fn uint(&mut self) -> Result<u64, Error> {
        uint(self.next()?, self.what)
    }

    pub(crate) fn bool(&mut self) -> Result<bool, Error> {
        match self.next()? {
            Value::Bool(b) => Ok(b),
            _ => Err(Error::Malformed(self.what)),
        }
    }

    pub(crate) fn bytes(&mut self, max: usize) -> Result<Vec<u8>, Error> {
        bytes(self.next()?, max, self.what)
    }

    pub(crate) fn fixed<const N: usize>(&mut self) -> Result<[u8; N], Error> {
        fixed(self.next()?, self.what)
    }

    /// A list of `min..=max` items; `max` past the cap is `Error::Cap`.
    pub(crate) fn list(&mut self, min: usize, max: usize, what: &'static str) -> Result<Vec<Value>, Error> {
        list(self.next()?, min, max, what)
    }

    /// `Opt(X) := [] | [X]`.
    pub(crate) fn opt(&mut self) -> Result<Option<Value>, Error> {
        opt(self.next()?, self.what)
    }

    pub(crate) fn end(self) -> Result<(), Error> {
        if self.items.len() == 0 { Ok(()) } else { Err(Error::Malformed(self.what)) }
    }
}

fn list_of(v: Value, what: &'static str) -> Result<Vec<Value>, Error> {
    match v {
        Value::List(items) => Ok(items),
        _ => Err(Error::Malformed(what)),
    }
}

pub(crate) fn list(v: Value, min: usize, max: usize, what: &'static str) -> Result<Vec<Value>, Error> {
    let items = list_of(v, what)?;
    if items.len() > max {
        return Err(Error::Cap(what));
    }
    if items.len() < min {
        return Err(Error::Malformed(what));
    }
    Ok(items)
}

pub(crate) fn opt(v: Value, what: &'static str) -> Result<Option<Value>, Error> {
    let mut items = list_of(v, what)?;
    match items.len() {
        0 => Ok(None),
        1 => Ok(items.pop()),
        _ => Err(Error::Malformed(what)),
    }
}

pub(crate) fn uint(v: Value, what: &'static str) -> Result<u64, Error> {
    match v {
        Value::Int(i) if i >= 0 => Ok(i as u64),
        _ => Err(Error::Malformed(what)),
    }
}

pub(crate) fn bytes(v: Value, max: usize, what: &'static str) -> Result<Vec<u8>, Error> {
    match v {
        Value::Bytes(b) if b.len() <= max => Ok(b),
        Value::Bytes(_) => Err(Error::Cap(what)),
        _ => Err(Error::Malformed(what)),
    }
}

pub(crate) fn fixed<const N: usize>(v: Value, what: &'static str) -> Result<[u8; N], Error> {
    match v {
        Value::Bytes(b) => b.try_into().map_err(|_| Error::Malformed(what)),
        _ => Err(Error::Malformed(what)),
    }
}

/// Encoding helpers.
pub(crate) fn b(bytes: &[u8]) -> Value {
    Value::Bytes(bytes.to_vec())
}

pub(crate) fn u(n: u64) -> Value {
    // Wire uints in this protocol stay below 2^63 (ids < 2^32, wall ms, sequence numbers).
    Value::Int(i64::try_from(n).unwrap_or(i64::MAX))
}

pub(crate) fn opt_v(v: Option<Value>) -> Value {
    Value::List(v.into_iter().collect())
}
