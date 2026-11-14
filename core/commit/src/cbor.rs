//! Structure encoding helpers (spec/wire.md §1).

/// Strictly ascending (sorted, distinct) by a key.
pub(crate) fn strictly_ascending<T, K: Ord>(items: &[T], key: impl Fn(&T) -> K) -> bool {
    items.is_sorted_by(|a, b| key(a) < key(b))
}

/// Readers of a checked value read in place (`osis_base::cbor::Item`).
pub(crate) mod item {
    use crate::Error;
    use osis_base::Tid;
    use osis_base::cbor::{Item, List};
    use osis_base::format::TID_LEN;

    pub(crate) fn uint(v: Item) -> Result<u64, Error> {
        v.as_uint().ok_or(Error::Malformed("expected an unsigned integer"))
    }

    pub(crate) fn idx(v: Item) -> Result<usize, Error> {
        usize::try_from(uint(v)?).map_err(|_| Error::Malformed("index too large"))
    }

    pub(crate) fn list(v: Item) -> Result<List, Error> {
        v.as_list().ok_or(Error::Malformed("expected an array"))
    }

    pub(crate) fn bytes<const N: usize>(v: Item) -> Result<[u8; N], Error> {
        v.as_array().ok_or(Error::Malformed("expected a byte string of its length"))
    }

    pub(crate) fn tid(v: Item) -> Result<Tid, Error> {
        Ok(Tid::from_bytes(bytes::<TID_LEN>(v)?))
    }

    pub(crate) fn opt(v: Item) -> Result<Option<Item>, Error> {
        let l = v.as_list().filter(|l| l.len() <= 1).ok_or(Error::Malformed("expected an option"))?;
        Ok(l.first())
    }
}
