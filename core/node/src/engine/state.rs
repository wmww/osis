//! Local encoding of aspect states: the snapshot grammar (spec/crdt.md §8: deltas, states and
//! snapshots share it) under a context no write can match, with its pages kept beside it. Large
//! states are kept in pages (`engine::pages`).

use crate::error::{Error, Result};
use osis_base::{BlobId, CommitId, Link, Ts, Value};
use osis_crdt::{CounterRange, DeltaCtx, DeltaKind, Fragment, Frontiers, Interner, PageError, PageSink, PageSource, Snapshot, Source, decode_snapshot, encode_snapshot};
use std::collections::BTreeMap;

/// Pages of a locally stored state: link hash = BLAKE3 of the plaintext, key zero, blob ID
/// distinct per put (a decode refuses one blob linked twice, and equal pages can recur).
#[derive(Default)]
pub struct LocalPages(pub BTreeMap<[u8; 32], Vec<u8>>, u64);

impl PageSink for LocalPages {
    fn put(&mut self, plaintext: &[u8]) -> std::result::Result<Link, PageError> {
        let hash = osis_base::hash::hash(plaintext);
        self.0.insert(hash, plaintext.to_vec());
        self.1 += 1;
        let mut id = hash.to_vec();
        id.extend(self.1.to_le_bytes());
        Ok(Link { hash, blob: BlobId(osis_base::hash::hash(&id)), suite: 1, key: [0; 32] })
    }
}

impl PageSource for LocalPages {
    fn get(&mut self, link: &Link) -> std::result::Result<Vec<u8>, PageError> {
        let p = self.0.get(&link.hash).ok_or(PageError::Missing)?;
        if osis_base::hash::hash(p) != link.hash {
            return Err(PageError::Corrupt);
        }
        Ok(p.clone())
    }
}

fn ctx() -> DeltaCtx {
    DeltaCtx { ts: Ts::default(), own: Source::commit(CommitId([0; 32])), range: CounterRange::EMPTY, kind: DeltaKind::Snapshot }
}

/// `[snapshot bytes, [page*]]`.
pub fn encode(f: &Fragment) -> Result<Vec<u8>> {
    let mut pages = LocalPages::default();
    let snap = Snapshot { absorbed: Default::default(), authors: Default::default(), nonce: [0; 16], fragment: f.clone(), frontiers: Frontiers::default() };
    let bytes = encode_snapshot(&snap, &ctx(), Some(&mut pages))?;
    let v = Value::List(vec![Value::Bytes(bytes), Value::List(pages.0.into_values().map(Value::Bytes).collect())]);
    Ok(osis_base::encode(&v))
}

pub fn decode(b: &[u8]) -> Result<Fragment> {
    let lim = osis_base::Limits { max_depth: 4, max_bytes: b.len() };
    let v = osis_base::decode(b, &lim).map_err(|_| Error::Corrupt("state"))?;
    let Value::List(items) = v else { return Err(Error::Corrupt("state")) };
    let [Value::Bytes(snap), Value::List(pages)] = items.as_slice() else { return Err(Error::Corrupt("state")) };
    let mut lp = LocalPages::default();
    for p in pages {
        if let Value::Bytes(p) = p {
            lp.0.insert(osis_base::hash::hash(p), p.clone());
        }
    }
    let mut interner = Interner::new();
    let s = decode_snapshot(snap, &ctx(), &mut interner, Some(&mut lp)).map_err(|_| Error::Corrupt("state"))?;
    Ok(s.fragment)
}

#[cfg(test)]
mod tests {
    use osis_base::{Tid, Ts, Value};
    use osis_crdt::{Encoding, Source, View, Writer, create};
    use std::borrow::Cow;

    /// A map of structs of registers.
    struct V(u8);

    impl View for V {
        fn encoding(&self) -> Option<Encoding> {
            Some([Encoding::Map, Encoding::Struct, Encoding::Register][usize::from(self.0)])
        }
        fn project<'a>(&self, v: &'a Value) -> Option<Cow<'a, Value>> {
            Some(Cow::Borrowed(v))
        }
        fn field(&self, _: u64) -> Option<V> {
            (self.0 == 1).then_some(V(2))
        }
        fn field_default(&self, _: u64) -> Option<Value> {
            None
        }
        fn case(&self, _: u64) -> Option<V> {
            None
        }
        fn element(&self) -> Option<V> {
            (self.0 == 0).then_some(V(1))
        }
        fn key(&self) -> Option<V> {
            (self.0 == 0).then_some(V(2))
        }
    }

    /// spec/crdt.md §8: equal structs written in one commit page into equal field-map pages;
    /// the local state round-trips (each put is its own blob, never one blob linked twice).
    #[test]
    fn equal_pages_round_trip_spec_8() {
        let s = Value::Map((0..4).map(|i| (Value::Int(i), Value::Str("x".repeat(30_000)))).collect());
        let v = Value::Map((0..2).map(|k| (Value::Int(k), s.clone())).collect());
        let mut w = Writer::new(Ts::from_u64(1 << 16).unwrap(), Source::node(Tid::from_bytes([1; 15])), 1);
        let st = create(&mut w, &V(0), &v).unwrap();
        assert_eq!(super::decode(&super::encode(&st).unwrap()).unwrap(), st);
    }
}
