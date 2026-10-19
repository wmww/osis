//! Local encoding of aspect states: the snapshot grammar (spec/crdt.md §8: deltas, states and
//! snapshots share it) under a context no write can match, with its pages kept beside it.

use crate::error::{Error, Result};
use osis_core::{BlobId, CommitId, Link, Ts, Value};
use osis_crdt::{CounterRange, DeltaCtx, DeltaKind, Fragment, Frontiers, Interner, PageError, PageSink, PageSource, Snapshot, Source, decode_snapshot, encode_snapshot};
use std::collections::BTreeMap;

/// Pages of a locally stored state: link hash = BLAKE3 of the plaintext, key zero.
#[derive(Default)]
pub struct LocalPages(pub BTreeMap<[u8; 32], Vec<u8>>);

impl PageSink for LocalPages {
    fn put(&mut self, plaintext: &[u8]) -> std::result::Result<Link, PageError> {
        let hash = osis_core::hash::hash(plaintext);
        self.0.insert(hash, plaintext.to_vec());
        Ok(Link { hash, blob: BlobId(hash), suite: 1, key: [0; 32] })
    }
}

impl PageSource for LocalPages {
    fn get(&mut self, link: &Link) -> std::result::Result<Vec<u8>, PageError> {
        let p = self.0.get(&link.hash).ok_or(PageError::Missing)?;
        if osis_core::hash::hash(p) != link.hash {
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
    let snap = Snapshot { nonce: [0; 16], fragment: f.clone(), frontiers: Frontiers::default() };
    let bytes = encode_snapshot(&snap, &ctx(), Some(&mut pages))?;
    let v = Value::List(vec![Value::Bytes(bytes), Value::List(pages.0.into_values().map(Value::Bytes).collect())]);
    Ok(osis_core::encode(&v))
}

pub fn decode(b: &[u8]) -> Result<Fragment> {
    let lim = osis_core::Limits { max_depth: 4, max_bytes: b.len() };
    let v = osis_core::decode(b, &lim).map_err(|_| Error::Corrupt("state"))?;
    let Value::List(items) = v else { return Err(Error::Corrupt("state")) };
    let [Value::Bytes(snap), Value::List(pages)] = items.as_slice() else { return Err(Error::Corrupt("state")) };
    let mut lp = LocalPages::default();
    for p in pages {
        if let Value::Bytes(p) = p {
            lp.0.insert(osis_core::hash::hash(p), p.clone());
        }
    }
    let mut interner = Interner::new();
    let s = decode_snapshot(snap, &ctx(), &mut interner, Some(&mut lp)).map_err(|_| Error::Corrupt("state"))?;
    Ok(s.fragment)
}
