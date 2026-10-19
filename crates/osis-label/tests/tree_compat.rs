//! osis-commit's chunk-tree writer and reader (header lists) and osis-label's agree until they
//! are one module (issues/tree-unify.md): same trees, each reads the other's, same refusals
//! (spec/wire.md §6).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

use osis_commit::{BlobSink as _, MemoryBlobs, Prefix};
use osis_core::format::CHUNK_MIN;
use osis_core::{ChunkParams, Link};
use osis_crypto::{Secret32, link_hash, link_tree_hash};
use osis_label::tree::node_plaintext;
use osis_label::{LinkSource, TreeSink};

/// Label's sink and source over commit's in-memory blobs (key zero, fresh salt per blob).
struct Both {
    m: MemoryBlobs,
    dedup: Secret32,
    n: u8,
}

impl Both {
    fn put(&mut self, hash: [u8; 32], pt: &[u8]) -> Link {
        self.n = self.n.wrapping_add(1);
        let (blob, key) = self.m.put(&Prefix { salt: [self.n; 16], expiry: None, commitments: vec![] }, pt).unwrap();
        Link { hash, blob, suite: 1, key }
    }
}

impl TreeSink for Both {
    fn chunk(&mut self, bytes: &[u8]) -> Result<Link, osis_label::Error> {
        let h = link_hash(&self.dedup, bytes);
        Ok(self.put(h, bytes))
    }
    fn node(&mut self, level: u64, links: &[Link]) -> Result<Link, osis_label::Error> {
        let hashes: Vec<[u8; 32]> = links.iter().map(|l| l.hash).collect();
        let pt = node_plaintext(level, links)?;
        Ok(self.put(link_tree_hash(&self.dedup, level, &hashes), &pt))
    }
}

impl LinkSource for Both {
    fn plaintext(&mut self, link: &Link) -> Result<Vec<u8>, osis_label::Error> {
        osis_commit::BlobSource::get(&mut self.m, link).map_err(|_| osis_label::Error::Missing)
    }
}

fn data(n: usize) -> Vec<u8> {
    let mut out = vec![0u8; n];
    osis_core::hash::Hasher::new().update(&[9]).finalize_xof(&mut out);
    out
}

fn both() -> Both {
    Both { m: MemoryBlobs::default(), dedup: Secret32::from_bytes([4; 32]), n: 0 }
}

// spec/wire.md §6: both writers build the same tree; each reader reads the other's.
#[test]
fn commit_and_label_trees_agree() {
    let max = 4 << 20;
    for n in [0, 1, CHUNK_MIN, 1_500_000] {
        let d = data(n);
        let mut b = both();
        let dedup = b.dedup.clone();
        let c_root = osis_commit::write_tree(&d, &dedup, &mut b.m, &mut || Ok(Prefix { salt: [0xee; 16], expiry: None, commitments: vec![] })).unwrap();
        let l_root = osis_label::write_tree(&mut b, ChunkParams::FORMAT, &d).unwrap();
        assert_eq!(c_root.hash, l_root.hash, "root hash at {n} bytes");
        assert_eq!(osis_label::read_tree(&c_root, &dedup, &mut b, ChunkParams::FORMAT, max).unwrap(), d);
        assert_eq!(osis_commit::read_tree(&l_root, &dedup, &mut b.m, max).unwrap(), d);
    }
}

// spec/wire.md §6: both refuse a non-final short chunk (bad input) and stop at the caller's
// bound (local) on repeated links.
#[test]
fn commit_and_label_refuse_alike() {
    let mut b = both();
    let dedup = b.dedup.clone();
    let short = b.chunk(&[1u8; 100]).unwrap();
    let root = b.node(1, &[short, short]).unwrap();
    assert!(matches!(osis_label::read_tree(&root, &dedup, &mut b, ChunkParams::FORMAT, 1 << 20), Err(osis_label::Error::Malformed(_))));
    assert!(matches!(osis_commit::read_tree(&root, &dedup, &mut b.m, 1 << 20), Err(osis_commit::Error::Malformed(_))));
    let full = b.chunk(&vec![2u8; CHUNK_MIN]).unwrap();
    let root = b.node(1, &[full; 8]).unwrap();
    let bound = 3 * CHUNK_MIN;
    let l = osis_label::read_tree(&root, &dedup, &mut b, ChunkParams::FORMAT, bound).unwrap_err();
    let c = osis_commit::read_tree(&root, &dedup, &mut b.m, bound).unwrap_err();
    assert_eq!(osis_core::Classified::class(&l), osis_core::ErrorClass::Local);
    assert_eq!(osis_core::Classified::class(&c), osis_core::ErrorClass::Local);
    // and a node whose level is not one above its children
    let bad = b.node(2, &[full]).unwrap();
    assert!(osis_label::read_tree(&bad, &dedup, &mut b, ChunkParams::FORMAT, 1 << 20).is_err());
    assert!(osis_commit::read_tree(&bad, &dedup, &mut b.m, 1 << 20).is_err());
}
