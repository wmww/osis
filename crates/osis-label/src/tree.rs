//! Chunk, tree-node and page blobs and the blob store plugs (spec/wire.md §6,
//! spec/data-model.md §6, spec/crypto.md §6). The chunk-tree writer and reader are osis-commit's
//! `tree` module, re-exported here under the same names; `BlobWriter`/`BlobReader` are the
//! blob-backed `TreeSink` and `LinkSource`, and implement osis-crdt's `PageSink`/`PageSource` for
//! pages and link pages.

pub use osis_commit::tree::{HashSink, Kid, LinkSource, TreeReader, TreeSink, TreeWriter, kids_len, node_hash, node_plaintext, parse_node, read_tree, write_tree};

use crate::blob::{Level, Prefix, frame, open};
use crate::Error;
use osis_core::{BlobId, ChunkParams, Link, WallMs};
use osis_crdt::{PageError, PageParams, PageSink, PageSource};
use osis_crypto::{CryptoRngCore, SUITE_1, Secret32, commitment, delete_token, link_hash, token_hash};
use std::collections::{BTreeSet, HashMap};

/// How the chunk, tree-node and page blobs of one delta (or one header list) are framed: the
/// thing's dedup secret keys the content hashes; expiry and token secrets go into each prefix
/// (spec/wire.md §5, spec/crypto.md §7).
#[derive(Clone)]
pub struct Framing {
    pub dedup: Secret32,
    pub expiry: Option<WallMs>,
    /// `(level, token secret)`; a chunk token is `kdf("delete token", secret, prefix salt)`.
    pub tokens: Vec<(Level, Secret32)>,
}

/// Token level of the author-chain write secret (spec/crypto.md §7); the others are thing secrets.
const AUTHOR_CHAIN: Level = 2;

impl Framing {
    /// Whether a blob framed earlier keeps its encryption when a delta framed with `self` reuses
    /// it (spec/sync.md §1): its expiry is not earlier than this one's, and its thing-secret token
    /// commitments (admin and thing write secret) are exactly this framing's under its salt.
    /// Author-chain tokens need not match.
    pub fn keeps(&self, prefix: &Prefix) -> bool {
        let expiry_ok = match (prefix.expiry(), self.expiry) {
            (None, _) => true,
            (Some(_), None) => false,
            (Some(old), Some(new)) => old >= new,
        };
        let salt = prefix.salt();
        let mine: Result<BTreeSet<[u8; 17]>, _> = self
            .tokens
            .iter()
            .filter(|(l, _)| *l != AUTHOR_CHAIN)
            .map(|(l, s)| commitment(*l, &token_hash(delete_token(s, salt).expose()), salt))
            .collect();
        let theirs: BTreeSet<[u8; 17]> = prefix.commitments().iter().filter(|c| c[0] != AUTHOR_CHAIN).copied().collect();
        expiry_ok && mine.is_ok_and(|m| m == theirs)
    }
}

/// One blob written: its ID, prefix salt and chunk token hashes in `Framing::tokens` order (the
/// header's chunk list, spec/wire.md §4; osis-commit's `AspectWrite::chunks` takes ID and salt).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Written {
    pub id: BlobId,
    pub salt: [u8; 16],
    pub token_hashes: Vec<[u8; 16]>,
}

/// Where blobs go.
pub trait BlobSink {
    fn put(&mut self, id: BlobId, blob: Vec<u8>) -> Result<(), Error>;
}

/// Where blobs come from (`BlobFetch`, notes/architecture.md §2): `Missing` when not held.
pub trait BlobFetch {
    fn fetch(&mut self, id: &BlobId) -> Result<Vec<u8>, Error>;
}

/// A blob store both ways (the node's backs it with osis-store's blob area).
pub trait BlobStore: BlobSink + BlobFetch {}
impl<T: BlobSink + BlobFetch + ?Sized> BlobStore for T {}

/// In-memory blob store for tests.
#[derive(Default, Debug)]
pub struct MemoryBlobs(pub HashMap<BlobId, Vec<u8>>);

impl BlobSink for MemoryBlobs {
    fn put(&mut self, id: BlobId, blob: Vec<u8>) -> Result<(), Error> {
        self.0.insert(id, blob);
        Ok(())
    }
}

impl BlobFetch for MemoryBlobs {
    fn fetch(&mut self, id: &BlobId) -> Result<Vec<u8>, Error> {
        self.0.get(id).cloned().ok_or(Error::Missing)
    }
}

/// Writes chunk, tree-node, page and link-page blobs under one framing, each with a fresh salt
/// and key, and records what it wrote. Built from a [`Reuse`] index of the value's current tree
/// (`BlobWriter::reusing`, which takes the index's framing), a
/// chunk or node of equal content hash keeps its blob when the re-encryption rule allows
/// (spec/sync.md §1); reused blobs are not in `written` (the delta does not introduce them).
pub struct BlobWriter<'a> {
    framing: &'a Framing,
    store: &'a mut dyn BlobStore,
    rng: &'a mut dyn CryptoRngCore,
    written: Vec<Written>,
    reuse: Option<&'a Reuse>,
    reused: usize,
    page_params: PageParams,
}

impl<'a> BlobWriter<'a> {
    pub fn new(framing: &'a Framing, store: &'a mut dyn BlobStore, rng: &'a mut dyn CryptoRngCore) -> BlobWriter<'a> {
        BlobWriter { framing, store, rng, written: Vec::new(), reuse: None, reused: 0, page_params: PageParams::FORMAT }
    }

    /// Dedup by reuse against an index of the current tree, framing with the index's framing
    /// (the re-encryption rule was evaluated against it).
    pub fn reusing(reuse: &'a Reuse, store: &'a mut dyn BlobStore, rng: &'a mut dyn CryptoRngCore) -> BlobWriter<'a> {
        let mut w = BlobWriter::new(&reuse.framing, store, rng);
        w.reuse = Some(reuse);
        w
    }

    /// Page parameters reported to osis-crdt (`FORMAT` on the wire; tests shrink them).
    pub fn with_page_params(mut self, p: PageParams) -> BlobWriter<'a> {
        self.page_params = p;
        self
    }

    /// Blobs reused instead of written.
    pub fn reused(&self) -> usize {
        self.reused
    }

    /// A reusable old chunk: held, intact, equal bytes, and kept by the re-encryption rule.
    fn reuse_chunk(&mut self, hash: &[u8; 32], bytes: &[u8]) -> Result<Option<Link>, Error> {
        let Some(old) = self.reuse.and_then(|r| r.chunks.get(hash)).copied() else { return Ok(None) };
        let blob = match self.store.fetch(&old.blob) {
            Ok(b) => b,
            Err(Error::Storage) => return Err(Error::Storage),
            Err(_) => return Ok(None),
        };
        if old.suite != SUITE_1 || crate::blob::blob_id(&blob) != old.blob {
            return Ok(None);
        }
        Ok(match open(&blob, &Secret32::from_bytes(old.key)) {
            Ok((prefix, pt)) if pt == bytes && self.framing.keeps(&prefix) => Some(old),
            _ => None,
        })
    }

    pub fn written(&self) -> &[Written] {
        &self.written
    }

    pub fn into_written(self) -> Vec<Written> {
        self.written
    }

    /// Frames `plaintext` as a blob whose link carries `hash`.
    pub fn put_blob(&mut self, hash: [u8; 32], plaintext: &[u8]) -> Result<Link, Error> {
        let salt = Prefix::random_salt(self.rng);
        let secrets: Vec<(Level, &Secret32)> = self.framing.tokens.iter().map(|(l, s)| (*l, s)).collect();
        let (prefix, token_hashes) = Prefix::for_chunk(salt, self.framing.expiry, &secrets)?;
        let (key, blob) = frame(&prefix, plaintext, self.rng)?;
        let id = crate::blob::blob_id(&blob);
        self.store.put(id, blob)?;
        self.written.push(Written { id, salt, token_hashes });
        Ok(Link { hash, blob: id, suite: SUITE_1, key: *key.expose() })
    }
}

impl TreeSink for BlobWriter<'_> {
    fn chunk(&mut self, bytes: &[u8]) -> Result<Link, osis_commit::Error> {
        let hash = link_hash(&self.framing.dedup, bytes);
        if let Some(old) = self.reuse_chunk(&hash, bytes)? {
            self.reused += 1;
            return Ok(old);
        }
        Ok(self.put_blob(hash, bytes)?)
    }
    fn node(&mut self, level: u64, kids: &[Kid]) -> Result<Link, osis_commit::Error> {
        let hash = node_hash(&self.framing.dedup, level, kids);
        if let Some((old, children)) = self.reuse.and_then(|r| r.nodes.get(&hash))
            && *children == kids_digest(kids)
        {
            let old = *old;
            self.reused += 1;
            return Ok(old);
        }
        Ok(self.put_blob(hash, &node_plaintext(level, kids)?)?)
    }
}

/// Pages and link pages: content hash `kdf("link", d, plaintext)`.
impl PageSink for BlobWriter<'_> {
    fn put(&mut self, plaintext: &[u8]) -> Result<Link, PageError> {
        Ok(self.put_blob(link_hash(&self.framing.dedup, plaintext), plaintext)?)
    }
    fn params(&self) -> PageParams {
        self.page_params
    }
}

/// Digest of a node's exact links (a node is reused only over the very blobs it links; its
/// content hash covers the lengths).
fn kids_digest(kids: &[Kid]) -> [u8; 32] {
    let mut h = osis_core::hash::Hasher::new();
    for (l, _) in kids {
        h.update(&l.hash).update(&l.blob.0).update(&[l.suite]).update(&l.key);
    }
    h.finalize()
}

/// What a new version of a large value may reuse from the current tree (spec/sync.md §1,
/// notes/local-store.md): chunk links by content hash, and node links whose blob the
/// re-encryption rule keeps, with the digest of their children. Memory: one link per chunk and
/// node of the current tree.
pub struct Reuse {
    /// The new delta's framing: the rule is evaluated against it, and the writer frames with it.
    framing: Framing,
    chunks: HashMap<[u8; 32], Link>,
    nodes: HashMap<[u8; 32], (Link, [u8; 32])>,
}

impl Reuse {
    /// Walks the tree under `root` through the held node blobs (each verified; a missing,
    /// corrupt or foreign node just indexes nothing below it), visiting at most
    /// `max_len / CHUNK_MIN + 1` chunk links. Only `Storage` fails.
    pub fn index(root: &Link, framing: Framing, fetch: &mut dyn BlobFetch, params: ChunkParams, max_len: usize) -> Result<Reuse, Error> {
        let mut r = Reuse { framing, chunks: HashMap::new(), nodes: HashMap::new() };
        let framing = &r.framing;
        let mut budget = (max_len / params.min.max(1)).saturating_add(1);
        let mut stack = vec![(*root, None)];
        let mut seen = std::collections::HashSet::new();
        while let Some((link, expect)) = stack.pop() {
            if !seen.insert(link.hash) {
                continue;
            }
            let Some((prefix, level, kids)) = Self::node(framing, fetch, &link, expect)? else { continue };
            if framing.keeps(&prefix) {
                r.nodes.insert(link.hash, (link, kids_digest(&kids)));
            }
            for (l, _) in kids.into_iter().rev() {
                if level > 1 {
                    stack.push((l, Some(level - 1)));
                    continue;
                }
                if budget == 0 {
                    return Ok(r);
                }
                budget -= 1;
                r.chunks.entry(l.hash).or_insert(l);
            }
        }
        Ok(r)
    }

    fn node(framing: &Framing, fetch: &mut dyn BlobFetch, link: &Link, expect: Option<u64>) -> Result<Option<(Prefix, u64, Vec<Kid>)>, Error> {
        let blob = match fetch.fetch(&link.blob) {
            Ok(b) => b,
            Err(Error::Storage) => return Err(Error::Storage),
            Err(_) => return Ok(None),
        };
        if link.suite != SUITE_1 || crate::blob::blob_id(&blob) != link.blob {
            return Ok(None);
        }
        let Ok((prefix, pt)) = open(&blob, &Secret32::from_bytes(link.key)) else { return Ok(None) };
        let Ok((level, kids)) = parse_node(&pt) else { return Ok(None) };
        if expect.is_some_and(|e| e != level) || node_hash(&framing.dedup, level, &kids) != link.hash {
            return Ok(None);
        }
        Ok(Some((prefix, level, kids)))
    }

    /// Never reuses `blob` (a chunk or node a server deleted, spec/sync.md §1): it is written
    /// afresh, and so is every node above it.
    pub fn exclude(&mut self, blob: &BlobId) {
        self.chunks.retain(|_, l| l.blob != *blob);
        self.nodes.retain(|_, (l, _)| l.blob != *blob);
    }

    /// Chunk links indexed.
    pub fn chunks(&self) -> usize {
        self.chunks.len()
    }
}

/// Fetches and decrypts linked blobs, checking the blob ID and suite.
pub struct BlobReader<'a> {
    pub dedup: &'a Secret32,
    fetch: &'a mut dyn BlobFetch,
    page_params: PageParams,
}

impl<'a> BlobReader<'a> {
    pub fn new(dedup: &'a Secret32, fetch: &'a mut dyn BlobFetch) -> BlobReader<'a> {
        BlobReader { dedup, fetch, page_params: PageParams::FORMAT }
    }

    /// Page parameters reported to osis-crdt (`FORMAT` on the wire; tests shrink them).
    pub fn with_page_params(mut self, p: PageParams) -> BlobReader<'a> {
        self.page_params = p;
        self
    }
}

impl BlobReader<'_> {
    fn open_link(&mut self, link: &Link) -> Result<Vec<u8>, Error> {
        if link.suite != SUITE_1 {
            return Err(Error::Crypto(osis_crypto::Error::UnknownSuite(u64::from(link.suite))));
        }
        let blob = self.fetch.fetch(&link.blob)?;
        if crate::blob::blob_id(&blob) != link.blob {
            return Err(Error::Verify("blob id"));
        }
        Ok(open(&blob, &Secret32::from_bytes(link.key))?.1)
    }
}

impl LinkSource for BlobReader<'_> {
    fn plaintext(&mut self, link: &Link) -> Result<Vec<u8>, osis_commit::Error> {
        Ok(self.open_link(link)?)
    }
}

impl PageSource for BlobReader<'_> {
    fn get(&mut self, link: &Link) -> Result<Vec<u8>, PageError> {
        let pt = self.open_link(link)?;
        if link_hash(self.dedup, &pt) != link.hash {
            return Err(PageError::Corrupt);
        }
        Ok(pt)
    }
    fn params(&self) -> PageParams {
        self.page_params
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use osis_core::{Value, encode};
    use osis_crypto::SeededRng;
    use proptest::prelude::*;

    const SMALL: ChunkParams = ChunkParams { min: 16, max: 64, mask_bits: 4 };

    fn data(n: usize, seed: u8) -> Vec<u8> {
        let mut out = vec![0u8; n];
        osis_core::hash::Hasher::new().update(&[seed]).finalize_xof(&mut out);
        out
    }

    fn framing() -> Framing {
        Framing { dedup: Secret32::from_bytes([7; 32]), expiry: Some(WallMs(99)), tokens: vec![(1, Secret32::from_bytes([1; 32])), (3, Secret32::from_bytes([3; 32]))] }
    }

    // spec/wire.md §6, spec/crypto.md §6: chunk and node blobs round trip through framing; the
    // reader verifies blob IDs and content hashes; prefixes carry expiry and chunk tokens.
    #[test]
    fn blob_round_trip() {
        let f = framing();
        let mut store = MemoryBlobs::default();
        let mut rng = SeededRng::from_u64(9);
        let d = data(5_000, 2);
        let mut w = BlobWriter::new(&f, &mut store, &mut rng);
        let root = write_tree(&mut w, SMALL, &d).unwrap();
        let written = w.into_written();
        assert_eq!(written.len(), store.0.len());
        for wr in &written {
            let p = Prefix::parse(&store.0[&wr.id]).unwrap();
            assert_eq!(p.expiry(), Some(WallMs(99)));
            assert_eq!(p.commitments().len(), 2);
            let tok = osis_crypto::delete_token(&f.tokens[1].1, p.salt());
            assert_eq!(p.match_token(tok.expose()), Some(3));
            assert_eq!(wr.token_hashes[1], osis_crypto::token_hash(tok.expose()));
        }
        let dedup = f.dedup.clone();
        let mut r = BlobReader::new(&dedup, &mut store);
        assert_eq!(read_tree(&root, &dedup, &mut r, SMALL, usize::MAX).unwrap(), d);
        assert!(matches!(read_tree(&root, &dedup, &mut r, SMALL, 100), Err(osis_commit::Error::TooLarge(_))));
        // Same content, another writer: same root hash, other blobs.
        let mut store2 = MemoryBlobs::default();
        let mut w2 = BlobWriter::new(&f, &mut store2, &mut rng);
        let root2 = write_tree(&mut w2, SMALL, &d).unwrap();
        assert_eq!(root2.hash, root.hash);
        assert_ne!(root2.blob, root.blob);
    }

    // spec/wire.md §6: a mismatched content hash, swapped blob or wrong level is bad input.
    #[test]
    fn reader_rejects() {
        let f = framing();
        let mut store = MemoryBlobs::default();
        let mut rng = SeededRng::from_u64(10);
        let d = data(3_000, 3);
        let root = write_tree(&mut BlobWriter::new(&f, &mut store, &mut rng), SMALL, &d).unwrap();
        let dedup = f.dedup.clone();
        let other = Secret32::from_bytes([8; 32]);
        assert!(matches!(read_tree(&root, &other, &mut BlobReader::new(&other, &mut store), SMALL, usize::MAX), Err(osis_commit::Error::Corrupt)));
        let mut bad = root;
        bad.hash[0] ^= 1;
        assert!(read_tree(&bad, &dedup, &mut BlobReader::new(&dedup, &mut store), SMALL, usize::MAX).is_err());
        // Replace one chunk blob by another's bytes: blob ID mismatch.
        let ids: Vec<BlobId> = store.0.keys().copied().collect();
        let swapped = store.0[&ids[1]].clone();
        store.0.insert(ids[0], swapped);
        assert!(read_tree(&root, &dedup, &mut BlobReader::new(&dedup, &mut store), SMALL, usize::MAX).is_err());
        // A level-2 root claimed over chunk links fails its level check.
        assert!(parse_node(&node_plaintext(49, &[(root, 1)]).unwrap()).is_err());
        assert!(parse_node(&node_plaintext(1, &[]).unwrap()).is_err());
        assert!(parse_node(&encode(&Value::List(vec![Value::Int(1), Value::List(vec![Value::Int(0)]), Value::List(vec![Value::Int(0)])]))).is_err());
        // The old two-item layout does not parse.
        assert!(parse_node(&encode(&Value::List(vec![Value::Int(1), Value::List(vec![Value::Link(root)])]))).is_err());
    }

    // spec/crdt.md §8, spec/wire.md §6: pages go through PageSink/PageSource as blobs with
    // content hash kdf("link", d, plaintext).
    #[test]
    fn pages() {
        let f = framing();
        let mut store = MemoryBlobs::default();
        let mut rng = SeededRng::from_u64(11);
        let link = PageSink::put(&mut BlobWriter::new(&f, &mut store, &mut rng), b"page").unwrap();
        assert_eq!(link.hash, link_hash(&f.dedup, b"page"));
        let dedup = f.dedup.clone();
        let mut r = BlobReader::new(&dedup, &mut store);
        assert_eq!(r.get(&link).unwrap(), b"page");
        let mut bad = link;
        bad.hash = [0; 32];
        assert_eq!(r.get(&bad), Err(PageError::Corrupt));
        bad = link;
        bad.blob = BlobId([1; 32]);
        assert_eq!(r.get(&bad), Err(PageError::Missing));
    }

    // spec/crdt.md §8, spec/sync.md §6, spec/commits.md §1: a paged snapshot goes out through
    // BlobWriter (pages framed with the delta's expiry and tokens, listed for the chunk list) and
    // back through BlobReader; without a page the commit cannot apply (Missing, fetch and retry).
    #[test]
    fn paged_snapshot() {
        use osis_crdt::{AnyView, CounterRange, DeltaCtx, DeltaKind, Frontiers, Interner, Snapshot, Source, Writer, create, decode_snapshot, encode_snapshot};
        use osis_core::{Tid, Ts};
        let params = PageParams { target: 2000, cut: ChunkParams { min: 128, max: 1024, mask_bits: 6 }, fanout: 8 };
        let ts = Ts::from_u64(1 << 40).unwrap();
        let own = Source::node(Tid::from_bytes([5; 15]));
        let elems: std::collections::BTreeSet<Value> = (0..500).map(|i| Value::Str(format!("element {i}"))).collect();
        let fragment = create(&mut Writer::new(ts, own.clone(), 1), &AnyView, &Value::Set(elems)).unwrap();
        let snap = Snapshot { absorbed: Default::default(), nonce: [0; 16], fragment, frontiers: Frontiers::default() };
        let cx = DeltaCtx { ts, own: Source::node(Tid::from_bytes([250; 15])), range: CounterRange::EMPTY, kind: DeltaKind::Snapshot };
        let f = framing();
        let mut store = MemoryBlobs::default();
        let mut rng = SeededRng::from_u64(12);
        let mut w = BlobWriter::new(&f, &mut store, &mut rng).with_page_params(params);
        let bytes = encode_snapshot(&snap, &cx, Some(&mut w)).unwrap();
        let written = w.into_written();
        assert!(written.len() > 3);
        for wr in &written {
            let p = Prefix::parse(&store.0[&wr.id]).unwrap();
            assert_eq!((p.expiry(), wr.token_hashes.len(), p.salt()), (f.expiry, 2, &wr.salt));
        }
        let mut r = BlobReader::new(&f.dedup, &mut store).with_page_params(params);
        assert_eq!(decode_snapshot(&bytes, &cx, &mut Interner::new(), Some(&mut r)).unwrap().fragment, snap.fragment);
        store.0.remove(&written[1].id);
        let mut r = BlobReader::new(&f.dedup, &mut store).with_page_params(params);
        assert!(matches!(decode_snapshot(&bytes, &cx, &mut Interner::new(), Some(&mut r)), Err(osis_crdt::Error::Page(PageError::Missing))));
    }

    proptest! {
        // spec/wire.md §6: round trip for random sizes incl. empty; incremental equals one-shot.
        #[test]
        fn round_trip(n in 0usize..3000, seed in any::<u8>(), piece in 1usize..500) {
            let f = framing();
            let d = data(n, seed);
            let mut store = MemoryBlobs::default();
            let mut rng = SeededRng::from_u64(u64::from(seed));
            let mut bw = BlobWriter::new(&f, &mut store, &mut rng);
            let mut w = TreeWriter::new(SMALL);
            for p in d.chunks(piece) {
                w.write(&mut bw, p).unwrap();
            }
            let root = w.finish(&mut bw).unwrap();
            let mut hs = HashSink::new(f.dedup.clone());
            prop_assert_eq!(write_tree(&mut hs, SMALL, &d).unwrap().hash, root.hash);
            let dedup = f.dedup.clone();
            prop_assert_eq!(read_tree(&root, &dedup, &mut BlobReader::new(&dedup, &mut store), SMALL, usize::MAX).unwrap(), d);
        }
    }
}
