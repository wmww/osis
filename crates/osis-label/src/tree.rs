//! Chunk trees, chunk/tree-node/page blobs and the blob store plugs (spec/wire.md §6,
//! spec/data-model.md §6, spec/crypto.md §6). `TreeWriter` streams bytes into a tree through a
//! `TreeSink`; `TreeReader` streams the chunks back through a `LinkSource`, verifying every
//! content hash. `BlobWriter`/`BlobReader` are the blob-backed sink and source, and implement
//! osis-crdt's `PageSink`/`PageSource` for pages and link pages.

use crate::blob::{Level, Prefix, frame, open};
use crate::Error;
use osis_core::cbor::{Limits, decode, encode};
use osis_core::format::{MAX_BLOB, TREE_FANOUT, TREE_MAX_LEVEL};
use osis_core::{BlobId, ChunkParams, Chunker, Link, Value, WallMs};
use osis_crdt::{PageError, PageSink, PageSource};
use osis_crypto::{CryptoRngCore, SUITE_1, Secret32, link_hash, link_tree_hash};
use std::collections::HashMap;

/// How the chunk, tree-node and page blobs of one delta (or one header list) are framed: the
/// thing's dedup secret keys the content hashes; expiry and token secrets go into each prefix
/// (spec/wire.md §5, spec/crypto.md §7).
pub struct Framing {
    pub dedup: Secret32,
    pub expiry: Option<WallMs>,
    /// `(level, token secret)`; a chunk token is `kdf("delete token", secret, prefix salt)`.
    pub tokens: Vec<(Level, Secret32)>,
}

/// One blob written: its ID and chunk token hashes in `Framing::tokens` order (the header's
/// chunk list, spec/wire.md §4).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Written {
    pub id: BlobId,
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

/// Receives the pieces of a tree as `TreeWriter` closes them and returns their links.
pub trait TreeSink {
    fn chunk(&mut self, bytes: &[u8]) -> Result<Link, Error>;
    fn node(&mut self, level: u64, links: &[Link]) -> Result<Link, Error>;
}

/// Returns a link's plaintext, decrypted but not yet hash-checked (the reader checks).
pub trait LinkSource {
    fn plaintext(&mut self, link: &Link) -> Result<Vec<u8>, Error>;
}

/// A tree node's plaintext `[level, [LINK+]]`.
pub fn node_plaintext(level: u64, links: &[Link]) -> Result<Vec<u8>, Error> {
    let level = i64::try_from(level).map_err(|_| Error::TooLarge("tree level"))?;
    Ok(encode(&Value::List(vec![Value::Int(level), Value::List(links.iter().copied().map(Value::Link).collect())])))
}

/// Parses a tree node: level 1..=48, 1..=512 links.
pub fn parse_node(plaintext: &[u8]) -> Result<(u64, Vec<Link>), Error> {
    let v = decode(plaintext, &Limits { max_depth: 4, max_bytes: MAX_BLOB })?;
    let Value::List(items) = v else { return Err(Error::Malformed("tree node")) };
    let [Value::Int(level), Value::List(links)] = items.as_slice() else { return Err(Error::Malformed("tree node")) };
    let level = u64::try_from(*level).map_err(|_| Error::Malformed("tree level"))?;
    if !(1..=TREE_MAX_LEVEL).contains(&level) || links.is_empty() || links.len() > TREE_FANOUT {
        return Err(Error::Malformed("tree node bounds"));
    }
    let links = links.iter().map(|l| match l {
        Value::Link(l) => Ok(*l),
        _ => Err(Error::Malformed("tree node link")),
    });
    Ok((level, links.collect::<Result<_, _>>()?))
}

/// Streaming chunk-tree builder (spec/wire.md §6). Holds the current chunk and one open node per
/// level.
pub struct TreeWriter {
    chunker: Chunker,
    buf: Vec<u8>,
    chunks: u64,
    levels: Vec<OpenLevel>,
}

#[derive(Default)]
struct OpenLevel {
    links: Vec<Link>,
    closed: u64,
}

impl TreeWriter {
    /// `ChunkParams::FORMAT` on the wire; tests shrink it.
    pub fn new(params: ChunkParams) -> TreeWriter {
        TreeWriter { chunker: Chunker::new(params), buf: Vec::new(), chunks: 0, levels: Vec::new() }
    }

    pub fn write(&mut self, sink: &mut dyn TreeSink, mut data: &[u8]) -> Result<(), Error> {
        while let Some(i) = self.chunker.next_boundary(data) {
            let (head, rest) = data.split_at_checked(i).ok_or(Error::Malformed("chunker bound"))?;
            self.buf.extend_from_slice(head);
            self.emit_chunk(sink)?;
            data = rest;
        }
        self.buf.extend_from_slice(data);
        Ok(())
    }

    fn emit_chunk(&mut self, sink: &mut dyn TreeSink) -> Result<(), Error> {
        let link = sink.chunk(&self.buf)?;
        self.buf.clear();
        self.chunks += 1;
        self.push(sink, 0, link)
    }

    /// Adds a link to the open node of level `li + 1`, closing it by the node rule.
    fn push(&mut self, sink: &mut dyn TreeSink, li: usize, link: Link) -> Result<(), Error> {
        if self.levels.len() <= li {
            self.levels.resize_with(li + 1, OpenLevel::default);
        }
        let open = self.levels.get_mut(li).ok_or(Error::Malformed("tree level"))?;
        let zero = link.hash[0] == 0;
        open.links.push(link);
        let n = open.links.len();
        if n >= TREE_FANOUT || (n >= 2 && zero) {
            self.close(sink, li)?;
        }
        Ok(())
    }

    fn close(&mut self, sink: &mut dyn TreeSink, li: usize) -> Result<(), Error> {
        let level = u64::try_from(li + 1).map_err(|_| Error::TooLarge("tree level"))?;
        if level > TREE_MAX_LEVEL {
            return Err(Error::TooLarge("tree level"));
        }
        let open = self.levels.get_mut(li).ok_or(Error::Malformed("tree level"))?;
        let links = std::mem::take(&mut open.links);
        open.closed += 1;
        let link = sink.node(level, &links)?;
        self.push(sink, li + 1, link)
    }

    /// Closes every open node and returns the root link (always an interior node; an empty value
    /// is one empty chunk).
    pub fn finish(mut self, sink: &mut dyn TreeSink) -> Result<Link, Error> {
        if !self.buf.is_empty() || self.chunks == 0 {
            self.emit_chunk(sink)?;
        }
        let mut li = 0;
        loop {
            if self.levels.get(li).is_some_and(|l| !l.links.is_empty()) {
                self.close(sink, li)?;
            }
            if self.levels.get(li).is_some_and(|l| l.closed == 1) {
                let up = self.levels.get_mut(li + 1).ok_or(Error::Malformed("tree root"))?;
                return match (up.links.pop(), up.links.is_empty(), up.closed) {
                    (Some(root), true, 0) => Ok(root),
                    _ => Err(Error::Malformed("tree root")),
                };
            }
            li += 1;
            if li >= self.levels.len() {
                return Err(Error::Malformed("tree root"));
            }
        }
    }
}

/// Builds the tree of `data` in one call.
pub fn write_tree(sink: &mut dyn TreeSink, params: ChunkParams, data: &[u8]) -> Result<Link, Error> {
    let mut w = TreeWriter::new(params);
    w.write(sink, data)?;
    w.finish(sink)
}

/// Streaming reader: yields the chunks in order, holding one node per level. Verifies every
/// content hash, levels and bounds; a mismatch is bad input. Work is bounded by the value size:
/// a chunk other than the last shorter than `min_chunk` (or empty) is bad input, and at most
/// `max_len / min_chunk + 1` chunks are visited (`TooLarge` beyond; issues/tree-reader-bounds.md).
pub struct TreeReader {
    root: Option<Link>,
    /// Per open node: its level and the links not yet visited, reversed.
    stack: Vec<(u64, Vec<Link>)>,
    min_chunk: usize,
    chunks_left: usize,
}

impl TreeReader {
    /// `min_chunk` is `CHUNK_MIN` on the wire (`ChunkParams::min`); `max_len` the most bytes the
    /// caller accepts.
    pub fn new(root: Link, min_chunk: usize, max_len: usize) -> TreeReader {
        let min_chunk = min_chunk.max(1);
        TreeReader { root: Some(root), stack: Vec::new(), min_chunk, chunks_left: (max_len / min_chunk).saturating_add(1) }
    }

    fn enter(&mut self, dedup: &Secret32, src: &mut dyn LinkSource, link: &Link, expect: Option<u64>) -> Result<(), Error> {
        let (level, mut links) = parse_node(&src.plaintext(link)?)?;
        if expect.is_some_and(|e| e != level) {
            return Err(Error::Verify("tree level"));
        }
        let hashes: Vec<[u8; 32]> = links.iter().map(|l| l.hash).collect();
        if link_tree_hash(dedup, level, &hashes) != link.hash {
            return Err(Error::Verify("tree node content hash"));
        }
        links.reverse();
        self.stack.push((level, links));
        Ok(())
    }

    /// The next chunk, or `None` at the end.
    pub fn next_chunk(&mut self, dedup: &Secret32, src: &mut dyn LinkSource) -> Result<Option<Vec<u8>>, Error> {
        if let Some(root) = self.root.take() {
            self.enter(dedup, src, &root, None)?;
        }
        loop {
            let Some((level, links)) = self.stack.last_mut() else { return Ok(None) };
            let level = *level;
            let Some(link) = links.pop() else {
                self.stack.pop();
                continue;
            };
            if level == 1 {
                if self.chunks_left == 0 {
                    return Err(Error::TooLarge("value"));
                }
                self.chunks_left -= 1;
                let last = self.stack.iter().all(|(_, l)| l.is_empty());
                let chunk = src.plaintext(&link)?;
                if link_hash(dedup, &chunk) != link.hash {
                    return Err(Error::Verify("chunk content hash"));
                }
                if !last && chunk.len() < self.min_chunk {
                    return Err(Error::Malformed("chunk below the minimum before the last"));
                }
                return Ok(Some(chunk));
            }
            self.enter(dedup, src, &link, Some(level - 1))?;
        }
    }
}

/// Reads a whole tree chunked with `params`; `TooLarge` beyond `max_len` bytes.
pub fn read_tree(root: &Link, dedup: &Secret32, src: &mut dyn LinkSource, params: ChunkParams, max_len: usize) -> Result<Vec<u8>, Error> {
    let mut r = TreeReader::new(*root, params.min, max_len);
    let mut out = Vec::new();
    while let Some(c) = r.next_chunk(dedup, src)? {
        if out.len().saturating_add(c.len()) > max_len {
            return Err(Error::TooLarge("value"));
        }
        out.extend_from_slice(&c);
    }
    Ok(out)
}

/// A sink that only computes content hashes (blob ID and key zero): tree shape and root hash
/// without encryption. Records `(level, links)` per node in closing order.
pub struct HashSink {
    pub dedup: Secret32,
    pub chunks: u64,
    pub nodes: Vec<(u64, usize)>,
}

impl HashSink {
    pub fn new(dedup: Secret32) -> HashSink {
        HashSink { dedup, chunks: 0, nodes: Vec::new() }
    }
}

fn hash_link(hash: [u8; 32]) -> Link {
    Link { hash, blob: BlobId([0; 32]), suite: SUITE_1, key: [0; 32] }
}

impl TreeSink for HashSink {
    fn chunk(&mut self, bytes: &[u8]) -> Result<Link, Error> {
        self.chunks += 1;
        Ok(hash_link(link_hash(&self.dedup, bytes)))
    }
    fn node(&mut self, level: u64, links: &[Link]) -> Result<Link, Error> {
        self.nodes.push((level, links.len()));
        let hashes: Vec<[u8; 32]> = links.iter().map(|l| l.hash).collect();
        Ok(hash_link(link_tree_hash(&self.dedup, level, &hashes)))
    }
}

/// Writes chunk, tree-node, page and link-page blobs under one framing, each with a fresh salt
/// and key, and records what it wrote.
pub struct BlobWriter<'a> {
    framing: &'a Framing,
    sink: &'a mut dyn BlobSink,
    rng: &'a mut dyn CryptoRngCore,
    written: Vec<Written>,
}

impl<'a> BlobWriter<'a> {
    pub fn new(framing: &'a Framing, sink: &'a mut dyn BlobSink, rng: &'a mut dyn CryptoRngCore) -> BlobWriter<'a> {
        BlobWriter { framing, sink, rng, written: Vec::new() }
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
        self.sink.put(id, blob)?;
        self.written.push(Written { id, token_hashes });
        Ok(Link { hash, blob: id, suite: SUITE_1, key: *key.expose() })
    }
}

impl TreeSink for BlobWriter<'_> {
    fn chunk(&mut self, bytes: &[u8]) -> Result<Link, Error> {
        self.put_blob(link_hash(&self.framing.dedup, bytes), bytes)
    }
    fn node(&mut self, level: u64, links: &[Link]) -> Result<Link, Error> {
        let hashes: Vec<[u8; 32]> = links.iter().map(|l| l.hash).collect();
        let hash = link_tree_hash(&self.framing.dedup, level, &hashes);
        self.put_blob(hash, &node_plaintext(level, links)?)
    }
}

/// Pages and link pages: content hash `kdf("link", d, plaintext)`.
impl PageSink for BlobWriter<'_> {
    fn put(&mut self, plaintext: &[u8]) -> Result<Link, PageError> {
        Ok(self.put_blob(link_hash(&self.framing.dedup, plaintext), plaintext)?)
    }
}

/// Fetches and decrypts linked blobs, checking the blob ID and suite.
pub struct BlobReader<'a> {
    pub dedup: &'a Secret32,
    fetch: &'a mut dyn BlobFetch,
}

impl<'a> BlobReader<'a> {
    pub fn new(dedup: &'a Secret32, fetch: &'a mut dyn BlobFetch) -> BlobReader<'a> {
        BlobReader { dedup, fetch }
    }
}

impl LinkSource for BlobReader<'_> {
    fn plaintext(&mut self, link: &Link) -> Result<Vec<u8>, Error> {
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

impl PageSource for BlobReader<'_> {
    fn get(&mut self, link: &Link) -> Result<Vec<u8>, PageError> {
        let pt = self.plaintext(link)?;
        if link_hash(self.dedup, &pt) != link.hash {
            return Err(PageError::Corrupt);
        }
        Ok(pt)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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

    // spec/wire.md §6: node closing rule (>= 2 links and hash starting 0x00, or 512), the root
    // is an interior node, levels link the level below, the root hash depends on content only.
    #[test]
    fn shape_and_hashes() {
        let d = data(200_000, 1);
        let mut hs = HashSink::new(Secret32::from_bytes([7; 32]));
        let root = write_tree(&mut hs, SMALL, &d).unwrap();
        assert_eq!(hs.chunks as usize, osis_core::chunker::chunk_lengths(&d, SMALL).len());
        let top = hs.nodes.iter().map(|n| n.0).max().unwrap();
        assert!(top >= 2);
        assert_eq!(hs.nodes.iter().filter(|n| n.0 == top).count(), 1);
        assert!(hs.nodes.iter().all(|n| n.1 >= 1 && n.1 <= TREE_FANOUT));
        // Streaming in odd pieces gives the same root.
        let mut hs2 = HashSink::new(Secret32::from_bytes([7; 32]));
        let mut w = TreeWriter::new(SMALL);
        for piece in d.chunks(777) {
            w.write(&mut hs2, piece).unwrap();
        }
        assert_eq!(w.finish(&mut hs2).unwrap().hash, root.hash);
        // One chunk still has a level-1 root.
        let mut hs3 = HashSink::new(Secret32::from_bytes([7; 32]));
        write_tree(&mut hs3, SMALL, b"tiny").unwrap();
        assert_eq!(hs3.nodes, vec![(1, 1)]);
        let mut hs4 = HashSink::new(Secret32::from_bytes([7; 32]));
        write_tree(&mut hs4, SMALL, b"").unwrap();
        assert_eq!((hs4.chunks, hs4.nodes.clone()), (1, vec![(1, 1)]));
    }

    // spec/wire.md §6: a node closes at 512 links when no hash starts with 0x00.
    #[test]
    fn fanout_cap() {
        struct NoZero(u64);
        impl TreeSink for NoZero {
            fn chunk(&mut self, _: &[u8]) -> Result<Link, Error> {
                self.0 += 1;
                Ok(hash_link([1; 32]))
            }
            fn node(&mut self, level: u64, links: &[Link]) -> Result<Link, Error> {
                assert!(links.len() <= 512);
                if level == 1 && links.len() < 512 {
                    assert_eq!(self.0, 1100);
                }
                Ok(hash_link([2; 32]))
            }
        }
        let p = ChunkParams { min: 1, max: 1, mask_bits: 63 };
        write_tree(&mut NoZero(0), p, &[5; 1100]).unwrap();
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
        assert!(matches!(read_tree(&root, &dedup, &mut r, SMALL, 100), Err(Error::TooLarge(_))));
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
        assert_eq!(read_tree(&root, &other, &mut BlobReader::new(&other, &mut store), SMALL, usize::MAX), Err(Error::Verify("tree node content hash")));
        let mut bad = root;
        bad.hash[0] ^= 1;
        assert!(read_tree(&bad, &dedup, &mut BlobReader::new(&dedup, &mut store), SMALL, usize::MAX).is_err());
        // Replace one chunk blob by another's bytes: blob ID mismatch.
        let ids: Vec<BlobId> = store.0.keys().copied().collect();
        let swapped = store.0[&ids[1]].clone();
        store.0.insert(ids[0], swapped);
        assert!(read_tree(&root, &dedup, &mut BlobReader::new(&dedup, &mut store), SMALL, usize::MAX).is_err());
        // A level-2 root claimed over chunk links fails its level check.
        assert!(parse_node(&node_plaintext(49, &[root]).unwrap()).is_err());
        assert!(parse_node(&node_plaintext(1, &[]).unwrap()).is_err());
        assert!(parse_node(&encode(&Value::List(vec![Value::Int(1), Value::List(vec![Value::Int(0)])]))).is_err());
    }

    /// Plaintexts by content hash, counting fetches (hostile trees built by hand).
    #[derive(Default)]
    struct ByHash(HashMap<[u8; 32], Vec<u8>>, usize);
    impl LinkSource for ByHash {
        fn plaintext(&mut self, link: &Link) -> Result<Vec<u8>, Error> {
            self.1 += 1;
            self.0.get(&link.hash).cloned().ok_or(Error::Missing)
        }
    }

    // spec/wire.md §6 (issues/tree-reader-bounds.md): reader work is bounded by the value size:
    // an empty or short chunk before the last is bad input; repeated links (legal: identical
    // chunks share a blob) cost at most max_len / min + 1 chunk fetches.
    #[test]
    fn reader_bounds() {
        let d = Secret32::from_bytes([7; 32]);
        let mut src = ByHash::default();
        let node = |src: &mut ByHash, level: u64, child: Link| {
            let links = vec![child; TREE_FANOUT];
            let hash = link_tree_hash(&d, level, &vec![child.hash; TREE_FANOUT]);
            src.0.insert(hash, node_plaintext(level, &links).unwrap());
            hash_link(hash)
        };
        let empty = hash_link(link_hash(&d, b""));
        src.0.insert(empty.hash, vec![]);
        let n1 = node(&mut src, 1, empty);
        let root = node(&mut src, 2, n1);
        assert_eq!(read_tree(&root, &d, &mut src, SMALL, usize::MAX), Err(Error::Malformed("chunk below the minimum before the last")));
        assert!(src.1 < 5);
        let full = vec![9u8; SMALL.min];
        let c = hash_link(link_hash(&d, &full));
        src.0.insert(c.hash, full);
        let n1 = node(&mut src, 1, c);
        let n2 = node(&mut src, 2, n1);
        let root = node(&mut src, 3, n2);
        src.1 = 0;
        assert_eq!(read_tree(&root, &d, &mut src, SMALL, 10 * SMALL.min), Err(Error::TooLarge("value")));
        assert!(src.1 <= 11 + 3, "{}", src.1);
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
