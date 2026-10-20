//! Chunk trees (spec/wire.md §6, spec/data-model.md §6, spec/crypto.md §6): the one writer and
//! reader, used for header lists here (`lists.rs`) and for large values and pages by osis-label
//! (which re-exports these items and adds blob framing). `TreeWriter` streams bytes into a tree
//! through a `TreeSink`; `TreeReader` streams the chunks back through a `LinkSource`, verifying
//! every content hash and length, and seeks by the lengths the nodes carry.

use crate::Error;
use osis_core::cbor::{Limits, decode, encode};
use osis_core::format::{CHUNK_MAX, MAX_BLOB, TREE_FANOUT, TREE_MAX_LEVEL};
use osis_core::{BlobId, ChunkParams, Chunker, Link, Value};
use osis_crypto::{SUITE_1, Secret32, link_hash, link_tree_hash};

/// A child of a tree node: its link and the plaintext length of its subtree.
pub type Kid = (Link, u64);

/// Receives the pieces of a tree as `TreeWriter` closes them and returns their links.
pub trait TreeSink {
    fn chunk(&mut self, bytes: &[u8]) -> Result<Link, Error>;
    fn node(&mut self, level: u64, kids: &[Kid]) -> Result<Link, Error>;
}

/// Returns a link's plaintext, decrypted but not yet hash-checked (the reader checks).
pub trait LinkSource {
    fn plaintext(&mut self, link: &Link) -> Result<Vec<u8>, Error>;
}

/// A tree node's plaintext `[level, [LINK+], [len+]]`.
pub fn node_plaintext(level: u64, kids: &[Kid]) -> Result<Vec<u8>, Error> {
    let level = i64::try_from(level).map_err(|_| Error::TooLarge("tree level"))?;
    let links = Value::List(kids.iter().map(|(l, _)| Value::Link(*l)).collect());
    let lens = kids.iter().map(|(_, n)| i64::try_from(*n).map(Value::Int).map_err(|_| Error::TooLarge("tree length")));
    Ok(encode(&Value::List(vec![Value::Int(level), links, Value::List(lens.collect::<Result<_, _>>()?)])))
}

/// Parses a tree node: level 1..=48, 1..=512 links, one length per link, the lengths' sum
/// within u64.
pub fn parse_node(plaintext: &[u8]) -> Result<(u64, Vec<Kid>), Error> {
    let v = decode(plaintext, &Limits { max_depth: 4, max_bytes: MAX_BLOB })?;
    let Value::List(items) = v else { return Err(Error::Malformed("tree node")) };
    let [Value::Int(level), Value::List(links), Value::List(lens)] = items.as_slice() else { return Err(Error::Malformed("tree node")) };
    let level = u64::try_from(*level).map_err(|_| Error::Malformed("tree level"))?;
    if !(1..=TREE_MAX_LEVEL).contains(&level) || links.is_empty() || links.len() > TREE_FANOUT || lens.len() != links.len() {
        return Err(Error::Malformed("tree node bounds"));
    }
    // a child of a level-k node holds at most 512^(k-1) chunks of at most CHUNK_MAX bytes
    let fan = u64::try_from(TREE_FANOUT).unwrap_or(u64::MAX);
    let max = u32::try_from(level - 1).ok().and_then(|e| fan.checked_pow(e)).and_then(|x| x.checked_mul(CHUNK_MAX as u64)).unwrap_or(u64::MAX);
    let mut sum = 0u64;
    let mut kids = Vec::with_capacity(links.len());
    for (l, n) in links.iter().zip(lens) {
        let (Value::Link(l), Value::Int(n)) = (l, n) else { return Err(Error::Malformed("tree node link")) };
        let n = u64::try_from(*n).map_err(|_| Error::Malformed("tree length"))?;
        if n > max {
            return Err(Error::Malformed("tree length"));
        }
        sum = sum.checked_add(n).ok_or(Error::Malformed("tree length"))?;
        kids.push((*l, n));
    }
    Ok((level, kids))
}

/// Plaintext length under a node (lengths parsed by `parse_node` sum within u64).
pub fn kids_len(kids: &[Kid]) -> u64 {
    kids.iter().fold(0u64, |a, (_, n)| a.saturating_add(*n))
}

/// A tree node's content hash: over its level and its children's hashes and lengths
/// (spec/wire.md §6).
pub fn node_hash(dedup: &Secret32, level: u64, kids: &[Kid]) -> [u8; 32] {
    let children: Vec<([u8; 32], u64)> = kids.iter().map(|(l, n)| (l.hash, *n)).collect();
    link_tree_hash(dedup, level, &children)
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
    kids: Vec<Kid>,
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
        let len = u64::try_from(self.buf.len()).map_err(|_| Error::TooLarge("chunk"))?;
        self.buf.clear();
        self.chunks += 1;
        self.push(sink, 0, (link, len))
    }

    /// Adds a child to the open node of level `li + 1`, closing it by the node rule.
    fn push(&mut self, sink: &mut dyn TreeSink, li: usize, kid: Kid) -> Result<(), Error> {
        if self.levels.len() <= li {
            self.levels.resize_with(li + 1, OpenLevel::default);
        }
        let open = self.levels.get_mut(li).ok_or(Error::Malformed("tree level"))?;
        let zero = kid.0.hash[0] == 0;
        open.kids.push(kid);
        let n = open.kids.len();
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
        let kids = std::mem::take(&mut open.kids);
        open.closed += 1;
        let link = sink.node(level, &kids)?;
        self.push(sink, li + 1, (link, kids_len(&kids)))
    }

    /// Bytes held: the open chunk and the children of the open nodes.
    pub fn buffered(&self) -> usize {
        self.buf.len() + self.levels.iter().map(|l| l.kids.len()).sum::<usize>() * std::mem::size_of::<Kid>()
    }

    /// Closes every open node and returns the root link (always an interior node; an empty value
    /// is one empty chunk).
    pub fn finish(mut self, sink: &mut dyn TreeSink) -> Result<Link, Error> {
        if !self.buf.is_empty() || self.chunks == 0 {
            self.emit_chunk(sink)?;
        }
        let mut li = 0;
        loop {
            if self.levels.get(li).is_some_and(|l| !l.kids.is_empty()) {
                self.close(sink, li)?;
            }
            if self.levels.get(li).is_some_and(|l| l.closed == 1) {
                let up = self.levels.get_mut(li + 1).ok_or(Error::Malformed("tree root"))?;
                return match (up.kids.pop(), up.kids.is_empty(), up.closed) {
                    (Some((root, _)), true, 0) => Ok(root),
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

/// Streaming reader: yields the chunks in order, holding one node per level (memory: one chunk
/// plus the path). Verifies every content hash and level (`Corrupt`), the node bounds, and every
/// length it passes or reads: a node's lengths sum to its parent's claim, a chunk is as long as
/// claimed (`Malformed`). `seek` positions it by the lengths alone, so it fetches only the nodes
/// on the path to the target chunk. Work is bounded by the value size: a chunk other than the
/// last shorter than `min_chunk` (or empty) is bad input, and at most `max_len / min_chunk + 1`
/// chunks are visited per pass (`TooLarge` beyond; repeated links are legal: identical chunks
/// share a blob). An error leaves the reader where it was, so a `Missing` blob can be fetched and
/// the call retried (lazy fetch, spec/sync.md §6).
pub struct TreeReader {
    root: Link,
    /// The root node once read (children reversed): kept across seeks.
    root_node: Option<(u64, Vec<Kid>)>,
    total: Option<u64>,
    /// Per open node: its level and the children not yet passed, reversed.
    stack: Vec<(u64, Vec<Kid>)>,
    /// Bytes to pass, without fetching, before the next chunk returned (`seek`).
    skip: u64,
    min_chunk: usize,
    budget: usize,
    chunks_left: usize,
}

impl TreeReader {
    /// `min_chunk` is `CHUNK_MIN` on the wire (`ChunkParams::min`); `max_len` the most bytes the
    /// caller accepts.
    pub fn new(root: Link, min_chunk: usize, max_len: usize) -> TreeReader {
        let min_chunk = min_chunk.max(1);
        let budget = (max_len / min_chunk).saturating_add(1);
        TreeReader { root, root_node: None, total: None, stack: Vec::new(), skip: 0, min_chunk, budget, chunks_left: budget }
    }

    /// Children held on the open path and in the kept root.
    pub fn path_links(&self) -> usize {
        self.stack.iter().chain(&self.root_node).map(|(_, l)| l.len()).sum()
    }

    /// The tree's plaintext length as its root claims, once the root was read.
    pub fn total(&self) -> Option<u64> {
        self.total
    }

    /// Restarts at byte `offset` of the plaintext: the next chunk returned starts there (`None`
    /// at or past the end). Fetches nothing; the next `next_chunk` fetches the nodes below the
    /// root (kept once read) on the path to the chunk holding `offset`, and that chunk.
    pub fn seek(&mut self, offset: u64) {
        self.stack.clear();
        self.stack.extend(self.root_node.clone());
        self.skip = offset;
        self.chunks_left = self.budget;
    }

    fn node(dedup: &Secret32, src: &mut dyn LinkSource, link: &Link, expect: Option<(u64, u64)>) -> Result<(u64, Vec<Kid>), Error> {
        let (level, mut kids) = parse_node(&src.plaintext(link)?)?;
        if expect.is_some_and(|(l, _)| l != level) || node_hash(dedup, level, &kids) != link.hash {
            return Err(Error::Corrupt);
        }
        if expect.is_some_and(|(_, n)| n != kids_len(&kids)) {
            return Err(Error::Malformed("tree length"));
        }
        kids.reverse();
        Ok((level, kids))
    }

    /// The next chunk (from the seek offset on, after a `seek`), or `None` at the end.
    pub fn next_chunk(&mut self, dedup: &Secret32, src: &mut dyn LinkSource) -> Result<Option<Vec<u8>>, Error> {
        if self.root_node.is_none() {
            let node = Self::node(dedup, src, &self.root, None)?;
            self.total = Some(kids_len(&node.1));
            self.root_node = Some(node.clone());
            self.stack.push(node);
        }
        loop {
            let Some((level, kids)) = self.stack.last() else { return Ok(None) };
            let level = *level;
            let Some((link, len)) = kids.last().copied() else {
                self.stack.pop();
                continue;
            };
            if self.skip > 0 && self.skip >= len {
                self.skip -= len;
                self.pop_link();
                continue;
            }
            if level > 1 {
                let node = Self::node(dedup, src, &link, Some((level - 1, len)))?;
                self.pop_link();
                self.stack.push(node);
                continue;
            }
            if self.chunks_left == 0 {
                return Err(Error::TooLarge("value"));
            }
            let n = self.stack.len();
            let last = self.stack.iter().enumerate().all(|(i, (_, l))| l.len() <= usize::from(i + 1 == n));
            let mut chunk = src.plaintext(&link)?;
            if link_hash(dedup, &chunk) != link.hash {
                return Err(Error::Corrupt);
            }
            if u64::try_from(chunk.len()).ok() != Some(len) {
                return Err(Error::Malformed("tree length"));
            }
            if !last && chunk.len() < self.min_chunk {
                return Err(Error::Malformed("chunk below the minimum before the last"));
            }
            self.pop_link();
            self.chunks_left -= 1;
            // skip < len = chunk.len()
            chunk.drain(..usize::try_from(std::mem::take(&mut self.skip)).unwrap_or(usize::MAX).min(chunk.len()));
            return Ok(Some(chunk));
        }
    }

    fn pop_link(&mut self) {
        if let Some((_, l)) = self.stack.last_mut() {
            l.pop();
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
    fn node(&mut self, level: u64, kids: &[Kid]) -> Result<Link, Error> {
        self.nodes.push((level, kids.len()));
        Ok(hash_link(node_hash(&self.dedup, level, kids)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    const SMALL: ChunkParams = ChunkParams { min: 16, max: 64, mask_bits: 4 };

    fn data(n: usize, seed: u8) -> Vec<u8> {
        let mut out = vec![0u8; n];
        osis_core::hash::Hasher::new().update(&[seed]).finalize_xof(&mut out);
        out
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
            fn node(&mut self, level: u64, kids: &[Kid]) -> Result<Link, Error> {
                assert!(kids.len() <= 512);
                if level == 1 && kids.len() < 512 {
                    assert_eq!(self.0, 1100);
                }
                Ok(hash_link([2; 32]))
            }
        }
        let p = ChunkParams { min: 1, max: 1, mask_bits: 63 };
        write_tree(&mut NoZero(0), p, &[5; 1100]).unwrap();
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
    impl TreeSink for ByHash {
        fn chunk(&mut self, bytes: &[u8]) -> Result<Link, Error> {
            let h = link_hash(&Secret32::from_bytes([7; 32]), bytes);
            self.0.insert(h, bytes.to_vec());
            Ok(hash_link(h))
        }
        fn node(&mut self, level: u64, kids: &[Kid]) -> Result<Link, Error> {
            let h = node_hash(&Secret32::from_bytes([7; 32]), level, kids);
            self.0.insert(h, node_plaintext(level, kids)?);
            Ok(hash_link(h))
        }
    }

    /// A hand-built node over `kids` in `src`.
    fn put_node(src: &mut ByHash, d: &Secret32, level: u64, kids: &[Kid]) -> Link {
        let hash = node_hash(d, level, kids);
        src.0.insert(hash, node_plaintext(level, kids).unwrap());
        hash_link(hash)
    }

    // spec/wire.md §6 (issues/tree-reader-bounds.md): reader work is bounded by the value size:
    // an empty or short chunk before the last is bad input; repeated links (legal: identical
    // chunks share a blob) cost at most max_len / min + 1 chunk fetches.
    #[test]
    fn reader_bounds_spec_wire_6() {
        let d = Secret32::from_bytes([7; 32]);
        let mut src = ByHash::default();
        let node = |src: &mut ByHash, level: u64, child: Kid| put_node(src, &d, level, &vec![child; TREE_FANOUT]);
        let empty = hash_link(link_hash(&d, b""));
        src.0.insert(empty.hash, vec![]);
        let n1 = node(&mut src, 1, (empty, 0));
        let root = node(&mut src, 2, (n1, 0));
        assert!(matches!(read_tree(&root, &d, &mut src, SMALL, usize::MAX), Err(Error::Malformed("chunk below the minimum before the last"))));
        assert!(src.1 < 5);
        let full = vec![9u8; SMALL.min];
        let c = hash_link(link_hash(&d, &full));
        src.0.insert(c.hash, full);
        let n = SMALL.min as u64;
        let n1 = node(&mut src, 1, (c, n));
        let n2 = node(&mut src, 2, (n1, n * 512));
        let root = node(&mut src, 3, (n2, n * 512 * 512));
        src.1 = 0;
        assert!(matches!(read_tree(&root, &d, &mut src, SMALL, 10 * SMALL.min), Err(Error::TooLarge("value"))));
        assert!(src.1 <= 11 + 3, "{}", src.1);
    }

    // spec/wire.md §6: lengths a node carries must match what they describe: a chunk shorter or
    // longer than its claim, or a node whose lengths do not sum to its parent's claim, is bad
    // input; a node with a length count other than its link count does not parse.
    #[test]
    fn lengths_checked_spec_wire_6() {
        let d = Secret32::from_bytes([7; 32]);
        let mut src = ByHash::default();
        let a = vec![1u8; 20];
        let ca = hash_link(link_hash(&d, &a));
        src.0.insert(ca.hash, a);
        let bad = put_node(&mut src, &d, 1, &[(ca, 21)]);
        assert!(matches!(read_tree(&bad, &d, &mut src, SMALL, usize::MAX), Err(Error::Malformed("tree length"))));
        let ok = put_node(&mut src, &d, 1, &[(ca, 20), (ca, 20)]);
        assert_eq!(read_tree(&ok, &d, &mut src, SMALL, usize::MAX).unwrap().len(), 40);
        let top = put_node(&mut src, &d, 2, &[(ok, 39)]);
        assert!(matches!(read_tree(&top, &d, &mut src, SMALL, usize::MAX), Err(Error::Malformed("tree length"))));
        let two = encode(&Value::List(vec![Value::Int(1), Value::List(vec![Value::Link(ca); 2]), Value::List(vec![Value::Int(20)])]));
        assert!(parse_node(&two).is_err());
        let neg = encode(&Value::List(vec![Value::Int(1), Value::List(vec![Value::Link(ca)]), Value::List(vec![Value::Int(-1)])]));
        assert!(parse_node(&neg).is_err());
        let over = encode(&Value::List(vec![Value::Int(1), Value::List(vec![Value::Link(ca); 3]), Value::List(vec![Value::Int(i64::MAX); 3])]));
        assert!(parse_node(&over).is_err());
        // per-level bounds: a chunk is at most CHUNK_MAX, a level-1 node 512 of them
        let one = |level: i64, n: u64| encode(&Value::List(vec![Value::Int(level), Value::List(vec![Value::Link(ca)]), Value::List(vec![Value::Int(n as i64)])]));
        let cmax = CHUNK_MAX as u64;
        assert!(parse_node(&one(1, cmax)).is_ok() && parse_node(&one(1, cmax + 1)).is_err());
        assert!(parse_node(&one(2, 512 * cmax)).is_ok() && parse_node(&one(2, 512 * cmax + 1)).is_err());
    }

    // spec/wire.md §6: a seek fetches the root and the nodes on the path to the target chunk,
    // and that chunk only; the bytes from there on equal a full read's.
    #[test]
    fn seek_fetches_the_path_spec_wire_6() {
        let d = Secret32::from_bytes([7; 32]);
        let p = ChunkParams { min: 16, max: 32, mask_bits: 63 };
        let bytes = data(32 * 3000, 2);
        let mut src = ByHash::default();
        let root = write_tree(&mut src, p, &bytes).unwrap();
        let mut r = TreeReader::new(root, p.min, usize::MAX);
        let (top, _) = parse_node(&src.0[&root.hash]).unwrap();
        assert!(top >= 2);
        for at in [0u64, 1, 31, 32, 50_000, 95_999, 96_000, 1 << 40] {
            r.seek(at);
            src.1 = 0;
            let got = r.next_chunk(&d, &mut src).unwrap();
            let want = bytes.get(at as usize..).filter(|b| !b.is_empty()).map(|b| b[..b.len().min(32 - at as usize % 32)].to_vec());
            assert_eq!(got, want, "{at}");
            assert!(src.1 <= top as usize + 1, "{at}: {} fetches", src.1);
            assert_eq!(r.total(), Some(bytes.len() as u64));
        }
        r.seek(95_990);
        let mut rest = Vec::new();
        while let Some(c) = r.next_chunk(&d, &mut src).unwrap() {
            rest.extend(c);
        }
        assert_eq!(rest, bytes[95_990..]);
        // a seek whose path node is missing fails Missing and, once it is back, the retry
        // returns the bytes at the target
        let (_, kids) = parse_node(&src.0[&root.hash]).unwrap();
        let (n1, n1_len) = kids[1];
        let held = src.0.remove(&n1.hash).unwrap();
        let at = kids[0].1 + 7;
        r.seek(at);
        assert!(matches!(r.next_chunk(&d, &mut src), Err(Error::Missing)));
        src.0.insert(n1.hash, held);
        let got = r.next_chunk(&d, &mut src).unwrap().unwrap();
        assert_eq!(got, bytes[at as usize..at as usize + got.len()]);
        assert!(n1_len > 7);
    }

    // spec/wire.md §6: seeks on an empty value (one empty chunk), a single chunk, and across
    // zero-length children (passed without a fetch; reading through one before the last is
    // still bad input).
    #[test]
    fn seek_edges_spec_wire_6() {
        let d = Secret32::from_bytes([7; 32]);
        let mut src = ByHash::default();
        let empty = write_tree(&mut src, SMALL, b"").unwrap();
        let mut r = TreeReader::new(empty, SMALL.min, usize::MAX);
        r.seek(0);
        assert_eq!(r.next_chunk(&d, &mut src).unwrap(), Some(vec![]));
        assert_eq!(r.next_chunk(&d, &mut src).unwrap(), None);
        r.seek(3);
        assert_eq!(r.next_chunk(&d, &mut src).unwrap(), None);
        let one = write_tree(&mut src, SMALL, b"single chunk").unwrap();
        let mut r = TreeReader::new(one, SMALL.min, usize::MAX);
        r.seek(7);
        assert_eq!(r.next_chunk(&d, &mut src).unwrap(), Some(b"chunk".to_vec()));
        r.seek(12);
        assert_eq!(r.next_chunk(&d, &mut src).unwrap(), None);
        // [a (20), empty (0), b (20)]
        let (a, b) = (vec![1u8; 20], vec![2u8; 20]);
        let (la, lb, le) = (hash_link(link_hash(&d, &a)), hash_link(link_hash(&d, &b)), hash_link(link_hash(&d, b"")));
        src.0.insert(la.hash, a);
        src.0.insert(lb.hash, b.clone());
        src.0.insert(le.hash, vec![]);
        let root = put_node(&mut src, &d, 1, &[(la, 20), (le, 0), (lb, 20)]);
        let mut r = TreeReader::new(root, SMALL.min, usize::MAX);
        r.seek(25);
        src.1 = 0;
        assert_eq!(r.next_chunk(&d, &mut src).unwrap(), Some(b[5..].to_vec()));
        assert_eq!(src.1, 2, "root and b only");
        r.seek(20);
        assert!(matches!(r.next_chunk(&d, &mut src), Err(Error::Malformed("chunk below the minimum before the last"))));
    }
}
