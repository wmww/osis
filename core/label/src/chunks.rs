//! Large atomic values (spec/data-model.md §6): `chunk_value` decides inline or link by
//! `CHUNK_THRESHOLD` and writes the canonical bytes into a chunk tree; `read_value` reads one
//! back whole. A blob or string read as a stream walks the tree a chunk at a time (`TreeReader`;
//! osis `ValueStream`), its length from `string_head`.

use crate::Error;
use crate::tree::{LinkSource, TreeReader, TreeSink, write_tree};
use osis_base::format::{CHUNK_THRESHOLD, MAX_VALUE_DEPTH};
use osis_base::cbor::{MAJOR_BYTES, MAJOR_TEXT, head_len};
use osis_base::{ChunkParams, Limits, Link, Value, decode, encode};
use osis_crypto::Secret32;

/// Chunking parameters: `FORMAT` on the wire; tests shrink them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LargeParams {
    pub chunk: ChunkParams,
    /// A value whose canonical encoding exceeds this many bytes is chunked; at or below, never.
    pub threshold: usize,
}

impl LargeParams {
    pub const FORMAT: LargeParams = LargeParams { chunk: ChunkParams::FORMAT, threshold: CHUNK_THRESHOLD };
}


/// Parses the canonical byte or text string head that starts a large blob or string's bytes:
/// `(major, len, head bytes)`, or `None` when `b` is too short to tell.
pub fn string_head(b: &[u8]) -> Result<Option<(u8, u64, usize)>, Error> {
    let Some(&ib) = b.first() else { return Ok(None) };
    let major = ib >> 5;
    if major != MAJOR_BYTES && major != MAJOR_TEXT {
        return Err(Error::Malformed("large value is not a byte or text string"));
    }
    let n = match ib & 31 {
        a @ 0..24 => return Ok(Some((major, u64::from(a), 1))),
        24 => 1,
        25 => 2,
        26 => 4,
        27 => 8,
        _ => return Err(Error::Malformed("string head")),
    };
    let Some(arg) = b.get(1..1 + n) else { return Ok(None) };
    let len = arg.iter().fold(0u64, |a, &x| (a << 8) | u64::from(x));
    if head_len(len) != 1 + n {
        return Err(Error::Malformed("string head not shortest"));
    }
    Ok(Some((major, len, 1 + n)))
}

/// A set element, map key or whole value: chunked iff its canonical encoding exceeds the
/// threshold. Returns what takes its place (itself, or its root link).
pub fn chunk_value(sink: &mut dyn TreeSink, params: LargeParams, v: &Value) -> Result<Value, Error> {
    let bytes = encode(v);
    if bytes.len() <= params.threshold {
        return Ok(v.clone());
    }
    Ok(Value::link(write_tree(sink, params.chunk, &bytes)?))
}

/// Streams the canonical bytes of a large value from its root link, fetching chunks on demand.
/// At the end the value must exceed the threshold (a chunked small value is bad input).
struct LargeReader<'a> {
    tree: TreeReader,
    dedup: &'a Secret32,
    src: &'a mut dyn LinkSource,
    threshold: usize,
    max_len: usize,
    chunk: Vec<u8>,
    pos: usize,
    total: usize,
    done: bool,
}

impl<'a> LargeReader<'a> {
    /// `max_len`: the most bytes the caller accepts (`TooLarge` beyond).
    fn new(root: Link, dedup: &'a Secret32, src: &'a mut dyn LinkSource, params: LargeParams, max_len: usize) -> LargeReader<'a> {
        LargeReader { tree: TreeReader::new(root, params.chunk.min, max_len), dedup, src, threshold: params.threshold, max_len, chunk: Vec::new(), pos: 0, total: 0, done: false }
    }

    /// The unread rest of the current chunk, fetching the next chunk when it is used up; empty
    /// at the end. A `Missing` chunk can be fetched and the call retried.
    fn fill(&mut self) -> Result<&[u8], Error> {
        while self.pos >= self.chunk.len() && !self.done {
            let next = self.tree.next_chunk(self.dedup, self.src)?;
            if self.tree.total().is_some_and(|t| t > u64::try_from(self.max_len).unwrap_or(u64::MAX)) {
                return Err(Error::TooLarge("value"));
            }
            match next {
                Some(c) => {
                    self.total = self.total.saturating_add(c.len());
                    if self.total > self.max_len {
                        return Err(Error::TooLarge("value"));
                    }
                    self.chunk = c;
                    self.pos = 0;
                }
                None => {
                    if self.total <= self.threshold {
                        return Err(Error::Malformed("chunked value at or below CHUNK_THRESHOLD"));
                    }
                    self.chunk = Vec::new();
                    self.pos = 0;
                    self.done = true;
                }
            }
        }
        Ok(self.chunk.get(self.pos..).unwrap_or_default())
    }

    fn consume(&mut self, n: usize) {
        self.pos = self.pos.saturating_add(n).min(self.chunk.len());
    }

    /// Reads the whole value's canonical bytes.
    fn read_all(mut self) -> Result<Vec<u8>, Error> {
        let mut out = Vec::new();
        loop {
            let b = self.fill()?;
            if b.is_empty() {
                return Ok(out);
            }
            out.extend_from_slice(b);
            let n = b.len();
            self.consume(n);
        }
    }
}

/// Reads a whole large value (set element, map key, or a value read in full) and decodes it.
pub fn read_value(root: Link, dedup: &Secret32, src: &mut dyn LinkSource, params: LargeParams, max_len: usize) -> Result<Value, Error> {
    let bytes = LargeReader::new(root, dedup, src, params, max_len).read_all()?;
    Ok(decode(&bytes, &Limits { max_depth: MAX_VALUE_DEPTH, max_bytes: bytes.len() })?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tree::{BlobReader, BlobWriter, Framing, HashSink, MemoryBlobs};
    use osis_base::WallMs;
    use osis_crypto::SeededRng;
    use proptest::prelude::*;

    // min above the 64-byte gear window, so cuts are content-defined as with the format.
    const SMALL: LargeParams = LargeParams { chunk: ChunkParams { min: 64, max: 512, mask_bits: 5 }, threshold: 128 };

    fn data(n: usize, seed: u8) -> Vec<u8> {
        let mut out = vec![0u8; n];
        osis_base::hash::Hasher::new().update(&[seed, 1]).finalize_xof(&mut out);
        out
    }

    fn framing() -> Framing {
        Framing { dedup: Secret32::from_bytes([7; 32]), expiry: Some(WallMs(99)), keys: vec![(3, dk(3))], class: crate::blob::Class::Durable }
    }

    fn dk(b: u8) -> osis_crypto::VerifyingKey {
        osis_crypto::DeleteSecret::derive(&Secret32::from_bytes([b; 32])).verifying_key()
    }

    fn write_bytes(store: &mut MemoryBlobs, f: &Framing, rng: &mut SeededRng, d: &[u8]) -> Value {
        chunk_value(&mut BlobWriter::new(f, store, rng), SMALL, &Value::Bytes(d.to_vec())).unwrap()
    }

    // spec/data-model.md §6: above CHUNK_THRESHOLD a blob is chunked, at or below it is not;
    // the tree holds its canonical bytes; equal content gives equal root hashes, other links.
    // spec/data-model.md §6 (chunk threshold)
    #[test]
    fn threshold() {
        let f = framing();
        let mut store = MemoryBlobs::default();
        let mut rng = SeededRng::from_u64(0);
        // Head of 2 bytes: 126 payload bytes is exactly the threshold.
        for (n, large) in [(0, false), (126, false), (127, true), (1000, true)] {
            let d = data(n, 0);
            let v = write_bytes(&mut store, &f, &mut rng, &d);
            assert_eq!(matches!(v, Value::Link(_)), large, "{n}");
            assert_eq!(encode(&Value::Bytes(d.clone())).len() > SMALL.threshold, large);
            let Value::Link(l) = v else {
                assert_eq!(v, Value::Bytes(d));
                continue;
            };
            let mut r = BlobReader::new(&f.dedup, &mut store);
            assert_eq!(read_value(*l, &f.dedup, &mut r, SMALL, usize::MAX).unwrap(), Value::Bytes(d.clone()));
            let mut hs = HashSink::new(f.dedup.clone());
            let Value::Link(h) = chunk_value(&mut hs, SMALL, &Value::Bytes(d.clone())).unwrap() else { panic!() };
            assert_eq!(h.hash, l.hash);
            let Value::Link(l2) = write_bytes(&mut store, &f, &mut rng, &d) else { panic!() };
            assert_eq!(l2.hash, l.hash);
            assert_ne!(l2.blob, l.blob);
        }
        assert_eq!(chunk_value(&mut HashSink::new(f.dedup.clone()), SMALL, &Value::Int(5)).unwrap(), Value::Int(5));
    }

    // spec/data-model.md §6: a chunked value at or below the threshold is bad input.
    // spec/data-model.md §6 (chunk threshold)
    #[test]
    fn small_chunked_rejected() {
        let f = framing();
        let mut store = MemoryBlobs::default();
        let mut rng = SeededRng::from_u64(0);
        let root = write_tree(&mut BlobWriter::new(&f, &mut store, &mut rng), SMALL.chunk, &encode(&Value::Bytes(vec![1; 20]))).unwrap();
        let mut r = BlobReader::new(&f.dedup, &mut store);
        assert_eq!(read_value(root, &f.dedup, &mut r, SMALL, usize::MAX), Err(Error::Malformed("chunked value at or below CHUNK_THRESHOLD")));
    }

    // spec/data-model.md §5, §6: a large blob or string's bytes start with its canonical string
    // head, which gives the payload length once enough bytes are in; any other head is bad
    // input. A text value round-trips through its tree.
    #[test]
    fn string_head_spec_data_model_6() {
        let head = |v: &Value| string_head(&encode(v)).unwrap().unwrap();
        assert_eq!(head(&Value::Bytes(vec![1; 5])), (MAJOR_BYTES, 5, 1));
        assert_eq!(head(&Value::Bytes(vec![1; 300])), (MAJOR_BYTES, 300, 3));
        assert_eq!(head(&Value::Str("é".repeat(40_000))), (MAJOR_TEXT, 80_000, 5));
        assert_eq!(string_head(&[]), Ok(None));
        assert_eq!(string_head(&encode(&Value::Bytes(vec![1; 300]))[..2]), Ok(None));
        assert!(string_head(&[0x59, 0x00, 0x05]).is_err(), "not shortest");
        assert!(string_head(&encode(&Value::Int(5))).is_err());
        assert!(string_head(&[0x5f]).is_err(), "indefinite length");
        let f = framing();
        let mut store = MemoryBlobs::default();
        let mut rng = SeededRng::from_u64(0);
        let s = Value::Str("héllo wörld ✓ 𝄞 ".repeat(40));
        let Value::Link(root) = chunk_value(&mut BlobWriter::new(&f, &mut store, &mut rng), SMALL, &s).unwrap() else { panic!() };
        let mut r = BlobReader::new(&f.dedup, &mut store);
        assert_eq!(read_value(*root, &f.dedup, &mut r, SMALL, usize::MAX).unwrap(), s);
    }

    /// Serves blobs from a store but only those in `allow`, counting fetches.
    struct Gate<'a> {
        store: &'a mut MemoryBlobs,
        fetches: usize,
        missing_once: Option<osis_base::BlobId>,
    }
    impl crate::tree::BlobFetch for Gate<'_> {
        fn fetch(&mut self, id: &osis_base::BlobId) -> Result<Vec<u8>, Error> {
            if self.missing_once == Some(*id) {
                self.missing_once = None;
                return Err(Error::Missing);
            }
            self.fetches += 1;
            self.store.fetch(id)
        }
    }

    // spec/wire.md §6 (TreeReader), spec/sync.md §6: a Missing chunk mid-stream leaves the
    // reader in place; the retry continues with the same bytes.
    #[test]
    fn resume_mid_stream() {
        let f = framing();
        let mut store = MemoryBlobs::default();
        let mut rng = SeededRng::from_u64(0);
        let d = data(3000, 0);
        let Value::Link(root) = write_bytes(&mut store, &f, &mut rng, &d) else { panic!() };
        let root = *root;
        let victim = *store.0.keys().next().unwrap();
        let mut gate = Gate { store: &mut store, fetches: 0, missing_once: Some(victim) };
        let mut r = BlobReader::new(&f.dedup, &mut gate);
        let mut lr = LargeReader::new(root, &f.dedup, &mut r, SMALL, usize::MAX);
        let mut out = Vec::new();
        let mut misses = 0;
        loop {
            match lr.fill() {
                Ok([]) => break,
                Ok(b) => {
                    let n = b.len();
                    out.extend_from_slice(b);
                    lr.consume(n);
                }
                Err(Error::Missing) => misses += 1,
                Err(e) => panic!("{e}"),
            }
        }
        assert_eq!(misses, 1);
        assert_eq!(out, encode(&Value::Bytes(d)));
    }

    // spec/wire.md §6: content hashes cover lengths, so a tree whose nodes lie about them has
    // another root hash than the honest tree of the same bytes (never equal as a value); a
    // reader rejects it, and an honest rewrite reuses its chunks but none of its nodes.
    #[test]
    fn lying_lengths_spec_wire_6() {
        struct Liar<'a, 'b>(&'a mut BlobWriter<'b>);
        impl TreeSink for Liar<'_, '_> {
            fn chunk(&mut self, b: &[u8]) -> Result<Link, osis_commit::Error> {
                self.0.chunk(b)
            }
            fn node(&mut self, level: u64, kids: &[crate::tree::Kid]) -> Result<Link, osis_commit::Error> {
                let mut k = kids.to_vec();
                if let [a, b, ..] = k.as_mut_slice() {
                    a.1 += 1;
                    b.1 -= 1;
                }
                self.0.node(level, &k)
            }
        }
        let f = framing();
        let mut store = MemoryBlobs::default();
        let mut rng = SeededRng::from_u64(0);
        let d = data(20_000, 0);
        let canon = encode(&Value::Bytes(d.clone()));
        let mut bw = BlobWriter::new(&f, &mut store, &mut rng);
        let liar = write_tree(&mut Liar(&mut bw), SMALL.chunk, &canon).unwrap();
        let mut hs = HashSink::new(f.dedup.clone());
        assert_ne!(write_tree(&mut hs, SMALL.chunk, &canon).unwrap().hash, liar.hash);
        let mut r = BlobReader::new(&f.dedup, &mut store);
        assert_eq!(read_value(liar, &f.dedup, &mut r, SMALL, usize::MAX), Err(Error::Malformed("tree length")));
        let (honest, written, reused) = rewrite(&mut store, &f, 15, &d, Some(liar));
        assert_ne!(honest.hash, liar.hash);
        assert!(written >= 1 && written <= hs.nodes.len() && reused as u64 >= hs.chunks, "{written} written, {reused} reused");
    }

    /// Writes `d` as a blob value with `f`, reusing from the tree under `old` if given; returns
    /// the root, blobs written and blobs reused.
    fn rewrite(store: &mut MemoryBlobs, f: &Framing, seed: u64, d: &[u8], old: Option<Link>) -> (Link, usize, usize) {
        let reuse = old.map(|o| crate::tree::Reuse::index(&o, f.clone(), store, SMALL.chunk, usize::MAX).unwrap());
        let mut rng = SeededRng::from_u64(seed);
        let mut bw = match &reuse {
            Some(r) => BlobWriter::reusing(r, store, &mut rng),
            None => BlobWriter::new(f, store, &mut rng),
        };
        let Value::Link(root) = chunk_value(&mut bw, SMALL, &Value::Bytes(d.to_vec())).unwrap() else { panic!() };
        let root = *root;
        let (written, reused) = (bw.written().len(), bw.reused());
        let mut r = BlobReader::new(&f.dedup, store);
        assert_eq!(read_value(root, &f.dedup, &mut r, SMALL, usize::MAX).unwrap(), Value::Bytes(d.to_vec()));
        (root, written, reused)
    }

    // spec/sync.md §1, notes/local-store.md: a new version reuses the current tree's blobs by
    // content hash; an insert in the middle writes O(change) new blobs.
    #[test]
    fn dedup_by_reuse() {
        let f = framing();
        let mut store = MemoryBlobs::default();
        let d = data(20_000, 0);
        let (root, n, _) = rewrite(&mut store, &f, 1, &d, None);
        let mut d2 = d.clone();
        d2.splice(10_000..10_000, *b"inserted");
        let (root2, written, reused) = rewrite(&mut store, &f, 2, &d2, Some(root));
        assert_ne!(root2.hash, root.hash);
        assert!(written <= 12, "written {written} of {n}");
        assert!(reused * 10 >= n * 9, "reused {reused} of {n}");
        // Same content again: the root itself is reused, nothing written.
        let (root3, written, _) = rewrite(&mut store, &f, 3, &d2, Some(root2));
        assert_eq!((root3, written), (root2, 0));
        // Old blobs not held (lazily fetched): written afresh.
        store.0.retain(|id, _| *id == root2.blob);
        let (_, written, reused) = rewrite(&mut store, &f, 4, &d2, Some(root2));
        assert!(reused == 0 && written > n / 2);
    }

    // spec/sync.md §1: the re-encryption rule: a reused blob keeps its encryption unless its
    // expiry is earlier than the new delta's or its commitments to the thing's delete keys are
    // not exactly the new delta's; author-chain commitments need not match beside an admin or
    // writer key, but need the new delta's own key where it lists no level 2 or only level 2: else
    // that author could delete a blob the delta's retention gives it no right over.
    #[test]
    fn reencryption_rule() {
        let fr = |expiry: Option<u64>, keys: Vec<(u8, u8)>| Framing { dedup: Secret32::from_bytes([7; 32]), expiry: expiry.map(WallMs), keys: keys.into_iter().map(|(l, b)| (l, dk(b))).collect(), class: crate::blob::Class::Durable };
        let base = fr(Some(100), vec![(1, 1), (2, 2), (3, 3)]);
        let d = data(5_000, 0);
        let cases = [
            (fr(Some(100), vec![(1, 1), (2, 2), (3, 3)]), true),
            (fr(Some(50), vec![(1, 1), (2, 2), (3, 3)]), true),
            (fr(Some(100), vec![(1, 1), (2, 9), (3, 3)]), true),
            (fr(Some(100), vec![(1, 1), (3, 3)]), false),
            (fr(Some(101), vec![(1, 1), (2, 2), (3, 3)]), false),
            (fr(None, vec![(1, 1), (2, 2), (3, 3)]), false),
            (fr(Some(100), vec![(1, 1), (2, 2), (3, 4)]), false),
            (fr(Some(100), vec![(2, 2), (3, 3)]), false),
            (fr(Some(100), vec![(1, 1), (2, 2)]), false),
        ];
        for (i, (f2, keep)) in cases.into_iter().enumerate() {
            let mut store = MemoryBlobs::default();
            let (root, n, _) = rewrite(&mut store, &base, 1, &d, None);
            let (root2, written, reused) = rewrite(&mut store, &f2, 2, &d, Some(root));
            if keep {
                assert_eq!((root2, written), (root, 0), "case {i}");
            } else {
                assert_eq!((written, reused), (n, 0), "case {i}");
                let p = crate::blob::Prefix::parse(&store.0[&root2.blob]).unwrap();
                assert_eq!(p.expiry(), f2.expiry, "case {i}");
            }
        }
        // author-only chunks: the same author's reuse keeps them; another's, or a delta with no
        // level 2, does not
        for (keys, keep) in [(vec![(2, 2)], true), (vec![(2, 9)], false), (vec![], false), (vec![(1, 1)], false)] {
            let mut store = MemoryBlobs::default();
            let (root, _, _) = rewrite(&mut store, &fr(None, vec![(2, 2)]), 1, &d, None);
            let (root2, _, _) = rewrite(&mut store, &fr(None, keys.clone()), 2, &d, Some(root));
            assert_eq!(root2 == root, keep, "{keys:?}");
        }
        // a chunk no author can delete needs no level 2 to stay
        let mut store = MemoryBlobs::default();
        let (root, _, _) = rewrite(&mut store, &fr(None, vec![]), 1, &d, None);
        assert_eq!(rewrite(&mut store, &fr(None, vec![(2, 2)]), 2, &d, Some(root)).0, root);
        let mut store = MemoryBlobs::default();
        let (root, n, _) = rewrite(&mut store, &fr(None, vec![(3, 3)]), 1, &d, None);
        let (_, written, _) = rewrite(&mut store, &fr(Some(5), vec![(3, 3)]), 2, &d, Some(root));
        assert_eq!((written, n > 0), (0, true));
    }

    proptest! {
        // spec/data-model.md §6: round trip for random sizes around and above the threshold.
        #[test]
        fn round_trip(n in 0usize..3000, seed in any::<u8>()) {
            let f = framing();
            let d = data(n, seed);
            let mut store = MemoryBlobs::default();
            let mut rng = SeededRng::from_u64(u64::from(seed));
            let v = write_bytes(&mut store, &f, &mut rng, &d);
            let enc = encode(&Value::Bytes(d.clone()));
            match v {
                Value::Link(root) => {
                    let root = *root;
                    prop_assert!(enc.len() > SMALL.threshold);
                    let mut r = BlobReader::new(&f.dedup, &mut store);
                    prop_assert_eq!(read_value(root, &f.dedup, &mut r, SMALL, usize::MAX).unwrap(), Value::Bytes(d));
                    let mut r = BlobReader::new(&f.dedup, &mut store);
                    prop_assert_eq!(LargeReader::new(root, &f.dedup, &mut r, SMALL, usize::MAX).read_all().unwrap(), enc.clone());
                    let mut r = BlobReader::new(&f.dedup, &mut store);
                    prop_assert!(matches!(LargeReader::new(root, &f.dedup, &mut r, SMALL, enc.len() - 1).read_all(), Err(Error::TooLarge(_))));
                }
                v => {
                    prop_assert!(enc.len() <= SMALL.threshold);
                    prop_assert_eq!(v, Value::Bytes(d));
                }
            }
        }
    }
}
