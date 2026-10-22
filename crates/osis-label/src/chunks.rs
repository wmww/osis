//! Large atomic values (spec/data-model.md §6): the write path decides inline or link by
//! `CHUNK_THRESHOLD` and streams canonical bytes into a chunk tree; readers stream them back
//! lazily, one chunk plus the tree path in memory (spec/requirements.md, Scale).

use crate::Error;
use crate::tree::{LinkSource, TreeReader, TreeSink, TreeWriter, write_tree};
use osis_core::format::{CHUNK_THRESHOLD, MAX_VALUE_DEPTH};
use osis_core::{ChunkParams, Limits, Link, Value, decode, encode};
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

const MAJOR_BYTES: u8 = 2;
const MAJOR_TEXT: u8 = 3;

/// Canonical (shortest) CBOR head of a byte or text string of `len` bytes.
fn string_head(major: u8, len: u64) -> Vec<u8> {
    let m = major << 5;
    // Each arm's cast is lossless for its range.
    match len {
        0..24 => vec![m | len as u8],
        24..0x100 => vec![m | 24, len as u8],
        0x100..0x1_0000 => [&[m | 25][..], &(len as u16).to_be_bytes()].concat(),
        0x1_0000..0x1_0000_0000 => [&[m | 26][..], &(len as u32).to_be_bytes()].concat(),
        _ => [&[m | 27][..], &len.to_be_bytes()].concat(),
    }
}

/// Parses a canonical byte or text string head: `(major, len, head bytes)`, or `None` when `b`
/// is too short to tell.
fn parse_string_head(b: &[u8]) -> Result<Option<(u8, u64, usize)>, Error> {
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
    if string_head(major, len).len() != 1 + n {
        return Err(Error::Malformed("string head not shortest"));
    }
    Ok(Some((major, len, 1 + n)))
}

/// Streaming UTF-8 check: holds at most 3 bytes of an incomplete sequence.
#[derive(Default)]
struct Utf8 {
    carry: Vec<u8>,
}

impl Utf8 {
    fn feed(&mut self, mut data: &[u8]) -> Result<(), Error> {
        const BAD: Error = Error::Malformed("text is not UTF-8");
        while !self.carry.is_empty() {
            let Some((&b, rest)) = data.split_first() else { return Ok(()) };
            self.carry.push(b);
            data = rest;
            match std::str::from_utf8(&self.carry) {
                Ok(_) => self.carry.clear(),
                Err(e) if e.error_len().is_none() => {}
                Err(_) => return Err(BAD),
            }
        }
        match std::str::from_utf8(data) {
            Ok(_) => Ok(()),
            Err(e) if e.error_len().is_none() => {
                self.carry = data.get(e.valid_up_to()..).unwrap_or_default().to_vec();
                Ok(())
            }
            Err(_) => Err(BAD),
        }
    }

    fn finish(&self) -> Result<(), Error> {
        if self.carry.is_empty() { Ok(()) } else { Err(Error::Malformed("text is not UTF-8")) }
    }
}

/// Streams a blob or string of a declared length into its place in a value: inline at or below
/// the threshold (buffered, at most `threshold` bytes), else a chunk tree written through the
/// sink as the bytes arrive.
pub struct ValueWriter {
    /// Large only: the string head, written with the first bytes.
    head: Vec<u8>,
    text: Option<Utf8>,
    left: u64,
    /// Inline only: the payload so far.
    inline: Option<Vec<u8>>,
    tree: Option<TreeWriter>,
}

impl ValueWriter {
    pub fn bytes(params: LargeParams, len: u64) -> ValueWriter {
        ValueWriter::new(params, MAJOR_BYTES, len)
    }

    /// Checks UTF-8 as the bytes arrive.
    pub fn text(params: LargeParams, len: u64) -> ValueWriter {
        ValueWriter::new(params, MAJOR_TEXT, len)
    }

    fn new(params: LargeParams, major: u8, len: u64) -> ValueWriter {
        let head = string_head(major, len);
        let total = u64::try_from(head.len()).unwrap_or(u64::MAX).saturating_add(len);
        let large = total > u64::try_from(params.threshold).unwrap_or(u64::MAX);
        let tree = large.then(|| TreeWriter::new(params.chunk));
        let inline = (!large).then(Vec::new);
        ValueWriter { head: if large { head } else { Vec::new() }, text: (major == MAJOR_TEXT).then(Utf8::default), left: len, inline, tree }
    }

    /// Whether the value goes by link.
    pub fn is_large(&self) -> bool {
        self.tree.is_some()
    }

    pub fn write(&mut self, sink: &mut dyn TreeSink, data: &[u8]) -> Result<(), Error> {
        let n = u64::try_from(data.len()).map_err(|_| Error::TooLarge("write"))?;
        self.left = self.left.checked_sub(n).ok_or(Error::TooLarge("value longer than its declared length"))?;
        if let Some(u) = &mut self.text {
            u.feed(data)?;
        }
        match (&mut self.tree, &mut self.inline) {
            (Some(t), _) => {
                if !self.head.is_empty() {
                    t.write(sink, &std::mem::take(&mut self.head))?;
                }
                Ok(t.write(sink, data)?)
            }
            (None, Some(buf)) => {
                buf.extend_from_slice(data);
                Ok(())
            }
            (None, None) => Err(Error::Malformed("value writer state")),
        }
    }

    /// The value's place in the enclosing value: `Value::Bytes`/`Value::Str` inline, or the
    /// root `Value::Link`.
    pub fn finish(self, sink: &mut dyn TreeSink) -> Result<Value, Error> {
        if self.left != 0 {
            return Err(Error::Malformed("value shorter than its declared length"));
        }
        if let Some(u) = &self.text {
            u.finish()?;
        }
        if let Some(mut t) = self.tree {
            t.write(sink, &self.head)?;
            return Ok(Value::Link(t.finish(sink)?));
        }
        let buf = self.inline.unwrap_or_default();
        Ok(match self.text {
            Some(_) => Value::Str(String::from_utf8(buf).map_err(|_| Error::Malformed("text is not UTF-8"))?),
            None => Value::Bytes(buf),
        })
    }

    /// Bytes held: the inline payload, or the open chunk and tree path.
    pub fn buffered(&self) -> usize {
        self.inline.as_ref().map_or(0, Vec::len) + self.tree.as_ref().map_or(0, TreeWriter::buffered)
    }
}

/// A set element, map key or whole value: chunked iff its canonical encoding exceeds the
/// threshold. Returns what takes its place (itself, or its root link).
pub fn chunk_value(sink: &mut dyn TreeSink, params: LargeParams, v: &Value) -> Result<Value, Error> {
    let bytes = encode(v);
    if bytes.len() <= params.threshold {
        return Ok(v.clone());
    }
    Ok(Value::Link(write_tree(sink, params.chunk, &bytes)?))
}

/// Streams the canonical bytes of a large value from its root link, fetching chunks on demand.
/// At the end the value must exceed the threshold (a chunked small value is bad input).
pub struct LargeReader<'a> {
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
    pub fn new(root: Link, dedup: &'a Secret32, src: &'a mut dyn LinkSource, params: LargeParams, max_len: usize) -> LargeReader<'a> {
        LargeReader { tree: TreeReader::new(root, params.chunk.min, max_len), dedup, src, threshold: params.threshold, max_len, chunk: Vec::new(), pos: 0, total: 0, done: false }
    }

    /// Restarts at canonical byte `offset`: the next `fill` fetches only the tree path to the
    /// chunk holding it (spec/wire.md §6 lengths).
    pub fn seek(&mut self, offset: u64) {
        // inside the chunk held (`total` counts up to its end): just move
        let end = self.total as u64;
        let start = end.saturating_sub(self.chunk.len() as u64);
        if !self.chunk.is_empty() && (start..=end).contains(&offset) {
            self.pos = (offset - start) as usize;
            return;
        }
        self.tree.seek(offset);
        self.chunk = Vec::new();
        self.pos = 0;
        self.total = usize::try_from(offset).unwrap_or(usize::MAX);
        self.done = false;
    }

    /// The unread rest of the current chunk, fetching the next chunk when it is used up; empty
    /// at the end. A `Missing` chunk can be fetched and the call retried.
    pub fn fill(&mut self) -> Result<&[u8], Error> {
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

    pub fn consume(&mut self, n: usize) {
        self.pos = self.pos.saturating_add(n).min(self.chunk.len());
    }

    /// Bytes held: the current chunk and the links on the tree path.
    pub fn buffered(&self) -> usize {
        self.chunk.len() + self.tree.path_links() * std::mem::size_of::<Link>()
    }

    /// Reads the whole value's canonical bytes.
    pub fn read_all(mut self) -> Result<Vec<u8>, Error> {
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

impl std::io::Read for LargeReader<'_> {
    fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
        let b = self.fill().map_err(std::io::Error::other)?;
        let n = b.len().min(out.len());
        out.get_mut(..n).unwrap_or_default().copy_from_slice(b.get(..n).unwrap_or_default());
        self.consume(n);
        Ok(n)
    }
}

/// Reads a whole large value (set element, map key, or a value read in full) and decodes it.
pub fn read_value(root: Link, dedup: &Secret32, src: &mut dyn LinkSource, params: LargeParams, max_len: usize) -> Result<Value, Error> {
    let bytes = LargeReader::new(root, dedup, src, params, max_len).read_all()?;
    Ok(decode(&bytes, &Limits { max_depth: MAX_VALUE_DEPTH, max_bytes: bytes.len() })?)
}

/// Streams the payload of a large blob or string: its declared length is known after the head;
/// `seek` serves range reads, fetching only the tree path to the target chunk (tree nodes carry
/// lengths, spec/wire.md §6). Text is checked as UTF-8 as it streams from the start.
pub struct StringReader<'a> {
    inner: LargeReader<'a>,
    /// UTF-8 check of text read from the start; a seek elsewhere turns it off (a range may start
    /// inside a character).
    text: Option<Utf8>,
    is_text: bool,
    /// Bytes of the string head.
    head: u64,
    len: u64,
    /// Payload bytes before the read position.
    pos: u64,
}

impl<'a> StringReader<'a> {
    pub fn open(root: Link, dedup: &'a Secret32, src: &'a mut dyn LinkSource, params: LargeParams, max_len: usize) -> Result<StringReader<'a>, Error> {
        let mut inner = LargeReader::new(root, dedup, src, params, max_len);
        let mut head = Vec::new();
        let (major, len, n) = loop {
            if let Some(h) = parse_string_head(&head)? {
                break h;
            }
            let b = inner.fill()?;
            let Some(&x) = b.first() else { return Err(Error::Malformed("truncated string head")) };
            head.push(x);
            inner.consume(1);
        };
        let head = u64::try_from(n).unwrap_or(u64::MAX);
        let total = head.saturating_add(len);
        if total <= u64::try_from(params.threshold).unwrap_or(u64::MAX) {
            return Err(Error::Malformed("chunked value at or below CHUNK_THRESHOLD"));
        }
        if total > u64::try_from(max_len).unwrap_or(u64::MAX) {
            return Err(Error::TooLarge("value"));
        }
        let is_text = major == MAJOR_TEXT;
        Ok(StringReader { inner, text: is_text.then(Utf8::default), is_text, head, len, pos: 0 })
    }

    /// Payload length in bytes.
    pub fn len(&self) -> u64 {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn is_text(&self) -> bool {
        self.is_text
    }

    pub fn buffered(&self) -> usize {
        self.inner.buffered()
    }

    /// Reads up to `out.len()` payload bytes; 0 at the end, after checking nothing follows.
    pub fn read_some(&mut self, out: &mut [u8]) -> Result<usize, Error> {
        let left = self.len - self.pos;
        if left == 0 {
            if !self.inner.fill()?.is_empty() {
                return Err(Error::Malformed("bytes after the string"));
            }
            if let Some(u) = &self.text {
                u.finish()?;
            }
            return Ok(0);
        }
        let b = self.inner.fill()?;
        if b.is_empty() {
            return Err(Error::Malformed("string shorter than its head"));
        }
        let n = b.len().min(out.len()).min(usize::try_from(left).unwrap_or(usize::MAX));
        let piece = b.get(..n).unwrap_or_default();
        if let Some(u) = &mut self.text {
            u.feed(piece)?;
        }
        out.get_mut(..n).ok_or(Error::Malformed("read buffer"))?.copy_from_slice(piece);
        self.inner.consume(n);
        self.pos += n as u64;
        Ok(n)
    }

    /// Moves to payload byte `to` (at most `len`). Fetches nothing: the next read fetches the
    /// tree path to the chunk holding it. Text is UTF-8 checked again only from position 0.
    pub fn seek(&mut self, to: u64) -> Result<(), Error> {
        if to > self.len {
            return Err(Error::Malformed("seek past the end"));
        }
        if to == self.pos {
            return Ok(());
        }
        self.inner.seek(self.head.saturating_add(to));
        self.pos = to;
        self.text = (self.is_text && to == 0).then(Utf8::default);
        Ok(())
    }

    /// The payload position.
    pub fn position(&self) -> u64 {
        self.pos
    }
}

impl std::io::Read for StringReader<'_> {
    fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
        self.read_some(out).map_err(std::io::Error::other)
    }
}

impl std::io::Seek for StringReader<'_> {
    fn seek(&mut self, to: std::io::SeekFrom) -> std::io::Result<u64> {
        let target = match to {
            std::io::SeekFrom::Start(n) => Some(n),
            std::io::SeekFrom::End(d) => self.len.checked_add_signed(d),
            std::io::SeekFrom::Current(d) => self.pos.checked_add_signed(d),
        };
        let target = target.ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidInput, "seek before the start"))?.min(self.len);
        StringReader::seek(self, target).map_err(std::io::Error::other)?;
        Ok(target)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tree::{BlobReader, BlobWriter, Framing, HashSink, MemoryBlobs};
    use osis_core::WallMs;
    use osis_crypto::SeededRng;
    use proptest::prelude::*;
    use std::io::Read;

    // min above the 64-byte gear window, so cuts are content-defined as with the format.
    const SMALL: LargeParams = LargeParams { chunk: ChunkParams { min: 64, max: 512, mask_bits: 5 }, threshold: 128 };

    fn data(n: usize, seed: u8) -> Vec<u8> {
        let mut out = vec![0u8; n];
        osis_core::hash::Hasher::new().update(&[seed, 1]).finalize_xof(&mut out);
        out
    }

    fn framing() -> Framing {
        Framing { dedup: Secret32::from_bytes([7; 32]), expiry: Some(WallMs(99)), keys: vec![(3, dk(3))] }
    }

    fn dk(b: u8) -> osis_crypto::VerifyingKey {
        osis_crypto::DeleteSecret::derive(&Secret32::from_bytes([b; 32])).verifying_key()
    }

    fn write_bytes(store: &mut MemoryBlobs, f: &Framing, rng: &mut SeededRng, d: &[u8], piece: usize) -> Value {
        let mut bw = BlobWriter::new(f, store, rng);
        let mut w = ValueWriter::bytes(SMALL, d.len() as u64);
        for p in d.chunks(piece.max(1)) {
            w.write(&mut bw, p).unwrap();
        }
        w.finish(&mut bw).unwrap()
    }

    // spec/data-model.md §6: above CHUNK_THRESHOLD a blob is chunked, at or below it is not;
    // the tree holds its canonical bytes; equal content gives equal root hashes, other links.
    // spec/data-model.md §6 (chunk threshold)
    #[test]
    fn threshold() {
        let f = framing();
        let mut store = MemoryBlobs::default();
        let mut rng = SeededRng::from_u64(1);
        // Head of 2 bytes: 126 payload bytes is exactly the threshold.
        for (n, large) in [(0, false), (126, false), (127, true), (1000, true)] {
            let d = data(n, 3);
            let v = write_bytes(&mut store, &f, &mut rng, &d, 50);
            assert_eq!(matches!(v, Value::Link(_)), large, "{n}");
            assert_eq!(encode(&Value::Bytes(d.clone())).len() > SMALL.threshold, large);
            let Value::Link(l) = v else {
                assert_eq!(v, Value::Bytes(d));
                continue;
            };
            let mut r = BlobReader::new(&f.dedup, &mut store);
            assert_eq!(read_value(l, &f.dedup, &mut r, SMALL, usize::MAX).unwrap(), Value::Bytes(d.clone()));
            let mut hs = HashSink::new(f.dedup.clone());
            let Value::Link(h) = chunk_value(&mut hs, SMALL, &Value::Bytes(d.clone())).unwrap() else { panic!() };
            assert_eq!(h.hash, l.hash);
            let Value::Link(l2) = write_bytes(&mut store, &f, &mut rng, &d, 7) else { panic!() };
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
        let mut rng = SeededRng::from_u64(2);
        let root = write_tree(&mut BlobWriter::new(&f, &mut store, &mut rng), SMALL.chunk, &encode(&Value::Bytes(vec![1; 20]))).unwrap();
        let mut r = BlobReader::new(&f.dedup, &mut store);
        assert_eq!(read_value(root, &f.dedup, &mut r, SMALL, usize::MAX), Err(Error::Malformed("chunked value at or below CHUNK_THRESHOLD")));
    }

    // spec/data-model.md §5, §6: text streams with UTF-8 checks across write boundaries; a
    // declared length must be met exactly.
    #[test]
    fn text_and_lengths() {
        let f = framing();
        let mut store = MemoryBlobs::default();
        let mut rng = SeededRng::from_u64(3);
        let s = "héllo wörld ✓ 𝄞 ".repeat(40);
        let mut bw = BlobWriter::new(&f, &mut store, &mut rng);
        let mut w = ValueWriter::text(SMALL, s.len() as u64);
        for p in s.as_bytes().chunks(3) {
            w.write(&mut bw, p).unwrap();
        }
        let Value::Link(root) = w.finish(&mut bw).unwrap() else { panic!() };
        let mut r = BlobReader::new(&f.dedup, &mut store);
        let mut sr = StringReader::open(root, &f.dedup, &mut r, SMALL, usize::MAX).unwrap();
        assert!(sr.is_text());
        assert_eq!(sr.len(), s.len() as u64);
        let mut out = String::new();
        sr.read_to_string(&mut out).unwrap();
        assert_eq!(out, s);
        let mut w = ValueWriter::text(SMALL, 2);
        assert!(w.write(&mut HashSink::new(f.dedup.clone()), &[0xc3, 0x28]).is_err());
        let mut w = ValueWriter::text(SMALL, 1);
        w.write(&mut HashSink::new(f.dedup.clone()), &[0xc3]).unwrap();
        assert!(w.finish(&mut HashSink::new(f.dedup.clone())).is_err());
        let mut w = ValueWriter::bytes(SMALL, 3);
        assert!(w.write(&mut HashSink::new(f.dedup.clone()), &[1; 4]).is_err());
        let mut w = ValueWriter::bytes(SMALL, 300);
        w.write(&mut HashSink::new(f.dedup.clone()), &[1; 299]).unwrap();
        assert!(w.finish(&mut HashSink::new(f.dedup.clone())).is_err());
        assert_eq!(ValueWriter::text(SMALL, 2).finish(&mut HashSink::new(f.dedup.clone())), Err(Error::Malformed("value shorter than its declared length")));
    }

    // spec/data-model.md §6, spec/sync.md §6: range reads skip into the payload; a reader stops
    // at a missing chunk and resumes once it is fetched (lazy fetch).
    #[test]
    fn range_and_lazy() {
        let f = framing();
        let mut store = MemoryBlobs::default();
        let mut rng = SeededRng::from_u64(4);
        let d = data(5000, 5);
        let Value::Link(root) = write_bytes(&mut store, &f, &mut rng, &d, 333) else { panic!() };
        // Opening fetches only the path to the first chunk: blobs arrive one by one on Missing.
        struct Lazy<'a>(&'a mut MemoryBlobs, Option<osis_core::BlobId>);
        impl crate::tree::BlobFetch for Lazy<'_> {
            fn fetch(&mut self, id: &osis_core::BlobId) -> Result<Vec<u8>, Error> {
                let r = self.0.fetch(id);
                if r.is_err() {
                    self.1 = Some(*id);
                }
                r
            }
        }
        let mut held = MemoryBlobs::default();
        let mut fetched = 0;
        loop {
            let mut lazy = Lazy(&mut held, None);
            let mut r = BlobReader::new(&f.dedup, &mut lazy);
            match StringReader::open(root, &f.dedup, &mut r, SMALL, usize::MAX).map(|s| s.len()) {
                Ok(n) => {
                    assert_eq!(n, 5000);
                    break;
                }
                Err(Error::Missing) => {}
                Err(e) => panic!("{e}"),
            }
            fetched += 1;
            let id = lazy.1.unwrap();
            held.0.insert(id, store.0[&id].clone());
        }
        assert!(fetched > 0 && held.0.len() < store.0.len());
        let mut store2 = store;
        let mut r = BlobReader::new(&f.dedup, &mut store2);
        let mut sr = StringReader::open(root, &f.dedup, &mut r, SMALL, usize::MAX).unwrap();
        sr.seek(1234).unwrap();
        let mut out = vec![0; 100];
        sr.read_exact(&mut out).unwrap();
        assert_eq!(out, d[1234..1334]);
        sr.seek(5000).unwrap();
        assert_eq!(sr.read_some(&mut out).unwrap(), 0);
        assert!(sr.seek(5001).is_err());
        // Backwards, then through io::Seek from the end.
        sr.seek(10).unwrap();
        sr.read_exact(&mut out).unwrap();
        assert_eq!(out, d[10..110]);
        assert_eq!(std::io::Seek::seek(&mut sr, std::io::SeekFrom::End(-100)).unwrap(), 4900);
        sr.read_exact(&mut out).unwrap();
        assert_eq!(out, d[4900..]);
    }

    /// Serves blobs from a store but only those in `allow`, counting fetches.
    struct Gate<'a> {
        store: &'a mut MemoryBlobs,
        fetches: usize,
        missing_once: Option<osis_core::BlobId>,
    }
    impl crate::tree::BlobFetch for Gate<'_> {
        fn fetch(&mut self, id: &osis_core::BlobId) -> Result<Vec<u8>, Error> {
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
        let mut rng = SeededRng::from_u64(6);
        let d = data(3000, 6);
        let Value::Link(root) = write_bytes(&mut store, &f, &mut rng, &d, 3000) else { panic!() };
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

    // spec/sync.md §6, spec/wire.md §6: a read after a seek interrupted by a Missing chunk
    // resumes where it stopped; open rejects a declared length at or below the threshold or
    // above the caller's bound.
    #[test]
    fn seek_resumes_spec_sync_6() {
        let f = framing();
        let mut store = MemoryBlobs::default();
        let mut rng = SeededRng::from_u64(8);
        let d = data(4000, 7);
        let Value::Link(root) = write_bytes(&mut store, &f, &mut rng, &d, 4000) else { panic!() };
        // A blob in the middle of the reading order goes missing once.
        let mut order = Vec::new();
        {
            struct Log<'a>(&'a mut MemoryBlobs, &'a mut Vec<osis_core::BlobId>);
            impl crate::tree::BlobFetch for Log<'_> {
                fn fetch(&mut self, id: &osis_core::BlobId) -> Result<Vec<u8>, Error> {
                    self.1.push(*id);
                    crate::tree::BlobFetch::fetch(self.0, id)
                }
            }
            let mut log = Log(&mut store, &mut order);
            let mut r = BlobReader::new(&f.dedup, &mut log);
            LargeReader::new(root, &f.dedup, &mut r, SMALL, usize::MAX).read_all().unwrap();
        }
        // The last chunk goes missing once; a seek fetches nothing before it is read.
        let victim = *order.last().unwrap();
        let mut gate = Gate { store: &mut store, fetches: 0, missing_once: Some(victim) };
        let mut r = BlobReader::new(&f.dedup, &mut gate);
        let mut sr = StringReader::open(root, &f.dedup, &mut r, SMALL, usize::MAX).unwrap();
        sr.seek(3990).unwrap();
        let (mut out, mut misses, mut buf) = (Vec::new(), 0, [0u8; 7]);
        loop {
            match sr.read_some(&mut buf) {
                Ok(0) => break,
                Ok(n) => out.extend_from_slice(&buf[..n]),
                Err(Error::Missing) => misses += 1,
                Err(e) => panic!("{e}"),
            }
        }
        assert_eq!((out.as_slice(), misses), (&d[3990..], 1));
        assert!(gate.fetches * 2 < order.len(), "{} of {}", gate.fetches, order.len());
        let mut r = BlobReader::new(&f.dedup, &mut store);
        assert!(matches!(StringReader::open(root, &f.dedup, &mut r, SMALL, 3000), Err(Error::TooLarge(_))));
        let small = LargeParams { threshold: 5000, ..SMALL };
        let mut r = BlobReader::new(&f.dedup, &mut store);
        assert!(matches!(StringReader::open(root, &f.dedup, &mut r, small, usize::MAX), Err(Error::Malformed(_))));
    }

    // spec/wire.md §6 (lengths in tree nodes): reading the last MiB of a multi-chunk value
    // fetches only the chunks of that range and the tree nodes on their path (format constants).
    #[test]
    fn tail_read_fetches_the_path_spec_wire_6() {
        use std::cell::Cell;
        struct Count<'a>(&'a MemoryBlobs, &'a Cell<usize>);
        impl crate::tree::BlobFetch for Count<'_> {
            fn fetch(&mut self, id: &osis_core::BlobId) -> Result<Vec<u8>, Error> {
                self.1.set(self.1.get() + 1);
                self.0.0.get(id).cloned().ok_or(Error::Missing)
            }
        }
        const MIB: usize = 1 << 20;
        let f = framing();
        let mut store = MemoryBlobs::default();
        let mut rng = SeededRng::from_u64(13);
        let d = data(8 * MIB, 9);
        let mut bw = BlobWriter::new(&f, &mut store, &mut rng);
        let mut w = ValueWriter::bytes(LargeParams::FORMAT, d.len() as u64);
        w.write(&mut bw, &d).unwrap();
        let Value::Link(root) = w.finish(&mut bw).unwrap() else { panic!() };
        // Chunks overlapping the last MiB, and the tree's height.
        let canon = encode(&Value::Bytes(d.clone()));
        let mut end = 0;
        let lens = osis_core::chunker::chunk_lengths(&canon, ChunkParams::FORMAT);
        let in_range = lens.iter().filter(|&&n| {
            end += n;
            end > canon.len() - MIB
        });
        let in_range = in_range.count();
        let mut hs = HashSink::new(f.dedup.clone());
        write_tree(&mut hs, ChunkParams::FORMAT, &canon).unwrap();
        let height = hs.nodes.iter().map(|n| n.0).max().unwrap() as usize;
        assert!(lens.len() > 4 * in_range, "{} chunks, {in_range} in range", lens.len());
        let fetches = Cell::new(0);
        let mut src = Count(&store, &fetches);
        let mut r = BlobReader::new(&f.dedup, &mut src);
        let mut sr = StringReader::open(root, &f.dedup, &mut r, LargeParams::FORMAT, usize::MAX).unwrap();
        // a seek inside the chunk held, or to the position itself, fetches nothing
        fetches.set(0);
        sr.seek(1000).unwrap();
        let mut b = [0u8; 10];
        sr.read_exact(&mut b).unwrap();
        sr.seek(1010).unwrap();
        sr.seek(5).unwrap();
        sr.read_exact(&mut b).unwrap();
        assert_eq!((&b[..], fetches.get()), (&d[5..15], 0));
        sr.seek(sr.len() - MIB as u64).unwrap();
        let mut out = Vec::new();
        sr.read_to_end(&mut out).unwrap();
        assert_eq!(out, d[d.len() - MIB..]);
        // One node per level, plus a node per level where the range crosses into the next.
        assert!(fetches.get() <= in_range + 2 * height, "{} fetches: {in_range} chunks, height {height}", fetches.get());
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
        let mut rng = SeededRng::from_u64(14);
        let d = data(20_000, 10);
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

    // spec/requirements.md (Scale: no whole value in memory), reduced constants: the writer
    // holds one chunk and the open nodes, the reader one chunk and the tree path.
    #[test]
    fn memory_bound() {
        let f = framing();
        let mut store = MemoryBlobs::default();
        let mut rng = SeededRng::from_u64(7);
        let n = 200_000;
        // Three levels of open nodes at most here; the bound is below the value's size.
        let path = 3 * osis_core::format::TREE_FANOUT * std::mem::size_of::<Link>();
        assert!(SMALL.chunk.max + path < n);
        let mut bw = BlobWriter::new(&f, &mut store, &mut rng);
        let mut w = ValueWriter::bytes(SMALL, n as u64);
        let mut wmax = 0;
        for i in 0..n / 1000 {
            w.write(&mut bw, &data(1000, i as u8)).unwrap();
            wmax = wmax.max(w.buffered());
        }
        let Value::Link(root) = w.finish(&mut bw).unwrap() else { panic!() };
        assert!(wmax <= SMALL.chunk.max + path, "{wmax}");
        let mut r = BlobReader::new(&f.dedup, &mut store);
        let mut sr = StringReader::open(root, &f.dedup, &mut r, SMALL, usize::MAX).unwrap();
        let (mut rmax, mut total) = (0, 0);
        let mut buf = [0u8; 100];
        loop {
            let k = sr.read_some(&mut buf).unwrap();
            rmax = rmax.max(sr.buffered());
            if k == 0 {
                break;
            }
            total += k;
        }
        assert_eq!(total, n);
        assert!(rmax <= SMALL.chunk.max + path, "{rmax}");
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
        let mut w = ValueWriter::bytes(SMALL, d.len() as u64);
        w.write(&mut bw, d).unwrap();
        let Value::Link(root) = w.finish(&mut bw).unwrap() else { panic!() };
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
        let d = data(20_000, 8);
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
    // not exactly the new delta's; author-chain commitments need not match.
    #[test]
    fn reencryption_rule() {
        let fr = |expiry: Option<u64>, keys: Vec<(u8, u8)>| Framing { dedup: Secret32::from_bytes([7; 32]), expiry: expiry.map(WallMs), keys: keys.into_iter().map(|(l, b)| (l, dk(b))).collect() };
        let base = fr(Some(100), vec![(1, 1), (2, 2), (3, 3)]);
        let d = data(5_000, 9);
        let cases = [
            (fr(Some(100), vec![(1, 1), (2, 2), (3, 3)]), true),
            (fr(Some(50), vec![(1, 1), (2, 2), (3, 3)]), true),
            (fr(Some(100), vec![(1, 1), (2, 9), (3, 3)]), true),
            (fr(Some(100), vec![(1, 1), (3, 3)]), true),
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
        let mut store = MemoryBlobs::default();
        let (root, n, _) = rewrite(&mut store, &fr(None, vec![(3, 3)]), 1, &d, None);
        let (_, written, _) = rewrite(&mut store, &fr(Some(5), vec![(3, 3)]), 2, &d, Some(root));
        assert_eq!((written, n > 0), (0, true));
    }

    proptest! {
        // spec/data-model.md §6: round trip for random sizes around and above the threshold.
        #[test]
        fn round_trip(n in 0usize..3000, seed in any::<u8>(), piece in 1usize..400) {
            let f = framing();
            let d = data(n, seed);
            let mut store = MemoryBlobs::default();
            let mut rng = SeededRng::from_u64(u64::from(seed));
            let v = write_bytes(&mut store, &f, &mut rng, &d, piece);
            let enc = encode(&Value::Bytes(d.clone()));
            match v {
                Value::Link(root) => {
                    prop_assert!(enc.len() > SMALL.threshold);
                    let mut r = BlobReader::new(&f.dedup, &mut store);
                    let mut sr = StringReader::open(root, &f.dedup, &mut r, SMALL, usize::MAX).unwrap();
                    let mut out = Vec::new();
                    sr.read_to_end(&mut out).unwrap();
                    prop_assert_eq!(out, d);
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
