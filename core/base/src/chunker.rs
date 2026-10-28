//! Content-defined chunker (spec/wire.md §6): gear hash over bytes, shared by chunk trees
//! (`Chunker`) and pages (`PageCutter`). Sizes are `format` constants.
//!
//! Rule: `h = 0` at each chunk start, `h = (h << 1) + G[byte]` (mod 2^64) per byte; with `n` bytes
//! in the chunk after the byte, cut if `n >= min` and the top `mask_bits` bits of `h` are zero, or
//! `n == max`. Boundaries depend only on the bytes since the previous boundary.

use crate::format::{CHUNK_MASK_BITS, CHUNK_MAX, CHUNK_MIN};
use std::sync::LazyLock;

/// Gear table: entry `i` is the little-endian u64 at bytes `8i..8i+8` of the 2048-byte BLAKE3
/// XOF of `"osis v1 gear table"` (spec/wire.md §6).
pub static GEAR: LazyLock<[u64; 256]> = LazyLock::new(|| {
    let mut xof = [0u8; 2048];
    crate::hash::Hasher::new().update(b"osis v1 gear table").finalize_xof(&mut xof);
    let mut t = [0u64; 256];
    for (dst, src) in t.iter_mut().zip(xof.as_chunks::<8>().0) {
        *dst = u64::from_le_bytes(*src);
    }
    t
});

/// Chunk size parameters; `min <= max`, `1 <= mask_bits <= 63`. Tests use small ones.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChunkParams {
    pub min: usize,
    pub max: usize,
    pub mask_bits: u32,
}

impl ChunkParams {
    /// The format's parameters.
    pub const FORMAT: ChunkParams = ChunkParams { min: CHUNK_MIN, max: CHUNK_MAX, mask_bits: CHUNK_MASK_BITS };

    /// One gear step; true if `n` bytes with hash `h` meet the content condition.
    fn step(&self, gear: &[u64; 256], h: &mut u64, n: usize, b: u8) -> bool {
        #[allow(clippy::indexing_slicing)] // u8 index into a 256-entry table
        let g = gear[usize::from(b)];
        *h = (*h << 1).wrapping_add(g);
        n >= self.min && h.checked_shr(64 - self.mask_bits).unwrap_or(0) == 0
    }
}

impl Default for ChunkParams {
    fn default() -> ChunkParams {
        ChunkParams::FORMAT
    }
}

/// Incremental chunker: feed bytes in any pieces; cuts are the same as for the whole input.
#[derive(Clone, Debug)]
pub struct Chunker {
    params: ChunkParams,
    h: u64,
    /// Bytes in the current chunk.
    n: usize,
}

impl Chunker {
    pub fn new(params: ChunkParams) -> Chunker {
        Chunker { params, h: 0, n: 0 }
    }

    /// Scans `data` as the continuation of the current chunk. Returns `Some(i)` if the chunk ends
    /// after `data[..i]` (the chunker is then reset; feed `data[i..]` next), `None` if all of
    /// `data` belongs to the current chunk.
    pub fn next_boundary(&mut self, data: &[u8]) -> Option<usize> {
        let gear = &*GEAR;
        for (i, &b) in data.iter().enumerate() {
            self.n += 1;
            if self.params.step(gear, &mut self.h, self.n, b) || self.n >= self.params.max {
                self.reset();
                return Some(i + 1);
            }
        }
        None
    }

    /// Bytes fed since the last boundary.
    pub fn pending(&self) -> usize {
        self.n
    }

    /// Starts a new chunk.
    pub fn reset(&mut self) {
        self.h = 0;
        self.n = 0;
    }
}

/// One-shot: chunk lengths of `data` (the last chunk may be short). Empty input has no chunks.
pub fn chunk_lengths(data: &[u8], params: ChunkParams) -> Vec<usize> {
    let mut c = Chunker::new(params);
    let mut out = Vec::new();
    let mut rest = data;
    while let Some(i) = c.next_boundary(rest) {
        out.push(i);
        rest = rest.get(i..).unwrap_or(&[]);
    }
    if !rest.is_empty() {
        out.push(rest.len());
    }
    out
}

/// Page boundaries (spec/wire.md §6, pages): feed each element's canonical bytes, then
/// `end_element`. `h = 0` at each page start, never reset inside a page; the page closes after the
/// first element at one of whose bytes the content condition held, or at whose end the page holds
/// `max` bytes or more.
#[derive(Clone, Debug)]
pub struct PageCutter {
    params: ChunkParams,
    h: u64,
    /// Bytes in the current page.
    n: usize,
    /// The content condition held inside the current element.
    hit: bool,
}

impl PageCutter {
    pub fn new(params: ChunkParams) -> PageCutter {
        PageCutter { params, h: 0, n: 0, hit: false }
    }

    /// Feeds bytes of the current element (in any pieces).
    pub fn feed(&mut self, bytes: &[u8]) {
        if self.hit {
            self.n = self.n.saturating_add(bytes.len());
            return;
        }
        let gear = &*GEAR;
        for &b in bytes {
            self.n = self.n.saturating_add(1);
            self.hit |= self.params.step(gear, &mut self.h, self.n, b);
        }
    }

    /// Ends the current element. True if the page closes after it; the cutter then starts a new page.
    pub fn end_element(&mut self) -> bool {
        let cut = self.hit || self.n >= self.params.max;
        if cut {
            *self = PageCutter::new(self.params);
        }
        cut
    }

    /// Bytes in the current page.
    pub fn pending(&self) -> usize {
        self.n
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    const SMALL: ChunkParams = ChunkParams { min: 64, max: 1024, mask_bits: 8 };

    /// splitmix64 stream: fixed pseudo-random test input.
    fn data(seed: u64, len: usize) -> Vec<u8> {
        let mut s = seed;
        (0..len)
            .map(|_| {
                s = s.wrapping_add(0x9e37_79b9_7f4a_7c15);
                let mut z = s;
                z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
                z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
                (z ^ (z >> 31)) as u8
            })
            .collect()
    }

    fn incremental(d: &[u8], params: ChunkParams, pieces: &[usize]) -> Vec<usize> {
        let mut it = pieces.iter().cycle();
        let mut lens = Vec::new();
        let mut c = Chunker::new(params);
        let mut cur = 0usize;
        let mut rest = d;
        while !rest.is_empty() {
            let take = (*it.next().unwrap()).clamp(1, rest.len());
            let (mut piece, tail) = rest.split_at(take);
            while let Some(i) = c.next_boundary(piece) {
                lens.push(cur + i);
                cur = 0;
                piece = &piece[i..];
            }
            cur += piece.len();
            rest = tail;
        }
        if cur > 0 {
            lens.push(cur);
        }
        lens
    }

    /// Reference page rule straight from spec/wire.md §6: page lengths for elements of `sizes`.
    fn pages_reference(d: &[u8], sizes: &[usize], p: ChunkParams) -> Vec<usize> {
        let (mut out, mut h, mut n, mut hit, mut pos) = (Vec::new(), 0u64, 0usize, false, 0usize);
        for &s in sizes {
            for &b in &d[pos..pos + s] {
                h = (h << 1).wrapping_add(GEAR[b as usize]);
                n += 1;
                hit |= n >= p.min && h >> (64 - p.mask_bits) == 0;
            }
            pos += s;
            if hit || n >= p.max {
                out.push(n);
                (h, n, hit) = (0, 0, false);
            }
        }
        if n > 0 {
            out.push(n);
        }
        out
    }

    proptest! {
        // spec/wire.md §6: min/max honoured (only the last chunk may be below min).
        #[test]
        fn bounds(seed: u64, len in 0usize..20_000) {
            let d = data(seed, len);
            let l = chunk_lengths(&d, SMALL);
            prop_assert_eq!(l.iter().sum::<usize>(), len);
            for (i, &n) in l.iter().enumerate() {
                prop_assert!(n <= SMALL.max);
                prop_assert!(n >= SMALL.min || i + 1 == l.len());
            }
        }

        // spec/wire.md §6: incremental feeding equals one-shot.
        #[test]
        fn incremental_equals_one_shot(seed: u64, len in 0usize..10_000, pieces in prop::collection::vec(1usize..3000, 1..8)) {
            let d = data(seed, len);
            prop_assert_eq!(incremental(&d, SMALL, &pieces), chunk_lengths(&d, SMALL));
        }

        // spec/wire.md §6: boundaries depend only on content: a prefix edit leaves later chunks
        // equal once the cuts resynchronize.
        #[test]
        fn content_defined(seed: u64, prefix in prop::collection::vec(any::<u8>(), 0..300)) {
            let d = data(seed, 30_000);
            let mut e = prefix.clone();
            e.extend_from_slice(&d);
            let cuts = |x: &[u8]| {
                let mut acc = 0;
                chunk_lengths(x, SMALL).into_iter().map(|n| { acc += n; acc }).collect::<Vec<_>>()
            };
            let a = cuts(&d);
            let b: Vec<usize> = cuts(&e).into_iter().filter_map(|c| c.checked_sub(prefix.len())).collect();
            // After the first shared cut, every later cut is shared.
            if let Some(first) = a.iter().find(|c| b.contains(c)) {
                let ta: Vec<_> = a.iter().filter(|c| *c >= first).collect();
                let tb: Vec<_> = b.iter().filter(|c| *c >= first).collect();
                prop_assert_eq!(ta, tb);
            }
            prop_assert!(a.iter().any(|c| b.contains(c)), "never resynchronized");
        }

        // spec/wire.md §6, pages: PageCutter (elements fed in pieces) matches the rule as written.
        #[test]
        fn pages_match_rule(seed: u64, sizes in prop::collection::vec(1usize..400, 0..100), split in 1usize..50) {
            let d = data(seed, sizes.iter().sum());
            let mut c = PageCutter::new(SMALL);
            let (mut got, mut pos) = (Vec::new(), 0);
            for &s in &sizes {
                for piece in d[pos..pos + s].chunks(split) {
                    c.feed(piece);
                }
                pos += s;
                let n = c.pending();
                if c.end_element() {
                    got.push(n);
                }
            }
            if c.pending() > 0 {
                got.push(c.pending());
            }
            prop_assert_eq!(got, pages_reference(&d, &sizes, SMALL));
        }
    }

    // spec/wire.md §6: gear table from the BLAKE3 XOF of "osis v1 gear table", little-endian.
    #[test]
    fn gear_table_entries() {
        let mut r = blake3::Hasher::new().update(b"osis v1 gear table").finalize_xof();
        let mut first = [0u8; 8];
        r.fill(&mut first);
        r.set_position(2040);
        let mut last = [0u8; 8];
        r.fill(&mut last);
        assert_eq!(GEAR[0], u64::from_le_bytes(first));
        assert_eq!(GEAR[255], u64::from_le_bytes(last));
    }

    // spec/wire.md §6: frozen boundaries of the format chunker on fixed input.
    #[test]
    fn format_boundaries_pinned() {
        let d = data(42, 1 << 20);
        let l = chunk_lengths(&d, ChunkParams::FORMAT);
        assert_eq!(l[..5], [32326, 27705, 65314, 24980, 17510]);
        // Same cuts from the rule as written (1-byte elements make pages plain chunks).
        let r = pages_reference(&d[..200_000], &[1; 200_000], ChunkParams::FORMAT);
        assert_eq!(r[..5], l[..5]);
    }

    // spec/wire.md §6: format parameters give chunks of about CHUNK_MIN + 64 KiB.
    #[test]
    fn format_average() {
        let d = data(1, 8 << 20);
        let l = chunk_lengths(&d, ChunkParams::FORMAT);
        let avg = d.len() / l.len();
        assert!((60 << 10..100 << 10).contains(&avg), "avg {avg}");
        assert!(l.iter().all(|&n| n <= CHUNK_MAX));
    }

    // spec/wire.md §6: the last chunk ends at the end of the input.
    #[test]
    fn empty_and_tiny() {
        assert!(chunk_lengths(&[], SMALL).is_empty());
        assert_eq!(chunk_lengths(&[1, 2, 3], SMALL), vec![3]);
        let z = chunk_lengths(&[0; 5000], SMALL);
        assert_eq!(z.iter().sum::<usize>(), 5000);
        assert!(z.iter().all(|&n| n <= SMALL.max));
    }

    // spec/wire.md §6, pages: an element can push a page past max; it closes after that element.
    #[test]
    fn page_closes_at_or_above_max() {
        let mut c = PageCutter::new(SMALL);
        c.feed(&[0; 1500]);
        assert_eq!(c.pending(), 1500);
        assert!(c.end_element());
        assert_eq!(c.pending(), 0);
    }
}
