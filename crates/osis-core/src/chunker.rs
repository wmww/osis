//! Content-defined chunker (spec/crdt.md §8, spec/data-model.md §6): gear hash with normalized
//! masks (FastCDC style), shared by chunk trees and paging. Sizes are `format` constants; the gear
//! table and masks are provisional (plans/protocol-spec.md item 4).
//!
//! Rule: the hash restarts at every chunk start, `h = (h << 1) + GEAR[byte]` per byte; with `n`
//! bytes in the chunk after the byte, cut if `n == max`, else if `n >= min` and
//! `h & (n < avg ? mask_hard : mask_easy) == 0`. Boundaries depend only on the bytes since the
//! previous boundary.

use crate::format::{CHUNK_AVG, CHUNK_MAX, CHUNK_MIN};

/// splitmix64, for the gear table. provisional.
const fn splitmix64(state: u64) -> (u64, u64) {
    let s = state.wrapping_add(0x9e37_79b9_7f4a_7c15);
    let mut z = s;
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    (s, z ^ (z >> 31))
}

/// Gear table: 256 splitmix64 outputs from seed `"osisgear"` as a big-endian u64. provisional.
#[allow(clippy::indexing_slicing)] // const evaluation; i < 256
pub const GEAR: [u64; 256] = {
    let mut t = [0u64; 256];
    let mut state = u64::from_be_bytes(*b"osisgear");
    let mut i = 0;
    while i < 256 {
        let (s, z) = splitmix64(state);
        state = s;
        t[i] = z;
        i += 1;
    }
    t
};

/// Chunk size parameters. `avg` must be a power of two with `min <= avg <= max`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChunkParams {
    pub min: usize,
    pub avg: usize,
    pub max: usize,
}

impl ChunkParams {
    /// The format's parameters.
    pub const FORMAT: ChunkParams = ChunkParams { min: CHUNK_MIN, avg: CHUNK_AVG, max: CHUNK_MAX };

    /// Masks with `log2(avg) + 2` and `log2(avg) - 2` top bits set. provisional.
    fn masks(&self) -> (u64, u64) {
        let bits = self.avg.max(16).trailing_zeros();
        let top = |k: u32| if k == 0 { 0 } else { u64::MAX << (64 - k.min(64)) };
        (top(bits + 2), top(bits - 2))
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
    mask_hard: u64,
    mask_easy: u64,
    h: u64,
    /// Bytes in the current chunk.
    n: usize,
}

impl Chunker {
    pub fn new(params: ChunkParams) -> Chunker {
        let (mask_hard, mask_easy) = params.masks();
        Chunker { params, mask_hard, mask_easy, h: 0, n: 0 }
    }

    /// Scans `data` as the continuation of the current chunk. Returns `Some(i)` if the chunk ends
    /// after `data[..i]` (the chunker is then reset; feed `data[i..]` next), `None` if all of
    /// `data` belongs to the current chunk.
    pub fn next_boundary(&mut self, data: &[u8]) -> Option<usize> {
        let p = self.params;
        for (i, &b) in data.iter().enumerate() {
            #[allow(clippy::indexing_slicing)] // u8 index into a 256-entry table
            let g = GEAR[usize::from(b)];
            self.h = (self.h << 1).wrapping_add(g);
            self.n += 1;
            let mask = if self.n < p.avg { self.mask_hard } else { self.mask_easy };
            let cut = self.n >= p.max || (self.n >= p.min && self.h & mask == 0);
            if cut {
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

    /// Starts a new chunk (paging cuts after a whole element).
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

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    const SMALL: ChunkParams = ChunkParams { min: 64, avg: 256, max: 1024 };

    fn data(seed: u64, len: usize) -> Vec<u8> {
        let mut s = seed;
        (0..len)
            .map(|_| {
                let (n, z) = splitmix64(s);
                s = n;
                z as u8
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

    proptest! {
        // spec/crdt.md §8: min/max honoured (only the last chunk may be below min).
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

        // spec/crdt.md §8: incremental feeding equals one-shot.
        #[test]
        fn incremental_equals_one_shot(seed: u64, len in 0usize..10_000, pieces in prop::collection::vec(1usize..3000, 1..8)) {
            let d = data(seed, len);
            prop_assert_eq!(incremental(&d, SMALL, &pieces), chunk_lengths(&d, SMALL));
        }

        // spec/crdt.md §8: boundaries depend only on content: a prefix edit leaves later chunks
        // equal once the cuts resynchronize; equal inputs give equal chunks.
        #[test]
        fn content_defined(seed: u64, prefix in prop::collection::vec(any::<u8>(), 0..300)) {
            let d = data(seed, 30_000);
            let mut e = prefix.clone();
            e.extend_from_slice(&d);
            prop_assert_eq!(chunk_lengths(&d, SMALL), chunk_lengths(&d.clone(), SMALL));
            let cuts = |x: &[u8]| {
                let mut acc = 0;
                chunk_lengths(x, SMALL).into_iter().map(|n| { acc += n; acc }).collect::<Vec<_>>()
            };
            let a = cuts(&d);
            let b: Vec<usize> = cuts(&e).into_iter().filter_map(|c| c.checked_sub(prefix.len())).collect();
            // After the first shared cut, every later cut is shared: cuts depend only on the
            // bytes since the previous cut.
            if let Some(first) = a.iter().find(|c| b.contains(c)) {
                let ta: Vec<_> = a.iter().filter(|c| *c >= first).collect();
                let tb: Vec<_> = b.iter().filter(|c| *c >= first).collect();
                prop_assert_eq!(ta, tb);
            }
            // And cuts resynchronize after an edit (a forced cut at `max` can delay it).
            prop_assert!(a.iter().any(|c| b.contains(c)), "never resynchronized");
        }
    }

    // spec/crdt.md §8: format parameters give an average near 64 KiB.
    #[test]
    fn format_average() {
        let d = data(1, 8 << 20);
        let l = chunk_lengths(&d, ChunkParams::FORMAT);
        let avg = d.len() / l.len();
        assert!((40 << 10..100 << 10).contains(&avg), "avg {avg}");
        assert!(l.iter().all(|&n| n <= CHUNK_MAX));
    }

    #[test]
    fn empty_and_tiny() {
        assert!(chunk_lengths(&[], SMALL).is_empty());
        assert_eq!(chunk_lengths(&[1, 2, 3], SMALL), vec![3]);
        let z = chunk_lengths(&[0; 5000], SMALL);
        assert_eq!(z.iter().sum::<usize>(), 5000);
        assert!(z.iter().all(|&n| n <= SMALL.max));
    }
}
