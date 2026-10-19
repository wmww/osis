//! Chunker (spec/wire.md §6): never panics; chunks cover the input within the size bounds, and
//! incremental feeding (split at a fuzzed point) equals one-shot chunking.
#![no_main]

use libfuzzer_sys::fuzz_target;
use osis_core::ChunkParams;
use osis_core::chunker::{Chunker, chunk_lengths};

const SMALL: ChunkParams = ChunkParams { min: 64, avg: 256, max: 1024 };

fuzz_target!(|data: &[u8]| {
    let Some((&split, data)) = data.split_first() else { return };
    for params in [SMALL, ChunkParams::FORMAT] {
        let lens = chunk_lengths(data, params);
        assert_eq!(lens.iter().sum::<usize>(), data.len());
        for (i, &n) in lens.iter().enumerate() {
            assert!(n <= params.max && (n >= params.min || i + 1 == lens.len()));
        }
        // Feed in two pieces.
        let cut = (usize::from(split) * 37).min(data.len());
        let mut c = Chunker::new(params);
        let mut got = Vec::new();
        let mut cur = 0;
        for piece in [&data[..cut], &data[cut..]] {
            let mut rest = piece;
            while let Some(i) = c.next_boundary(rest) {
                got.push(cur + i);
                cur = 0;
                rest = &rest[i..];
            }
            cur += rest.len();
        }
        if cur > 0 {
            got.push(cur);
        }
        assert_eq!(got, lens);
    }
});
