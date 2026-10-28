//! osis-crdt benches: text read (linearization, spec/crdt.md §6), one insert op, snapshot encode
//! of a text built by the synthetic typist (osis_bench::text).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

use osis_bench::bench;
use osis_bench::text::{replay, snapshot_len, synthetic};

fn main() {
    let edits = synthetic(20_000, 3);
    let (state, _) = replay(&edits, 10);
    let n = match state.read() {
        Some(osis_core::Value::Str(s)) => s.len(),
        _ => 0,
    };
    bench("crdt/text_read", Some(n), || state.read());
    bench("crdt/text_snapshot", Some(n), || snapshot_len(&state));
    bench("crdt/text_replay_1k", None, || replay(&edits[..1000], 10));
}
