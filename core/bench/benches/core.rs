//! osis-core benches: CBOR encode/decode (spec/data-model.md §5), chunker (spec/wire.md §6), tid
//! derivation (spec/wire.md §3).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

use osis_bench::bench;
use osis_core::chunker::chunk_lengths;
use osis_core::{ChunkParams, CreationRecord, Limits, Tid, Value, decode, encode};
use std::collections::BTreeMap;

/// A struct-like map of 64 fields with text, ints, bytes and a nested list.
fn sample_value() -> Value {
    let mut m = BTreeMap::new();
    for i in 0..64i64 {
        let v = match i % 4 {
            0 => Value::Str(format!("field number {i}")),
            1 => Value::Int(i * 1_000_003),
            2 => Value::Bytes(vec![i as u8; 32]),
            _ => Value::List((0..8).map(Value::Int).collect()),
        };
        m.insert(Value::Int(i), v);
    }
    Value::Map(m)
}

fn main() {
    let v = sample_value();
    let bytes = encode(&v);
    bench("core/cbor_encode", Some(bytes.len()), || encode(&v));
    bench("core/cbor_decode", Some(bytes.len()), || decode(&bytes, &Limits::DEFAULT).unwrap());

    let mut data = vec![0u8; 4 << 20];
    osis_core::hash::Hasher::new().update(b"osis bench chunker").finalize_xof(&mut data);
    bench("core/chunk_4MiB", Some(data.len()), || chunk_lengths(&data, ChunkParams::FORMAT));

    let rec = CreationRecord::Thing { owner: Tid::from_bytes([1; 15]), nonce: [2; 32] };
    bench("core/tid_of_record", None, || rec.tid());
}
