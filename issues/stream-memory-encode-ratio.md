# stream_memory_big_map: encode memory ratio check fails
> Summary: The by-hand test `tests_stream::stream_memory_big_map` fails run alone: `encode-new` peaks at 4656 KiB against `encode-old` 8544 KiB (1.8x), under the asserted 3x.
> Priority: low
> Tags: crdt, tests

Reproduce: `cargo test -p osis-crdt --lib -- --ignored --exact tests_stream::stream_memory_big_map --nocapture`. Decide whether the 3x bound is stale (the encoder writes bytes directly) or the encoder regressed, then fix the bound or the cost. The release-check crdt line in notes/coordination.md (Release checks) runs it too (no `--skip stream_memory`), so it fails there as well.
