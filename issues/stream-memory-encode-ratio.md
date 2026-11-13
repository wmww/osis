# stream_memory_big_map: encode memory ratio check fails
> Summary: The by-hand test `tests_stream::stream_memory_big_map` fails run alone on main: `encode-new` peaks at 4656 KiB against `encode-old` 8416 KiB (1.8x), under the asserted 3x.
> Priority: low
> Tags: crdt, tests

Reproduce: `cargo test -p osis-crdt --lib -- --ignored --exact tests_stream::stream_memory_big_map --nocapture`. Decide whether the 3x bound is stale (the encoder writes bytes directly now) or the encoder regressed, then fix the bound or the cost. The release-check crdt line in notes/coordination.md (Release checks) also runs this test without `--skip stream_memory`, so it fails there by construction.
