# keel-decode-bounds
- Unsafe is forbidden workspace-wide, so no counting global allocator for "peak allocation" tests: the decoder charges what it allocates (`decode_charged`) and tests compare a value's heap size by capacities instead.
- The fuzz corpus is untracked and absent in a fresh worktree: `cargo run -p osis-vectors --bin fuzz-seeds` first.
- `stream_memory_big_map` (by hand) measures RSS with the encoder's output in the sink; a ratio between two encoders is dominated by that output, so the bound is the output plus a few pages.
