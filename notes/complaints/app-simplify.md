# app-simplify
- Machine load ~40: a one-line change in osis-schema `path.rs` rebuilt the engine tree for `cargo test -p osis` in 14 min (normally under a minute). Nothing wrong with the build; budget for it when touching osis-schema.
- (review) The close-time tokio panic did not reproduce from the CLI run one at a time on a quiet box (0 of 60); 12 runs in parallel did (3 of 48). An in-process test with 8 threads opening and closing `Runtime::Own` databases hit it 20+ times per run: a reliable repro beats CLI loops.
