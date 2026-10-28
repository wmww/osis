# app-simplify
- Machine load ~40: a one-line change in osis-schema `path.rs` rebuilt the engine tree for `cargo test -p osis` in 14 min (normally under a minute). Nothing wrong with the build; budget for it when touching osis-schema.
- (review) The close-time tokio panic did not reproduce from the CLI run one at a time on a quiet box (0 of 60); 12 runs in parallel did (3 of 48). An in-process test with 8 threads opening and closing `Runtime::Own` databases hit it 20+ times per run: a reliable repro beats CLI loops.
- (review) The gate runs `spec_map.py --uncited` after the 3-minute test and clippy steps; a new test without a spec citation fails it there. Run `python3 tools/spec_map.py --uncited` (instant) before the gate after adding a test.
