# sheave-r12-genesis
> Summary: snags that cost real time in the genesis-seed task: timing-lucky sync tests, a colliding test seed, ad hoc tracing.

- Three osis-sync tests (`growth::record_blobs_*`, `first::a_new_reader_logs_no_copy_*`, `first::what_a_reader_fetches_*`) passed by delivery-order luck and failed once blob bytes moved; tracing why took four rounds of `eprintln!` across `read/live.rs`, `inbox/serve.rs` and the test. A trace of record-blob judgements (per node: rows, held, shown, unneeded, gone, deletes sent) in `harness::trace` would have shown the dropped loser in one run. Now issues/record-blob-forgotten-loser.md.
- `growth::record_blobs_*` seeded each sealer `round * 3 + i` over writers {0, 2, 3}: writer 3 at round r and writer 0 at r + 1 drew one rng and sealed one blob, which hid and then confused the real race. A policy or harness helper for per-iteration seeds (hash of the iteration's coordinates) would prevent it.
- Comparing a test against the base needed a second claimed worktree and a full rebuild there; a documented "run this test on origin/main" recipe (which worktree, which target) would have saved working it out.
