# sync-cleanup
- `tools/wt claim` handed out wt1 with a 9 GB target (stacked generations); left as is.
- `cargo test-net` (first build of the net feature set in this worktree) ran past 3 min and was moved to the background mid-command; start it with `run_in_background` from the outset.
- Review: `cargo test --workspace -- --ignored work_sets_match_full_passes` spent minutes after the test passed compiling every crate's doctests under load (rustdoc); `--test it -p osis-sim` style narrowing would skip that.
