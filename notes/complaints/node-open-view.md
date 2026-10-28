# node-open-view
- `cargo test ... | tee log | grep ...` in a background job reports exit 0 even when a test fails (no `pipefail`); one failure went unnoticed until the log was read. Use `set -o pipefail` or check the log's `test result` lines.
- `cargo test --workspace` stops at the first failing test binary, so the later binaries did not run either; rerun after fixing.
- Reviewer: `tools/wt claim` handed out wt2 with a 9 GB target (stacked generations) and only warned.
- Reviewer: comparing against main meant `git checkout main -- core/*/src` in the worktree, patching the test to compile there, building, copying the binary to scratch and restoring; a `tools/wt` helper to build main's test binary for a given test file would save a few steps.
- Reviewer: the brief called the `node/edges` rows new; they predate the branch (only the meta row's view grew).
