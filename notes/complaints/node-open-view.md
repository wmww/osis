# node-open-view
- `cargo test ... | tee log | grep ...` in a background job reports exit 0 even when a test fails (no `pipefail`); one failure went unnoticed until the log was read. Use `set -o pipefail` or check the log's `test result` lines.
- `cargo test --workspace` stops at the first failing test binary, so the later binaries did not run either; rerun after fixing.
