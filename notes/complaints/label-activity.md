# label-activity
- `cargo test --workspace 2>&1 > log` (wrong redirect order) splits results between the log and the task output; use `> log 2>&1`.
