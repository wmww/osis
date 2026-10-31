# label-activity
- `cargo test --workspace 2>&1 > log` (wrong redirect order) splits results between the log and the task output; use `> log 2>&1`.
- Review: the worker did not run `spec_map.py --gaps`, so a reworded spec sentence (register rule) broke the gate's first step; it is cheap (1 s), worth running whenever spec wording changes.
