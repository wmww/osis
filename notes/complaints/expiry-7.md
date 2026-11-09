# expiry-7
- `cargo test ... | grep` in the background: the task's output stays empty until the pipe closes, and `claudewait` kept reporting a run whose cargo was gone. Writing to a log file and reading it was reliable.
- `cargo test -p X --test it a:: b::` needs `--` before two filters, as notes/coordination.md says; easy to forget.
