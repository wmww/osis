# fathom-review-12
- A cargo test started while a backgrounded `cargo test` of the same crate was building raced it: the background run tested the binary from before an edit, so one new failing test was missing from its results. Run one cargo test per worktree at a time.
