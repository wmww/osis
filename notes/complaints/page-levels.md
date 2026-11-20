# page-levels
> Summary: Workflow notes from the page-levels branch.

- The engine has no knob for wire page parameters (`LocalPages` and osis-blob always use `PageParams::FORMAT`), so an engine-level reproduction of a deep link tree needs GBs (or a hash-grinding writer at about 10 MB); the step-isolation test plants a snapshot fault instead (`Core::snapshot_fault`).
- A first `cargo test -p osis-engine --lib -- <one test>` in a fresh worktree took about 4 minutes of building: run it in the background from the start.
