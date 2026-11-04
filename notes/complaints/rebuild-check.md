# rebuild-check
- Editing sources while a baseline `cargo test --workspace` was still compiling in the same worktree makes it unclear which source the baseline built: wait for the build to finish (or build `--no-run` first) before editing.
- Tier-1 CPU on a shared box (load 20-35) varies by tens of percent between runs; an on/off comparison needs one binary with a runtime switch, run back to back.
- Death dates looked checkable as "derived from held bodies" but are arrival-order dated by design (spec/commits.md §5); the brief's list of aspects included them.
