# delete-memberships
- `tools/prune-incremental.sh` run from a worktree finds nothing: it takes `git rev-parse --show-toplevel` (the worktree) as the root of `.worktrees/`. The disk filled mid-task (0 bytes free, a commit failed); running it from the main checkout freed 24 GB.
- `osis-crdt` lib tests fail at most non-default `OSIS_CRDT_SEED`s on main too (`tests_laws::entry_copies::forged_entry_copies_join_and_expire_alike_spec_5_6`, `tests_life::sweep_laws_spec_sync_7`, `tests_seq_ops::small_joins_follow_cached_placement_spec_6`; e.g. seeds 2134411, 231666, 33), so trying a crdt change at other seeds needs a main comparison run for every failure.
- A `cat > file 2>/dev/null || ...` probe in a Bash call waited on stdin for minutes before it was moved to the background.
- Review: comparing crdt lib tests across seeds against main needs a `tools/bin-at origin/main --lib osis-crdt` build (about 4 min at low load) and the clean-tree dance; a one-line seed-diff tool would help.
- A crdt-model change breaks held-model (it builds on the model's `death`), which `cargo test -p <crate>` for the touched crates misses: 11 gate failures here. Workers touching crdt-model should also run `cargo test -p held-model`.
- Rework: a proptest failure writes its seed into `props.proptest-regressions`, which `git add -A` then picks up; easy to commit a pinned seed by accident.
- Second review: rebasing onto main conflicted in notes/time-limits.md (both sides appended a line at the log's end); every branch logging overruns hits this.
