# spec-validity
- Cold worktree under load 50: first tier 1 took 9.5 min, no-fail-fast again 10.5 min. `cargo test --workspace` stops at the first failing crate, so one wrong new test hid the other crates' failures for a whole round: use `--no-fail-fast` when a change touches several crates.
- A role-class check in `verify_part` could not be pinned by a vector: `commit_hostile` drops a bad part at its author, so the bundle never holds it. Checks a hostile writer must get past go under `rules` (`check_holders_parts`).
- Review: `StaticSchema` hides a parse error (the schema declares nothing, so a probe fails with "not declared by its schema"; `TEST.error()` shows the cause).

- header-list-decode-memory: a failing proptest leaves `core/commit/proptest-regressions/` untracked in the worktree (not gitignored); easy to commit by accident. `unsafe` is forbidden in test binaries too, so an allocation bound has to read VmHWM from /proc, which is coarse.
- Review: VmHWM is per process, so a peak check in a shared test binary reads other tests' peaks. Re-exec the test binary with `--exact` and an env var (`hostile_list_refused_by_shape`).
