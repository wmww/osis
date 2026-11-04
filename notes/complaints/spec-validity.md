# spec-validity
- Cold worktree under load 50: first tier 1 took 9.5 min, no-fail-fast again 10.5 min. `cargo test --workspace` stops at the first failing crate, so one wrong new test hid the other crates' failures for a whole round: use `--no-fail-fast` when a change touches several crates.
- A role-class check in `verify_part` could not be pinned by a vector: `commit_hostile` drops a bad part at its author, so the bundle never holds it. Checks a hostile writer must get past go under `rules` (`check_holders_parts`).
