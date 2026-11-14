# cleanup-schema
- `tools/dup_windows.py` prints nothing when it finds no copies: an empty output reads like a failed run. A "no repeated windows" line would settle it.
- The `#[deprecated]` probe works well (one clippy run lists every use site, GUI crates need a second run with `-p`), but its raw output is ~1500 lines: aggregate by function name and by `core/<crate>` prefix, excluding the crate's own `src/`, to see the unused or test-only ones.
- Review gate over every time limit (gate wall 538/220 s, `build` 1142/93 CPU-s) at load 24: a fresh claim of this worktree plus an osis-base change rebuilds the whole tree, which the build share does not allow for; 147 s more went to waiting for the heavy lock.
