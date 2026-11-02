# header-actor
- `wt`/`claudewait` not on PATH in the subagent shell (known); a `claudewait X || <full path> X` fallback ran the wait twice and overran the tool timeout.
- First tier-1 run without `--no-fail-fast` stopped at the first failing crate (osis-commit), hiding the vectors failure until a second 3-minute run; use `--no-fail-fast` when a change may break several crates.
- The brief named spec/api.md; the file is notes/api.md.
- Review: `cargo test --workspace --no-run` lists 13 `tests/it/main.rs` executables with no crate name; finding osis-node's needed `-p osis-node --no-run` to print its hash. The rejudge CPU probe at 2000 commits was noise-dominated (8-70 ms both sides at load 18); 8000 commits and three runs each were needed to see main and branch alike.
- Review: `tools/gate.sh` after `git rebase main | tail -1` ran on a conflicted mid-rebase tree (tail ate the exit) and passed; check `git status` before gating. Released the worktree before a fresh-offset oracle finished; re-claiming gave wt3, not wt4.
