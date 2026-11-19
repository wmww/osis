# s2-engine
- Editing a test file while a long `tools/heavy cargo test` ran made that run report a stale failure (the binary was built from the earlier text): make no edits during the run, or expect to re-run the crate.
- Squashing with `git reset --soft origin/main` after another worktree's fetch had moved origin/main staged a revert of everything landed since (the memory's "no soft-reset squash" rule, met anyway); recovered by resetting soft to the branch's own base from the reflog. Squash onto the claim's base commit, never a remote ref.
