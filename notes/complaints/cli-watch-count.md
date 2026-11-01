# cli-watch-count
> Summary: Workflow notes from the watch --count / NoHosts sync / port 4040 task.

- Fresh worktree (wt4): first `cargo build --workspace --tests` took 138 s and outlived the Bash tool's 120 s default; start a cold first build with run_in_background.
- No in-process way to make a change reach a running CLI `watch` (two `Osis` on one `MemStore` do not see each other), so the CLI test can only show the initial lines are not counted (via `--timeout`), not that a later change is.
