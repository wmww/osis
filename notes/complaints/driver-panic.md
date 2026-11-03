# driver-panic
- `wt`/`claudewait` not on PATH in the subagent shell again; used the plugin cache paths from notes/coordination.md.
- First `cargo test -p osis` in this worktree rebuilt the tree from osis-store up (4.5 min): the worktree's target was not warm for the `-p` build.
- My first background clippy redirected into a scratch dir I had not made yet; the shell error showed only in the task output (rc=1 from the redirect, not clippy).
