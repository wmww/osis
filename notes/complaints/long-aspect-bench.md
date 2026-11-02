# long-aspect-bench (tiller-long-aspect-bench)
- The scratchpad is tmpfs: stores there have no real fsync and eat RAM. Durable numbers need a directory on disk (I used a symlink into the worktree's `target/`).
- redb without durable commits never reuses a freed page: the first fill grew 200 KB per message, 2 GiB at 10^4, before I looked. Bench fills now fsync every 50 commits.
- A background run piped through `cut`/`grep`/`head` shows nothing until it ends, and a `timeout` killing it loses the buffered lines: log to a file.
- `wt` worktree `target/` got a new release test binary mid-run; copying it to the scratch dir first let builds go on during hour-long runs.
- Mutation checks by `git checkout <file>` after an edit also drop uncommitted work in that file: commit first (lost and redid an edit here).
- `perf record` is refused here (`perf_event_paranoid` 4); phase spans (`osis_node::costs`) are what is left.
- A foreground `claudewait` loop gets moved to the background after 180 s by the harness: one `claudewait` per call only.
