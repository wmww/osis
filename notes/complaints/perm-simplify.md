# perm-simplify
- `tools/wt claim` found the worktree's target at 15 GB and wiped it: the first build was cold.
- Load 25-30 from other agents: `cargo test -p osis-perm` incremental builds took 3-4 min at times.
- `cargo test ... | tail` hides cargo's exit (the first repro run "passed" with exit 0); grep the `test result` line.
- `bench::` eprintln output needs `--nocapture`; easy to start a long release run that prints nothing.
- `bench_10k_edges` from-scratch time is bimodal under load (0.22 s or 0.6-0.9 s, same binary): compare before/after interleaved, several runs.
- Review: a foreground Bash command the harness moves to the background after 180 s runs as SCHED_IDLE (`chrt -p`; can't be undone unprivileged); with a periodic sim-sweep at nice 0 on all cores the moved `cargo test` sat 15+ min at 0.4% CPU. `run_in_background` from the start stays SCHED_OTHER. notes/build.md says moved commands run at normal priority: not on this box. Start anything that may pass 3 min with `run_in_background`.
- Review: `pkill -f <cargo command>` also matched the Bash tool's own `bash -c` wrapper and killed the rest of the chained command.
