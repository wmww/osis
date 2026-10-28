# perm-simplify
- `tools/wt claim` found the worktree's target at 15 GB and wiped it: the first build was cold.
- Load 25-30 from other agents: `cargo test -p osis-perm` incremental builds took 3-4 min at times.
- `cargo test ... | tail` hides cargo's exit (the first repro run "passed" with exit 0); grep the `test result` line.
- `bench::` eprintln output needs `--nocapture`; easy to start a long release run that prints nothing.
