# perm-simplify
- `tools/wt claim` found the worktree's target at 15 GB and wiped it: the first build was cold.
- Load 25-30 from other agents: `cargo test -p osis-perm` incremental builds took 3-4 min at times.
- `cargo test ... | tail` hides cargo's exit (the first repro run "passed" with exit 0); grep the `test result` line.
- `bench::` eprintln output needs `--nocapture`; easy to start a long release run that prints nothing.
- `bench_10k_edges` from-scratch time is bimodal under load (0.22 s or 0.6-0.9 s, same binary): compare before/after interleaved, several runs.
