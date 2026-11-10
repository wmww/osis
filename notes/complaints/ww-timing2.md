# ww-timing2 (profiling test setup)
- `perf record` fails (even `-e cpu-clock:u`, paranoid 2, unsandboxed); callgrind and `tools/icount` work. `tools/cpuprof` exists but I found it only after profiling.
- `wt release` after reverting a profile change in Cargo.toml rebuilds the whole tree under the restored profile (`cargo test --no-run` to mark): minutes of CPU for nothing when the worktree is about to be reused.
