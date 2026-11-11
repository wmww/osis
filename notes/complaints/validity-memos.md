# validity-memos
- `tools/icount` printed `INSTR unavailable`: `perf_event_paranoid` is 4 on this box now (icount needs <= 2), so instruction counts came from callgrind (about 7 min for one `member_churn` seed) and CPU seconds.
- A `tools/heavy cargo run ...` queued behind a gate builds the tree as it is when the lock comes, not when it was started: edits made while it waits land in the "baseline" run. Build first, then run the binary under the lock.
