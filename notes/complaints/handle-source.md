# handle-source complaints
> Summary: Mishaps met on branch handle-source.

- Disk full (`/` at 100%, ~200 MB free) mid-task from other worktrees' targets (6.5-8.6 GB each, 7 worktrees): `cargo test -p osis-cli` failed writing fingerprints; nothing of mine to free.
- A `du -sh /home/ai/*` probe ran past 120 s on the full disk and moved to the background; stopped with TaskStop.
- notes/client-port.md §8 (a) names `core/osis/src/signal.rs`; there is no such file (signals are not an `osis` call yet).
- `tools/icount` prints `INSTR unavailable` on this box (no perf events in the VM), so old-vs-new needed many interleaved CPU-time runs at load 25 (±20% per run).
