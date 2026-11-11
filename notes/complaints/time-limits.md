# time-limits complaints
- `RUSTC_BOOTSTRAP=1 cargo test` (for libtest's `--report-time`) dirties every crate whose build script tracks it (proc-macro2, thiserror, anyhow, ...): a full rebuild, 2740 CPU-s, and another one back. Per-test times come from running the test binaries directly (`tools/limits.py tests`).
- "Alone under the lock" is not alone: builds of other agents kept the box at 85-100% busy and load 15-45 through every measurement. CPU-s barely moved (base unit 2.26-2.29 CPU-s per quantum over 10 runs); wall did (clean build 220-478 s).
- A measurement script that checks out another revision mid-run fails on any uncommitted edit, and then times a no-op: commit before starting it, and don't edit the worktree while it runs.
- Every lock wait was 10-25 min (others' gates).
- Editing the worktree while a background gate ran: the gate built the half-edited tree and failed to compile (my mistake; the footgun is in notes/build.md).
- `cargo clean` for the clean-build measurement made the next gate's clippy, GUI lint and unification check cold (318, 445, 1770 CPU-s): over their limits for a reason no branch has.
- The task changed twice mid-run (gate sizes, then perf fixes, not sizes): the measurement batches were sized for the first brief.
- Review: the brief said rebase on `main`, but local main lagged origin/main by four commits (the duplicate issue to merge lived only there); rebased on origin/main.
