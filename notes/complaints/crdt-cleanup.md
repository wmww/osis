# crdt-cleanup
> Summary: Mishaps and slow spots met on the crdt-cleanup branch.

- `MCommit` (testutil) has no source, and `Tid` has no public constructor from 16 bytes (`Tid::from_bytes([n; 15])`): a temporary differential test took two compile rounds to find the helpers other tests use.
- Old-vs-new release timing needs two binaries; checking `main`'s `core/crdt/src` out over the worktree, building, and checking `HEAD` back out works without stash, but rebuilds the crate both ways.
- The `seq_ops` fuzz target builds its own target dir under `core/test/fuzz/target` per worktree (a cold nightly build, a couple of minutes).
- `claudewait` reported "exit code unknown, finished earlier" at once for a background command that began with `uptime;` (it seems to track the first process), while the loop after it ran two more minutes: read the log instead.
- Review: `cargo fuzz list` from the fuzz dir fails without `--fuzz-dir .` (it looks for `fuzz/` at the repo root); the README says so, easy to miss. The `box` target warns on an unused `Codec` import (not this branch).
- Review: no fragment generator yields raw stamps (Derived kept) or anchors; `writes()` maps to owners, so a stamp differential needs its own collector.
- Review: the first gate run failed on `runtime::close_while_driver_runs_no_timer_panic` (main's, flaky about 1 in 20 under load; issues/close-timer-panic-flaky.md); the rerun passed.
