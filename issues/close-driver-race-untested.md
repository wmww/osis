# Close's driver handover has no reliable test
> Summary: nothing in tier 1 fails when `close` on `Runtime::Tokio` stops waiting for the driver task (`net::wait_ended`) or when the driver's timers stop waiting on a queued control message (`quiet` in `run_host`); the one race test catches the first about a third of runs.
> Tags: osis, tests

The property (notes/api.md Handle and sync): after `close` returns the app may shut its runtime down, and no driver poll touches a timer of a shut-down runtime. `runtime::tokio_runtime_close_then_shutdown_no_timer_panic` (tier 2, 8 threads × 40 open/close rounds) panics in about a third of runs with `wait_ended` removed; with the `quiet` gating removed no runtime test fails. Asserting `num_alive_tasks() == 0` right after `close` is not a fix: the task is released after the guard `close` waits on drops, so it failed 68 of 400 runs under load with the code correct.

A deterministic test needs a seam: e.g. a test hook that holds the driver inside an engine call (`block_in_place`) while `close` runs, then releases it after the runtime's shutdown began.
