# labels-cost-review2
- A temp `probe_trace` test had to be patched in and reverted by hand twice to diff a scenario's trace with and without full passes. `sim-sweep` could take `--full-passes`: a work-set difference is otherwise slow to look at.
- `std::backtrace` shows no frames in the test profile, so a "who marked this label" probe needs prints at each caller.
- The root disk hit 0 bytes free mid-review: `cargo test-net` failed with "failed to parse process output" on three crates, nothing said disk. wt4's `target/debug/incremental` alone was 19 GB. Space came back on its own, then fell to 6 GB free.
- An unknown `OSIS_*` variable panics `testenv`: a probe switch must use another prefix.
