# labels-cost-review2
- A temp `probe_trace` test had to be patched in and reverted by hand twice to diff a scenario's trace with and without full passes. `sim-sweep` could take `--full-passes`: a work-set difference is otherwise slow to look at.
- `std::backtrace` shows no frames in the test profile, so a "who marked this label" probe needs prints at each caller.
