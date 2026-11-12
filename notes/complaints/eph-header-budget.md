# eph-header-budget
- The brief assumed a co-reader peer's listing keeps invalid memory commits known; in fact a reader's entry goes with its body (present nowhere), so the memory reader path was already bounded. The real gaps were durable invalid headers (kept for good, any source) and unstamped invalid entries at a host (outside `unvouched_cap`). A quick probe test before designing saved a wrong fix.
- `holds_nothing` already names a pass helper in node-sync (`pass/bodies.rs`); clashing method names on `SyncEngine` across files surface only as E0034 at every call site.
- Forgetting runs only at a Tick (`serve_timers`): hand-driven tests must `advance` before counting headers.
