# idle-pass
- The issue's "0.4 s a grant" was a debug-only cross-check: `rejudge_once` decodes every held commit under `debug_assertions`. Tier 1 and probes pay it; release grants are 5-6 ms. Probing a cost, run `--release` first.
- `perf` cannot open events here; temporary spans (`costs::span`) were the only profiler, and a span in osis-engine rebuilds the release tree (3 min).
- Sim runs that part differ by rng draws too, so blob IDs differ after the first parted step: compare the (TICK, TRACE) sequence up to the first difference, not the digests.
