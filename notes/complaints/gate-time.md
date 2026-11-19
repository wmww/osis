# gate-time
- The gate log gives a property stage's wall per test but no CPU-s per property: the per-property table took a separate run of each under the lock (about 2,400 CPU-s). `run_jobs` already holds each worker's thread clock; summing it into its summary line would put each property's CPU-s in every gate log (the order harness's pool would need the same).
- issues/test-time.md lever 5 (packages rebuilt, 35-45% of rotation) was stale by 4x: profile before trusting a lever's share.
