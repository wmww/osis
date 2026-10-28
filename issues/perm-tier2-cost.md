# osis-perm's tier-2 random runs take 30-45 minutes per seed on one core
> Summary: `cargo test --workspace --test it -- --ignored` over core/perm with one `OSIS_PERM_SEED` runs 12 ignored tests (`roster`, `differential`, `queries`, `incremental`) in 29-45 min, most of it one long test running alone at the tail; workers and reviewers were told to run two or three seeds per branch, which put 1-2 hours of single-threaded waiting into every perm task. Tier-2 oracles should take minutes.
> Tags: tests, permissions, performance

Measured today: 28.8 min (seed 5151, load ~20), 38 min (seeds 11, 202, 3003), 42-45 min (seeds 7, 11), each with a long single-threaded tail. The generators are the same as tier 1's at larger `samples`/steps.

Fix: find the tail (`--test-threads=1` with `RUSTC_BOOTSTRAP=1 ... -Z unstable-options --report-time`, or time each ignored test by name), then make every tier-2 perm test finish in a few minutes: cut `samples` and history length to what still exercises the paths (the tests count which paths ran: keep the counts asserted), split one long random run into several tests so cargo runs them in parallel, and move anything that only proves scale into a release-only `budget`/`scale::` check. Until then the per-branch list in notes/testing.md leaves these runs to the coordinator, one seed per round in the background.
