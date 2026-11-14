# Shrinking a differential seed takes minutes and can hang
> Summary: `OSIS_SYNC_SHRINK=1` shrinks one candidate at a time, plays each twice (converge's determinism check), and runs inside the seed's 600 CPU-s timeout, while the differential's world cap (200,000 deliveries, about 280x a clean history's 724) lets a livelocked candidate run for minutes: a 13 s seed took over 10 min to shrink or hung, and agents wrote their own parallel ddmin.
> Priority: normal
> Tags: sync, tests

What agents met (sync rebuild, one day): shrinks of 6-8 min each (sync-removed-write, sync-sweep: 46 steps in 363 s), one past the 600 CPU-s seed timeout with no output (seed 11, cards integration: a shrunk candidate livelocked), and a by-hand parallel ddmin written in its place (22 min, recompiling a test per candidate). A worker's own livelock bug (`Tick` inputs at one clock time) ran a convergence seed to 54,000+ deliveries over many minutes before failing.

Where (core/sync/tests/it, core/base/src/testenv.rs):
- `converge` plays every history twice and compares traces; `shrinking` calls it per candidate, so each candidate pays the determinism check. Checking determinism once, on the failing seed, then playing candidates once halves a shrink.
- `testenv::shrinking` tries candidates sequentially on one thread; the chunk removals at one size are independent and could run on `run_jobs`' threads (first failing candidate in order wins, so the result stays a function of the seed).
- The shrink runs inside the seed's `SEED_TIMEOUT_SECS`, so a long shrink is reported hung and loses its progress. A shrink should print each smaller failing script as it finds it.
- `w.cap = 200_000` in convergence, sims and flows (`RULE_CAP` is 2,000). A candidate that storms should count as "does not fail this way" after a cap near ten times the original run's deliveries, and the differential's own cap should be a small multiple of a history's typical deliveries (notes/arbitrary-values.md: at 0 every history storms; at infinity a livelock runs to the seed timeout).
