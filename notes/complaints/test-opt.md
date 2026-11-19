# test-opt
- `tools/limits.py tests` and `tools/pertest.py run` each waited 5+ min for the heavy lock behind a gate; the two together cost about 30 min of the session before any evidence.
- The gate log prints a property stage's wall per test but no CPU-s or instructions per property: which property costs what took separate single-seed runs.
- A multi-threaded `held_set_decides` run's instruction count moves with thread timing (which of two alike nodes is met first): compare with `OSIS_SEED_THREADS=1`.
