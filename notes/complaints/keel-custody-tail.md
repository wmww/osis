# keel-custody-tail
- The issue's repro (`-- 8000 custody`) was clean on main; only `random_worlds_hold_large` (per-thread seeds) hit it. An issue's repro line should name the run that fails.
- tests_custody's `deliver` advances a millisecond before each delivery, so "received first, then the rest at once" needs an explicit advance before a `same_ms` batch; my first hand test put all six in one ms and discriminated nothing. Check a hand test fails under the old rule before trusting it.
