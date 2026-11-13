# test-optimizer-4
- A python tool edited while a queued `tools/heavy python3 tool.py ...` waited for the lock ran the edited code when the lock came free (an argument it had dropped became a filter: 0 tests). Same footgun as queued cargo runs; `tools/pertest.py` now builds before taking the lock itself.
- Per-test counts (`--exact`, one process each) hide every cached setup's saving: the pertest totals cannot judge a caching change; count the module in one process instead.
