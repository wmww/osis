# cli-cleanup
- `cli::*` wall time swings 11 s to 19 s between identical runs on a loaded box: one run says nothing about a test merge's saving; count store opens instead (each invocation opens and closes its store).
- Removing a test broke an issue's repro pointer; only `tools/policy.py` at commit caught it. Run it before the first commit, not at the end.
