# keel-mut-audit
- `tools/mutate.py` under one `tools/heavy` hold: a batch of 10 engine plants held the lock about 40 min (4 min of tests per plant). Added `MUTATE_HEAVY=1` (each test binary its own hold, the build unlocked).
- A probe build in the audit's worktree overwrites the test binaries a running batch still runs (same artifact paths): probes need a second worktree.
- The batch read `OSIS_MUTANT` per call; now once per site (a `OnceLock` per plant).
- Foreground `claudewait` loops past 180 s get moved to the background by the harness; one `claudewait` per call.
- Per-plant holds waited 4-10 min each behind other agents' holds (2 plants per 30 min): `MUTATE_PER_HOLD` groups plants per hold and the binaries now run side by side.
- Editing `tools/mutate.py` while a batch runs breaks it: the held child runs the script again from disk.
