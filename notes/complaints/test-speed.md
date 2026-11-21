# test-speed
- A whole-suite `tools/pertest.py run` took 7.5 min under the lock at 8 jobs (3,994 processes) and the engine and sync `--modules` run 3.5 more; a cached profile of main (refreshed by whoever lands a big change) would save each test-speed job those 11 minutes.
- Comparing a harness cache against fresh runs by `eprintln!` probes under `--nocapture` interleaves lines from a test's own threads and libtest's: long probe lines were cut and a diff said DIFFER where nothing differed. Print a short hash per line and match it with `grep -o`.
- The box ran 2-3x slower in wall time for minutes at a stretch (other agents' builds): the same `order::` run took 35 s, then 91 s, then 131 s. Instructions were the only figure worth reading.
- `git reset --hard` to drop a wip commit also dropped uncommitted note edits made after it: wip-commit everything before any reset, as notes/build.md says.
