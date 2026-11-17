# keel-seed65
- The brief's lead (a failed write leaves engine and store apart) was wrong: the live engine's index digest and sync set equalled a fresh load right after the failing Run. The disk fault only delayed node 0's D sync; the power cycle "fixed" it because a start opens every entry. Comparing live against `World::copy` + `power_off` early would have saved hours.
- The quiet checks run inside `World::run`, so a failing seed panics mid-script, before any probe placed after `play`; probes had to go into the harness check itself.
- `w.engine(i).forget_commits(..)` called directly is invisible to sync (no step runs); go through `w.write`.
- Several harness quirks cost runs: a 4-node hand world needs `w.cap = STORM_CAP`; `Disk(i, n, Fail)` after quiet may hit no write at all.
