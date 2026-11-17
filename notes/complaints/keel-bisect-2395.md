# keel-bisect-2395
- Bisecting a seed costs a full osis-sync test build per step (~4 min); the bisect range was 11 commits, so 4 steps took 15 minutes. The first bad commit only changed timing: both bugs were older. A bisect of a random seed names a trigger, not a cause.
- `unreached_must_holds` runs inside every `World::run`, so a scratch replay that wants to inspect a failing world panics before it can; I patched in an env escape for the debug session. A harness switch to skip quiet checks in scratch replays would save that.
- `OSIS_SYNC_TRACE=<node>:<token>` found the seed 95 cause in minutes once used (a Pull's joins lost, the next naming none): reach for it before writing state dumps.
