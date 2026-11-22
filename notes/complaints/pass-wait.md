# Complaints: pass-wait
> Summary: `World::run` waits out a pass under way, so a restart reproducer cannot use it and steps by `advance`; the World's monotonic clock runs on across `power_off`, unlike a real process.

- `World::run` extends its horizon by `PASS_WAIT_MS` while a pass is under way, so any test of a pass's wait across restarts must avoid `run` (`advance` with `power_off`/`power_on` between) or the wait-out hides the bug.
- The harness's monotonic clock is the world's and keeps running across `power_off`; a real restart may start it again. Nothing durable may be dated on it, but no test would notice one that was.
