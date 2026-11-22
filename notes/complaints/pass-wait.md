# Complaints: pass-wait
> Summary: `World::run` waits out a pass under way, so a restart reproducer cannot use it and steps by `advance`; the World's monotonic clock runs on across `power_off`, unlike a real process.

- `World::run` extends its horizon by `PASS_WAIT_MS` while a pass is under way, so any test of a pass's wait across restarts must avoid `run` (`advance` with `power_off`/`power_on` between) or the wait-out hides the bug.
- The harness's monotonic clock is the world's and keeps running across `power_off`; a real restart may start it again. Nothing durable may be dated on it, but no test would notice one that was.
- The brief's "drop the pass when S leaves the sync set" broke holding.rs's release test: leave's `releasing` wants passes of sync IDs already out of the set. Nothing in status's state shows that wants come from outside its own set; found only by the full crate run.
