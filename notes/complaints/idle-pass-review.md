# idle-pass-review
- A test's first `advance` after a clock jump only clamps: a resync needs a second. My first assert read 0 passes as "fix not working".
- Comparing pass policies by a temporary env switch in `schedule_pass` plus a host-rows timeline probe took minutes and answered "does anything rely on the regular pass"; 1500 steps at a minute each took 2 min in dev.
