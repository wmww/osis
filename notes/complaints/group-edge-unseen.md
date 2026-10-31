# group-edge-unseen
- A compound Bash command moved to the background by the 120 s cap kept running its later steps (git apply, more tests) after I killed the test it was blocked on; the worktree changed under me. Keep revert/apply steps out of commands that may run long.
- No gdb/perf on the box: a spinning sim test (re-upload storm) had to be found with eprintln in `World::pump`; `OSIS_TRACE_UPLOADS=1` was the useful tool once found.
- Reviewer: a storm that runs once per pass only shows across `w.advance` steps (`w.run()` still returns true); `OSIS_TRACE_UPLOADS=1` plus a few hour-long advances found it.
- review 2: the first review's repro asserted `w.run()` settled though the storm ran on: a re-upload per tick reads as settled; only a traffic tally (`World::start_tally`) shows it.
