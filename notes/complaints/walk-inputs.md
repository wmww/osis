# walk-inputs
> Summary: footguns met fixing the walk's reading inputs.

- Each osis-engine debug build of `--tests` took 3-6 min; a single-test probe rebuilds the `it` binary (about 3 min), so probing which fix a test needs (revert, run, restore) is slow. Batch probes.
- `Timeline::reads_now` printing every `facts.reads` miss is noise: ordinary updates call `reads` on fresh commits (stored fact `None`) all the time. Debug on `reads_now` alone.
- The obvious fails-before test (a void flag) passed with its fix reverted: the voided commit's own `put_meta` touched it before any read. Check a new test against the reverted fix before trusting it.
- A debug check per walk read (re-reading every stale commit at each `Core::timelines()`) passed every test but cost 3.6-4x instructions on the gate, 31 tests over the bound. Price a new debug check with `tools/icount` on one heavy test before pushing.
