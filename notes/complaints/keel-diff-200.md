# keel-diff-200
> Summary: Mishaps met chasing the full-size differential classes.

- The brief's 7-step class-3 script no longer failed on any listed world at the start commit: seed numbers had moved again. Shrinking the current seed (OSIS_SHRINK_MATCH) was the only way to the real case, and it was a different shape (a keying's history) than the issue described.
- The must-hold check runs inside `World::run`, so `OSIS_NO_END_CHECKS=1` does not let a by-hand probe inspect a failing world; I had to gate the run checks locally to read state after the failure.
- A full 200-seed sweep is four heavy holds of about 4 minutes each, but other agents' holds and box load stretched one to 42 minutes, and three seeds hit the 600 CPU-s hang limit at load (102, 165, 181), so a sweep's hang count depends on the box.
- `cargo test` in the sweep script rebuilt the test binary between holds, so editing the tree during a sweep changes what later holds run; copy the binary first and run the copy.
