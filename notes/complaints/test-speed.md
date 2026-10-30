# test-speed
- The box was quiet for only the first ~15 min; after that other agents held load 10-30, so wall-time comparisons needed alternating A/B runs and CPU-s from copied binaries. A "quiet box" brief only holds if the coordinator keeps others idle for the measuring window.
- First gate after `wt claim`: `kit/target` was cold, the GUI test step took 137 s (3-4 s warm). Worth knowing when reading a first gate's timings.
- `tools/wt` was replaced by the plugin `wt` mid-task; the new `wt` isn't on PATH in an already-running session.
- An unknown `OSIS_*` variable makes `cargo test --workspace` fail in about 9 s; easy to misread as a fast run if you only look at the time.
- That failing run also wrote a bogus `core/crdt/proptest-regressions/tests_undo.txt` (proptest saves the env-var panic as a failing case); check `git status` for new regression files before committing.
