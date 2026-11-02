# forged-copies
> Summary: Worker mishaps on the forged-creation-copies fix.

- The hostile differentials at `PROPTEST_CASES=4000` pass the `-p osis-crdt --lib` filter through `grep`, which reports the pipe's exit: the first 4000-case run printed `exited with code 0` beside a FAILED line. Use `set -o pipefail` or `${PIPESTATUS[0]}` from the start, as notes/build.md says.
- A failing proptest seed reproduced only through the test's own function (`hostile_lockstep(seed, ..)`), not through a copy of its first half: the difference was a guard (`holds_dots`) that the copy skipped. Reproduce with the real function first, then bisect.
- `cargo +nightly fuzz run` on `delta` spent longer building osis-crdt under nightly than the four minutes of fuzzing; start it early in the task, in the background.
