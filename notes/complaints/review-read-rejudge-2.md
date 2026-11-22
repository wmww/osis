# review-read-rejudge-2
- Checking a narrowed read's invariant ("the record carries exactly the parts held as bodies") took a scratch eprintln probe with a forced backtrace across the engine suite: an env-gated debug check of that invariant at each read would have answered it at once.
- `cargo test ... -- --nocapture 2>&1 > log` (wrong redirect order) sent the probe's stderr to the task output instead of the log: put `> log 2>&1`.
