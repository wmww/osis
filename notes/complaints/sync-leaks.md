# sync-leaks
- A mutation probe chaining `git commit wip; sed; cargo test; git reset` past 120 s was moved to the background mid-chain; the resets ran later, so nothing could be edited until it ended. Keep a probe's cargo run in its own (backgrounded) call, the restore in the next.
- `mkdir -p` the scratch dir before redirecting into it: the first full test run failed at once on a missing dir.
