# churn-361
- The Net has no way to dump node state when `settle` detects a loop. Diagnosing took temporary edits: a dump in `settle`, `Memory::forgotten` printed in `ephemeral_dump`, and roles via `role_of`. A test-only `Net::loop_dump` behind an env var would save the next chase. A new `OSIS_*` name must go in testenv-known.txt first, or the run panics.
- `SETTLE_ROUNDS` turns any wait-bound storm (relay delay, `SETTLE_MS`) into a "loop", because the clock stands still in a settle. Advancing the clock past `SETTLE_MS` when a loop is detected tells a storm from a true loop in one run.
