# chat-typed
- osis-crdt `testutil::history(r, types, n, ..)` gives writer i `types[i % len]`: an `n` below `types.len()` silently writes only the first `n` types. `settled` passed 9 types with `n = 3`, so the register stop was never tested against text or list deltas (it was unsound there: bare anchors).
- No cheap way to see what a long aspect's state holds: I measured growth with `format!("{:?}", engine.state(..)).len()`; a records/bytes count on `Fragment` would make such tier-1 checks plain.
- (reviewer) sim-sweep has no per-seed timeout: a hanging `revoke_while_writing` seed stalled the per-branch sweep for 28 min with no output (it prints only at the end); found the seeds by running each under `timeout` (issues/sim-revoke-while-writing-hangs.md).
