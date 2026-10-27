# Deaths replay costs the aspect's history per late delta
> Summary: On an aspect with a relative keep bound (every `/members`, any keep-at-least or keep-at-most content aspect), a batch holding a delta out of `(ts, ID)` order, a snapshot or a validity flip re-joins every held body and the whole state once (`retention::settle_due`; batched per node-sync step by `Engine::defer_deaths`): O(aspect history) per such batch, against spec/requirements.md Scale.
> Tags: node, retention, performance

Batched (one replay per marked aspect per transaction, or per node-sync step): a sync step of many late deltas costs one replay, so an out-of-order `/members` history is no longer O(n²). Left: each sync pass with a late delta on a bounded aspect pays one replay.

Measured (`cargo test --release --workspace --test it scale::late_delta_deaths_cost -- --ignored --nocapture`, `OSIS_SCALE_N` sets N; a set of N one-element commits, late deltas by another writer older than all of them): N = 3000: unbounded 2-3 ms per late delta, keep-at-least 115-165 ms each, 123-173 ms for 5 in one batch. N = 10^4: unbounded 2-6 ms, keep-at-least 380 ms each and for the batch; of that, reading and decrypting the held bodies 285 ms (about 29 µs each), joins 16 ms, the state 8 ms. Concurrent writers make about half the received deltas late, so a bounded aspect of 10^4 held commits costs about 0.4 s per sync pass that brings a late change.

Before: only keep-at-most aspects paid, joining the delta with the bodies under a pending keep-at-most timer (few) plus a scan of every timer record.

Fix direction: skip reading bodies a late delta cannot change: a body whose last death is at or before the late delta's `ts` is final, but the replay still needs the state as of that position to judge later bodies (per-write deaths would give it; issues/deaths-dropped-superseder.md has the same root). Or keep decoded bodies of bounded aspects cached between passes (memory: the aspect's history).
