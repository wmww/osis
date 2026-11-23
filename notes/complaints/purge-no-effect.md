# purge-no-effect
- `cargo test -p osis-engine` while another cargo command waits on the target lock moves both past the Bash timeout; a single `--exact` engine it test takes minutes when its build queues behind another.
- The value-less meaning spans ~40 engine tests across shred/waits/order/resnapshot: one rule change touches many hand tests that each restate the old semantics; a property-first suite would have needed one change.
- The value-less meaning had grown a whole mechanism (cover once quiet, its timers, `Load::leftovers`, two tests) that only existed to carry value-less leftovers; finding it took following a failing compact test, not a grep of the follow-up issue.
- `cargo build` of osis-engine tests after a crdt edit takes about 4 minutes here; one engine `--exact` it test after a lib edit about 3: batch edits per build.
- The osis listing failures looked like a liveness-rule gap; the first cause was that `forgettable` forgets a commit kept only for purged parts at once, so the listing never runs. Only a probe test with `held_parts`/`header` showed it: no engine view says "forgotten" in a listing failure.
- The compact-seq rebase carried a value-less content template through eight files (seq, seq_span, seq_wire, walk, lifecycle); its own test exercised expiry, which the gone-write rule turns into "nothing held", so the cost test had to move to deleted elements.
