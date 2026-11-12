# Requirements wording for expired writes a node missed
> Summary: spec/requirements.md (Convergence limits) says nodes can read differently "until a writer of that data next writes it or notices the difference"; for an expiring edit a node missed, the build converges once a writer holding its leftover has been quiet for `MAX_DRIFT` (or its cost trigger fires), not at the writer's next write. Proposed wording for Tess.
> Priority: low
> Tags: tess-call, retention, ephemeral

## What the build does
An expired write's body is deleted at hosts at T and its leftover uploads nowhere, so a node that missed the write (offline, restarted, or the author cut off until after T) gets the leftover's creations and resets only in a writer's snapshot. The trigger writes that snapshot once the bodies it would drop cost more than `FACTOR` times it, or once the aspect holds a leftover and has been quiet at the writer for `MAX_DRIFT` (spec/sync.md §7 Trigger, Cover once quiet; notes/engine-retention.md). Durable and ephemeral alike.

## The mismatch
"Next writes it" does not hold: one more write does not carry the leftover unless it sets off the cost trigger. "Notices the difference" holds only loosely (the writer acts on holding an uncovered leftover, not on seeing a difference).

## Proposed wording (Convergence limits, last sentence)
> Nodes can read differently until a writer of that data notices the difference, writes enough more of it, or has seen it unchanged for about an hour.

The hour is `MAX_DRIFT`, the window in which nodes already disagree about an expiry by their clocks.
