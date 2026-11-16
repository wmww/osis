# fathom-timed-refusal
- A three-node `World` test with a partitioned peer passes `RULE_CAP` (2000 deliveries) from dial ticks alone; the storm message says so, but the cap is per world, not per node (`history::world` scales it by n, a hand-built world does not).
- A "stale refusal by a peer judging the node departed" is hard to stage: before a rotation covering the departure the departed node still opens S by the shared read secret (a Hit), so no ByRole is refused.
