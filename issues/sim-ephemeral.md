# Sim: no scenario covers synced ephemeral data
> Summary: The network simulator's scenarios and convergence checks look at durable state only; synced ephemeral data (ephemeral commits, the node-sync lane, server in-memory entries, relay-only signals) runs in no sim scenario. Add one with ephemeral writes under faults and an ephemeral-state comparison among holders.
> Tags: tests, sim, node

- What exists: osis-node `tests/it/ephemeral.rs` `random_window_converges_*` (four writers, two servers, random writes, partitions, node and server restarts, a small server cap on odd seeds; tier 1 four seeds, tier 2 `random_window_converges_large` with `OSIS_EPH_START`/`OSIS_EPH_SEEDS`). It runs on the tier-1 `Net` harness: no lossy links, clock skew, crashes mid-write or rogue servers.
- Wanted: a sim scenario (core/test/sim/src/net/scenarios.rs) with ephemeral writes in the workload, and a check (net/check.rs) that every node holding an ephemeral thing reads the same ephemeral state after the heal; signals counted at most once per connected device.
- Not cheap: the checker's state digest and the workload are durable-only today, so both need an ephemeral side.
