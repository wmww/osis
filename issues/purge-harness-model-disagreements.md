# Purge harness: held-model says never received for a held keep-at-least text body
> Summary: `order::arrival_order_purge_large_spec_commits_5` seed 3045 (as made) holds a `t:text.0` body under keep at least that held-model calls `NeverReceived`. Not triaged.
> Priority: normal
> Tags: engine, retention, tests

- Replay: `OSIS_ORDER_SEED=3045 OSIS_ORDER_LEN=60 cargo test -p osis-node --test it -- --include-ignored --exact order::arrival_order_purge_large_spec_commits_5` (5-15 s).
- Commit #4 (keep at least 30 min, an insert, a delete, an insert anchored on it) held; the model says never received: its writes value-less with no reason in the model, or stripped of a delta's values no longer held value-less. Compare the node's value-less list for the aspect with the model's.
- Not one of the engine-retention differences held.rs leaves unreported until the retention steps (`engine_retention`): those cover own state, not keep-at-least.
