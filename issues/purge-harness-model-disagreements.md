# Purge harness: a held keep-at-least text body read where held-model calls it never received
> Summary: `order::arrival_order_purge_large_spec_commits_5` seed 3045 (order #0 at an earlier clock, after 79 ingests) reads `t:text.0` as "3x" where held-model reads "x": the node holds a keep-at-least text body the model calls `NeverReceived`; `arrival_order_exhaustive_large_spec_crdt_4_8` seed 704323 (as made) reads "v75" against the model's "v5". Not triaged.
> Priority: normal
> Tags: engine, retention, tests

- Replay: `OSIS_ORDER_SEED=3045 OSIS_ORDER_LEN=60 cargo test -p osis-node --test it -- --include-ignored --exact order::arrival_order_purge_large_spec_commits_5` (5-15 s).
- Commit #4 (keep at least 30 min, an insert, a delete, an insert anchored on it) held; the model says never received: its writes value-less with no reason in the model, or stripped of a delta's values no longer held value-less. Compare the node's value-less list for the aspect with the model's.
- Also `OSIS_ORDER_SEED=704323 OSIS_ORDER_LEN=30 ... order::arrival_order_exhaustive_large_spec_crdt_4_8` (commit #9 of 15, as made).
