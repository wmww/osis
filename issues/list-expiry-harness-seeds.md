# Two failures the expiring list oracle finds at the base
> Summary: `order::arrival_order_list_expiry_large_spec_crdt_4_7` fails at the merge base too on two seeds, neither about marks. Seed 7520036: past T a body still holds a value of an expired delta (`value_past_end`: Content, `expired true`), which may be a value kept past its expiry, so look at it first. Seed 7520035: a list delete by a writer later demoted, then a compaction, reads `None` in one arrival order and `[]` in another.
> Tags: security, crdt, engine, tests

Repro: `OSIS_ORDER_SEED=<seed> OSIS_ORDER_LEN=40 cargo test -p osis-node --test it -- --ignored --exact order::arrival_order_list_expiry_large_spec_crdt_4_7`. Checked against the base by overlaying its `core/crdt`, `core/engine` and `core/test/crdt-model` under this test file. Not investigated further.

Also seen at the base, unrelated: sim `purge_falls` and `purge_falls_churn` seed 7410503, "the purge never reached the writer".
