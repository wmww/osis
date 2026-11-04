# Two failures the expiring list oracle finds at the base
> Summary: `order::arrival_order_list_expiry_large_spec_crdt_4_7` fails at the merge base too on two seeds, neither about marks. Seed 7520036: past T a body still holds a value of an expired delta (`value_past_end`: Content, `expired true`), which may be a value kept past its expiry, so look at it first. Seed 7520035: a list delete by a writer later demoted, then a compaction, reads `None` in one arrival order and `[]` in another.
> Tags: security, crdt, engine, tests

Repro: `OSIS_ORDER_SEED=<seed> OSIS_ORDER_LEN=40 cargo test -p osis-node --test it -- --ignored --exact order::arrival_order_list_expiry_large_spec_crdt_4_7`. Checked against the base by overlaying its `core/crdt`, `core/engine` and `core/test/crdt-model` under this test file. Not investigated further.

Also seen at the base, unrelated: sim `purge_falls` and `purge_falls_churn` seed 7410503, "the purge never reached the writer".

Also at the base (offset 9200000, plain run: 3 of 40 seeds): 9200001, 9200020 and 9200037 fail the debug rebuild check (item 271): `t:listtext.0`'s state differs from a rebuild from held bodies (`apply/atomic.rs` `check_rebuilt`). Possibly drop-rejoin-robust's ground (leftover bodies).

Offset 9220000 (plain run, 40 seeds): 7 fail alike at main and on removed-keys, all the same rebuild check on `t:listtext.0`: 9220006, 9220011, 9220018, 9220021, 9220029, 9220035, 9220036. So about 1 seed in 6-10 fails at main: this oracle is not usable per branch until fixed.
