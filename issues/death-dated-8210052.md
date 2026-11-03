# A death dated where the oracle has none, seed 8210052
> Summary: `order::arrival_order_alike_large_spec_permissions_5_2` seed 8210052 fails as made: a held `t:reg.0` body has a death the oracle (every body kept) does not. Not analysed.
> Tags: engine, retention, tests

Replay: `OSIS_ORDER_SEED=8210052 OSIS_ORDER_LEN=60 cargo test --workspace --test it order::arrival_order_alike_large_spec_permissions_5_2 -- --include-ignored` (`OSIS_ORDER_SHRINK=0`: seconds). Held 38 of 59, as made: `death dated early or missing` on a `t:reg.0` delta, `here Some`, earliest superseders `None`. History with `Require`, `Breaking`, `Compact`, `Demote` and `Forged` steps, no purge. 1 of 60 from 8210000. Still fails after order-batch (which stated the 733028 shape as a limit, spec/commits.md §5).
