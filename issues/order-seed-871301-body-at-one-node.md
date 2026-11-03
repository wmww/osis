# Arrival order: a body known at one node only at seed 871301
> Summary: `arrival_order_alike` seed 871301 fails on main too (seen at 87ef7039): with late parts, one arrival order leaves a `t:docs.0` body known at one node only.
> Tags: tests, engine

Repro: `OSIS_ORDER_SEED=871301 OSIS_ORDER_LEN=60 cargo test --workspace --test it order::arrival_order_alike_large_spec_permissions_5_2 -- --include-ignored` (about 150 s, mostly shrinking).

`order #0 (as made, want) vs order #1 with late parts (got) [reversed]: body Some((.., "t:docs.0")) known at one node only`. The history has forged commits among rosters and nested writes. Not looked into further.
