# Order alike seed 52040 fails on main
> Summary: `order::arrival_order_alike_large` seed 52040 (len 60) fails on main under relative keep bounds: "body dropped before its keep-at-most bound" on `t:gonemap.0`, no purge. 52018 and `arrival_order_purge_large` 900000 pass now. Not diagnosed.
> Tags: engine, tests

Replay: `OSIS_ORDER_SEED=52040 OSIS_ORDER_LEN=60 cargo test -p osis-node --test it order::arrival_order_alike_large_spec_permissions_5_2 -- --ignored --exact`. The shrink takes about 16 min and stays long (about 45 steps); the failing order is the held set reversed: `body dropped before its keep-at-most bound: CommitId(ecf37ba4808c4100..) (Content) t:gonemap.0: here None, earliest superseders None`.
