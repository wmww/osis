# A death dated early or missing at one arrival order, seed 733028
> Summary: `order::arrival_order_alike_large_spec_permissions_5_2` fails at seed 733028 on main (2964db75): a held body's first death is missing at one order. Not analysed.
> Tags: engine, retention, tests

Replay: `OSIS_ORDER_SEED=733028 OSIS_ORDER_LEN=60 cargo test --workspace --test it order::arrival_order_alike_large_spec_permissions_5_2 -- --include-ignored` (about 90 s). Held 15 of 23 commits, order #2: `death dated early or missing` on a `t:docs.0` delta, `here None`, earliest superseders present. Same text on main and on keep-in-removal, so not that branch's. Its history has `Undo`, `Breaking` and `Require` steps. 1 of 60 from 733000.

Also seed 8210052 (same oracle, same text, on main 765e91c6 and on simplify-retention): `t:reg.0`, `here Some`, earliest superseders `None`, history with `Require`, `Breaking`, `Compact`, `Demote` and `Forged` steps, no purge. 1 of 60 from 8210000. Replay as above with `OSIS_ORDER_SEED=8210052` (about 80 s).
