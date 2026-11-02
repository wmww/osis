# Three order seeds fail on main
> Summary: `order::arrival_order_alike_large` fails at seeds 52018 and 52040 on main before the purge re-judge too, and `order::arrival_order_purge_large` at 900000, all under relative keep bounds: 52018 a part given again stays missing at one order, 52040 "body dropped before its keep-at-most bound" on `t:gonemap.0`. No purge in `history`. Not diagnosed.
> Tags: engine, tests

Replay: `OSIS_ORDER_SEED=52018 OSIS_ORDER_LEN=60 cargo test --workspace --test it order::arrival_order_alike_large -- --include-ignored`. Offsets 41000 and the default pass.

Same family: `order::arrival_order_purge_large` seed 900000 on main's engine with this history (`tools/bin-at origin/main OUT --take core/node/tests/it/order.rs`): "death dated early or missing" on `t:docs.0`, keep at most 0, no purge request on the aspect: the node dates a death the keep-all oracle does not. Replay: `OSIS_ORDER_SHRINK=0 OSIS_ORDER_SEED=900000 OSIS_ORDER_LEN=60 cargo test --workspace --test it order::arrival_order_purge_large -- --include-ignored`. The shrink takes 8 minutes and stays at 75 commits.
