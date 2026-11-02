# Two arrival_order_alike seeds fail on main
> Summary: `order::arrival_order_alike_large` fails at seeds 52018 and 52040 on main before the purge re-judge too, both under relative keep bounds: 52018 a part given again stays missing at one order, 52040 "body dropped before its keep-at-most bound" on `t:gonemap.0`. No purge in `history`. Not diagnosed.
> Tags: engine, tests

Replay: `OSIS_ORDER_SEED=52018 OSIS_ORDER_LEN=60 cargo test --workspace --test it order::arrival_order_alike_large -- --include-ignored`. Offsets 41000 and the default pass.
