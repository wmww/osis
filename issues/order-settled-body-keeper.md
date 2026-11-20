# order: once settled a node shows other than the node keeping every body (t:docs.0)
> Summary: osis-engine `order::held_set_decides_plain` at seed 96748645654 (Settled, OSIS_ORDER_LEN=60) fails "now, settled: shows other than the node keeping every body" on a `t:docs.0` value, every commit held, order #5. Fails on main's binary.
> Priority: normal
> Tags: engine, tests

Replay: `OSIS_ORDER_SEED=96748645654 OSIS_ORDER_LEN=60 cargo test -p osis-engine --test it -- --ignored --exact order::held_set_decides_plain` (fails within 10 s; shrink with `OSIS_ORDER_SHRINK=1` and `OSIS_SHRINK_MATCH` set to the failure text).

Next: shrink it, then find which body-keeping or listing rule lets the read differ.
