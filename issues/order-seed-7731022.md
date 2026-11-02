# Arrival-order seed 7731022 judges a history differently by order
> Summary: `arrival_order_alike_large` seed 7731022 fails on main aef0e279 and on keep-after-removal, so it is not from that branch; not investigated.
> Tags: tests, engine

Repro: `OSIS_ORDER_SEED=7731022 OSIS_ORDER_LEN=60 cargo test -p osis-node --test it order::arrival_order_alike_large_spec_permissions_5_2 -- --ignored --exact` (about 200 s: it shrinks). Found at `OSIS_ORDER_START=7731000`; also failed on main 6bfd4f0b, before seed-5288. The replay prints the shrunk history; it holds a `Forged` step.
