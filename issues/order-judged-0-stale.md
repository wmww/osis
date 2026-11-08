# Order oracles' "a per-node check judged nothing" fails every full-size run
> Summary: `Seen::check` in core/node/tests/it/order.rs asserts `judged[0] > 0` for the timed harnesses (alike, exhaustive) at 20 seeds or more, but nothing increments `judged[0]` any more (retention-2 removed its one counter), so `arrival_order_alike_large_spec_permissions_5_2` and `arrival_order_exhaustive_large_spec_crdt_4_8` fail at `OSIS_FULL=1` or any explicit range of 20+ seeds even with 0 failing seeds. Per-branch runs (6 and 4 seeds) skip the check, so it hid. The full-size runs are blind until fixed.
> Priority: normal
> Tags: tests, node

Seen in the periodic run on main e3cdd005f (the assertion is unchanged on 8f3cd8d05): alike 300 seeds from 28648832432 (26000 orders, 0 failing) and exhaustive 200 seeds from 31520452698 (156012 orders, 0 failing) both panic at order.rs:2373 with `judged: [0, ...]`.
Replay: `OSIS_ORDER_START=28648832432 OSIS_ORDER_SEEDS=20 cargo test -p osis-node --test it -- --ignored --exact order::arrival_order_alike_large_spec_permissions_5_2`.
Fix: drop index 0 from `judged` and the assertion (or count what check replaced it), so the coverage assertion checks only counters something increments; then rerun both at full size with fresh offsets.
