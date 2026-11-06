# Settled harness seed 91703 loses a live write
> Summary: `order::arrival_order_settled_large_spec_commits_5` and `_settled_purges_large_` fail at seed 91703 (plain size, `OSIS_ORDER_START=91700`) on main as on body-keep: in order #1 (reversed) `later` finds a live write of `t:map.0` lost (the node keeping every body has it; this one did not get it back). Possible data loss; not studied.
> Tags: engine, retention, tests

Replay: `OSIS_ORDER_SEED=91703 cargo test -p osis-node --test it -- --ignored --exact order::arrival_order_settled_large_spec_commits_5` (about 1 s); `OSIS_ORDER_SHRINK=1` shrinks it. First re-run on current main. Related shape: issues/fallen-snapshot-at-its-writer.md (also `live_write_lost` under the settled harness).
