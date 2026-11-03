# Order purge seed 29340 fails on main
> Summary: `order::arrival_order_purge_large_spec_commits_5` fails at seed 29340 (offset 29300) on main at 765e91c6 and on seed-27243 alike: reverse arrival order gives an extra `t:reg.0` entry in a per-aspect count map (want has none). Not diagnosed.
> Tags: engine, retention, tests

Replay: `OSIS_ORDER_SHRINK=0 OSIS_ORDER_SEED=29340 OSIS_ORDER_LEN=60 cargo test --workspace --test it order::arrival_order_purge_large_spec_commits_5 -- --include-ignored` (17 s). Held 61 of 87 commits, order #0 (as made) vs #1 (reverse). The shrink ran over 25 min under load 30 without finishing; run unshrunk first. Its history has `Purge`, `Demote`, `Compact` and `Forged` steps.
