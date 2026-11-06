# Settled order seed 7032: a body dropped before its keep-at-most bound; its shrink runs for hours
> Summary: `order::arrival_order_settled_large_spec_commits_5` seed 7032 (in the OSIS_FULL range only) still fails on main in 3 s: at one order of the whole set a `t:docs.0` body is dropped before its keep-at-most bound with no superseder. The harness then shrinks a 150-commit settled history, which ran for over an hour and read as a hang. Not triaged.
> Tags: engine, retention, tests

- Replay unshrunk (5 s): `OSIS_ORDER_SEED=7032 OSIS_ORDER_LEN=60 OSIS_ORDER_SHRINK=0 cargo test -p osis-node --test it -- --include-ignored --exact order::arrival_order_settled_large_spec_commits_5`. `OSIS_ORDER_STATS=1` prints the history.
- Failure: held all 150 commits, order #3: "body dropped before its keep-at-most bound: (Content) t:docs.0, earliest superseder None".
- Pin with `check(7032, &h, Cfg { all_up_to: 0, every_held: false, random: 8, subsets: 4, split: 2, clock: 2, par_orders: false, threads: 1, sync: true, settled: true, model: false })`, `h` from the replay's output.
- Harness cost: `shrink` of a settled history (60 steps plus about 700 settle steps) has no time budget; a failing settled seed in a full run looks hung. Give it a budget or shrink only the 60 generated steps.
