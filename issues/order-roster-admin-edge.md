# The order harness judges a roster differently after a sync exchange
> Summary: osis-engine `order::held_set_decides_plain` fails on some seeds (seed 153359937795, length 60): "histories judged differently by what was held … after the sync exchange", expecting an empty roster but finding an Admin edge. Fails alike on main's binary (seen at the review of lost-content-2). Cause not read.
> Priority: normal
> Tags: engine, tests

Replay: `OSIS_ORDER_SEED=153359937795 OSIS_ORDER_LEN=60 cargo test -p osis-engine --test it -- --ignored --exact order::held_set_decides_plain` (`OSIS_ORDER_SHRINK=1` shrinks it). First shrink it and read which commit's verdict differs between the held sets (a role write's validity reading differently by arrival order: the held-set property, notes/test-properties.md).

Also seed 915130969958 (length 60): "settled: shows other than the node keeping every body" on a roster; fails alike on main's binary (70776140d), seen at the test-cost-3 gate. Possibly the same class: shrink both with `OSIS_SHRINK_MATCH`.
