# Settled order histories at seed 551505 read apart from the keep-everything node
> Summary: `order::arrival_order_settled_large_spec_commits_5` and `..._settled_purges_large_...` fail at seed 551505 (60 steps): after the settling compactions a fresh node reads a `t:list.0` as `None` where the node keeping every body reads `["v8"]` (the unshrunk settled run shows it as a `t:reg.0`, `"g"` against `"also"`). Both histories carry the same hostile two-thing commit. Not root-caused.
> Priority: normal
> Tags: engine, tests

Replay: `OSIS_ORDER_SEED=551505 OSIS_ORDER_LEN=60 cargo test -p osis-node --test it -- --ignored --exact order::arrival_order_settled_large_spec_commits_5` (and `..._settled_purges_large_...`; `OSIS_ORDER_SHRINK=1` shrinks).

Not caused by the signal harness: the settled history fails on main d16753369 (no signals there), and the purges history (which writes signals) fails the same way run by the signal branch's harness against d16753369's engine.

What the shrinks show: both shrunk histories keep `Forged { by: 2, a: 3, b: 4, how: 1, op: 14, k: 2, v: 8 }` (a hostile commit writing `t:list.0` = `["v8"]` on one thing and `t:book.0` on another, its author possibly without a chain to them), and both end in the same reading: fresh node `t:list.0` `None`, keep-everything node `["v8"]`, in an order with every commit held, "now, settled". Start there: is the forged commit valid at the keep-everything node, and what drops its `t:list.0` part at the fresh node after the compactions.

Shrinking is weak here: the arrival orders are drawn from the commit count, so dropping a step reshuffles every order and the one-pass shrinker keeps 23 to 40 steps plus the settled tail. A hand-built reproducer (the forged commit, a writer's compaction of `t:list.0`, two arrival orders) is the next step.
