# Seed reproducers take hand work the harnesses could do
> Summary: The order harness's `OSIS_ORDER_SHRINK=1` stops before a fixpoint and its dump omits a pack's purge items; the ephemeral and node random tests log no advance amounts, so their step logs do not replay as a script. Each cost a seed chase hours of hand shrinking.
> Priority: low
> Tags: tests, node

- **Order shrink** (core/node/tests/it/order.rs `shrink`): one pass drops each step once. A removal redraws the seed's shuffles and subsets, so a step that mattered only to one order looks needed: seed 86543989744 stopped at 27 of 60 steps; repeating the pass until nothing drops reached 9. Repeat the pass to a fixpoint.
- **Order dump** (`OSIS_ORDER_DUMP=1`): no line for a pack header's `purge` list, which is what showed which request named which commit for 86543989744.
- **Random step logs** (osis-node ephemeral and sync random tests): the logged steps leave out each clock advance's amount, so a failing run cannot be replayed as a script. With the amounts, a greedy step-dropping script shrank an ephemeral never-quiet seed to an 11-write reproducer in minutes, after hours of hand-built worlds.
