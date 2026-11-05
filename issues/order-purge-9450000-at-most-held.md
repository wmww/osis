# Purge oracle at offset 9450000: bodies held past a keep-at-most bound the model drops
> Summary: `arrival_order_purge_large_spec_commits_5` at `OSIS_ORDER_START=9450000` (plain size) fails seeds 9450000, 9450001, 9450004 on main (fa1866104) too: a node holds a body held-model gives `MustDrop(AtMost { .. })`. Not triaged.
> Tags: engine, retention, tests

Found by the purge-3001 branch's budget run; same failures with its fix reverted.
- 9450000: as made, `t:reg.0` body, `MustDrop(AtMost { carrier: false })`.
- 9450001, 9450004: order #0 at an earlier clock, `t:gone.0` body, `MustDrop(AtMost { carrier: true })`.
- 9460005 (purge-3001 review run, offset 9460000): the same shape as 9450001.

Replay: `OSIS_ORDER_SEED=<seed> OSIS_ORDER_LEN=60 OSIS_ORDER_SHRINK=0 cargo test -p osis-node --test it -- --include-ignored order::arrival_order_purge_large_spec_commits_5` (about 1-4 s each). First check whether the engine or the model is wrong (spec/commits.md §5 Keep bounds; held-model's keep-at-most fates are new in item 288, so either side may be wrong).
