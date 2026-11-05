# Order purge seed 9500003: a purged snapshot body held against held-model
> Summary: `order::arrival_order_purge_large_spec_commits_5` seed 9500003: the node keeps the body of a compaction snapshot a purge request names, held-model says `MustDrop(PurgedSnapshot)`; fails with the leftovers branch's engine changes reverted too. Not diagnosed: engine or model.
> Tags: engine, retention, tests

Repro: `OSIS_ORDER_SEED=9500003 OSIS_ORDER_LEN=60 cargo test -p osis-node --test it order::arrival_order_purge_large_spec_commits_5 -- --ignored --exact` (under a second unshrunk). Found by the leftovers review at offset 9500000.

Shrunk, for `check(9500003, &h, Cfg { all_up_to: 0, every_held: false, random: 8, subsets: 4, split: 2, clock: 2, par_orders: false, threads: 1, sync: true, settled: false, model: true })`:
`h = vec![Aim(Leave { by: 1, t: 3 }), Aim(Compact { by: 1, t: 3, op: 0 }), Advance { who: Some(0), ms: 1571 }, Aim(Purge { by: 0, t: 4, of: 1, back: 1, v: 0 })]`

Failure: held all 12 commits (base 9), as made: `held-model differs: commit d7a9b601.. (#10) on t:reg.0: the node holds its body, the model's fate is MustDrop(PurgedSnapshot)`. A writer leaves, then compacts (its snapshot likely invalid after the leave), then the owner purges it. Question: does a purge request drop a named snapshot that is invalid here (spec/commits.md §5 Purge: "A snapshot a request names itself has no values of its own: its body is dropped"), and whose right is judged by its own retention.
