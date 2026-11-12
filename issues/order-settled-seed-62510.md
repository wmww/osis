# A settled node reads an older value than the keep-everything node (plain seed 62510)
> Summary: `order::held_set_decides_plain` seed 62510 (Settled emphasis) fails on main: a node given the history newest first, then the settling compactions, reads `t:reg.0` of thing 0 as "g" where the node keeping every body reads "v5" (unshrunk: `t:text.0`, "x" vs "xx"). Not a held-model difference: the order oracle's settled check. Listed in tools/known_failures.txt.
> Priority: normal
> Tags: tests, node, retention

## Repro
`OSIS_ORDER_SEED=62510 OSIS_ORDER_LEN=60 tools/heavy cargo test -p osis-node --test it -- --ignored --exact order::held_set_decides_plain` (4 s). `OSIS_ORDER_SHRINK=1` (5 min) shrinks it to `settled(h)` with

```
h = vec![NewTop { by: 2 }, Aim(Undo { by: 0, back: 0 }), Aim(New { by: 0, parent: 3, write: false }), Aim(RemoveFlow { by: 2, t: 2, holder: 0, lower: false }), Aim(PurgeSet { by: 2, t: 0, op: 11, v: 5, fits: true }), Aim(Demote { by: 0, t: 2, holder: 2, at: 2, to_read: false }), Aim(Demote { by: 0, t: 6, holder: 2, at: 0, to_read: true })]
```

Cfg `{ all_up_to: 4, every_held: false, random: 6, subsets: 4, split: First(2), clock: 2, sync: true, late: false, settled: true, model: true, addenda: false, away: false }`, order #1: the history's commits newest first, then the settling tail as made.

## Direction
Decide first whether the engine or the harness is wrong: 2 writes `v5` and 2's roles are then disputed (2 removes 0 on thing 2; 0 lowers 2 there and on thing 6). Candidates: a write dropped as invalid by the reversed order (2's lowering before its write) that no settling compaction carries back, which the settled check should spare as `settled_check_spares_aspects_no_writer_compacted_spec_commits_5` does when no writer is left; or a live body dropped under a cover that later counted for nothing (spec/commits.md §5 Covered, Limit), which would also be a spare, not a bug. Then a hand-written reproducer and the fix.
