# The engine applies an edge write held-model does not
> Summary: osis-engine `order::held_set_decides_plain` fails at a rate: held-model reads a role commit's `roles.0` write as not applied where the node applies it ("applied: model false, node true"). Seeds 300644506442 (Settings), 610442177300 (Lists), 777000000046 (Settled) at `OSIS_ORDER_LEN=60`; 1 failing of 100 seeds over two ranges of 50. Shrunk to 5 steps; cause not read.
> Priority: normal
> Tags: engine, perm, tests

Every failing seed states the same: `held-model differs: commit … applied: model false, node true; parts ["<thing> roles.0 mint admin Some(<admin>)"]`, of a role commit.

Replay: `OSIS_ORDER_SEED=300644506442 OSIS_ORDER_LEN=60 cargo test -p osis-engine --test it -- --ignored --exact order::held_set_decides_plain` under `tools/heavy` (one seed is about 90 to 120 CPU-s: over the short lane); `OSIS_ORDER_SHRINK=1` shrinks it.

Seed 300644506442 shrunk (5 steps; the commit judged differently is #35 of the 48 base commits, a setup role commit, with all 55 commits held, order #0, at `now`):

```
let h = vec![Demote { by: 0, t: 0, holder: 2, at: 0, to_read: false }, Aim(Box::new(New { by: 0, parent: 6, write: false })), NewTop { by: 2 }, Aim(Box::new(GrantFlow { by: 2, t: 5, holder: 3, role: Role::Admin })), Forged { by: 2, a: 5, b: 5, how: 2, op: 11, k: 2, v: 3 }];
```

Rate: `OSIS_ORDER_START=1000000 OSIS_ORDER_SEEDS=50` passes; `OSIS_ORDER_START=777000000000 OSIS_ORDER_SEEDS=50` fails at seed 777000000046 alone.

Not the snapshot-carries class (content judged by a list naming a snapshot, notes/perm-paths.md, Snapshot carries): this is the walk's edge-class status against the model's. To do: read which of the two is right for the shrunk script (the forged commit by 2 on thing 5 beside 2's grant to 3), then a hand test.

Seed 421200482733 (PartsAway) fails on main too (466eb5afb); not yet read whether it states the same.

Seed 278997924631 (Addenda) fails on main (5fa1ed684) with the same model-false/node-true shape of a content commit minting a thing (`holds.0`, `created.0`, `t:reg.0` parts), not a role commit's `roles.0`; not yet read whether it shares the cause.

Also seed 410914575349 (PartsAway), failing on a main binary.
