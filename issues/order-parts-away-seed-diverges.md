# held_set_decides_plain: a PartsAway history reads a removed register after the sync exchange
> Summary: `OSIS_ORDER_SEED=939670910565 OSIS_ORDER_LEN=60 cargo test -p osis-node --test it -- --ignored --exact order::held_set_decides_plain` fails on main (f71188d0f and later): with every commit held, order #1 (reverse), after the sync exchange a node reads a thing's `t:reg.0` as a string where the node keeping every body reads `None` (PartsAway emphasis: parts held away and parts left out as covered).
> Priority: normal
> Tags: tests, node, sync

Shrunk (`OSIS_ORDER_SHRINK=1`, 14 steps, 41 commits):
`Mixed { by: 0, t: 0, op: 18, k: 0, v: 4 }, Mixed { by: 0, t: 0, op: 18, k: 0, v: 9 }, Forged { by: 2, a: 2, b: 2, how: 1, op: 27, k: 2, v: 4 }, Aim(New { by: 0, parent: 7, write: true }), TwoEdges { by: 0, a: 1, b: 2, holder: 1, role: Write }, Aim(Nested { by: 0, other: 2, t: 2, k: 1, text: true, compact: true, also: true }), Aim(Signal { by: 1, t: 1, v: 7 }), Aim(Setting { by: 0, t: 0, op: 4, rule: 3 }), Aim(PurgeNamed { by: 2, t: 1, of: 1, back: 0, v: 5 }), Advance { who: Some(2), ms: 1982 }, RecordOnly { by: 1, under: None }, Aim(Nested { by: 2, other: 0, t: 5, k: 1, text: true, compact: true, also: true }), Forged { by: 0, a: 1, b: 0, how: 1, op: 27, k: 2, v: 4 }, Removals { by: 2, other: 1, v: 0 }`
with `Cfg { all_up_to: 4, random: 6, subsets: 4, split: 2, clock: 2, sync: true, model: true, away: true, .. }`; want `Ok(None)`, got `Ok(Some(Str("n")))`.
