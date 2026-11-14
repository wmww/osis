# The node applies a forged two-thing edge commit held-model rejects
> Summary: `order::held_set_decides_plain` at `OSIS_ORDER_START=5019` (RecordOnly seed): a `Forged { how: 2 }` role commit (G's first admin setting another peer's edge on two record-only-linked things, the second's first admin being the first) is applied by the node in the as-made order and rejected by held-model (`applied: model false, node true; parts [... roles.0 ...]`). Fails on main with the explicit history too. If the node is the wrong side this is a permission bypass: raise to critical.
> Priority: normal
> Tags: security, tests, node, permissions

## Reproducer
Shrunk (seed 5019, the plain `Cfg` as the replay line prints, `away: false`):
`vec![RecordOnly { by: 0, under: None }, RecordOnly { by: 2, under: None }, Aim(RemoveFlow { by: 2, t: 2, holder: 3, lower: false }), Sync { from: 2, to: 0 }, Aim(New { by: 2, parent: 5, write: false }), Forged { by: 0, a: 6, b: 7, how: 2, op: 19, k: 1, v: 5 }]`
Fails on the whole held set, order #0, before the sync exchange: commit #8.

## Direction
Decide from spec/permissions.md (§1 first admin, §5 role commits on several things) whether the author held admin on both things at the commit, fix the wrong side, and add the shrunk history as a hand-written test.
