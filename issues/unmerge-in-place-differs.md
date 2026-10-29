# In-place un-merge differs from a rebuild on nested map writes
> Summary: order alike seeds 12060, 12161, 12209, 12236 (range 12000+300) hit the debug assertion in `atomic::unmerge_fell` ("in-place un-merge ... differs from a rebuild") on `/t/map`; reproduces on main b38e3ecd, not caused by the retention-spec branch.
> Tags: node, crdt, tests

Shrunk (call `check(seed, &h, LARGE)` from a scratch test in order.rs):
- 12161: `vec![Nested { by: 1, other: 2, t: 0, k: 2, text: false, compact: true, also: true }, Sync { from: 2, to: 0 }, Write { by: 0, t: 1, op: 22, k: 2, v: 1 }, Compact { by: 0, t: 1, op: 25 }, Edge { by: 0, t: 3, member: 2, role: Some(Role::Read) }, New { by: 0, parent: 5, write: false }, New { by: 0, parent: 6, write: true }]`
- 12236: `vec![Edge { by: 0, t: 5, member: 1, role: Some(Role::Write) }, Nested { by: 0, other: 2, t: 2, k: 1, text: false, compact: true, also: true }, Edge { by: 0, t: 1, member: 2, role: None }, Write { by: 1, t: 5, op: 6, k: 1, v: 4 }, Edge { by: 2, t: 3, member: 1, role: Some(Role::Write) }, Write { by: 1, t: 4, op: 16, k: 0, v: 7 }, Nested { by: 1, other: 0, t: 0, k: 1, text: false, compact: true, also: true }]`

Both: another writer's write nested in an entry (`Nested`), compacted, then a role change; likely the in-place path (`holds_dots` / `remove_dots`) misses writes nested under a stripped creation that `rebuilt` drops, or the reverse. 12060 and 12209 not shrunk further (long histories; rerun with `OSIS_ORDER_SEED`).
