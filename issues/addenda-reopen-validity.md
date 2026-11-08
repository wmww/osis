# An addendum's validity differs between a reopened index and a rebuilt one
> Summary: `order::arrival_order_addenda_large_spec_permissions_5_2` fails at about one seed in three: after its writer, Carol, is demoted, re-granted and demoted again by Alice, a node's reopened index judges Carol's addendum (body not held) valid where a rebuild of the same index judges it invalid. Found once every addenda history writes an addendum; not root-caused.
> Priority: normal
> Tags: engine, tests

Replay: `OSIS_ORDER_START=14618693202 OSIS_ORDER_SEEDS=6 cargo test -p osis-node --test it -- --ignored --exact order::arrival_order_addenda_large_spec_permissions_5_2` (seeds 14618693203 and 14618693204 fail; `OSIS_ORDER_SEED=14618693204 OSIS_ORDER_LEN=60 OSIS_ORDER_SHRINK=1` shrinks).

Shrunk, for `check(14618693204, &h, Cfg { addenda: true, model: true, sync: true, ..LARGE })` (setup: Alice admin of G, Bob write, Carol admin; every thing index is G):

```
Write { by: 1, t: 0, op: 0, k: 0, v: 0 }, Sync { from: 1, to: 2 }, Advance { who: None, ms: 1000 },
Demote { by: 0, t: 0, holder: 1, at: 0, to_read: false }, Sync { from: 0, to: 2 },
Edge { by: 2, t: 0, holder: 1, role: Some(Write) },
Aim(Demote { by: 0, t: 6, holder: 2, at: 4, to_read: false }), Aim(Edge { by: 0, t: 2, holder: 2, role: Some(Admin) }),
Sync { from: 2, to: 0 }, Aim(Demote { by: 0, t: 2, holder: 2, at: 5, to_read: false })
```

Carol answers Alice's demotion of Bob with an addendum on G; Alice, not yet holding it, demotes Carol, grants her admin again, receives her commits and demotes her again. With every commit held, as made: the P4 check (`index_digest` after `reload` + `reexamine` against after `rebuild_index` + `reexamine`) shows Carol's addendum commit `valid: [true]` reopened and `[false]` rebuilt, its part missing (`missing: {0}`). One of the two incremental and from-scratch judgments of the least-fixpoint addenda rule (spec/permissions.md §5.2, Addenda: an addendum without its body still counts as its writer's write, listing nothing) is wrong. Start with which is right by the spec, then make the incremental path the same as the rebuild (a small tier-1 test from the steps above).
