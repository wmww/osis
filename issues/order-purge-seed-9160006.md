# Purge order seed 9160006: a map entry read at one order only
> Summary: `order::arrival_order_purge_large_spec_commits_5` seed 9160006 fails on main (branch point 77de19d3) and after remove-moves alike: holding all but three commits first, then those, a node reads `t:map.0` without key `k0` that the as-made order shows. Not triaged.
> Tags: engine, retention, tests

Found by the remove-moves review at a fresh offset (`OSIS_ORDER_START=9160000 OSIS_ORDER_SEEDS=60`). Shrunk (pin with `check(9160006, &h, Cfg { sync: true, ..LARGE })`, fails in 2 s):

```
h = vec![aim(Breaking { by: 2, t: 0, op: 3, v: 3, fits: false }), aim(Typed { by: 2, t: 1, op: 29, k: 2, v: 6 }), aim(Nested { by: 2, other: 1, t: 6, k: 2, text: false, compact: false, also: false }), aim(Compact { by: 1, t: 0, op: 0 }), aim(Purge { by: 1, t: 2, of: 0, back: 2, v: 2 }), aim(Typed { by: 1, t: 5, op: 30, k: 2, v: 6 }), aim(Purge { by: 1, t: 6, of: 1, back: 2, v: 4 }), aim(New { by: 0, parent: 5, write: false }), aim(New { by: 0, parent: 7, write: false }), aim(Demote { by: 0, t: 4, holder: 1, at: 3, to_read: false })]
```

Failing order: held `[0..=8, 12..=19]` of 20 commits (base 9), then the rest (`9, 10, 11`), against the whole set as made: reads on `t:map.0` want `{k0: {0: "v3", 1: 3}, k2: {0: "v1", 1: 1}}`, got `{k2: ...}` only. The full seed takes about 8 minutes (its shrink).

Still fails after drop-rejoin items 1+2 (leftover-bodies): same order, same missing `k0`.
