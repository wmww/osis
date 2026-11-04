# A death the oracle dates is missing at a node (required retention, undo)
> Summary: order seed 5317004 (`arrival_order_alike_large`): a held Content body on `t:docs.0` has no death at one arrival order while the keep-every-body oracle dates one; fails on main's engine too, no absolute bound involved.
> Tags: engine, tests

Found reviewing abs-keep (the harness's new ops shifted the seed's history). Shrunk, no ops 30/31, fails with the final tick off too:

`check(5317004, &h, LARGE)` with `h = vec![Aim(Require { by: 2, t: 2, op: 9, rule: 1 }), Aim(Demote { by: 2, t: 4, holder: 2, at: 4, to_read: false }), Aim(Demote { by: 2, t: 6, holder: 1, at: 2, to_read: false }), Aim(Demote { by: 0, t: 3, holder: 2, at: 2, to_read: false }), Aim(Require { by: 2, t: 0, op: 28, rule: 0 }), Forged { by: 1, a: 6, b: 4, how: 0, op: 26, k: 2, v: 6 }, Aim(Nested { by: 1, other: 0, t: 5, k: 1, text: true, compact: true, also: false }), Aim(Undo { by: 0, back: 0 })]`

`dating`: "death dated early or missing: (Content) t:docs.0: here None, earliest superseders Some(..)". Full seed: `OSIS_ORDER_SEED=5317004 OSIS_ORDER_LEN=60 cargo test -p osis-node --test it -- --ignored --exact order::arrival_order_alike_large_spec_permissions_5_2`. Not traced.
