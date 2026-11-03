# Order seed 112134: a bounded app aspect's entry differs by arrival order
> Summary: `arrival_order_alike` seed 112134 fails on main too (seen at 3435984b): arrival in reverse order leaves an extra `bounded_held` row for a typed app aspect that the made order does not.
> Tags: engine, tests

Repro: `OSIS_ORDER_SEED=112134 OSIS_ORDER_LEN=60 cargo test --workspace --test it order::arrival_order_alike_large_spec_permissions_5_2 -- --include-ignored`. Shrunk: `vec![Aim(Require { by: 0, t: 2, op: 18, rule: 3 }), Aim(Leave { by: 2, t: 5 }), Aim(Typed { by: 2, t: 2, op: 12, k: 0, v: 1 }), Aim(Require { by: 0, t: 0, op: 17, rule: 1 }), Aim(Breaking { by: 2, t: 0, op: 12, v: 2, fits: false }), Advance { who: None, ms: 3907653 }]`; the reverse order holds an extra `t:brief.0` count in `bounded_held` on one thing.
