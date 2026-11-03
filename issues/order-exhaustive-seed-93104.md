# Exhaustive order seed 93104: a `t:docs.0` death missing in one order
> Summary: `OSIS_ORDER_SEED=93104 OSIS_ORDER_LEN=30 cargo test --workspace --test it order::arrival_order_exhaustive_large_spec_crdt_4_8 -- --include-ignored` (shrunk: a typed docs op by 0, its undo, a demotion of 1 on that thing, a typed docs op by 1) fails on main (checked at 17bb3b05 with `tools/bin-at`): in order [0..8, 14, 13, 12, 11, 10, 9] a content commit's `t:docs.0` write has no death at the node though its earliest superseder is at ts 6. Found by the repeated-key branch's oracle run at 93100; unrelated to that change (same failure on the base).
> Tags: tests, engine, order

Shrunk history: `Aim(Typed { by: 0, t: 1, op: 26, k: 0, v: 7 }), Aim(Undo { by: 0, back: 1 }), Aim(Demote { by: 0, t: 1, holder: 1, at: 3, to_read: false }), Aim(Typed { by: 1, t: 0, op: 26, k: 0, v: 6 })` with `Cfg { all_up_to: 6, every_held: true, random: 0, subsets: 2, split: usize::MAX, par_orders: true, threads: 1, sync: true }`.
