# Arrival-order divergence: demotions around a compacted nested write
> Summary: `order::arrival_order_alike_large_spec_permissions_5_2` fails at seed 15085 (periodic run, range 15000+300): two demotions of member 1 plus a compacted Nested write by 2 give order-dependent results. Shrunk history below.
> Tags: tests, engine, permissions

Replay: `OSIS_ORDER_SEED=15085 OSIS_ORDER_LEN=60 cargo test --workspace --test it order::arrival_order_alike_large_spec_permissions_5_2 -- --include-ignored`.

Shrunk: `check(15085, &h, Cfg { all_up_to: 0, every_held: false, random: 8, subsets: 4, split: 2, par_orders: false, threads: 1 })` with
`h = vec![Nested { by: 2, other: 0, t: 5, k: 2, text: false, compact: false, also: false }, Write { by: 0, t: 6, op: 3, k: 2, v: 9 }, Nested { by: 2, other: 0, t: 0, k: 2, text: false, compact: true, also: true }, Write { by: 1, t: 2, op: 0, k: 1, v: 0 }, Write { by: 1, t: 6, op: 16, k: 1, v: 2 }, Edge { by: 0, t: 2, member: 1, role: Some(Write) }, Edge { by: 0, t: 7, member: 1, role: Some(Write) }, Demote { by: 0, t: 4, member: 1, at: 1, to_read: true }, Edge { by: 0, t: 4, member: 2, role: Some(Write) }, Demote { by: 0, t: 6, member: 1, at: 5, to_read: true }]`

Possibly from snapshot-vouch (option A: a valid snapshot vouches for its carried writes).
