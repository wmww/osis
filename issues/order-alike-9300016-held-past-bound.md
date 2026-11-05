# Order alike seed 9300016: a body held past its bound in one order
> Summary: `order::arrival_order_alike_large_spec_permissions_5_2` seed 9300016: in order #8 a node still holds Content body bcd95e06 of `t:map.0` two hours later, past its bound (`bounded_held` per-node check), deaths dated at one ts. Fails on 02be71d2e too (before whole-2b). Not triaged.
> Tags: engine, retention, tests

Repro: `OSIS_ORDER_SEED=9300016 OSIS_ORDER_LEN=60 cargo test -p osis-node --test it -- --ignored --exact order::arrival_order_alike_large_spec_permissions_5_2` (130 s). Found in periodic run 15 (alike 9300000+300).

Shrunk, for `check(9300016, &h, Cfg { all_up_to: 0, every_held: false, random: 8, subsets: 4, split: 2, clock: 2, par_orders: false, threads: 1, sync: true, settled: false })`:
`h = vec![Aim(Leave { by: 1, t: 2 }), Aim(Roster { by: 0, t: 2 }), Forged { by: 0, a: 3, b: 0, how: 4, op: 25, k: 2, v: 1 }, Aim(NestedItem { by: 2, other: 0, t: 2, k: 0, compact: true, also: false }), Forged { by: 2, a: 1, b: 4, how: 1, op: 11, k: 0, v: 4 }, Aim(Write { by: 2, t: 0, op: 27, k: 2, v: 0 }), Aim(Roster { by: 0, t: 5 }), Aim(Require { by: 2, t: 0, op: 31, rule: 3 }), Aim(Breaking { by: 0, t: 1, op: 8, v: 9, fits: false }), Aim(New { by: 0, parent: 4, write: true }), Aim(Require { by: 0, t: 2, op: 15, rule: 3 }), Aim(NestedItem { by: 1, other: 0, t: 4, k: 2, compact: true, also: true }), Aim(Require { by: 2, t: 2, op: 19, rule: 3 })]`

Failure: `held [0..=25] of 26 commits (base 9), order #8 [14, 10, 20, 13, 22, 23, 18, 0, 25, 2, 6, 21, 17, 9, 1, 19, 24, 11, 15, 4, 7, 16, 8, 3, 12, 5], later: body held past its bound: CommitId(bcd95e06f8092e0a..) (Content) Tid(..) t:map.0, deaths Some((Ts(111411200000196608), Ts(111411200000196608)))`.
