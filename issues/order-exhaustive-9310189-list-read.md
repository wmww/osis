# Order exhaustive seed 9310189: a list element read after a dropped body is given again
> Summary: `order::arrival_order_exhaustive_large_spec_crdt_4_8` seed 9310189: in order #6 at an earlier clock, after the body dropped before a flip (afee1a36) is given again, a node reads `t:list.0` as `["v2"]` where the as-made order reads nothing. Fails on 02be71d2e too (before whole-2b). Not triaged.
> Tags: engine, retention, tests

Repro: `OSIS_ORDER_SEED=9310189 OSIS_ORDER_LEN=30 cargo test -p osis-node --test it -- --ignored --exact order::arrival_order_exhaustive_large_spec_crdt_4_8` (57 s). Found in periodic run 15 (exhaustive 9310000+200, 1 of 200).

Shrunk, for `check(9310189, &h, Cfg { all_up_to: 6, every_held: true, random: 0, subsets: 2, split: 18446744073709551615, clock: 24, par_orders: true, threads: 1, sync: true, settled: false })`:
`h = vec![Aim(Typed { by: 2, t: 0, op: 30, k: 1, v: 2 }), Sync { from: 2, to: 1 }, Advance { who: Some(0), ms: 1006 }, Forged { by: 2, a: 0, b: 0, how: 1, op: 20, k: 1, v: 3 }, Aim(Undo { by: 0, back: 0 }), Aim(Compact { by: 0, t: 0, op: 30 }), Aim(Compact { by: 0, t: 1, op: 30 }), Edge { by: 0, t: 0, holder: 1, role: None }]`

Failure: `held [0..8, 10, 11, 13, 14] of 15 commits (base 9): order #0 (as made) [.., 10, 11, 13, 14] vs order #6 at an earlier clock Clock { at: 11, early: WallMs(1700000000745) } [.., 13, 11, 10, 14]: after the bodies dropped before a flip ({afee1a36}) were given again: reads on t:list.0: want None, got Some(List([Str("v2")]))`. An undo over a forged write plus compactions and a role removal; possibly near issues/copies-outlive-purge-expiry.md (undo copies), but the symptom is a read, not "body X holds a value of Y".
