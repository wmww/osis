# Undo leaves a dead keep-at-most-0 body held
> Summary: order exhaustive seed 64197 (fresh range 64000+200; fails on main too): two writes into a keep-at-most-0 map and two undos by one node leave a body whose write is dead held instead of dropped in the killing transaction (spec/commits.md §5: at most 0 is prompt). Found by the snapshot-vouch oracle run.
> Tags: retention, engine, tests

Repro: `OSIS_ORDER_SEED=64197 cargo test -p osis-node --test it -- --ignored order::arrival_order_exhaustive_large_spec_crdt_4_8`. Shrunk: `vec![Write { by: 0, t: 1, op: 19, k: 0, v: 3 }, Write { by: 0, t: 1, op: 19, k: 1, v: 6 }, Undo { by: 0, back: 0 }, Undo { by: 0, back: 2 }]`; as made, all 13 commits held: "dead body kept under keep at most 0" on a `/t/gonemap` body, here and at the oracle dated at the same `ts`. No snapshot, demotion or invalid delta is involved. Likely the undo path (a kill by an undo commit, or an undo of an undo) not reaching `check_at_most` with the body's death.
