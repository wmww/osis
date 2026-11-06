# A keep-at-most-0 body dropped that the held-model or in-order delivery keeps
> Summary: `order::arrival_order_purge_large_spec_commits_5` seeds 3023 and 3045 and `parts::parts_differential_large_spec_commits_4` seed 79 (variant 5) drop a `t:gone.0` body (keep at most 0) that the held-model or in-order delivery keeps; all three still fail on main (seed replays, about 1-4 s each). Not triaged.
> Tags: engine, retention, tests

- order seed 3023, shrunk (pin with `check(3023, &h, Cfg { all_up_to: 0, every_held: false, random: 8, subsets: 4, split: 2, clock: 2, par_orders: false, threads: 1, sync: true, settled: false, model: true })`, fails in 0.04 s):
  ```
  h = vec![Aim(Write { by: 1, t: 2, op: 18, k: 1, v: 7 }), Aim(Purge { by: 1, t: 4, of: 2, back: 2, v: 9 }), Aim(Undo { by: 1, back: 1 }), Aim(Message { by: 1, t: 3, v: 4 }), Advance { who: Some(0), ms: 1839 }, Aim(Typed { by: 0, t: 7, op: 17, k: 1, v: 6 })]
  ```
  (`Aim(x)` is `Aim(Box::new(x))`.) Every commit held, as made: the node drops the body of #7 (`t:gone.0`, writer, keep at most 0; an undo of #5 by the same author) with reason `Other`; the model keeps it (`Keep(Plain)`, no deaths). Not an order question: the whole set in the order made already differs.
- parts seed 79 variant 5 (frontier blobs held away, cut and shuffled delivery): `t:gone.0` ends valid missing where whole delivery has it valid held, and stays so after the blobs arrive. Replay: `OSIS_PARTS_START=79 OSIS_PARTS_SEEDS=1 cargo test -p osis-node --test it -- --ignored --exact parts::parts_differential_large_spec_commits_4`.
- `order::arrival_order_exhaustive_large_spec_crdt_4_8` seeds 913024 and 913038 fail as made with the same shape (`t:gone.0` body dropped with reason `Other`, model `Keep(Plain)`, no deaths), on main too.
- Seed 3045 fails as made too ("held-model differs"). Replay a seed: `OSIS_ORDER_SEED=3023 OSIS_ORDER_SHRINK=0 cargo test -p osis-node --test it -- --ignored --exact order::arrival_order_purge_large_spec_commits_5`.
- Likely one bug.
