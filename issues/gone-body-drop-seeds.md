# A keep-at-most-0 body dropped that the held-model or in-order delivery keeps
> Summary: Pre-existing on main (not from no-roster): `order::arrival_order_purge_large_spec_commits_5` seeds 3023, 3045 (and one more) and `parts::parts_differential_large_spec_commits_4` seed 79 variant 5 drop a `t:gone.0` body (keep at most 0) that the held-model or in-order delivery keeps. Found by OSIS_FULL runs on branch no-roster, whose generator change (roster steps gone, demotion frontier blobs held away) brought these shapes to the default ranges. Not triaged.
> Tags: engine, retention, tests

- order seed 3023, shrunk (pin with `check(3023, &h, Cfg { all_up_to: 0, every_held: false, random: 8, subsets: 4, split: 2, clock: 2, par_orders: false, threads: 1, sync: true, settled: false, model: true })`, fails in 0.04 s on main 13a03774d and on no-roster alike):
  ```
  h = vec![Aim(Write { by: 1, t: 2, op: 18, k: 1, v: 7 }), Aim(Purge { by: 1, t: 4, of: 2, back: 2, v: 9 }), Aim(Undo { by: 1, back: 1 }), Aim(Message { by: 1, t: 3, v: 4 }), Advance { who: Some(0), ms: 1839 }, Aim(Typed { by: 0, t: 7, op: 17, k: 1, v: 6 })]
  ```
  (`Aim(x)` is `Aim(Box::new(x))`.) Every commit held, as made: the node drops the body of #7 (`t:gone.0`, writer, keep at most 0; an undo of #5 by the same author) with reason `Other`; the model keeps it (`Keep(Plain)`, no deaths). Not an order question: the whole set in the order made already differs.
- parts seed 79 variant 5 (frontier blobs held away, cut and shuffled delivery): `t:gone.0` ends valid missing where whole delivery has it valid held, and stays so after the blobs arrive. Fails the same on main 13a03774d with no-roster's `parts.rs` taken in (`tools/bin-at main OUT --take core/node/tests/it/parts.rs`). Replay: `OSIS_PARTS_START=79 OSIS_PARTS_SEEDS=1 cargo test -p osis-node --test it -- --ignored --exact parts::parts_differential_large_spec_commits_4`.
- Likely one bug. See also issues/order-purge-seed-9160006.md (another purge-order seed failing on main) and issues/settled-seed-7032.md.
