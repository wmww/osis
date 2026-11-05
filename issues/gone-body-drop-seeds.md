# A keep-at-most-0 body dropped at one delivery order only
> Summary: OSIS_FULL runs on branch no-roster: `order::arrival_order_purge_large_spec_commits_5` seeds 3023, 3045 (and one more) and `parts::parts_differential_large_spec_commits_4` seed 79 variant 5 drop a `t:gone.0` body (keep at most 0) that the held-model or in-order delivery keeps. Not triaged; the generators changed with the branch (roster steps gone, demotion frontier blobs held away), so whether main has it is unknown.
> Tags: engine, retention, tests

- order: the held-model keeps a keep-at-most-0 `t:gone.0` body, the node dropped it (reason `Other`). Replay: `OSIS_ORDER_SEED=3023 OSIS_ORDER_LEN=60 cargo test -p osis-node --test it order::arrival_order_purge_large_spec_commits_5 -- --include-ignored`.
- parts seed 79 variant 5 (frontier blobs held away, cut and shuffled delivery): `t:gone.0` ends valid missing where in-order delivery has it valid held, and stays so after the blobs arrive. First run of this harness that really holds a demotion's frontier blobs away. Replay: `OSIS_PARTS_START=79 OSIS_PARTS_SEEDS=1 cargo test -p osis-node --test it -- --ignored --exact parts::parts_differential_large_spec_commits_4`.
- Likely one bug. See also issues/order-purge-seed-9160006.md (another purge-order seed failing on main).
