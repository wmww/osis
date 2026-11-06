# A keep-at-most-0 body never received in one delivery, held in another (parts seed 79)
> Summary: `parts::parts_differential_large_spec_commits_4` seed 79 variant 5 (frontier blobs held away, cut and shuffled delivery) ends with a `t:gone.0` body valid missing where whole delivery has it valid held, and stays so after the blobs arrive; purge seed 3045 fails at a different check (a `t:text.0` body held where the held model says never received). Not triaged.
> Tags: engine, retention, tests

- Replay: `OSIS_PARTS_START=79 OSIS_PARTS_SEEDS=1 cargo test -p osis-node --test it -- --ignored --exact parts::parts_differential_large_spec_commits_4` (2 s).
- `OSIS_ORDER_SEED=3045 OSIS_ORDER_LEN=60 cargo test -p osis-node --test it -- --include-ignored --exact order::arrival_order_purge_large_spec_commits_5`: "commit (#4) on t:text.0: the node holds its body, the model's fate is NeverReceived" (as made).
