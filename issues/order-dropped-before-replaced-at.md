# held_set_decides_plain: a body dropped as covered before its replaced-at ahead of the clock
> Summary: `OSIS_ORDER_SEED=904526897` (Keeps) and `OSIS_ORDER_SEED=904527026` (Settings), each `OSIS_ORDER_LEN=60 cargo test -p osis-node --test it -- --ignored --exact order::held_set_decides_plain`, fail on main: at an early clock a node drops a `t:gone.0` body as covered while its replaced-at is still ahead of the clock (by 38-552 ms) and a held setting keeps history there; held-model keeps it until the clock reaches its replaced-at (spec/commits.md §5 Keep bounds, Dated only where history is kept; held-model AMBIGUITIES.md 68). Not yet looked at.
> Priority: normal
> Tags: tests, engine, held-model

Both are order #0 at an earlier clock (`Clock { at: 35 | 39, .. }`), held-model's check between ingests: `dropped a body in history`, "dropped as covered at <now>, replaced at <r>, the settings held keep it to <r>". `OSIS_ORDER_DUMP=1` prints the index differences.
