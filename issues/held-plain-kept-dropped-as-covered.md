# held_set_decides_plain: a commit dropped as covered that the held settings keep forever
> Summary: `order::held_set_decides_plain` at `OSIS_ORDER_SEED=472457420585 OSIS_ORDER_LEN=60` fails on main: after 64 ingests (order #0 at an earlier clock), held-model says commit #35 on `kept.0` is dropped as covered while the engine keeps it live (the settings held keep it to `u64::MAX`), or the reverse.
> Priority: normal
> Tags: engine, held-model, tests

- Replay: `OSIS_ORDER_SEED=472457420585 OSIS_ORDER_LEN=60 cargo test -p osis-engine --test it -- --ignored --exact order::held_set_decides_plain` (Keeps emphasis). Fails alike on origin/main c13899995; found by the fathom-forged-edge gate (gate offset 472457420579), unrelated to that branch (perm certificates).
- Not shrunk (`OSIS_ORDER_SHRINK=1` runs past several minutes). First step: shrink, then decide whether the engine or held-model is wrong about covered drops under a keep-forever setting.
