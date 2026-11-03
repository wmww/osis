# Arrival order: a snapshot's death dated early at seed 74305
> Summary: `arrival_order_alike` seed 74305 fails on main before grant-reach too: one arrival order dates a content snapshot's death at the snapshot's own write time, not its superseder's.
> Tags: tests, engine, crdt

Repro: `OSIS_ORDER_SEED=74305 OSIS_ORDER_LEN=60 cargo test --workspace --test it order::arrival_order_alike_large_spec_permissions_5_2 -- --include-ignored` (about 160 s, mostly shrinking).

Fails at 5ccc2f6f: `death dated early or missing: ... (ContentSnapshot) ... t:map.0: here Some((Ts(...393218), Ts(...393218))), earliest superseders Some((Ts(...393218), Ts(...393220)))`. Not looked into further; the history has a forged commit (`Forged { by: 1, .. }`) among compactions.
