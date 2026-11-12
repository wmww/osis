# Ephemeral reverts with restarts: two nodes read a listed thing apart
> Summary: `ephemeral::ephemeral_reverts_with_restarts_alike_large_spec_crdt_4_6` seed 751305619689 ends with node a reading `Some("6")` and node b `None` for one listed thing (ephemeral.rs final compare). Fails on main e02c3195e too; not traced.
> Priority: normal
> Tags: ephemeral, tests

Replay: `OSIS_EPH_START=751305619689 OSIS_EPH_SEEDS=1 cargo test -p osis-node --test it -- --ignored --exact ephemeral::ephemeral_reverts_with_restarts_alike_large_spec_crdt_4_6` (0.3 s). 1 of 20 seeds at a gate's small size. The same harness without restarts (`ephemeral_reverts_within_rights_alike_large`) passed its 20.
