# Ephemeral reverts with restarts: two nodes read a listed thing apart
> Summary: `ephemeral::ephemeral_reverts_with_restarts_alike_large_spec_crdt_4_6` ends with one node reading a value and the other `None` for one listed thing (ephemeral.rs final compare); seeds 751305619689, 588738830735, 588738830743 (each fails on main too). Not traced.
> Priority: normal
> Tags: ephemeral, tests

Replay: `OSIS_EPH_START=751305619689 OSIS_EPH_SEEDS=1 cargo test -p osis-node --test it -- --ignored --exact ephemeral::ephemeral_reverts_with_restarts_alike_large_spec_crdt_4_6` (0.3 s). 1-2 of 20 seeds at a gate's small size, so the list line matches any seed of this shape. The same harness without restarts (`ephemeral_reverts_within_rights_alike_large`) passed its 20.
