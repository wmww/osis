# Ephemeral reverts with restarts: two nodes read a thing differently
> Summary: `ephemeral::ephemeral_reverts_with_restarts_alike_large_spec_crdt_4_6` seed 142475985467 (1 of 200 from 142475985360): after reverts while losing write, with node and host restarts, one node reads `Some(Str("21"))` and the other `None` for a listed thing. Fails on e3cdd005f and 8f3cd8d05. Cause not traced.
> Priority: normal
> Tags: ephemeral, node, tests

Replay (under 1 s): `OSIS_EPH_START=142475985467 OSIS_EPH_SEEDS=1 cargo test -p osis-node --test it -- --ignored --exact ephemeral::ephemeral_reverts_with_restarts_alike_large_spec_crdt_4_6`. The assertion is the final `eph_read` comparison (ephemeral.rs, `seed {seed}: {t:?}`), both nodes listing the thing in the same groups.

The same run's `ephemeral_reverts_within_rights_alike` failed seed 142475985472 (`None` against `Some(Str("0"))`) on e3cdd005f; that range passes on 8f3cd8d05 (retention step 4 merged between).
