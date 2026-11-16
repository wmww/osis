# Custody differential fails at small size since the closure and destruction commits
> Summary: `rotation::tests_custody` at small size (200 worlds) was clean at ac45a7ca4 and fails 3 (seeds 61, 87, 134) on main from somewhere in ac45a7ca4..9881720ce (write-only-what-you-hold, a weak keeps nothing, waiting-part needs, destruction), with the harness of either commit: a write the model counts is invalid at B (61, 87), R1 lacks a t epoch the model holds (134).
> Priority: normal
> Tags: engine, tests

Replay: `OSIS_CUSTODY_START=<seed> OSIS_CUSTODY_SEEDS=1 cargo test -p osis-engine --lib -- --ignored --exact rotation::tests_custody::engine_agrees_with_custody_model_large_spec_permissions_5_4`.

- Seeds 61 (`t5 node B: write #9: engine invalid, model valid`), 87 (`t6 node B: write #31`), 134 (`t14 node R1: t's epoch of #14 not held`).
- Seen alongside: after these commits a node's own t rotation is not recorded as a held rotation of its epoch (`EpochInfo::rotations` empty, `Core::keysets_noted(t)` empty at C in `a_seed_reseal_is_made_with_its_key_in_account_already_spec_crypto_9`), where before it was. The harness now reads a t commit's boxes off the commit itself, so it no longer depends on that index; whether the index is meant to be empty there is open.
- Not bisected. First step: bisect the 14 commits on seed 61.
