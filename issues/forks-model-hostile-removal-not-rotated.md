# Forks differential: the model rotates to take a forged removal, the engine does not
> Summary: `rotation::tests_forks::engine_agrees_with_forks_model_large_spec_permissions_5_4` seed 615470545354 fails at t14 on node 1: `model rotates Some(Rot { at: 11, ..., takes: [17] }), engine None`: after X forges two removals as 2 (#16 removes 1, #17 removes 0), the model's node 1 rotates to take #17; the engine's does not rotate.
> Priority: normal
> Tags: engine, perm, tests

- Replay: `OSIS_FORKS_START=615470545354 OSIS_FORKS_SEEDS=1 cargo test -p osis-engine --lib -- --ignored --exact rotation::tests_forks::engine_agrees_with_forks_model_large_spec_permissions_5_4`. Fails alike on origin/main 2e83c6046 (found by the fathom-test-opt-16 gate's random range).
- Either side may be wrong: the removal it would take removes node 1's peer 0 and is signed by 2, whom 0 removed at #5. Find whether the engine should take #17 (and so rotate) or the model counts a removal it must not; may share a cause with issues/forks-model-counting-differs.md or issues/account-removal-before-its-rotation.md.
