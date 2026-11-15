# Forks differential: the engine counts fewer revocations than the model
> Summary: `rotation::tests_forks::engine_agrees_with_forks_model_large_spec_permissions_5_4` seed 786082893264 fails at t12 on node 1: `counting: engine {2} ... model {2, 4} taken [4]`: the engine leaves out a revocation the model counts once taken.
> Priority: normal
> Tags: engine, perm, tests

- Replay: `OSIS_FORKS_START=786082893264 OSIS_FORKS_SEEDS=1 cargo test -p osis-engine --lib -- --ignored --exact rotation::tests_forks::engine_agrees_with_forks_model_large_spec_permissions_5_4`. Fails alike on origin/main c5e71ac3d (found by the fathom-test-opt-13 gate's random range, which forgets nothing on that seed).
- Either side may be wrong: find which taken revocation (4) the engine does not count and why; may share a cause with issues/forks-model-seed-67-rebuild-differs.md or issues/account-removal-before-its-rotation.md.
