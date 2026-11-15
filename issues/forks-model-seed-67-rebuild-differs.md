# Forks differential seed 67: a rebuild judges a role commit invalid the live index holds valid
> Summary: `rotation::tests_forks::engine_agrees_with_forks_model_large_spec_permissions_5_4` seed 67 fails `check_index`: rebuilt from the commit records, a role commit of an account at its first epoch (`roles.0` and `secrets.0` on another actor) reads `valid: [false, false]` where the live index holds `[true, true]`.
> Priority: normal
> Tags: engine, tests

- Replay: `OSIS_FORKS_START=67 OSIS_FORKS_SEEDS=1 cargo test -p osis-engine --lib -- --ignored --exact rotation::tests_forks::engine_agrees_with_forks_model_large_spec_permissions_5_4`. Fails alike on origin/main 2aff498af; the only failing seed of 0..200. Seed 786082893277 fails the same way (on main c5e71ac3d too).  Seeds 712821043685 and 712821043852 too (fathom-review-14 gate).
- A rebuild differing from the live index means the judgment depends on arrival order or on state the rebuild reads otherwise (inner signatures, `role_sigs`, the held set): either side may be the wrong one. Find which input the commit's validity reads differently.
