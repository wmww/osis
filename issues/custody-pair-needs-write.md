# custody differential: a pairing refused for want of write
> Summary: osis-engine `rotation::tests_custody::engine_agrees_with_custody_model_large_spec_permissions_5_4` fails on main: the engine refuses a pairing the custody model makes, "T paired by A: needs Write on <tid>".
> Priority: normal
> Tags: tests, engine

Fails on main at 99fbd07d7 with `OSIS_CUSTODY_START=192781816512 OSIS_CUSTODY_SEEDS=1` (`cargo test -p osis-engine --lib -- --ignored --exact rotation::tests_custody::engine_agrees_with_custody_model_large_spec_permissions_5_4`): `t13: T paired by A: needs Write on _AzGhh9-EL4gBpgAK7n6` (core/engine/src/rotation/tests_custody.rs:305), after forks of removals by A and C, a forger X and many pending commits. Either the engine lacks a role the model grants A at that step, or the harness asks for a pairing the engine rightly refuses. Found by the gate of g-rotation (which touches only the rotation property), replayed on main's own binary.
