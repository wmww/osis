# custody differential: a node drops a taken revocation
> Summary: osis-engine `rotation::tests_custody::engine_agrees_with_custody_model_large_spec_permissions_5_4` fails on main: "t17 node T: dropped a taken revocation [16, 8] -> [4, 8]" (a node's taken revocations shrink between steps).
> Priority: normal
> Tags: tests, engine

Fails on main at 8abe8e2d8 with `OSIS_CUSTODY_START=357482902476 OSIS_CUSTODY_SEEDS=1` (`cargo test -p osis-engine --lib -- --ignored --exact rotation::tests_custody::engine_agrees_with_custody_model_large_spec_permissions_5_4`): `t17 node T: dropped a taken revocation [16, 8] -> [4, 8]`. Found by the gate of s2-engine (external fires, which touches no rotation code), replayed on main's own binary. Either the engine forgets a revocation it took (spec/crypto.md §9), or the harness's check reads the taken set where it may rightly shrink.
