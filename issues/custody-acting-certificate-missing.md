# custody differential: the engine lacks an acting certificate the model has
> Summary: osis-engine `rotation::tests_custody::engine_agrees_with_custody_model_large_spec_permissions_5_4` fails on main: "t5 B acting: certificate engine None, model Some(...)" (a node acting for B has no certificate where the custody model has one).
> Priority: normal
> Tags: tests, engine

Fails on main at 5e4c817e2 with `OSIS_CUSTODY_START=210455287849 OSIS_CUSTODY_SEEDS=1` (`cargo test -p osis-engine --lib -- --ignored --exact rotation::tests_custody::engine_agrees_with_custody_model_large_spec_permissions_5_4`): `t5 B acting: certificate engine None, model Some(({11, 15, 22, 31, 35}, {4, 7}))`. Found by the gate of g-needs (the certificates rule), replayed on main's own binary with the same text. Either the engine fails to build an acting certificate the model expects (spec/permissions.md §5.4), or the model's expectation is wrong; not yet looked into.
