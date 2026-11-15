# The engine's account chain has no differential against a model of merges as joins
> Summary: The forks differential (`rotation::tests_forks`, both variants) is ignored: its oracle, roles-model `forks`, makes merges that name forks and carry answers, which merges no longer may (spec/crypto.md §9, Merges). Its checks (held keys only grow, a switch takes, revocations, rosters, settled heads) wait for the differential against roles-model `custody` (custody phase 4).
> Priority: critical
> Tags: engine, tests, security

- Interim sites: the two `#[ignore]`d tests in core/engine/src/rotation/tests_forks.rs.
- Replace: drive the engines through roles-model `custody` worlds (lockstep and random schedules, switches back, the thief certifying merges and re-sealing), comparing held seeds, heads, preferred head, taken revocations, roster, warning and which writes count; then delete `tests_forks` and the `forks` model's engine mirror.
- Until then the merge rules are checked by hand-written engine tests (`rotation::tests_signing`: concurrent merges are one epoch, lockstep storm bounded) and perm's chain tests.
