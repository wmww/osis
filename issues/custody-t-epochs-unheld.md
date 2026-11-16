# Custody differential: t epochs boxed to a node not held there
> Summary: `rotation::tests_custody`'s check that the t epochs the model holds at P's nodes and R1 are held in the engine fails in about 11 of 40 worlds: R1 (and A) lack a t epoch whose rotation was boxed to them, e.g. C's t rotation at an epoch R1 does not count. The check is off (`OSIS_CUSTODY_T_HELD=1` turns it on); it had read an empty map of mirrored t epochs, so it never ran before.
> Priority: normal
> Tags: engine, tests

Replay: `OSIS_CUSTODY_T_HELD=1 OSIS_CUSTODY_START=0 OSIS_CUSTODY_SEEDS=40 cargo test -p osis-engine --lib -- --ignored --exact rotation::tests_custody::engine_agrees_with_custody_model_large_spec_permissions_5_4`.

Seen at seed 7719005338 t7: R1 holds C's t rotation #9 applied, not pending, boxed to R1, yet R1's `core.epochs(t)` has no entry for its epoch (it knows A's fork of the same n). spec/crypto.md §4 (Reading-only secrets) keeps a secret learned from an invalid commit for reading, and notes/engine-validity-epochs.md says custody follows holding. Open: whether the engine drops the box (a bug) or the model over-claims what R1 is boxed (the harness marks every t rotation boxed to R1). Fix the side that contradicts the spec, turn the check back on (drop the env gate), and add a constructed test.
