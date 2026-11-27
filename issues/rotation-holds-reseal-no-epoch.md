# rotation_holds: a settled holder's re-seal fails with no read epoch
> Summary: osis-engine `rotation::tests_property::rotation_holds_large_spec_crypto_4` at full size fails at seed 329: in `settle`, a non-hostile peer with a role on an actor errors re-sealing it (`Keys(NoEpoch(Read))`); not looked into.
> Priority: normal
> Tags: engine, keys, tests

Replay: `OSIS_FULL=1 OSIS_ROTATION_START=329 OSIS_ROTATION_SEEDS=1 cargo test -p osis-engine --lib -- --ignored --exact rotation::tests_property::rotation_holds_large_spec_crypto_4` (1.5 s; fails at the size `OSIS_FULL` gives, 1 of 1000 seeds there). Panics at `run.reseal(p, t).unwrap()` in `settle` (core/engine/src/rotation/tests_property.rs). A holder whose role permits a re-seal holds no read epoch to seal under: either the re-seal should owe nothing there, or the node lacks a read secret its role gives.
