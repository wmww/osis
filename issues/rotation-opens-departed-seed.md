# rotation_holds fails a seed on main: a departed peer opens a rotator's epoch
> Summary: Seed 962141499239 of `rotation::tests_property::rotation_holds_large_spec_crypto_4` fails on main: `peer 1 (now Some(Sync)) opens Tid(..) Read epoch Epoch { n: 2, .. }, made by a rotator that saw it depart`. Not looked into; another pattern than issues/rotation-holder-lacks-box-seed.md.
> Priority: normal
> Tags: tests, rotation, security

Replay: `OSIS_ROTATION_START=962141499239 OSIS_ROTATION_SEEDS=1 cargo test -p osis-engine --lib -- --ignored --exact rotation::tests_property::rotation_holds_large_spec_crypto_4` (2 s). One of 100 seeds from 962141499200.
