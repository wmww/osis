# rotation_holds_large seed 937841741903: peers count different current epochs

> Summary: osis-engine property `rotation::tests_property::rotation_holds_large_spec_crypto_4` fails at seed 937841741903 (on main; engine code only).
> Priority: normal
> Tags: engine, tests

Replay: `OSIS_ROTATION_START=937841741903 OSIS_ROTATION_SEEDS=1 cargo test -p osis-engine --lib -- --ignored --exact rotation::tests_property::rotation_holds_large_spec_crypto_4`. Deterministic: `Write: peers 0 and 1 count different current epochs (rotated: true)` (tests_property.rs:512). Not root-caused.
