# rotation_holds: a departed peer opens a Read epoch its rotator saw it leave
> Summary: `rotation::tests_property::rotation_holds_tier2_spec_crypto_4` fails one seed: peer 3, departed, opens a Read epoch made by a rotator that had seen it depart. Either a rotation sealed to a removed holder or the property's view of "saw it depart" is wrong; not yet studied. Engine-only (no node sync in the harness).
> Priority: normal
> Tags: security, tests, engine

Replay: `OSIS_ROTATION_START=200451083602 OSIS_ROTATION_SEEDS=1 cargo test -p osis-engine --lib -- --ignored --exact rotation::tests_property::rotation_holds_tier2_spec_crypto_4` ("first held at step Some(26)"). Found by the net-pull review's derived set, whose branch changes nothing the engine runs.
