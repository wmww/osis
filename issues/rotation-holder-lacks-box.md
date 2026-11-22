# A rotation property seed: a holder with key access lacks a box
> Summary: osis-engine `rotation::tests_property::rotation_holds_large_spec_crypto_4` fails at `OSIS_ROTATION_START=147083058899`: "a holder of … with key access lacks a box", on main's lib binary (800ca0810) as on the engine-core-cleanup-2 branch. Not shrunk, cause not read.
> Priority: normal
> Tags: engine, keys, tests

Replay: `OSIS_ROTATION_START=147083058899 OSIS_ROTATION_SEEDS=1 cargo test -p osis-engine --lib -- --ignored --exact rotation::tests_property::rotation_holds_large_spec_crypto_4`. Today's key-hop change (27db87669: a key is an ordinary admin edge) and the rollback checks (264dc1a4c, 800ca0810) are recent suspects; bisect first.
