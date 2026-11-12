# rotation_holds seed 565001976595: a departed peer opens an epoch its rotator saw it leave
> Summary: `rotation_holds_large_spec_crypto_4` seed 565001976595 fails on main 01d07effc: peer 1 (departed) opens a Read epoch (n 4) of an actor, made by a rotator that saw the departure (first held at step 40). Cause not traced; may be one of the stated limits (issues/rotation-excuse-below-wider-than-seal.md, issues/remover-seals-to-ignorant-fork.md) or a new leak.
> Priority: normal
> Tags: security, rotation, tests

Replay: `OSIS_ROTATION_START=565001976595 OSIS_ROTATION_SEEDS=1 cargo test -p osis-engine --lib -- --ignored --exact rotation::tests_property::rotation_holds_large_spec_crypto_4`. Found by a gate's random seeds.
