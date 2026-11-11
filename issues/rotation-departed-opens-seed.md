# A departed holder opens an epoch its rotator saw it depart
> Summary: `rotation_holds_large_spec_crypto_4` seed 914120280755 fails on main: a peer now at Read opens a Write epoch made by a rotator that saw it depart. Not investigated.
> Priority: normal
> Tags: security, tests, rotation

Replay: `OSIS_ROTATION_START=914120280755 OSIS_ROTATION_SEEDS=1 cargo test -p osis-engine --lib -- --ignored --exact rotation::tests_property::rotation_holds_large_spec_crypto_4` (fails at main 54b6747e4, first held at step 37). The gate's random offset hits seeds like it; other seeds of the family fail with "a holder ... lacks a box" (notes/complaints/net-accounts.md). Find which: a key leak past a departure (spec/crypto.md §4) or a checker that reads the departure too early.
