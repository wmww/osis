# A holder with key access settles without a box
> Summary: `rotation_holds_large_spec_crypto_4` seeds 192411102837 and 377427562097 fail on main: after the due rotations a holder of an actor with key access lacks a box (liveness, not a leak). Not investigated.
> Priority: normal
> Tags: tests, rotation

Replay: `OSIS_ROTATION_START=192411102837 OSIS_ROTATION_SEEDS=1 cargo test -p osis-engine --lib -- --ignored --exact rotation::tests_property::rotation_holds_large_spec_crypto_4` (fails at main a4c482799). Find which holder, which actor, and why no re-seal or rotation boxes it (spec/permissions.md §3, every holder ends reading everything).
