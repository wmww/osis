# rotation_holds fails a seed on main: a departed peer opens an epoch made by a rotator that saw it depart
> Summary: Seed 59710880685 of `rotation::tests_property::rotation_holds_large_spec_crypto_4` fails rule 2 of `check`: peer 1 (now no role) opens actor 0's Sync epoch n4, made by peer 2 after it saw peer 1 depart (first held at step 42). Single actor, five peers; fails alike on main. Either a real seal to a departed peer (security) or a missing excuse in the check; not looked into.
> Priority: normal
> Tags: security, tests, rotation

Replay: `OSIS_ROTATION_START=59710880685 OSIS_ROTATION_SEEDS=1 cargo test -p osis-engine --lib -- --ignored --exact rotation::tests_property::rotation_holds_large_spec_crypto_4` (1 s). Found in a gate's 100 small-size seeds from 59710880610.
