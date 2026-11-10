# A holder of a current epoch lacks an earlier secret another holds
> Summary: the rotation property at tier-2 size fails on main: a write holder of a current epoch lacks an earlier superseded epoch that another holder of it holds (history adds incomplete). Not root-caused.
> Priority: normal
> Tags: keys, tests

`rotation::tests_property::rotation_holds_tier2_spec_crypto_4`, seed 1368490604 (`OSIS_ROTATION_START=1368490604 OSIS_ROTATION_SEEDS=1 cargo test -p osis-engine --lib -- --ignored --exact rotation::tests_property::rotation_holds_tier2_spec_crypto_4`): "Write holders [2] of current Epoch n 4 lack earlier Epoch n 2 peer 0 holds". Reproduces on main at 5f1db6e1f and on signing-e alike; one of 100 seeds from 1368490535. Next: a minimal reproducer of the property (every holder of a current epoch ends holding each earlier established secret a co-holder holds, notes/crypto.md History boxes), then the cause.
