# Rotation seed: writer encrypts under a forged epoch its departed forger opens
> Summary: `rotation_holds_large` (small size) seed 7312400234 fails rule 1 on main and on cover-rule alike: writer peer 4 encrypts under actor 0's Read epoch n 3 that peer 2 forged (`forges Rotating`) while it held the role, and peer 2, departed, opens it: a maker departure should block that epoch. Not triaged (leak or checker gap), not minimized.
> Priority: critical
> Tags: security, keys, tests

Replay: `OSIS_ROTATION_START=7312400234 OSIS_ROTATION_SEEDS=1 cargo test -p osis-engine --lib -- --ignored --exact rotation::tests_property::rotation_holds_large_spec_crypto_4`. Found among 300 fresh seeds from 7312400000 (cover-rule review).
- Start at: is peer 2's forged rotation's epoch current at peer 4, and does peer 4 know peer 2's departure (`direct_departures`, maker branch: `epoch_intro` author)?
