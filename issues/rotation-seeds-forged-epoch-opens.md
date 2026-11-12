# Rotation seeds: a departed peer opens epochs after a forged rotation
> Summary: `rotation_holds_large` (small size) seeds 7312400234 and 7312400003 fail on main and on cover-rule alike (the covers rule and the stricter Met change nothing). 7312400234 fails rule 1: writer peer 4 encrypts under actor 0's Read epoch n 3 that peer 2 forged (`forges Rotating`) while it held the role, and peer 2, departed, opens it: a maker departure should block that epoch. 7312400003 fails rule 2 (peer 3 opens a Sync epoch, n 3 here, n 2 on main, made by a rotator that saw it depart). Not triaged (leak or checker gap), not minimized.
> Priority: critical
> Tags: security, keys, tests

Replay: `OSIS_ROTATION_START=<seed> OSIS_ROTATION_SEEDS=1 cargo test -p osis-engine --lib -- --ignored --exact rotation::tests_property::rotation_holds_large_spec_crypto_4`. Found in 300 fresh seeds from 7312400000 (cover-rule review); the other 298 pass.
- Start at 7312400234: is peer 2's forged rotation's epoch current at peer 4, and does peer 4 know peer 2's departure (`direct_departures`, maker branch: `epoch_intro` author)?
