# Rotation seeds: a departed peer opens a sync epoch its rotator saw it leave
> Summary: `rotation_holds_large` seeds 5830000257 and 59710880685 (small size) fail rule 2: a departed peer opens a Sync epoch made by a rotator that saw it depart. Both fail alike on the covers rule before and after the pin (raise-followup 6704cdfb3, and cover-rule on main), and before the holds-departures-below checker change: neither the covers rule nor that checker change. Not yet triaged (leak or checker gap); both are Sync, so start at sync propagating through holder actors (net-6a). Not minimized.
> Priority: normal
> Tags: security, keys, tests

Replay: `OSIS_ROTATION_START=<seed> OSIS_ROTATION_SEEDS=1 cargo test -p osis-engine --lib -- --ignored --exact rotation::tests_property::rotation_holds_large_spec_crypto_4`.
- 5830000257: peer 3 opens a Sync epoch at n 2 (first held at step 20); the other 399 seeds from 5830000000 pass.
- 59710880685: peer 1 opens a Sync epoch at n 4 (first held at step 42); found by a gate.
