# rotation_holds: a first admin settles with Read blocked

> Summary: `rotation_holds_large_spec_crypto_4` seed 777063 (on main too) fails "the first admin of actor 0 settles with {Read} blocked": after the hostile removals and settle passes, actor 0's first admin still may not encrypt under its read epoch and makes no rotation for it. A liveness bug (the actor stops taking writes at its own admin) or a missing settle step; not yet traced.
> Priority: normal
> Tags: engine, keys, tests

Seed 415184714975 fails alike (main too). Replay: `OSIS_ROTATION_START=777063 OSIS_ROTATION_SEEDS=1 cargo test -p osis-engine --lib -- --ignored --exact rotation::tests_property::rotation_holds_large_spec_crypto_4`.

Shape (three actors, all first-admined by peer 0): peer 4 boxes nobody on actor 1 (a vandal's lockout, hostile); peer 3 forges a self-removal on actor 1 (hostile); peer 2 grants peer 4 on actor 0; peer 0 receives all but 18 commits, then removes hostile peers 4 from actors 0-2; settle runs re-seals and rotations on actors 0 and 1 and ends with actor 0's read blocked at peer 0. First step: print which departure the blocked read epoch fails to cover (`blocked_epoch`) and why peer 0's `ensure_rotated` makes nothing for it.
