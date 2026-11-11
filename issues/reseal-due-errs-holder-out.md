# reseal_due errs where a re-seal's holder actor can no longer be sealed

> Summary: `rotation_holds_large_spec_crypto_4` seed 3100000000277 (on main too) panics in `settle` on `reseal_due(..).unwrap()`: Misuse "the holder has no key access or no keyset this node may seal it to". `reseal_scan` judged the holder sealable (`members::sealed` Boxed), then `reseal_one` ran `ensure_rotated` first and `sealed` gave `Out`. A re-seal due before a rotation and moot after it should be skipped, not fail the whole pass (an app's re-seal pass would stop at it).
> Priority: normal
> Tags: engine, keys

Replay: `OSIS_ROTATION_START=3100000000277 OSIS_ROTATION_SEEDS=1 cargo test -p osis-engine --lib -- --ignored --exact rotation::tests_property::rotation_holds_large_spec_crypto_4`.

Shape: two actors, both first-admined by peer 0, actor 1 holding a role on actor 0; grants, demotions and `until`s on both (kinds 1, 4, 5, 6); peer 3 is given all but 14 commits; settle: peer 0 makes 3 re-seals and peer 3 makes 2 on actor 0, then a later `reseal_due` fails. The diagnosis above (`Boxed` at the scan, `Out` after `reseal_one`'s own `ensure_rotated`) is the likely path from reading `rotation::reseal_one`, not yet confirmed by a trace. Fix where the candidates come from, so a candidate list and its re-seals agree, rather than by swallowing the error.
