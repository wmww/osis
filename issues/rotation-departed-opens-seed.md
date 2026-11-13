# rotation_holds: a departed peer opens an epoch made by a rotator that saw it depart

> Summary: Seed 636429853021 of `rotation::tests_property::rotation_holds_large_spec_crypto_4` fails on main: `peer 2 (now Some(Read)) opens Tid(..) Admin epoch .., made by a rotator that saw it depart (first held at step Some(11))`, i.e. a key epoch reaches a peer its rotator saw leave (a possible confidentiality leak, or an oracle gap). Not looked into.
> Priority: normal
> Tags: security, tests, rotation

Replay: `OSIS_ROTATION_START=636429853021 OSIS_ROTATION_SEEDS=1 cargo test -p osis-engine --lib -- --ignored --exact rotation::tests_property::rotation_holds_large_spec_crypto_4` (13 s). One of 100 seeds from 636429852973.
