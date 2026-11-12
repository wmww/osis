# rotation_holds fails a seed on main: a departed peer opens a rotator's new epoch
> Summary: Seed 780551881542 of `rotation::tests_property::rotation_holds_large_spec_crypto_4` ends with peer 2 (role None) opening a thing's Read epoch n 2 made by a rotator that saw it depart (first held at step 14): a possible read leak. Fails alike on main at e1a8cae38; not looked into.
> Priority: normal
> Tags: tests, rotation, security

- Replay: `OSIS_ROTATION_START=780551881542 OSIS_ROTATION_SEEDS=1 cargo test -p osis-engine --lib -- --ignored --exact rotation::tests_property::rotation_holds_large_spec_crypto_4`.
