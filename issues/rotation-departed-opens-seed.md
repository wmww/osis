# rotation_holds fails a seed on main: a departed peer opens a later epoch
> Summary: Seed 942892035127 of `rotation::tests_property::rotation_holds_large_spec_crypto_4` has peer 3 (hostile, forges Listed, removed from actor 0) open actor 0's Read epoch n6, made by a rotator that saw it depart. Fails on main (ca16f83fa) as on unmerge-noops; not looked into.
> Priority: normal
> Tags: security, tests, rotation

Replay: `OSIS_ROTATION_START=942892035127 OSIS_ROTATION_SEEDS=1 cargo test -p osis-engine --lib -- --ignored --exact rotation::tests_property::rotation_holds_large_spec_crypto_4` (0.6 s). Panic: `peer 3 (now None) opens ... Read epoch Epoch { n: 6, .. }, made by a rotator that saw it depart (first held at step Some(31))`. The history ends with peer 0 removing hostile peers 2 and 3 and two hostile actors in a row, n6 made with peer 3 below. First triage: a real leak (a removed member reads the post-removal epoch) or a harness excuse missing; a hostile-only shape is `Priority: low`.
