# rotation_holds fails a seed on main: a departed peer opens an epoch made after its departure
> Summary: Seed 750502401262 of `rotation::tests_property::rotation_holds_large_spec_crypto_4` ends with peer 4 (no role left) opening a Sync epoch made by a rotator that saw it depart (safety: a leak, first held at step 48). Fails alike on main; not looked into.
> Priority: normal
> Tags: tests, rotation, security

Replay: `OSIS_ROTATION_START=750502401262 OSIS_ROTATION_SEEDS=1 cargo test -p osis-engine --lib -- --ignored --exact rotation::tests_property::rotation_holds_large_spec_crypto_4`. Panic: `seed 750502401262: peer 4 (now None) opens Tid(..) Sync epoch Epoch { n: 5, .. }, made by a rotator that saw it depart (first held at step Some(48))`. Found by the gate's properties stage (small size) of test-optimizer-2; reproduced on main 0cfe9942b.
