# rotation_holds: a departed peer opens a write epoch made by a rotator that saw it depart

> Summary: `rotation_holds_large_spec_crypto_4` seed 831606585869 fails on main (2563eea68, after sealer-mark): peer 4, now read, opens a write epoch (n 4) of an owners actor made by a rotator that saw it depart (maker departure rule, spec/crypto.md §4). Found by the crdt-slots gate; main's binary fails it alike.
> Priority: critical
> Tags: security, keys, engine, tests

Replay: `OSIS_ROTATION_START=831606585869 OSIS_ROTATION_SEEDS=1 cargo test -p osis-engine --lib -- --ignored --exact rotation::tests_property::rotation_holds_large_spec_crypto_4` (4 s). First re-run on current main; then shrink to a small reproducer and find the property the rule misses (notes/coordination.md: a seed-found fix in an area with a chain of patches is a class study).
