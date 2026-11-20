# rotation: a removal owing vouches is not due at the end of a history
> Summary: osis-engine `rotation::tests_property::rotation_holds_large_spec_crypto_4` at seed 352928056231 fails "end of history: a vouch trigger missed" (a removal not due that owes vouches). Fails on main's binary.
> Priority: normal
> Tags: engine, tests

Replay: `OSIS_ROTATION_START=352928056231 OSIS_ROTATION_SEEDS=1 cargo test -p osis-engine --lib -- --ignored --exact rotation::tests_property::rotation_holds_large_spec_crypto_4`.

Next: shrink it, then find which input of the vouch duty (notes/write-path-design.md) moves without waking it.
