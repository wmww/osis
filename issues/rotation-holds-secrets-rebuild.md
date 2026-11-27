# rotation_holds: a node's live `secrets` index differs from its store loaded afresh
> Summary: osis-engine `rotation::tests_property::rotation_holds_large_spec_crypto_4` fails at seed 910819980614 on main: the rebuild check finds the `secrets` table of one thing differing between the live index and the store reopened.
> Priority: normal
> Tags: engine, keys, tests

Replay (fails on origin/main 7dcf26f05 and after it): `OSIS_ROTATION_START=910819980614 OSIS_ROTATION_SEEDS=1 cargo test -p osis-engine --lib -- --ignored --exact rotation::tests_property::rotation_holds_large_spec_crypto_4`. Panic: "rebuilt from the commit records (want: this node's live index, got: its store loaded afresh), the index Table("secrets", ...)" (core/engine/src/engine/mod.rs, the rebuild check). Found by a gate's offset; 1 of 100 seeds there. Not yet looked into: a derived index that a restart computes differently, so a property of the index, whatever the rate.
