# Cached placement reads differently after a forged-copy join
> Summary: `tests_laws::forged_copies_join_alike_spec_4_1` (debug-only cached-read check) fails at proptest input seed = 17419099531132830180: a state that read (filled caches) before joining a forged copy reads "fbcbffbb", the same state after `drop_caches` reads "fbcbbbff". A cache not invalidated by the join; the proptest's random inputs hit it rarely (seen once in a gate run).
> Tags: crdt, tests

Repro: put `cc dacda965d676e4b8a6b92a440ac5c9a946a72fb6857b4652cebb8f4d035263bb` in `core/crdt/proptest-regressions/tests_laws.txt` (proptest wrote it there) and run `cargo test -p osis-crdt --lib tests_laws::forged_copies_join_alike_spec_4_1` (fails 3 of 3), or call `forged_laws(17419099531132830180, ..)` with the type that seed picks. Failing pair: `cached read 0 1`.
