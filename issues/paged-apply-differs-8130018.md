# Paged apply differs from whole at seeds 8130018-19
> Summary: `apply::tests_paged::paged_apply_matches_whole_large_spec_crdt_8` fails at step 26 of seeds 8130018 and 8130019 (one history: the harness seeds `Rng(seed | 1)`): node 1's `t:mix.0` state differs between page-by-page and whole apply after a demotion, snapshots and late `WaitBlobs` parts.
> Tags: engine, tests

Repro: `OSIS_PAGED_APPLY_START=8130018 OSIS_PAGED_APPLY_SEEDS=1 cargo test -p osis-engine --lib apply::tests_paged::paged_apply_matches_whole_large_spec_crdt_8 -- --ignored --exact` (deterministic, any thread count; 18 of 20 seeds from 8130000 pass). The panic shows only the first 3000 chars of each state, which are equal: the difference is past them (print a diff of the two states to find it).

Also: `Rng(seed | 1)` makes seeds 2k and 2k+1 the same history, so the default range 1..25 runs 12 histories twice (notes/testing.md, Seed loops).
