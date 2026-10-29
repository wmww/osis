# A forged copy shows once its delta is dropped under covers
> Summary: with compaction drops in the forged walks (a writer's hostile snapshot copying another value under a held tag's dot), the forged value shows at the end and peers disagree; on main's engine too. Suspected: the forged snapshot passes `covered` for the delta whose dot it copies (same dot, the join keeps its record), lands in `Meta::covered_by`, and `rebuilt` takes its copy as the delta's write.
> Tags: security, engine, retention, tests

Repro: in `walks::random_history` (core/node/tests/it/walks.rs, step 6) drop the `!forge` condition on the cover drops, then `OSIS_WALKS_FORGED_START=961118 OSIS_WALKS_FORGED_SEEDS=1` ("a forged copy shows") and 961728 ("peer 1 differs") of `walks::open_equals_rebuild_random_histories_forged`. Both fail with main's engine as well (checked with the dropped-voucher branch's walk change on main's `core/engine`, `core/node/src`).

Likely fix: a snapshot covers a body only if its records under the body's dots equal the body's (`covered`; spec/commits.md §5 "covered"), so every coverer's copies are the delta's writes. Then re-enable cover drops in the forged walks.
