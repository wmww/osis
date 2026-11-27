# Rotation judged after compaction: card refresh passes its loop bound
> Summary: osis-engine property `rotation::tests_carried::rotation_judged_alike_by_a_node_joining_after_compaction_plain_*` stops on `Engine::refresh_cards` (rewritten cards due again) running 4 rounds past its bound of 3, with no progress.
> Priority: normal
> Tags: engine, tests

Fails on main every run (seen at 7e751cf01 and later; not yet bisected): `cargo test -p osis-engine --lib -- --ignored --exact rotation::tests_carried::rotation_judged_alike_by_a_node_joining_after_compaction_plain_spec_crypto_4`. The loop guard (core/base/src/loop_guard.rs) reports the same card due again each round, progress `()`: a card rewrite that makes itself due again. In tools/known_failures.txt against this issue.
