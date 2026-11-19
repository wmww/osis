# Paged apply differs from whole apply
> Summary: osis-engine `apply::tests_paged::paged_apply_matches_whole_large_spec_crdt_8` fails on main: at some step, applying page by page holds a different index than applying whole.
> Priority: normal
> Tags: tests, engine

Fails on main at 26f8e7280 with `OSIS_PAGED_APPLY_START=874943289199 OSIS_PAGED_APPLY_SEEDS=1` (`cargo test -p osis-engine --lib -- --ignored --exact apply::tests_paged::paged_apply_matches_whole_large_spec_crdt_8`): `seed 874943289199 step 30: page-by-page apply differs from whole`, the first difference in the index digest (core/engine/src/apply/tests_paged.rs:386). Found by the gate of gimbal-terms-code (a pure rename), then replayed on main's own binary. It fails on some seeds only: the gate's random seeds pass it most runs (its tools/known_failures.txt line is `rate:`).
