# crdt-tests-cleanup
> Summary: Mishaps met cutting osis-crdt's tests: proptest cases and seeds outside cargo, a cheaper-looking helper that cost 3 G, `tests_seq::` matching `tests_seq_ops`.

- A copied lib binary run outside cargo runs 256 proptest cases (notes/build.md says so, easy to miss): the first baseline read 4x too high. And the crdt lib is mostly proptests that draw fresh seeds per run, so a module count moves ~8% between identical runs: compare with `PROPTEST_CASES=32 PROPTEST_DISABLE_FAILURE_PERSISTENCE=1 PROPTEST_RNG_SEED=1` set.
- Swapping a test-only early-stopping walk (`Fragment::holds_write`) for `held_writes` (the crate API) looked like pure line savings and cost 3 G in `sweep_is_bounded_and_finishes` (held_writes expands a range record of `MAX_DELTA_BARE` elements per element). Measure the module before committing any helper swap, even "obviously free" ones.
- `icount ... tests_seq::` also counts `tests_seq_ops::` (substring filter): add `--skip tests_seq_ops`.
- The briefed footgun files (rotation-tests*, engine-it-tests*) do not exist; the useful lessons were in perm-cleanup*, sync-tests-cleanup* and crdt-cleanup*.
- The crdt tests are already consolidated by earlier passes: near-identical tests are rare (the wire rejections were the one clear table), and duplicated blocks of 4+ lines across files are almost absent. Line cuts came from shared helpers (`joined`, `build`/`wrote`) at many sites, a few lines each.
