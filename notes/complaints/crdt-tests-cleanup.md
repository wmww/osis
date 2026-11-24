# crdt-tests-cleanup
> Summary: Mishaps met cutting osis-crdt's tests: a cheaper-looking helper that cost 3 G.

- Swapping a test-only early-stopping walk (`Fragment::holds_write`) for `held_writes` (the crate API) looked like pure line savings and cost 3 G in `sweep_is_bounded_and_finishes` (held_writes expands a range record of `MAX_DELTA_BARE` elements per element). Measure the module before committing any helper swap, even "obviously free" ones.
- The briefed footgun files (rotation-tests*, engine-it-tests*) do not exist; the useful lessons were in perm-cleanup*, sync-tests-cleanup* and crdt-cleanup*.
- The crdt tests are already consolidated by earlier passes: near-identical tests are rare (the wire rejections were the one clear table), and duplicated blocks of 4+ lines across files are almost absent. Line cuts came from shared helpers (`joined`, `build`/`wrote`) at many sites, a few lines each.
