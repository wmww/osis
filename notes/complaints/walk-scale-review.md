# walk-scale-review
> Summary: Snags met reviewing the component walk in osis-perm `paths`.

- `tools/mutate.py`: after a mutation that does not build, the rest are rebuilt and numbered anew, so `mutant-<k>.log` is not the k-th mutation given (the worker's "mutant-4's log missing"); rows now print their log path. The worker's "none" for the inert plant did not reproduce (it fails `a_path_joins_components_only_through_held_edges` alone and in batches).
- A full-size property under `tools/heavy --short` printed no `test result` line: past the short cap it is stopped, and grep for the result line hides that; run it under `tools/heavy`.
