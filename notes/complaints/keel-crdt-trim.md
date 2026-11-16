# keel-crdt-trim
> Summary: Cleanup-run footguns met trimming osis-crdt and crdt-model.

- The `#[deprecated]` probe reports a method by its defining path inside the crate (`lifecycle::<impl fragment::Fragment>::strip`) but by its re-export path from other crates (`osis_crdt::Fragment::strip`); aggregating by full path made engine-used methods look test-only. Normalise to `Type::method` before counting.
- osis-crdt keeps most items `pub` in private modules, so the probe's "unused outside the crate" list is mostly crate-internal items, not dead code; only items with no use in `src/` outside tests are candidates.
- `tools/policy.py` failed on main (171 spec-anchor violations from the reference-graph spec landing) while this ran; checked only that the count did not grow.
