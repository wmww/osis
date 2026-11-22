# The known-references index counts a strong twice where the scan finds one
> Summary: osis-engine `refs::known_references_are_a_scan_of_held_values_plain_spec_data_model_8` fails on some seeds (seed 39221095449, step 12, node 2): "rows by source" holds a strong on `x:m.0` with count 2 where the scan of held values finds 1. Fails alike on main's binary (4af7171a5; seen at the order-fails gate). Cause not read.
> Priority: normal
> Tags: engine, tests

Replay: `OSIS_KNOWN_REFS_START=39221095449 OSIS_KNOWN_REFS_SEEDS=1 cargo test -p osis-engine --test it -- --ignored --exact refs::known_references_are_a_scan_of_held_values_plain_spec_data_model_8` (about 2 s). First shrink it and read which join or drop moved the reference count without the state (spec/data-model.md §8 Known references): an index row counted twice is a strong that keeps its target needed after the value is gone.
