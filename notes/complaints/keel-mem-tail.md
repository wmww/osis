# keel-mem-tail
> Summary: Workflow notes from the bounded-memory tail (state reads, depth, tree reach, frontiers).

- Two default crdt tests fail on the base (`tests_decoder::seq_decoder_matches_model_spec_3_3`, `kitchen_sink_decoder_matches_model_spec_3_3`: impl `Malformed("fact class")`, model Ok), not in tools/known_failures.txt; checked by reverting this branch's crdt-facing change.
- Reads leave whole states in `Core::states` forever (any whole read of a 10^6-key map kept 1.9 GB resident); nothing in the notes said so. Found only by probing the cache size after a read.
- A first redirect into a scratchpad subdirectory that did not exist made a background test run exit at once; mkdir first.
