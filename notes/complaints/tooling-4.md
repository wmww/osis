# tooling-4
- crdt `rejects_bad_runs_spec_3_3`'s overlapping-runs case built a 5-item snapshot, rejected for its arity before any run decoded, so a mutation of the overlap check "survived" and read as a redundant check. A `rejects` case asserting only the error class passes on any earlier rejection: print the error once (`--nocapture`) when writing one.
