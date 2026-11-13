# place-chain-gap
- The brief pointed at `core/node/src/labeling/` for `place_chain`; labeling lives in `core/engine/src/labeling/` and `place_chain` in `core/node/src/sync/deliver.rs`.
- First version of the test passed by luck of ordering: the writer placed its chain while the team was not yet in its view of g's closure. The gap shows only when the writer learns g with the team already listed.
- Review: a scratchpad log directory must exist before a backgrounded `cargo test > dir/log` (the run fails at once, exit hidden by `echo`).
