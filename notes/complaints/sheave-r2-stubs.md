# sheave-r2-stubs
> Summary: Workflow snags met building R2 stubs.

- R1 disabled the osis-sync differential oracle by a `panic!` in `Model::closure`, which `history::ran` calls at every quiet `Run`: every World test that runs panicked, not only those checking the oracle, and 14 tests were labelled for the oracle that never used it. A disabled oracle should return "no model" (`harness/history.rs` `MODEL_OFF`), so World tests keep playing.
- R1 sorted ignored tests by failure message alone: many "entry by references" ones fail because they assert on a removed holder (which holds nothing under the model) or rely on entry with no reference. A one-line probe per test (does the peer still hold the thing?) would have labelled them right.
