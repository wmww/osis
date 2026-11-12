# purge-forgotten
- The fix needed a wire change in two places (purge item by stamp, snapshot `Facts`); about 140 test sites built `PurgeItem::Commit { commit, .. }` by hand. `Mutation::purge_commit` now hides the shape; prefer it in new tests.
- Hand-built snapshot bytes in crdt tests (`tests_decoder`, `tests_wire`, `tests_review`, `tests_life`) and the crdt model each spell the root arity; a root change touches all of them (`testutil::narrowest_facts` helps).
- `cargo build --workspace --tests` builds the GUI too (slow); plain `cargo build --tests` is core.
