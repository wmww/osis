# engine-it-tests-3
> Summary: footguns met fixing the copied-engine path wake and continuing the engine integration test consolidation.

- A copy that differs from its original can hide an engine bug rather than be one: a copy leaving the path wait unset was the same state a rollback leaves, so fixing the copy alone (clone the wait) would have passed the test and left the rollback miss. Before fixing a copy's gap, ask which production path reaches the same state.
- Trying every waiting commit when a wait is rebuilt fails the index check at an open ("opened from the persisted index: headers decoded"): an open from the persisted index must take the persisted views as decided.
- `tools/icount BIN -q <module>::` prints only the instruction total, not whether the tests passed: run the module from the same binary first.
