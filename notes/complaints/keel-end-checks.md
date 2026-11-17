# keel-end-checks
> Summary: Mishaps met moving the whole verdict checks to the end of history.

- Stopping a `tools/mutate.py` run mid-build (TaskStop) leaves the tree mutated with `.orig` copies beside the files: restore them by hand before anything else.
- `mutate.py` reports every mutant as "does not build" when one of a batch fails, without the compiler error; a substitution returning a borrow of a temporary (`&BTreeSet::new()`) was the culprit. Check a batch with `cargo check` on a hand-applied copy first.
- Every perm `first_held` fault planted at its incremental carry-over (`Kept::carry`, `inserted`, `extend`) was caught by no test, before or after: the brute check only sees keys an engine test asks for on a history long enough to move them.
