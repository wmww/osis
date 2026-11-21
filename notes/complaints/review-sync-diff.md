# review-sync-diff
> Summary: Footguns met reviewing sync-diff.

- `tools/mutate.py` printed "none" for a test filter matching no test (`running 0 tests`), the same as a plant no test catches: the worker's "none" for the fix's undo, which the reproducer does catch (rerun: caught), fits that. The row now says "no test ran".
