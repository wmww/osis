# a3-derive
> Summary: Mishaps met building A3's leaves and duty targets in the evidence derivation.

- `tools/mutate.py` batches wrap each OLD in `if <mutant> { NEW } else { OLD }`: an "index off" plant swapping a `BTreeMap::get(..).into_iter().flatten()` for `.values().flatten()` has another iterator type, so the whole batch reports "does not build" for each; such plants run one per invocation (a plain edit, one build each).
- A plant meant as "one level" (`todo.push(y)` only from the start) still walked two levels and survived; a plant shared by the incremental path and `check`'s from-scratch path is invisible to `check`, so only hand asserts catch it.
- The first mutation batch waited about 8 minutes for the heavy lock behind another gate.
