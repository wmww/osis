# sim-chain
- `tools/bin-at` checks the old revision out in the worktree for the whole build: reading source meanwhile reads the old tree (line numbers shifted under me). Read nothing, or read through `git show HEAD:path`, while it runs.
- The sim's trace keeps the last 40 lines only; finding when a wait began needed a probe test widening it and stepping the scenario by hand. A `--trace N` on `sim-sweep` would save that.
