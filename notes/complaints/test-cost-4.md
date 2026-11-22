# test-cost-4
> Summary: Footguns met cutting the debug rollback check's cost.

- Two `tools/mutate.py` runs in one worktree corrupt each other: a plant that "does not build in the batch" is built alone later, after the batch's holds start, so a second mutate.py started once the first's build "ended" edits the file under it (both runs then test a tree holding the other's plants). Run mutate.py batches one after another per worktree, or give every plant a type that builds in a batch.
- With `MUTATE_HEAVY=1` each plant waited 15-25 min for the lock behind gates; seven plants over one crate took over an hour. `MUTATE_PER_HOLD=N` puts N in one hold.
- `tools/cpuprof` over a whole test binary stops at 120,000 samples, so its shares cover only the first tests run (about 240 G at `CPUPROF_INSTR=2000000`); profile single tests, or raise the interval for a binary.
