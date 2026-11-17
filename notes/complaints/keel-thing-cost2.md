# keel-thing-cost2
- `tools/cpuprof` samples CPU time: at load 22-39 on 16 cores two runs of the same work gave per-make shares that disagreed with `tools/icount` (800 held cheaper than 100). Added `CPUPROF_INSTR=N` (instruction sampling per thread) to the tool.
- Its 48-frame stacks cut off the outer frames, so a FILTER naming the measured phase (a scoped thread in the probe) matched almost nothing. Raised to 160.
- An in-process instruction counter per `costs` span is impossible (`unsafe` is forbidden on the command line, so no `perf_event_open`); per-phase wall time on this box is noise (17 vs 38 ms for the same run).
- My probe script wrote its `.err` files through `$OLDPWD` into the worktree; caught before commit.
