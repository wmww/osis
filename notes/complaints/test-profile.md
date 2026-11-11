# test-profile complaints
> Summary: What slowed the test-profile task.

- `tools/cpuprof` keeps 400 k samples of 48 frames: a whole osis-node `it` run (about 1800 CPU-s at 2 ms) overflows it, and 48 frames stop short of the test function, so a sample cannot be charged to its test. A scratch copy at 4 ms and 100 frames did it.
- `cpuprof_report.py` symbolizes without inlines and libc internals come out as `??` (a fifth of all samples: malloc, realloc, free, memcpy); read `??` by its first named caller.
- A cold worktree took 13 min to build the default tests at load 40.
