# slim-tests
- `times` in a `$(...)` reports 0: a subshell's children start at 0. And a gate function setting `c=` clobbered `step`'s variable: the first CPU column read 992 for a 3 s step.
- `tools/cpuprof` wanted `llvm-symbolizer` or `-18`; the box has -21 and -22, so the samples were taken and the report refused (exit 1 after minutes of runs). Now finds any version.
- notes/testing.md's and CLAUDE.md's tier-1 numbers span many machines and loads: 2837 CPU-s (r4's one-at-a-time at load) against 1097 here by the same method. Only a run with old and new binaries interleaved means anything.
