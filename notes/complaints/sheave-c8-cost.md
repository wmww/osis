# sheave-c8-cost
> Summary: cpuprof samples lose their symbols when the profiled binary is rebuilt or deleted (bin-at, pertest), silently.

- I cpuprof'd tests on binaries in `target/` and in `pertest-*.bins/`; then `tools/bin-at` deleted the `target/` executables and `pertest.py run` its `.bins/` (no `PERTEST_KEEP_BINS`). `--report` on the kept samples then printed only `??` and libc frames, no error, and the comparison read as nonsense until I traced it. Cost: a rebuild of the engine binaries and a second profile run (about 15 min). Would prevent it: cpuprof copying the binary beside `OUT` (or storing its build id and refusing a mismatched or missing one in `--report`).
