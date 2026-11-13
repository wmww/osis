# test-optimizer-3
- No tool runs every default test alone under `tools/icount` (notes/testing.md, Default-test cost describes the procedure): each optimizer writes the same 30-line script again. A `tools/pertest BINS OUT` printing name, instructions, CPU-s would save it.
- A background profile queued behind `tools/heavy` runs whatever test binaries sit in target/ when the lock comes free: building in the meantime would have profiled the new code. Copy the default binaries first (about 1 GB) or wait to build.
- `cpuprof --report` has no caller view; who calls a hot function (or which test it is under) needed a throwaway script over the sample file.
