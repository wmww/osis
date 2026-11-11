# gate-perf
- A by-hand profile under `tools/heavy` waited 29 min for the lock (a TLC run and a gate ahead); single-seed runs unlocked gave the same profiles in minutes. Profiling one or two seeds of a property needs no lock.
- `tools/cpuprof --report` resolves the binary by the path it ran with: run it from the same directory (a relative `../../target/...` path symbolizes nothing elsewhere, silently: 0 samples match a filter).
- Listing tests by running every `target/debug/deps/*-<hash>` with `--list` hit a non-test binary that never exited: list only known test binaries.
