# gate-perf
- A by-hand profile under `tools/heavy` waited 29 min for the lock (a TLC run and a gate ahead); single-seed runs unlocked gave the same profiles in minutes. Profiling one or two seeds of a property needs no lock.
- `tools/cpuprof --report` resolves the binary by the path it ran with: run it from the same directory (a relative `../../target/...` path symbolizes nothing elsewhere, silently: 0 samples match a filter).
- Listing tests by running every `target/debug/deps/*-<hash>` with `--list` hit a non-test binary that never exited: list only known test binaries.
- Review: the `seen` skip never fires in the default `paged_apply_matches_whole` (stored checked only at the last step), so checking it took a by-hand run of the large property (2 seeds, 7.5 min on one thread).
