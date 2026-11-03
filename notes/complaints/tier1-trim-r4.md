# tier1-trim-r4
- Adding a dependency (here `chacha20` to osis-crypto) re-hashes every test executable: a measuring script holding the old `target/debug/deps/it-<hash>` path silently ran the stale binary for two rounds of numbers. Take paths from `cargo test --no-run --message-format=json` after every build.
- libtest captures output of threads a test spawns: an `eprintln!` probe in code a harness runs on its worker threads printed nothing without `--nocapture`, which read as "never called".
- `tools/cpuprof` keeps 48 frames: deep stream recursion loses the test frames, and a dependency without symbols can be named after a neighbour (`osis_label::blob::open` stood in for the forensic attack's own threads). Count calls with a probe before trusting a caller.
- CPU-s per test drifts 20-30% with the box's load between runs: compare builds in one run, tasks interleaved (the scratch `measure2.py` pattern), or by `tools/icount`.
