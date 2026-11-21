# judgment-vectors
- A throwaway `OSIS_PROBE_*` read through `testenv::str_var` panics (not in testenv-known.txt): probes must use `std::env::var_os` directly. notes/build.md (Probe variables) says the prefix is exempt without saying which reader.
- cpuprof has no callee view: finding that the sync-set probe inside `play_with` was a third of the test took an env-gated duplicate run (icount delta), not the profile.
