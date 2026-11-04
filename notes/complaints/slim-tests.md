# slim-tests
- `times` in a `$(...)` reports 0: a subshell's children start at 0. And a gate function setting `c=` clobbered `step`'s variable: the first CPU column read 992 for a 3 s step.
- `tools/cpuprof` wanted `llvm-symbolizer` or `-18`; the box has -21 and -22, so the samples were taken and the report refused (exit 1 after minutes of runs). Now finds any version.
- notes/testing.md's and CLAUDE.md's tier-1 numbers span many machines and loads: 2837 CPU-s (r4's one-at-a-time at load) against 1097 here by the same method. Only a run with old and new binaries interleaved means anything.
- Review: stopping a background `cargo test` with TaskStop mid-build left the `osis` `it` test failing to link (undefined hidden symbols) on the next engine change; a `touch core/osis/src/lib.rs` relinked the clean tree, the same mutant still failed there, so that mutant ran on node `it` instead. Let a mutant loop finish, or stop it between builds.
