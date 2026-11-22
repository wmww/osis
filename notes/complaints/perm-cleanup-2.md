# perm-cleanup-2
> Summary: Mishaps met making osis-perm's oracles and fixtures cheaper and tabling the hand worlds.

- The role-world fixture (`common::World::held_without`) scanned every commit per commit for its frontier: 61% of `scale::` and much of the binary was building held sets, invisible until a whole-module cpuprof. Profile a test's fixture before its oracle.
- `tools/cpuprof` with `CPUPROF_INSTR` runs the perm `it` binary fine (notes/test-harnesses.md says cpuprof kills it: that is the SIGPROF mode).
- A planted history fault was caught by the old walk oracle only through a product debug check that its `delta_valid` probes happened to trigger (walk.rs "history"), not by the oracle's own compare: read which check fails before crediting an oracle.
- Table rows report failures by name inside one libtest test: grep a mutant's log for the row names (`[a-z0-9_]+, trusting`; names hold digits), not for `FAILED` test lines.
