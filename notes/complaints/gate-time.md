# gate-time
- cpuprof silently kept only the first 120,000 samples: with the notes' suggested `CPUPROF_INSTR=2000000` a gate-size order run (1,900 G) was profiled over its first eighth only, which read the cached setup as the capping play's cost (17%; measured 0.7%). Now the report says TRUNCATED.
- Ten filter passes of `tools/cpuprof --report` re-symbolize the file each time (over 2 minutes for two profiles): one pass over several filters would help.
- Passing tests' stdout (a search's counts, a property's reach floor line) is not in gate logs, so a size question can't be answered from them.
