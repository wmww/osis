# atomic-first-sync review 2 (tiller-atomic-first-sync-review2)
- `pkill -f <name>` from a background Bash kills the shell running it (its command line holds the name): exit 144 and no run.
- A timing probe of first/second phases in dev mostly measures `check_unchanged` (debug only, O(pending) per apply): the "4x" of the first review was that. Cut it from the probe before comparing main and branch.
- `tools/cpuprof --report` needs llvm-symbolizer, not on this box: raw samples only.
- A new `OSIS_*` in testenv-known.txt taken by `bin-at --take` did not reach a test binary (the second time it was unknown): hardcode a probe's switch instead.
