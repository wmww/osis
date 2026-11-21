# sync-tests
- Most of osis-sync's default-test cost was the differential and the five sims: seed runners that notes/testing.md says are properties, still run as default tests. A grep for `Seeds::from_env` / `.run(` in a crate's default tests finds such runners faster than a profile.
- Per-module icount (`--exact` every test of a module, one process) overcounts the shared world fixtures: in the gate's one process `world(0, 4)` and the like are paid once for the binary. Judge a fixture change by the whole binary (`tools/icount BIN -q`); a single-thread `--report-time` run shows which test pays which fixture first.
- `tools/mutate.py` refuses an OLD that occurs twice (`g.drop_own(s, &b, c)?` in read/mod.rs): the batch stops before building, so check uniqueness with grep before a long batch.
