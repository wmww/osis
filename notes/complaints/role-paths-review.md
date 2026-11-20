# role-paths-review
> Summary: Workflow notes from reviewing the role-paths branch (role commits stating real paths).

- A probe env variable must start `OSIS_PROBE_`: any other unknown `OSIS_*` name fails every test of the run at once (`testenv::check_known`), which reads at first like the probe breaking the engine.
- The README's Open list conflicts on every rebase that crosses another branch adding an item: each of the branch's commits touching it conflicted in turn (renumbering by hand twice).
- The engine suites ran in about 70 s each here (lib, `it`), not the 3 to 6 minutes the worker's note gives: the probe sweep is cheap enough to repeat.
