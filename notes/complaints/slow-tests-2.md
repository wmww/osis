# slow-tests-2
- Undoing a throwaway patch with `git checkout <file>` also dropped my uncommitted change in that file (the forensic blob memo); commit (or wip-commit) before planting or patching a file you are editing.
- A test measured alone under `tools/icount` carries the process's shared setup: held-model's repair props each count `reach()` (about 17 G, once per process in a full run), osis `sharing::` tests their `World::cached` builds. Compare alone-vs-alone, and say so.
