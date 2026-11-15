# fathom-test-opt-13
- `wt claim fathom-test-opt-13 origin/main` started three commits behind a fresh `git fetch` (the claim's own ref was older); caught only by `git status` after the opt-12 merge. Check `git log HEAD..origin/main` right after claiming.
- An old-vs-new `tools/icount` needs the old binaries: a checkout of the base in the task worktree and a rebuild of three crates (about 5 min), then back. A `tools/icount-base <rev>` that builds a base's test binaries once into the scratchpad would save it.
- Debug `check_index` sampling never caught incremental-forget mistakes on its own schedule; forcing it after every forget for one run (then removing it) found every index difference at once. Worth a documented switch.
