# keel-diff-last
- `OSIS_SYNC_SHRINK=1` shrank seed 23 to `[PowerOff(4)]`: a world step naming a node past the world panicked on the index instead of being skipped as history steps are (fixed: `harness::step_of` skips it).
- The brief's seed-23 description (a reader keeps a removed role) no longer matched this build's failure (store entries kept under a sync ID not held); read the seed's own panic before studying a class.
- A hand test built from a seed's story passed with the fix undone: another bug (sync-key credentials passing the Departed filter) kept the member open, so the corner was never reached. Check a reproducer with `tools/mutate.py` before trusting it.
