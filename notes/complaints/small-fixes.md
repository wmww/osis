# small-fixes
> Summary: workflow notes from the small-fixes branch (bytes-only promotion, stale-copy reproducer, pass waits from the cause's place).

- `tools/mutate.py` with a `-- facade::` filter after `--test it` prints "Finished" in seconds but one probe took 3 min in the background with no progress line: the build of the mutated engine is the cost; nothing tells you it is building.
- `issues/until-roster-event.md` (item 3) was not on sync-rebuild when this branch started; it arrived with outsider-fix and was left for a later task.
