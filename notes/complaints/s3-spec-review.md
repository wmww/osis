# s3-spec-review complaints
> Summary: Workflow notes from reviewing the S3 vouches and addenda-gaps spec.

- `roles-model -- 1000000 vouches-state` passes `--short`'s 115 CPU-s cap before printing, and under `tools/heavy` its shrinking (debug, one core, `rederived` under `Rules::state` per candidate) held the box-wide lock for over half an hour after the all-core search ended. Shrinking should run after the lock is released, or the search should print the failing world indices so a trace can rerun one world unlocked.
