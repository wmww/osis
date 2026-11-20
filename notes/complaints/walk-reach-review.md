# walk-reach review
> Summary: Footguns met reviewing the walk by reach.

- Comparing a rewrite with the build before it needs the test at both commits: a detached checkout of the old commit plus an untracked copy of the dump test works, but going back fails on the untracked file (`git checkout` refuses to overwrite it): delete it first. `dump::paths_dump_readings` exists for this now.
- `tools/mutate.py ... | tail` hides the first rows: read each `mutant-N.log` (or grep the `| ` rows) instead.
