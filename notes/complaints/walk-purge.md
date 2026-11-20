# walk-purge
> Summary: Workflow snags met building the walk's purges (A1 step 4a-b).

- `cargo test -p osis-perm --test it -- --ignored paths::` (the brief's gate-size command) also runs the by-hand `dump::paths_dump_readings`, which panics without `OSIS_DUMP`: add `--skip paths::dump`.
- The dump hashed every reading in one column, so adding a reading moved every line: split it into columns (other readings, purged deltas, purge readings) first, regenerated the base with that dump, then compared column by column.
- `tools/mutate.py` builds the perm tests with roles-model as a dev-dependency: editing roles-model sources while a mutation batch builds would reach the plants' build; held model edits until it finished.
- Reading `reading()` with new fields grew every check: the soups' test took 23 s until `purged_copies` judged each snapshot once and `check` reused the reading's rights.
