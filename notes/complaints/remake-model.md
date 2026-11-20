# remake-model
> Summary: Workflow snags met while modelling `Rules::remake` in roles-model `paths`.

- The story had no way to replay one random world by index; the shrunk world it prints is a different world (its commit IDs move), so a failure could not be read alongside the world that produced it. Added `-- I paths-replay[-variant]` and failing world indices per property in `Stats::print`.
- The honest re-grants at `AFTER` were generated before the answers of ticks 7 to 11 existed, so their frontiers missed honest writes made at those ticks: invisible under vouches, a `quiet` failure once answers became edge writes. Moved into the answers loop at `AFTER`.
- A full story run at 100,000 worlds takes about 5 min of a hold; four holds per rule set, plus the family sample, is most of an hour of lock time per comparison.
