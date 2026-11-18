# keel-deletes-cost
- A whole-binary mutation batch (13 plants x osis-sync `it`, about 60 s each) took 27 min wall, mostly waiting for other agents' heavy holds; the tree cannot be built while it builds, and rebuilding the sync `it` binary while it runs would overwrite the mutant binary under the same hash.
- `claudewait` in a `||` chain gets moved to the background by the tool after 180 s and then reports "failed" though nothing failed.
- A `--exact` icount run of one deletes test mostly measures its fixture (the 4-node world is 35 G of a 40 G test); compare in-process module counts (`tools/icount BIN -q deletes::`) for fixture-free deltas.
