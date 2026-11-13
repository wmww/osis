# chunk-tree-4
- A header format change moves every commit and blob ID, and two tests turned out to pass on main only by their IDs: two covers at one stamp (`retention::none_writer_without_the_right_adds_no_cover_spec_commits_5`, the lower ID dropped) and the removal-first order (issues/removal-placed-by-blob-id.md). Each took a `tools/bin-at main --patch` build (1-2.5 min, the worktree checked out at main meanwhile, so no edits) and print instrumentation to tell from a regression.
- `tools/bin-at` rebuilds osis-node twice per use (there and back); three uses here cost about 8 min of builds.
- The relay-only "never pages" rule rested on the chunk list being empty (a validate check); nothing said so until the list went.
- Review: the node-ID-order trace needed print instrumentation across four files (stamp loop, flush, host take, fetch order); a per-node tag in debug output would have saved a round (engine pointers are not stable per node).
