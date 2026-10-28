# engine-simplify
- `tools/wt claim engine-simplify` printed the worktree path but exited 1; the worktree was fine.
- Bisecting `walks::open_equals_rebuild_random_histories` by seed: a run of one seed (`OSIS_WALKS_SEEDS=1`) always fails the test's end-of-run coverage assertion (`reached (dropped, invalid, ...)`), so "which seed fails" needs a grep for the real panic. The name also matches the `_moves` variants unless `--exact`.
- The task asked for the walks oracle "at a fresh seed range": it is a tier-1 test, so `-- --ignored` silently runs nothing.
