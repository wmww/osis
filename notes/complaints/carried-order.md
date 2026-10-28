# carried-order
> Summary: Workflow snags met fixing issues/carried-import-order.md.

- The issue's repro (`OSIS_WALKS_START=377 OSIS_WALKS_SEEDS=1`) still fails once fixed: the test's aggregate coverage assert (drops, invalid parts, ...) is not met by one seed. Now the per-seed walk is `random_history`, and the two seeds run alone in `open_equals_rebuild_random_histories_carried_imports`.
- `tools/wt claim` handed a worktree with a 10 GB target (stacked generations); harmless here, but the warning lands before the path it prints.
