# held-model keeps live deltas whatever the setting
> Summary: held-model still models "a live delta is read on its own, no cover drops it" (`model.rs` fate, `KeepWhy::Plain`; spec_commits.rs `keep_until_blocks_compaction`), while spec/commits.md §5 Kept while live drops a live delta under a cover where no setting keeps it while live; the adapter does not compare that fate, so nothing fails.
> Priority: normal
> Tags: tests, retention

The model is the independent reading of spec/commits.md §5 the engine is checked against (`node/tests/it/held.rs`). Its fate for a live (not replaced) non-snapshot delta returns `Keep(Plain)` before looking at covers; the spec now keeps a live delta only to its aspect's live bound (`Timeline::live_until`: for good under a D, to T under a T alone, none elsewhere) and drops it under a cover after that, its author only under its own covers (spec/sync.md §7 Own bodies, a node-sync rule the model may leave out). Update the model's rule and its tests (`keep_until_blocks_compaction_spec_commits_5` asserts the old rule), then check whether the adapter should compare live drops before a live bound as it does replaced ones before an absolute keep-at-least.
