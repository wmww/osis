# A swept hidden write's body is never covered
> Summary: Under purge on replace a body holding an edit into a removed map entry stays held for good after a compacting writer's sweep killed it: the sweep's reset leaves the entry no record in canonical form, so the edit joined into any snapshot recreates it (`covered` says no) and `replace::replaced` says no either (the join changes the state). The content is unreadable but persists in the body at every node, against purge on replace's property. Repro: waits.rs `repro_hidden_write_goes_at_compaction_spec_sync_7` (ignored).
> Priority: normal
> Tags: engine, retention, crdt

Before retention step 2 the keep-at-most bound dropped such a body at its death. Under the one-drop principle only a cover drops it, so the covered test (spec/commits.md §5 Covered: canonical bytes unchanged by the join) must accept a body whose writes the snapshot's resets prune, wherever the record went. Options: compare after pruning the body by the snapshot's effective resets on its paths; or have the sweep's commit keep the entry's tombstone in canonical form while a body under it is held. Check the held model's `crdt::covers` for the same case.
