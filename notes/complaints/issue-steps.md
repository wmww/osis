# issue-steps
> Summary: workflow mishaps met on branch issue-steps.

- `git checkout <rev> -- file` to try a revert stages the old file; a later `git checkout file` then restores that staged copy, not the working edit. Lost one refactor that way; experiment on a wip commit instead.
- A source that drops S and keeps it again leaves the registrar's view of its step stale (issues/sync-unbuilt.md, store and streams); found while debugging the re-grant test before keep-simple landed, cost an hour.
