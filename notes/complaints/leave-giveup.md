# leave-giveup
> Summary: workflow notes from the self-removal wait branch.

- The branch builds on `leave-unstuck` (not yet in sync-rebuild when started): `Opens::shared` exists only there. Rebase with `git rebase sync-rebuild` once it merges.
- The sync test World has no pairing, so the own-node skip of `Opens::shared` for a self-removal is tested only at the opens level and on the status fake, not end to end.
