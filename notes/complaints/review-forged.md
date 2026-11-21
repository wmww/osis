# review-forged
> Summary: reviewer complaints for forged-dead-write.

- Checking a probe against main's code needs a second build: `git checkout origin/main -- core/<crates>` in the worktree, probe appended, then `git checkout HEAD -- core` back (all committed first) cost a full engine rebuild each way (~2 min each); `tools/bin-at` can't take an uncommitted probe test.
- A hand `Fragment::Slots` whose text slot is exactly the register's embedding is not canonical (the join drops the slot), so a crdt probe built that way reports deaths no decoder lets in: build probes through the wire (`carried`) or with an extra write in the slot.
