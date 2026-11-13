# A placement again stays off a host when a cover falls without a head move
> Summary: a delete of a body placed again stands while the label's head at that host stays (spec/sync.md §6 Placed again once; notes/node-sync.md). A role change that invalidates the deleter's cover or killing write moves the head in the common cases, but a few falls move none, leaving the body off that host, at what may be its only holder, until the head next moves or the tombstone ends (30 days).
> Priority: low
> Tags: sync, node-sync

- Move the head (tested in `deletion`): a demotion (its rotation registers a step); a removal from a team holding the role (the label's group rotates for its stale box to the team). Move nothing and need none: self-removal, `until` and finalize audit nothing (spec/permissions.md §5.1); a purge never names a snapshot (spec/commits.md §5 Purge).
- Fall with no head move, all needing an honest disagreement window first:
  - the next explicit write on a grant whose departure (self-removal, `until`) was already rotated for audits the departed writer's cover (spec/permissions.md §5.1, "The next explicit write on that grant ... audits"): no new departure, no rotation;
  - a late edge write reorders the walk at the deleter (D rebuilt) and drops the cover's author's authority, its rotation registered before the placement again;
  - the deleter's trust set changes (local, nothing on the wire).
- Possible fix where the holder holds the cover itself: clear `BlobRec::again` on the aspect's commits when a held snapshot falls here (`relist_fallen`, `Engine::take_fallen`). A holder that never got the cover learns nothing of the deleter's grounds.
