# An ending that falls cannot be repaired once hosts deleted the thing
> Summary: Ending is judged with the thing's own data, then the data goes; a purge of `created.0` that later falls, or a stale creation copy, finds nothing to restore or nothing to re-judge the right with. Decide before step 7 of notes/expiry-creation-design.md.
> Priority: normal
> Tags: engine, sync

held-model (`spec_records.rs`, `props.rs`) found two faces of one gap:
- **A fallen ending.** Node A takes a purge of T's creation before the purger's earlier demotion arrives and forgets T; node B gets the demotion first and keeps T. They converge only if A can fetch T again, and step 7 has node-sync delete T's blobs at hosts. Property: an honest race between a demotion and an ending can lose a whole thing for good at A. Ordinary purges have the same shape, but lose one value, not a thing.
- **The right read from what went.** An admin by a grant on T itself ends T: the right is judged from T's `roles.0`, which the ending drops. A stale creation copy arriving while the purge commit is still held re-judges the purge without those roles, so T comes back. The design's limit only covers a stale copy after the purge commit is gone.

The model judges an ending with the data held and has its property tests fetch an ended thing's parts again, so they converge; that assumes hosts still have them.

Decided (Tess): no wait. An ending that later falls brings the thing back only if some node still holds a copy; otherwise it is gone, as with an ordinary purge. Hosts keeping an ended thing for a period (`ROLE_KEEP`, 90 days) would break prompt purge and disappearing messages. State this limit in spec/requirements.md with step 7.

Still to fix in step 7, whatever that choice: a stale creation copy re-judges a purge held without the thing's roles, so the thing comes back (the second face above).
