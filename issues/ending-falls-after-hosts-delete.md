# An ending that falls cannot be repaired once hosts deleted the thing
> Summary: Ending is judged with the thing's own data, then the data goes; a purge of `created.0` that later falls, or a stale creation copy, finds nothing to restore or nothing to re-judge the right with. Decide before step 7 of notes/expiry-creation-design.md.
> Priority: normal
> Tags: engine, sync, tess-call

held-model (`spec_records.rs`, `props.rs`) found two faces of one gap:
- **A fallen ending.** Node A takes a purge of T's creation before the purger's earlier demotion arrives and forgets T; node B gets the demotion first and keeps T. They converge only if A can fetch T again, and step 7 has node-sync delete T's blobs at hosts. Property: an honest race between a demotion and an ending can lose a whole thing for good at A. Ordinary purges have the same shape, but lose one value, not a thing.
- **The right read from what went.** An admin by a grant on T itself ends T: the right is judged from T's `roles.0`, which the ending drops. A stale creation copy arriving while the purge commit is still held re-judges the purge without those roles, so T comes back. The design's limit only covers a stale copy after the purge commit is gone.

The model judges an ending with the data held and has its property tests fetch an ended thing's parts again, so they converge; that assumes hosts still have them.

Options to weigh: hosts delete an ended thing only after a wait (`ROLE_KEEP`, what a purge commit already gets); an ending needs a right that outlives it (the record chain's), which lets a removed first admin end the thing; or accept the loss and say so in the requirements.

For Tess: if an ending later turns out to be invalid (the person ending the thing had already lost the right, but one node did not know yet), should the thing come back? Coming back means hosts wait before deleting ended things; gone for good means one node can lose a whole thing to an honest race.
