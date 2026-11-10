# Only a hostile writer can change an ended actor's roster
> Summary: Receivers take `roles.0` parts on an ended thing while its record is held (spec/commits.md §5), so a write on ended actor t ordered after its ending still changes t's frozen history and every dependent's authority; honest writers refuse it (`Core::writable`). An admin of t (any admin may end it) can end t and keep editing its roster with a modified client, while the other admins can no longer remove it: ending is a stronger move in an admin dispute than a removal.
> Priority: normal
> Tags: engine, permissions, security, tess-call

- Read, not run: `apply` judges a `roles.0` part on an ended t whose record is held (`judges_ending`) by t's timeline like any edge write; nothing compares its `ts` with the ending. An honest node that had not heard of the ending writes the same bytes.
- Under B (authority through an ended actor stands as its frozen history says) the history is frozen only for honest writers.
- Directions: (a) honest admins may write `roles.0` on an ended actor whose record they hold (the writer rule matches what receivers take; t's roster stays manageable, removals included); (b) receivers ignore edge writes on t ordered after its ending (an expiry's T; a purge request's `ts`), so the history is frozen for everyone; a fallen ending lets them count again.
