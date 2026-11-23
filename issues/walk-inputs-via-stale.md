# Some inputs to a commit's reading reach the walk only at the next rejudge
> Summary: engine: a void flag set for overlapping counters, a setting change that moves fires, and epoch standing reach the osis-perm walk only through `stale_commits`, touched at the next `rejudge_once`; walk reads between can lag on those inputs, and the `Core::timelines()` debug assert does not see it (it checks held-set changes only). Every input the walk reads should update it where it changes, as held-set changes do.
> Priority: normal
> Tags: engine, perm

Found by the walk-current review (notes/complaints/review-walk-current.md). Fix shape: list every input `Paths::sync` reads per commit; each setter updates the walk (batches once at their end), and the assert covers them too.
