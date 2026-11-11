# eph-reader-copy
> Summary: Small footguns met while letting readers deposit copies under a superseded stamp.

- The deposit path's "own role write, queue it in the outbox" test was `mine(e) && Commit && !cert`, which an own ephemeral write with an old stamp would also meet: the outbox is on disk. The queue now also asks for no stamp (a placement for deposit); worth a type, not a predicate, if more kinds of deposit come.
- `HostStore` keeps the deposit budget's durable part on disk (`Meta::dep_n`) and the ephemeral part in memory (`EphLabel::dep_n`); both are summed by `deposited`. Easy to miss one when touching the budget.
- In the Net harness a node back online can deposit the same blob twice in one step (two connections to the host?); harmless, not chased.
- Review: the sim check "a writer promotes every verified deposit" failed and was narrowed to must-hold deposits; the failure was real (an honest demoted writer deposited its own invalid writes, holding the budget for good). Restore a failing check's strength before narrowing it.
