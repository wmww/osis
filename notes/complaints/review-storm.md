# Complaints: review-storm
> Summary: `Core::rollback_classes` let a due-now list (`fallen`) sit in a "kept" class with a stale reason; the class list checks a field is classified, not that a kept field puts nothing due.

- `fallen` was classed "taken by node-sync, kept" (no node-sync reader exists): a rolled-back flip left `next_timer` at now and the next tick asked a needless snapshot (`resnapshot_fallen`), the same shape as the walks storm this branch fixed. A kept in-memory field that feeds `next_timer` deserves a second look whenever one storm of this kind is found.
