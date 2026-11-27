# A stub entering by entry judges every record blob unneeded
> Summary: Suspected, not reproduced: a node holding S as a stub with only unjudged entry secrets has no read thing, so it drops every record blob it opens, and records kept loose for role entries not yet arrived go with it.
> Priority: low
> Tags: sync, engine

`Engine::certificate_records(S)` reads `read_things_of(S)`, empty while the node's read secrets of S's thing are unjudged (its grant pends), so `cert_blobs_missing` finds every held record blob unneeded and the own store drops it (`forget_carrier`: its loose records go). Harmless when the record blob and the role entries awaiting its records come in one Fetch (the records are learned at once). If the record blob opens a step earlier, its records are loose when dropped, and the role entries then pend for records nothing brings again until S is pulled anew. Check with a scripted source showing the record blob a step before the grant's entry.
