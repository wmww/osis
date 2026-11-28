# A node keeps following a removed grant's signal
> Summary: a grant's fire stays in the inbox's held history after the grant is removed, so the removed node keeps following the signal and holds the thing as a stub (syncing its sync ID, its role entries) until the fire expires; whether a signal for a removed grant should still be followed is open (spec/sync-inbox.md §5: followed while held and its holder is read).
> Priority: low
> Tags: engine, sync

Grants belong to the thing and a removed party should hold nothing of it beyond what it retains; following the old fire keeps a stub it has no grant for. Either the follow ends with the grant it signalled (the node reads the removal under the stub), or the fire's expiry is the stated bound.
