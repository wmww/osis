# A forged ticket's sync ID is synced while its ticket is held
> Summary: A node syncs the sync ID of every held ticket for T that no held `sync.0` of T records (spec/sync-inbox.md §5 Ticket sync IDs: another admin's keying it has not seen), so a ticket naming another thing's sync ID keeps that sync ID synced, and its unopenable entries stored, for as long as the ticket is held.
> Priority: low
> Tags: sync, security

- Repro: osis-sync `tickets::a_forged_ticket_sync_id_pulls_in_and_cuts_off_nothing_spec_sync_hostile` (Bob stores entries of Alice's inbox under its sync ID; nothing of it opens, is held or read).
- Same class as a forged ticket for a thing whose `sync.0` never arrives, which the spec already accepts ("a forged claim only adds a thing whose secrets open nothing there"). A ticket in an inbox goes with the inbox's history; one written into a shared thing stays.
- Why the hint stays beside a held `sync.0`: two admins keying T at once each record a sync ID; a node holding only the loser's record learns the home only from a ticket naming it (`holding::concurrent_first_grants_*`, `a_grant_beside_a_siblings_keying_*`). Telling the two apart by the ticket's epoch fails: the winner's fresh ticket comes at an epoch the node established through the loser.
- A fix would keep unopenable entries of a hinted sync ID out of the store, or let a ticket prove its sync ID (its genesis step).
