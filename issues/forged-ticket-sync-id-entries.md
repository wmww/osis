# What a ticket's word still does until A2
> Summary: Built rules A2 removes (notes/holder-access-study.md, direction 1: a ticket is an offer only; no fetching on its word; the account's tickets go): a forged ticket's sync ID is synced while the ticket is held, and two of the ticket-word paths have no rule test. Close at A2 with those rules; build no tests for them before.
> Priority: low
> Tags: sync, security, tests

## A forged ticket's sync ID is synced while its ticket is held
A node syncs the sync ID of every held ticket for T that no held `sync.0` of T records (spec/sync-inbox.md §5 Ticket sync IDs: another admin's keying it has not seen), so a ticket naming another thing's sync ID keeps that sync ID synced, and its unopenable entries stored, for as long as the ticket is held.
- Repro: osis-sync `tickets::a_forged_ticket_sync_id_pulls_in_and_cuts_off_nothing_spec_sync_hostile` (Bob stores entries of Alice's inbox under its sync ID; nothing of it opens, is held or read).
- Same class as a forged ticket for a thing whose `sync.0` never arrives ("a forged claim only adds a thing whose secrets open nothing there"). A ticket in an inbox goes with the inbox's history; one written into a shared thing stays.
- Why the hint stays beside a held `sync.0`: two admins keying T at once each record a sync ID; a node holding only the loser's record learns the home only from a ticket naming it (`holding::concurrent_first_grants_*`, `a_grant_beside_a_siblings_keying_*`). Under A2 the holder's key part carries both keyings, so the hint has no job left.

## No rule test
- **Refetch through a ticket's sync ID**: `units::refetch` pulls anew the sync IDs a thing is held by, ticket hints included; only full-size differential seed 65 reaches the ticket arm (a reader holding T0 by its ticket's sync ID while no `sync.0` of T0 is held, and a thing under T0 released and reached again in that window).
- **A removal notice taken at a read ticket**: spec/sync-inbox.md §5 Carried commits takes a removal notice's commit once a strong reaches T where a read ticket opens, or once T's roster is held. Dropping the read-ticket clause (`flows::inbox::removals_due`'s `read_ticket`, `Core::removals_due` noted by `tickets::take_in`) fails no osis-sync test. Its case needs a read ticket with no grant to take (one from D's `tickets.0`, an account ticket), which A2 removes.
