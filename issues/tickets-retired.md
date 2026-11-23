# Tickets and taking up still built
> Summary: spec/ has no tickets (notes/a2-spec/README.md, Tickets go whole): a grant by a holder's writers is the holder's own data, one from outside a `grant@~0` fire, roles count over taken grants, holders are held for keys. The engine still builds tickets (the reference kind, `tickets.0`, the account's tickets, ticket sync IDs, key-change tickets), taking up and accepting, removal notices and grant copies under a holder's sync ID; each site is marked `Interim (issues/tickets-retired.md)`. A forged ticket's sync ID is synced while the ticket is held, and two ticket-word paths have no rule test. Stage A2 briefs 3 and 4 remove them; build no tests for them before.
> Priority: normal
> Tags: sync, engine, security, tests

## What stands in
- The ticket reference (osis-base `Ticket`, `TAG_TICKET`, its decode), `tickets.0` and the account's tickets in D (`sync/tickets.rs`, `flows::account`), the node's role over held tickets (`tickets::role_here`), entering a thing on a ticket at a strong (`units`), ticket sync IDs (`sync_ids::actors`, `sync::set`, `sync::rows`).
- Ticket fires on a grant (`flows::inbox`: the grant's parts), key-change tickets on a rotation (`rotation::unreached`), removal notices (`removal@~0`) and taking them.
- Taking up and accepting: a role through a grant counts once its holder's account took it up (holds a strong down the chain); declining is not taking up; a redeem is an accept. Under spec/permissions.md §4 Taken grants a grant is taken by its stated path or a held `grant@~0` fire, not by holding.
- A holder's sync ID carries every edge write naming it, taken or not (`Engine::holder_piece`); spec/permissions.md §4 Key part carries the edge pieces of taken grants only.
- Their tests (osis-engine `tickets`, `sync::tests_tickets`, osis-sync `tickets` and the ticket cases of `holding`) go with them, or are restated against the new rules.

## A forged ticket's sync ID is synced while its ticket is held
A node syncs the sync ID of every held ticket for T that no held `sync.0` of T records (another admin's keying it has not seen), so a ticket naming another thing's sync ID keeps that sync ID synced, and its unopenable entries stored, for as long as the ticket is held.
- Repro: osis-sync `tickets::a_forged_ticket_sync_id_pulls_in_and_cuts_off_nothing_spec_sync_hostile` (Bob stores entries of Alice's inbox under its sync ID; nothing of it opens, is held or read).
- Same class as a forged ticket for a thing whose `sync.0` never arrives ("a forged claim only adds a thing whose secrets open nothing there"). A ticket in an inbox goes with the inbox's history; one written into a shared thing stays.
- Why the hint stays beside a held `sync.0`: two admins keying T at once each record a sync ID; a node holding only the loser's record learns the home only from a ticket naming it (`holding::concurrent_first_grants_*`, `a_grant_beside_a_siblings_keying_*`). Under A2 the holder's key part carries both keyings, so the hint has no job left.

## No rule test
- **Refetch through a ticket's sync ID**: `units::refetch` pulls anew the sync IDs a thing is held by, ticket hints included; only full-size differential seed 65 reaches the ticket arm (a reader holding T0 by its ticket's sync ID while no `sync.0` of T0 is held, and a thing under T0 released and reached again in that window).
- **A removal notice taken at a read ticket**: The engine takes a removal notice's commit once a strong reaches T where a read ticket opens, or once T's roster is held. Dropping the read-ticket clause (`flows::inbox::removals_due`'s `read_ticket`, `Core::removals_due` noted by `tickets::take_in`) fails no osis-sync test. Its case needs a read ticket with no grant to take (one from D's `tickets.0`, an account ticket), which A2 removes.
