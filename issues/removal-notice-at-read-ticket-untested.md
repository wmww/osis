# A removal notice taken at a read ticket is reached by no test
> Summary: spec/sync-inbox.md §5 Carried commits takes a removal notice's commit once a strong reaches T where a read ticket opens, or once T's roster is held. `flows::inbox::removals_due` checks both, but dropping the read-ticket clause (`read_ticket`, and `Core::removals_due` noted by `tickets::take_in`) fails no osis-sync test: wherever a read ticket opened, its fire's grant had already brought T's roster.
> Priority: low
> Tags: tests, engine, sync

## Case it would need
A read ticket held with no grant to take (one from D's `tickets.0`, written by another node of the account), a strong reaching T, and the account removed from T before this node held any role commit on T. Only the read-ticket clause takes the notice then; without it the node waits for a roster that no peer will send, since they judge it departed.

## Open
- Build that case as a hand-built test, or show it cannot happen and drop the clause from the spec and from `removals_due`.
