# Ephemeral data: differences from durable still to remove
> Summary: Places where ephemeral data still differs from durable without following from "held in memory" (notes/ephemeral.md Principle): a node leaving a closure keeps its ephemeral state until restart, and presence at a peer keeping S unread is relearned per connection.
> Priority: normal
> Tags: ephemeral, engine, sync

## Leaving a closure
- Today (notes/ephemeral.md Restarts and lost access): a node that stops syncing a sync ID while it still reads the things keeps the ephemeral state of the things it held through it until restart; memory caps are per sync ID, so that state is under no cap. Durable holders keep their copies, so this is a memory rule, not a parity gap in itself.
- Plan: a node drops a thing's ephemeral state, its own writes included, when the thing leaves every closure the node syncs. Judged only for things the node had inside a settled closure (after a start the closure is what has arrived so far). Forgets locally without deleting at peers (their entries go by the existing outside-closure deletes). A thing coming back into a closure is fetched again (its sync ID pulled again).
- Not needed for deletes: a delete's purge request reaches holders through the groups its removals are on (notes/ephemeral.md Deletion).
- Tests: a thing removed from its only group and added back reads its ephemeral state again from the nodes that kept it; a restarted node's partial closure drops nothing.

## Presence at a peer keeping S unread
- Today (spec/sync-compaction.md §2, spec/sync-streams.md §4): a node relearns which memory entries such a peer holds on every connection, from each stream's listing of its live ephemeral entries. Only a peer restart loses them; a reconnect to the same running peer does not.
- Plan: list them again only after the peer restarted. Needs a design before building: the requester cannot tell a restart today (a cursor is sealed, and a restarted log draws its new incarnation only at its first append), the memory part of the node log has no cursor and keeps no deletion events, and the requester would keep presence per peer across connections. A cost on reconnects, not a correctness gap.
