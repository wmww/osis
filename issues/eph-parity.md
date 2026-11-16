# Ephemeral presence relearned per connection
> Summary: A node relearns which memory entries a peer keeping S unread holds on every connection, from each stream's listing of its live ephemeral entries (spec/sync-compaction.md §2, spec/sync-streams.md §4), though only a peer restart loses them. A cost on reconnects, not a correctness gap.
> Priority: low
> Tags: ephemeral, sync

Wanted: list them again only after the peer restarted. Needs a design first: the requester cannot tell a restart (a cursor is sealed, and a restarted log draws its new incarnation only at its first append), the memory part of the node log has no cursor and keeps no deletion events, and the requester would keep presence per peer across connections.
