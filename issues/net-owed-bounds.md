# What a co-reader's announcements make a node keep
> Summary: A co-reader can announce entries without bytes and never answer the Fetch: each makes a byteless entry row that the local pass keeps while the stream owes it (`stream_owes`), and each push an `Unsettled` position; a sharing session is exempt from the idle bound, so both grow for as long as the connection lasts, charged to no budget. The stream also never settles (only that source's status suffers). Needs a bound that follows from the stream's rule, not a timeout picked to fit.
> Priority: normal
> Tags: security, node, sync

## The case
`stream_apply` creates an entry row (`Kind::Unknown`, no bytes) for every `Added` without bytes a reader's reply or push names, and owes it on that stream until it is held, no longer listed, deleted by that source, or answered by that source's Fetch (with bytes or without). A Fetch has no deadline: a peer that keeps the connection and never answers keeps every row and every later position (`Pulling::unsettled`, one per push; pushes are unsolicited, so any rate). The rows are durable state; `charge_reader` charges only bytes, so nothing bounds them. The connection ending releases it all (the stored cursor is the last settled one), but `kept_while_up` keeps a session sharing a sync ID open however quiet.

## Directions
- Owe announcements in the stream's memory alone and create the row only when bytes arrive: the local pass then has nothing to keep (`stream_owes` goes), and what remains is per-connection memory, bounded by a cap on owed bodies past which the stream stops pulling (flow control, not a drop).
- Or: a Fetch outstanding when a reply to a later request of the same connection arrives was skipped (requests are answered in order on one connection): a failure, asked of the next source.
Either way add a test: a hand peer announcing n entries it never serves leaves O(1) rows at n and 10n.
