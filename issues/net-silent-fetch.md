# A co-reader that answers nothing holds its fetches
> Summary: A body is fetched from one source at a time; a co-reader that keeps its connection up (a sharing session is exempt from the idle bound) and answers no request at all keeps that Fetch out, so other streams owing the same body never ask for it and their positions wait. Skipped Fetches are caught only when a later stream request is answered.
> Priority: normal
> Tags: security, node, sync

## The case
`stream_fetch` skips a body `fetching` anywhere; `stream_settle_all` asks a stream's source only for bodies asked nowhere. `stream_skipped` fails a Fetch once a later request on its connection is answered, but a peer answering nothing gives no such answer, and a stream waiting on `MAX_WAITING` sends no further Pull. The dialer's stall timeout (node requests count as any, `ClientSession`) closes a peer that sends no byte at all for 2 min, but not one that keeps sending (pushes, its own requests) while answering nothing; a listener has no stall timeout for its own requests to the dialer (spec/sync.md §6 SHOULD, either side). What it holds back is bounded (`MAX_WAITING`), but the writes it announced first stall at this node while the connection lasts, even when an honest co-reader serves them.

## Directions
- A probe on the silent connection whose answer, in order, shows the Fetch skipped (needs the in-order rule to cover it, spec/wire.md §11.2 Pull).
- Or ask a second source for a body another stream owes while its fetch elsewhere is older than that stream's own announcement (costs a body crossing twice in a mesh).
