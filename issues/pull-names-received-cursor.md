# A Pull names the received cursor, read as stored
> Summary: The requester's Pull carries `recv` (the last cursor received, in hand included) while the server reads a Pull's cursor as what the requester stored and stops waiting on what it served up to it; a join's or page's Pull sent while a message owing a body is in hand so ends the server's wait early, and S counts caught up at the source while the requester has not stored it. Blocks the batched Fetch (issues/many-sync-ids-cost.md).
> Priority: normal
> Tags: sync

spec/sync-status.md §1 (caught up: every message carrying an event of S served to the source is reported applied, an Applied or a later Pull naming a cursor at or past the message's); spec/sync-streams.md §4 (Flow control: a stream waiting on a local bound of owed bodies sends no Pull).

## Where
- `streams/pull.rs` `send_pull`: a Pull goes while `pending` is under `PENDING_CAP` (a join, a page, a gap), naming `p.recv`, which a reply (`on_pull_reply`) and a Stream's arrival (`on_stream`) set before the message's bodies settle.
- `streams/serve.rs` `on_pull`: "the requester names the cursor it stored: what was served up to it is applied there" (`serve.unapplied.retain(|_, x| *x > pos)`).

## Seen
Not by a test on main. On `windlass-s1-first-fetch-wip` (several sync IDs' bodies in one Fetch) `streams::caught_up_matches_what_each_side_holds_spec_sync_status_1` fails at seed 58 (a side says caught up on S while its source lacks an entry of S): the batch changed message counts and so the interleavings that reach the case. Nothing on main keeps a Pull from going in that state, so main can reach it given a join or page while a Stream owing a body is in hand.

## Fix
A Pull names the stored cursor, or the server counts only Applied as applied. Then the batched Fetch.
