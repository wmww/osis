# Caught up does not wait for an ephemeral-only push
> Summary: A Stream carrying only ephemeral events names the cursor the log already stood at, so the Applied that answers it reads the same position as one sent before it: the server cannot tell it applied, and counts S caught up while its ephemeral entries are still on their way (spec/sync-status.md §1).
> Priority: normal
> Tags: sync, status, ephemeral

Found by extending `streams::caught_up_matches_what_each_side_holds_spec_sync_status_1` with ephemeral writes: seed 24 step 111 has b say its source caught up on S while the source lacks an ephemeral entry b pushed (the same on main before caught up was kept per sync ID). The memory part has no positions (spec/sync-streams.md §3 Node log), and Applied carries only a cursor (spec/wire.md §11.2), so "every message carrying an event of S served is reported applied" has no reading for a memory-only push. The history test logs durable entries only until this is settled.

What a user sees: not an early `wait_synced` on its own writes, whose held-elsewhere half (spec/sync-status.md §2) needs the source's stream to show each own entry, and an ephemeral entry has no position a report could cover. A false caught up shows as S heard out (status, the end of a complete pass) while an ephemeral entry this node relays is still on its way.

Needs a design: a report the requester can name per message (the Stream's `seq` in Applied), or a memory counter in the cursor. Whatever it is reads per sync ID like the rest of §1.

Also met: a push whose log has no position yet (an empty node log, ephemeral entries only) sends a Stream with no cursor and `report` set, which the peer rejects as malformed (core/sync/src/streams/serve.rs `push`). No real node holds ephemeral entries with an empty log; the streams tests log a durable entry first.
