# A member no longer ended misses what came past its until
> Summary: an ended member is served only up to `until` while its peer's stream moves on with the other members; if it is then judged holder or admissible again (spec/sync-opens.md §6), `until` is cleared and serving resumes from where the stream stands, so S's entries first logged between `until` and there never reach that peer until a listing from the start.
> Priority: normal
> Tags: sync, opens, streams

Reachable where a credential stops and starts counting again without closing the member first: a static entry dropped from S's roster and listed again before the peer's reported position passes `until`, or a head move undone at a store (none today). Fix shapes: the un-ending side closes the member with a Lost naming `until`'s cursor and lets it open again (the close now keeps where it stopped on the connection, so it costs a Lost each way and a join), or never un-ends a member whose stream was served past `until`.
