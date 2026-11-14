# A reconnect writes peer-record and stream rows per page
> Summary: A start with nothing new commits nothing, but the reconnect after it writes a few sync-store transactions per page of members and per stream reply, so a quiet restart's commits grow slowly with the sync IDs shared (osis-sync, 3 nodes, n things shared: about 8 at n = 2, 11 at n = 20 for the restarting node).
> Priority: low
> Tags: sync, opens, streams

- Opens: each Members page of a reconnect marks the members it names dirty (`Opens::dirty_member`) and `flush` writes them (`records::write`) though their rows hold the same values; one transaction per page step.
- Streams: each applied reply writes the stream's cursor though it did not move. Skipping that write (cursor unchanged, no member moved, no op) made `streams::a_reconnect_after_a_restart_costs_the_same_at_10n_spec_sync_streams_4` send a third Pull: something follows the cursor row's stamp; not narrowed.
- A member's own position no longer writes on a reconnect (notes/sync-streams.md, `Place::effective`).
- Measure: a variant of `growth::quiet_starts` that keeps the peers connected, at n and 10n.
