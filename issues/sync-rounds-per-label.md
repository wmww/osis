# A Sync of every label takes a round trip per two labels
> Summary: each Sync reserves `MAX_MESSAGE` of `WINDOW`, so opening or syncing N labels on one connection costs about N/2 round trips, nearly all of them empty.
> Tags: proto, node

`osis_proto::client::allowance` charges Sync its worst-case reply (8 MB of the 16 MB window): two go per round trip and the rest queue, with other requests behind them. Measured: 4 labels at 200 ms took 440 ms for empty replies. 100 groups at 100 ms RTT: about 5 s at every connect, and at every `wait_synced` and pre-sync. A live node no longer pays this for `sync_now` (`SyncEngine::refresh`).

Ideas: a Sync carrying a reply cap (`inline_limit` already says how much it wants) with the rest paged; or several labels per Sync.
