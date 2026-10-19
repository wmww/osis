# No timeout on requests to a server
> Summary: Neither osis-proto's `ClientSession` nor `SyncEngine` times out an outstanding request. A server (or middlebox) that silently drops a reply on an open stream leaves that label waiting on the connection for good: the node never retries there and never goes idle. Data still converges through other servers.
> Tags: sync, proto, tests

- Seen in the simulator: `osis_sim::replay("evil_server_drops", 1)` (ignored with this issue): one of two servers drops 10% of its messages without closing the stream; at quiescence the nodes read alike and the honest server holds every must-hold body, but `describe()` shows labels `Opening ... outstanding 2` at the dishonest server for good (`run_until_quiescent` never sees them idle). `evil_server` (hold back and replay, no drops) passes.
- Fix: a per-request deadline (a few minutes, on the node's clock) in the client session or the sync engine; on expiry close the connection and redial with backoff (spec/sync.md §6 says nothing about it; a sentence there may help other implementations).
