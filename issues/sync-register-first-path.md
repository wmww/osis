# A node keeping S unread with no path of S never gets one
> Summary: a sync holder that took its grant (sync record, S listed) but holds no step of S is never sent a Register by the reader it is connected to, so S never opens there; keep.rs registers the genesis by hand meanwhile.
> Priority: normal
> Tags: sync, tests

- Seen in core/sync/tests/it/keep.rs `kept_then_removed`: node 0 (reads S) and node 1 (keeps S unread, sync record from the grant, S in its sync set) are connected both ways (each dials the other by `Engine::dial_peers`), node 1 proved its account, yet no Register reaches node 1: its store holds no path of S and S is in no shared set. Registered by hand, everything after works over the connections (the write pulled and held, the removal's notice taken, S shredded).
- spec/sync-ids.md §6 Register (a genesis is registered at a node keeping S unread, "known from the grant") and spec/sync-opens.md §4 (walk state exists where J judges the peer a SyncHolder) say a reader that judges its peer a holder of sync alone registers S's path there. Find which side should act: the inbox module's `register` reads only store sources, and a peer with no path of S can open S by no store credential.
- Done when keep.rs drops its by-hand `take_register`.
