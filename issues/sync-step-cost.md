# Sync engine step cost grows with the store
> Summary: One `SyncEngine::handle` step (a Tick) costs about 13 ms at 10^4 things (release, memory store); every served byte chunk and every client-port request and reply is a step, so a port call costs about 35 ms there against 80 µs at a small store. Needs a profile.
> Tags: node-sync, performance

- Measured by `osis` `port::bench_worst_rows` (release, by hand): 10^4 things in 100 commits plus 1000 single-thing commits; `feed(Event::Tick)` 13-16 ms; a read through the port 33-40 ms (two steps), the same read locally under 1 ms.
- Suspects (each runs per `handle`): `spread_touches`, `update_pass_peers`, `state.flush`, `drop_lost_due`, `drop_left`, `stop_pushes`, `host_step`, `next_wake` (core/node/src/sync/mod.rs `handle`). A per-step cost linear in the store also slows every sync input at a host-sized store.
- Port side (notes/client-port.md Port stall bounds): a request could skip the step's tail (it changes no label state); a reply is a send only.
