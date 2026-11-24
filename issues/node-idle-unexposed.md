# Per-node idle: specified, reachable by no caller
> Summary: spec/sync-status.md §3 defines per-node idle (no request, fill or Hello outstanding on any connection) and osis-sync implements it (`Node::idle`, `Sessions::idle`), but nothing calls it and the `osis` API exposes no such status: expose it or drop the sentence and the code.
> Priority: low
> Tags: sync, status, api

`status` per sync ID and `wait_synced` are what an app reads; idle per node has no reader in core, the app, the CLI or the harness. It is a point-in-time fact (the next event may end it), so exposed as-is it is a poll. Either the `osis` handle offers it (e.g. a wait that ends when the node is idle, for a clean shutdown or a test), which needs a stated use, or spec/sync-status.md §3 drops the per-node clause (spec/sync-opens.md §1's "and the node is not idle while it waits" with it) and `Node::idle`/`Sessions::idle` go. Leaning: drop, since `wait_synced` covers what a user observes.
