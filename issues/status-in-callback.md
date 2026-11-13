# `status()` inside a callback lacks groups at other nodes
> Summary: `status()` read on the dispatcher (any callback, a tracked read made there) asks no connection, so groups sourced at another node, and those a connected node reports, are absent from it, while `on_status_change` shows them.
> Priority: low
> Tags: osis

- Where: sources.rs `merged_status` passes no connection status when `may_wait` is false. `status_feed` keeps each connection's last status, but only per listener.
- Reaches: libs/kit `Store::compute_things` reads `status()`; run in a callback it misses those groups.
- Likely shape: one node-wide cache of each connection's last status (one `filter::STATUS` subscription per connection, shared by every feed), read by `status()` when it must not wait. It would also cut per-listener port subscriptions to one per connection.
