# Each look at a waiting snapshot decodes it
> Summary: `strip_carried_waiting` decodes a waiting compaction snapshot part (pages included) on every `reexamine` while its aspect has a non-empty value-less list, so each pass costs O(waiting snapshots x their size) even when no list changed.
> Priority: low
> Tags: engine, retention

`reexamine` already reads and examines every pending commit each call (O(pending)). A drift- or epoch-pending snapshot used to stop at the header; `pending_drops` now decodes the part and compares its stripped fragment whenever its aspect's value-less list is non-empty, which an expiring aspect's always is. Cost grows with n waiting snapshots times their body size, per inbound batch, with nothing changed. A fix judges a waiting snapshot when it is stored and when its aspect's list grows (a purge or expiry applying names the pending snapshots on that aspect), not on every look.
