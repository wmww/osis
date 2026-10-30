# Signals in a relay-only commit's second projection are never delivered
> Summary: a relay-only commit whose parts have different readers goes as several blobs under one label. A node that reads more than one delivers the first blob it gets, records the commit ID as delivered and drops the rest unopened, so the signals in those blobs are lost. A correctness gap, not a security one.
> Tags: engine, node, ephemeral

`eph_place` (core/node/src/sync/ephemeral.rs:560-573) sends one relay blob per projection. Every projection has the full header, so all of them have the same commit ID. `ingest_ephemeral` drops any relay-only commit already in `delivered_set` (core/engine/src/ephemeral/remote.rs:802), and `deliver_relay` delivers only the parts that blob carries (:979). This happens for a signal batch touching things with different reader actors under one label, for example an item with its own secrets inside a shared group.

Fix direction: dedup relay-only deliveries by (commit, part) instead of by commit, or remember the delivered parts per commit ID for the same window.
