# What a source shows, and what crossed a connection, grow without a bound
> Summary: `Known` keeps every blob a source's stream listed (a hostile source can list any number of made-up IDs: each is a row of its record once durable), and each connection's `crossed` set keeps every blob whose bytes crossed it for the connection's life. Neither is bounded by what this node holds.
> Priority: normal
> Tags: sync, security

- `Known` (core/sync/src/streams/known.rs): presence is recorded for every `Added` applied, held here or not. Bounding it by the entries this node holds or fetched would lose presence of bodies fetched lazily (spec/sync-streams.md §4 Fill order counts a lazily fetched body settled once `known` records it at a source); bounding by the peer budget (spec/sync-ids.md §5) is the likely rule.
- `Serve::crossed` (serve.rs) enforces "a body crosses a connection once" (spec/sync-streams.md §4 Bodies) by a set per connection: memory in proportion to the bodies exchanged on a long-lived connection. A rule that needs no per-blob memory (crossed by stream position, or inline only on the first listing) would remove it.
