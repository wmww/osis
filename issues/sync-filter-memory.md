# Peer filters are memory nobody bounds in total
> Summary: Each peer's filter (up to 2^22 entries plus additions, 8 bytes each: 32-64 MiB) is held per connection with no cap on connections, and each kept record stores one, so a few strangers' full filters (about 5 MB each on the wire) take hundreds of MiB or evict every record under RECORD_BUDGET.
> Priority: low
> Tags: sync, security

- Unkept filters: one per served connection; spec/sync-transport.md §5 bounds frame buffers but not the state a connection builds (filters, members).
- Records: RECORD_BUDGET (256 MiB) holds 4-8 full filters; stated limit in spec/sync-hostile.md §2 (evicted peers are read from the start; nothing lost).
- Options: one memory bound over all connections' built state, closing the largest stranger first (the same rule as frame bytes); or a filter shape whose size follows what the two sides share rather than what the peer shows.
