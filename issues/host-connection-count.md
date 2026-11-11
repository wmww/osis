# Default connection cap against large rosters
> Summary: Tess: no connection count limit (the 256 default refused devices past it on large rosters); `max_connections` and eviction at the cap go; the queued-output byte bound stays; low-memory shedding is later work, not built now.
> Priority: normal
> Tags: host

## The case
Each served connection may make the transport hold `CONN_MEMORY` (2 MiB) per direction, so the default count follows from the default memory bound (notes/serving.md, Connection memory). An operator can raise both, but a default host serving one large group fills at 256 devices online. Not a memory problem: a product default.

## Decision (Tess)
No connection count limit: `max_connections` and the eviction at the cap go, for every node. Memory per connection is not a fixed 2 MiB in practice, and a count picked from it would mislead. The byte bound on queued output (`max_buffered_bytes`, served connections' unread output) is not a count and stays. Low memory is a later concern: if ever needed, a node detects it and sheds load (refusing or closing connections, evicting caches); nothing of that is built now.

Stated limit (spec/sync.md §10, notes/serving.md): transport buffers per connection are unbounded in total, so many connections can take a node's memory; handled by the later low-memory work if it is ever needed.

To build: remove `max_connections`, `ServingPolicy.connections`, the shared slot count's cap and the eviction at the cap (`make_room`, `Link::kept`/`Down::Keep` if nothing else needs them); keep `CONN_MEMORY`'s window sizes as transport tuning; update the tests that exercise the cap; spec/sync.md §10, notes/serving.md, the arbitrary-values table.
