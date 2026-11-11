# Default connection cap against large rosters
> Summary: the default `max_connections` is 256 (`max_buffered_bytes` / `link::CONN_MEMORY`), while spec/requirements.md says direct rosters hold thousands of holders: a host with more than 256 devices online at once refuses newcomers, since connections that share something are never evicted.
> Priority: normal
> Tags: host, tess-call

## The case
Each served connection may make the transport hold `CONN_MEMORY` (2 MiB) per direction, so the default count follows from the default memory bound (notes/serving.md, Connection memory). An operator can raise both, but a default host serving one large group fills at 256 devices online. Not a memory problem: a product default.

## Options
- Raise the defaults for nodes that host (a larger `max_buffered_bytes`, and the count with it).
- Derive the defaults from the machine's available memory at start.
- Keep 256 and say so where hosting is configured.
