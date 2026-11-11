# Default connection cap against large rosters
> Summary: the default `max_connections` is 256 (`max_buffered_bytes` / `link::CONN_MEMORY`), while spec/requirements.md says direct rosters hold thousands of holders: a host with more than 256 devices online at once refuses newcomers, since connections that share something are never evicted.
> Priority: normal
> Tags: host

## The case
Each served connection may make the transport hold `CONN_MEMORY` (2 MiB) per direction, so the default count follows from the default memory bound (notes/serving.md, Connection memory). An operator can raise both, but a default host serving one large group fills at 256 devices online. Not a memory problem: a product default.

## Decision (Tess)
A node started to serve (`osis serve`) sizes its defaults from the machine's memory: `max_buffered_bytes` defaults to a quarter of the RAM it sees at start, and `max_connections` follows as that bound / `CONN_MEMORY` (a 16 GB box: 4 GiB, 2048 connections). Every other node keeps 512 MiB / 256. Both stay settable; an explicit setting wins.

To build: read total RAM at `serve` start (one platform call; if it can't be read, keep the plain default); the fraction passes notes/arbitrary-values.md (at 0 nothing is served, at 1 a flood can take the box's memory); spec/sync.md §10 and notes/serving.md state it; a test that the defaults follow a given memory size.
