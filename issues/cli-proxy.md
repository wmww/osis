# Client port: what is left
> Summary: The `osis` API over the node-to-node connection (notes/client-port.md) is built: handle sources, the port, clients' things with bearer Auth, sync unit sources; every CLI command but `source` runs through a daemon. Left: the minimal query, a no-store build, a client cache, and the gaps below (thin clients' sharing calls and schemas, stall and deadline bounds, routed things through a daemon, read-behind after a move).
> Priority: low
> Tags: api, cli, proto, transport, security

## Not built
- **`query-min`**: `query(in, with, order Time, page <= QUERY_PAGE) -> Live`, a local scan dirty only on changes in the container's closure, an incremental page per change, through the port as a Sub (`MAX_QUERY_SUBS`); CLI `ls`. Count the work at 10^4 items. Same item as issues/api-deferred.md, Queries.
- **`thin-profile`** (Tess's decision: a default `store` feature on `osis`, outside notes/architecture.md §4's networking-only rule): `--no-default-features` keeps base, crypto, crdt, schema, commit, proto, transport and the port client; `connect`/`connect_socket` without a store; a gate step `cargo check -p osis --no-default-features`. `Inner` holds an engine, so the socket client's scratch store goes first and every API method's `Local` arm moves behind the feature.
- **`client-cache`**: no need shown (a read is one round trip; `on_change` already carries each value). If built: cached values only for live-subscribed aspects, invalidated when the subscription lapses, no write-through.
- Network clients ship only with a client listener key that does not rotate with reach.

## Gaps
- **Thin clients' sharing calls**: `grant`, `leave`, `make_link`, `wait_synced` are the node's only: their engine flows act with the node's authority and take no thing to act as, so a client row would be a confused deputy. Fix: the rest of `act_as` (issues/grant-rename-multi-actor.md).
- **Thin clients' schemas**: `register_schema` is the node's only (process-wide; a client's could retype the node's aspects), so a client's typed write reaches the node untyped unless the node itself registered it. Needs per-session schemas or a rule that the node itself registers them.
- **A removed client's actor stays** with its secrets, one record per client ever added.
- **Stalls**: one port worker per node serves every connection, and a big `write` holds the engine lock throughout, so a client stalls every caller (and the sync driver) as the node itself can; a client is less trusted. Per-connection workers would overlap only off-lock work.
- **No call deadline**: the session's stall timer counts any bytes, so a trickling hostile node holds the calling thread; a silent link waits for QUIC's idle and the stall timeouts. A deadline must not fail an honest large reply on a slow link.
- **Routed things through a daemon**: a call as the node itself on a thing read at another node is `Unsupported` through the daemon (the worker must not wait on a node); `source` needs the daemon stopped. Needs a worker per connection or an async row.
- **A move away can read behind**: after `unit_source(.., UnitSource::Node(..))` a read may show a value older than an acknowledged write until the source pulls (local writes are waited for at a peer, not the source). Closing it needs a "does the node hold this commit" check.
- **Who answers rule 4** (notes/client-port.md §8): a hostile source node first in the list answers for every thing unknown here routed to it.
- notes/arbitrary-values-table.md lacks rows for notes/client-port.md's Picked numbers.
