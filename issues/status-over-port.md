# A thin client's `status` lacks the node's own connections
> Summary: a thin client's `status()` lacks the node's `node_connections` (the port's status encoding drops them), so a client of a daemon sees only its own connection to the daemon, not whether the daemon reaches the nodes its groups are sourced at.
> Priority: low
> Tags: osis, cli

- core/osis/src/port/codec.rs `impl Port for Status`: `node_connections` is not on the wire; sources.rs `merge_status` merges a connection's `groups`, not its `node_connections`. Decide whether a client's status lists the node's connections too (and how they read beside its own), then carry them.
