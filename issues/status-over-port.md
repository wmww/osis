# `status` differs over the port and in the CLI
> Summary: a thin client's `status()` lacks the node's own `node_connections` (the port's status encoding drops them), and the CLI's `status` omits `GroupSync::leaving` and `refused_by`.
> Priority: low
> Tags: cli, osis

- core/osis/src/port/codec.rs `impl Port for Status`: `node_connections` is not on the wire, so a client of a daemon sees only its own connection to the daemon (sources.rs merges `there.groups`, not `there.node_connections`). Decide whether the client's status lists the node's connections too, then carry them.
- cli/src/cmd.rs `status_lines`/`status_json`: print `leaving` and `refused_by` per group.
