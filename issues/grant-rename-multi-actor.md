# Call role grants "grants", not "edges"; let a node act as several actors
> Summary: engine and perm types and some defined spec terms still say "edge" for a role grant (`Edge`, `EdgeWrite`, `node/edges`, "edge write", "edge admin", "record edge", "edge as restored"); Tess dislikes "edge" for a permission: rename to "grant". Second part: the API assumes one account per node (`me()`); expose `Osis::act_as(actor)` so a caller can act as any actor the node holds roles on, `me()` the default.
> Priority: low
> Tags: api, permissions, naming

- **Rename.** The `osis` API, CLI, notes and issues already say grant. Left: engine and perm names, the defined spec terms and spec lines about first admins. The perm walk's graph language (edges in the graph sense) stays. No wire change.
- **Multi-actor.** The permission model lets a node hold roles on several actors (two accounts, or client actors it keeps the seeds of, notes/client-port.md). `Osis::act_as` exists crate-internal for the client port's rows (reads, writes, reverts; notes/client-port.md §3). To make it public, the sharing, sync and process-wide calls must honour it (the engine's grant and demote flows act with the node's authority and take no actor). Pairing a second account into an existing node is then a flow over it.
