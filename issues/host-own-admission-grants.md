# `own` admission follows grants a connected sender makes
> Summary: under `host.0^` `admit: own` a node hosts every label of a group it reads whose hosts name its host key; a connected co-reader (no invite click needed, spec/sync.md §3) who learned that key from a shared group's `label.0` can make the node read a new group naming it, and so store up to the per-label caps on that node. Owner call: accept, or narrow `own`.
> Tags: security, node, host, owner-call

- Found in the sweep step 8 review. Non-readers cannot trigger it (`SyncEngine::labels` counts only groups with read secrets held), and admission only gates new registrations within the caps.
- Path: Bob co-reads group G with Alice; G's hosts name Alice's host address. Bob creates group X, grants Alice read (Bob is connected, so her node admits the grant without a click) and lists her host address in X's hosts. Alice's node now admits X's label: Bob stores up to `cap_bytes` (16 GiB default) per such group, up to the host-wide caps.
- Options: accept (bounded by caps, same exposure as any co-reader-placed data); count only groups whose `label.0` the node's own person wrote, or where it holds admin (breaks a family group whose other admin named the host); or an explicit list only (`labels`), dropping the automatic part of `own`.
