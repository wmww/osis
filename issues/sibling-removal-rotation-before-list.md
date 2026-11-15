# A removed node keeps rows after it leaves
> Summary: A node removed from its account learns its removal from the removal's rotation (custody: it boxes the node nothing) and stops syncing, but keeps some held rows: osis-sync `duties::a_node_removed_from_its_account_stops_syncing_*` passes its "syncs nothing" check and fails "holds no rows".
> Priority: normal
> Tags: engine, sync

- Not yet looked into: which rows stay (what the node read as the account and should drop on leaving, spec/permissions.md §3 Lost access, or rows kept by another rule). Check against Tess's storage rule: a node's storage is attributable to its synced groups; unsync everything leaves zero.
- Also check once joiner-target's rule (a rotation carrying no removal revokes nothing) lands: pairings are rotations, and on main a plain rotation revokes at outsiders, which several osis-sync sibling tests trip over.
