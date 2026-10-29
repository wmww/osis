# Receipts from a snapshot that later turns invalid
> Summary: frontiers of a held compaction snapshot are recorded as received while it is valid (`receipt::record` checks validity on arrival only) and stay after it turns invalid, so this node's later demotion frontiers can cover what only that snapshot claimed; a node that got the demotion first never records them. Unexamined.
> Tags: security, node, perm

Found while closing issues/snapshot-copy-residue.md (snapshots vouch). spec/permissions.md §5.2 says an invalid snapshot's frontiers count as not received; a snapshot valid when it arrived and invalid later (its author demoted with a frontier not listing it) keeps its receipts here. Effect: order-dependent receipts, so frontiers this node writes later may differ by arrival order. Fix sketch: derive the snapshot part of the receipt record from the held valid snapshots (as `Core::snapshots` holds their frontiers), or drop a snapshot's receipts on its flip.
