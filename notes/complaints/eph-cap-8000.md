# eph-cap-8000
- tests/it/net addresses messages by (node, ConnId), and a restarted node reuses ConnIds: second harness bug of this shape (after item 57's `forget_conn`). The sim keys messages by link id and cannot have it. Review: messages to a node now carry its restart count and stale ones are dropped (closes the class).
- Both "differs" failures were harness/check issues, not engine bugs; a debugging hour went to telling them apart (temporary eprintln traces in node-sync were the fastest tool).
