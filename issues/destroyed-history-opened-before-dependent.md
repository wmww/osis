# No test reaches a frozen-edge copy opened before the node's own destruction
> Summary: A node that opens a certificate copy of destroyed actor t's edges before its own destruction of t, holding no dependent yet (clocks apart at an expiry), keeps nothing of t at its destruction. Built for it: the copy stays at the hosts while the node's view is unsettled (`delete.rs::destroyed_certificate`), the record comes back from a held record blob once the dependent awaits it (`relearn_records`), and the record back refetches the dropped edges (`destroy::record_back`). The newcomer tests reach the record path (the destruction arrives with the record ahead of the dependent); none reaches a copy opened and dropped before the dependent.
> Priority: low
> Tags: tests, engine, node-sync

- Reaching it needs a node whose clock passes t's expiry after it opened the copy placed by nodes whose clocks passed it earlier, with the dependent's body not yet applied there.
- Open within it: a node whose view settles before the dependent's body reaches its hosts finds no dependent and deletes the copy; a placer does not place its own copy again once gone, so only another holder of the dependent places one.
