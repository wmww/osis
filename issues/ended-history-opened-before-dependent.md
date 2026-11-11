# No test reaches a frozen-edge copy opened before the node's own ending
> Summary: A node that opens a certificate copy of ended actor t's edges before its own ending of t, holding no dependent yet (clocks apart at an expiry), keeps nothing of t at its ending. Built for it: the copy stays at the hosts (`delete.rs::judge` leaves frozen history outside the label's closure), the record comes back from a held record blob once the dependent awaits it (`relearn_records`), and the record back refetches the dropped edges (`end::record_back`). The newcomer tests reach the record path (the ending arrives with the record ahead of the dependent); none reaches a copy opened and dropped before the dependent.
> Priority: low
> Tags: tests, engine, node-sync

- Reaching it needs a node whose clock passes t's expiry after it opened the copy placed by nodes whose clocks passed it earlier, with the dependent's body not yet applied there.
