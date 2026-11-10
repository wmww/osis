# An ended actor's history opened before its dependent can be lost
> Summary: A node that opens a certificate copy of ended actor t's edges (and t's record blob) before its own ending of t, while it holds no dependent of t yet (the dependent's body not applied yet, or clocks apart at the expiry), keeps nothing of t at its ending: it forgets the record, drops the edges and deletes the copy at the host. The placer never places a copy that went again, and the opened record blob is not read again, so the dependent arriving there is judged without t's history. Not reached by a test.
> Priority: normal
> Tags: engine, node-sync, permissions

- Reached only in a window: copies of t's history are placed under a label only once t ended at the placer and a dependent is in the label's closure, so a node syncing the label usually receives the dependent with the copy. Expiry clocks apart or a pass taking the copy before the dependent's body opens it.
- Same root as issues/raw-records-kept-for-good.md: a node's held records and opened record blobs disagree once it forgets a record.
- Directions: an ending keeps nothing only of what no entry under a synced label still carries (a record blob listing t, a copy holding t's edges: the label says a dependent needs them), so the keep follows the labels, not arrival; or re-read a label's record blobs and history copies when a dependent wakes on t (`Kind::Records` lists their tids).
