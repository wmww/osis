# Text state growth per commit
> Summary: Text state grows by about 13 bytes per commit forever (about 7x the text at a 2 s commit cadence on the automerge-paper trace). Owner to decide whether that is acceptable or stability-based GC comes forward.
> Tags: crdt, owner-call

Measurements and the batching rule: notes/crdt.md, Text size. Sequence records are never pruned (spec/crdt.md §4.2), so resets do not shrink state either (tension 14).

Options: accept, with the client rule of one commit per editing pause; or stability-based GC (drop per-commit stamps once every writer has acknowledged; needs frontiers and stalls on offline members).
