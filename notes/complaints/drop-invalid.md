# drop-invalid
- A drop and its undoing in one node-sync step (invalid on arrival, valid with the next commit of the batch) left the blob's bytes held and the entry opened, so `reopen_undropped` skipped it and nothing re-ingested it; only a Net test (`timed_dead::late_holder_*`) showed it, LocalPeer tests never do.
- Many LocalPeer tests sync once and expect what turned valid to read: each needs a second sync from a holder now. Easy to miss which peer holds the body (the author keeps its own; others drop).
- An oracle excuse read invalid bodies from the node under test (`rotation::tests::opened_by_invalid`); it broke as soon as the node stopped holding them.
