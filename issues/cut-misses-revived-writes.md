# A cut's holder misses what an expiring write superseded
> Summary: A holder granted without history never reads a lasting write that only an expiring write superseded once that write expires: the state the cut's lasting snapshot is cut from has pruned it, and spec/crdt.md §4.7 Snapshots forbids a lasting snapshot to carry it, so past T the holder reads less than every node holding the history (e.g. "k" put lasting, removed by a delta expiring at T, cut for N: past T others read "k", N never does).
> Priority: normal
> Tags: crdt, engine

The same holds for every non-value write of an expiring delta (a reset, a delete, a move): each supersedes something, so nothing a cut writes shows N what reads again at T, and the expiring snapshots' choice of writes (`snapshot::expiring_copies`, `write_expiring`) is unobservable for such writes until this is fixed.

A candidate: the cut's lasting snapshot carries the writes only expiring writes superseded (the state joined back with them), beside the expiring snapshots carrying the superseders: joined, they read as the history does before and after T. It breaks "a node holding the lasting snapshot but not the expiring one reads as without the delta" (§4.7 Snapshots): such a node reads the superseded write before T. Model it (held-model, any-order and cut properties) before choosing.
