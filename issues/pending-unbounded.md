# Pending commits have no bound and no age
> Summary: spec/requirements.md says peer input never causes unbounded storage, but a reader of a label (or a connected inbox sender) can grow what a node keeps pending for good: a commit by an author whose record never comes is durable, unsigned as far as the node can tell, and nothing ages it out.  Tess's call on what bound and what gives way.
> Tags: security, engine, sync

Bytes kept follow bytes delivered: each fresh header is a fresh commit ID, so per-commit limits bound nothing overall. An entry leaving the host does not free its pending row.

A commit with no part held (its header-only blob, or its part gone at its expiry) waits for its deltas synced or not, so one naming another's private part pends for good: its row is the signed header, one header's size, as an applied commit's would be, and shows nothing. A commit whose every delivered part is bad by itself pends the same way when split over blobs (the first waits for its thing's other part, the second is refused, the first stays), where the whole blob is refused and leaves no row: alike in what reads, the row costing what was delivered.

To decide: total bytes per label or author class, what is evicted (oldest unsigned first keeps a flood from pushing out what can verify), how a true commit evicted comes back (`SyncEngine::redeliver` can ingest its entry again).

Not a bound in itself, but the same call: a pending commit's other entries leave with the host's (`forget_blob`), so a true copy deleted from every host while junk holds its slot needs a holder's new upload. Keeping those blobs while the commit pends would let one sender grow one commit's copies by flood-and-delete.
