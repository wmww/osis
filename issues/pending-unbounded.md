# Pending commits have no bound and no age
> Summary: spec/requirements.md says peer input never causes unbounded storage, but a reader of a label (or a connected inbox sender) can grow what a node keeps pending for good: a commit by an author whose record never comes is durable, unsigned as far as the node can tell, and nothing ages it out.  Owner call on what bound and what gives way.
> Tags: security, engine, sync

Bytes kept follow bytes delivered: each fresh header is a fresh commit ID, so per-commit limits bound nothing overall. An entry leaving the host does not free its pending row.

To decide: total bytes per label or author class, what is evicted (oldest unsigned first keeps a flood from pushing out what can verify), how a true commit evicted comes back (`SyncEngine::redeliver` can ingest its entry again).
