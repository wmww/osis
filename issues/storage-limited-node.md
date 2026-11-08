# A storage-limited node cannot shed bodies on its own
> Summary: A node drops only covered, expired or purged bodies, so a node short on storage (a phone in a busy realm, a reader without write) holds every body until a writer compacts; nothing lets it evict bodies it does not serve and fetch them again when needed.
> Priority: low
> Tags: retention, sync

The state is exactly the join of the held bodies (spec/crdt.md §4.6), so evicting a body loses its live writes from the node's reads. How much a node stores is set by how often right holders compact (convenient mode) and by kept history, not by the node. Not promised by spec/requirements.md today.

Possible shapes, none designed: a node-local snapshot that is not a body (reintroduces a second state); evict-and-refetch of bodies whose writes are dead in the join anyway (nothing to lose, so only dead bodies of kept history qualify); a reader asking a writer to compact (a request, not a right).
