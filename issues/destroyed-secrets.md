# A destroyed thing's own secrets stay for good
> Summary: A thing with secrets of its own keeps its `k/` row and `Indexes::secrets` entry after it is destroyed and keeps nothing else: node-sync derives the delete keys for its blobs from them after the destruction (`Core::delete_chain`), and a plain thing it is first admin of derives its secrets from them while held. Drop them once the thing keeps nothing and node-sync knows no entry of a blob of a commit with a part on it.
> Priority: normal
> Tags: engine, node-sync

- One row per destroyed actor with secrets (groups, accounts) per node, for good (notes/growth.md row 5).
- The engine cannot tell when node-sync's deletes are done: node-sync's entry index can (as `Engine::forgettable` waits on it). Shape: the engine lists destroyed things whose record is gone but whose secrets are held; node-sync calls a drop once no known entry is of a commit on one, judged when an entry goes.
- While the thing keeps (spec/commits.md §5 Destruction) the secrets stay: a dependent's content may be keyed by its epochs.
