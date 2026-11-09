# What an ended thing still leaves at a node
> Summary: Ending (`retention/end.rs`) keeps a thing's own secrets rows, and for an ending by purge its record for good; a thing ended while others name it first admin loses that chain link until step 8.
> Priority: normal
> Tags: engine

- **Secrets.** A thing with secrets of its own keeps its `k/` row after it ends: the delete keys for its blobs derive from it and node-sync deletes after the ending. Drop it once its blobs are deleted at hosts.
- **Record and request.** An ending by purge keeps the record and the request's `purge.0` part while the request is held, with nothing that ever drops them: about one record per purged thing (notes/growth.md row 6).
- **Dependents.** Step 8 of notes/expiry-creation-design.md: until then, ending a plain thing that other things name as first admin leaves their record chain without its link. Only key actors are refused.
