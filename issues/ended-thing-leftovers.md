# What an ended thing still leaves at a node
> Summary: Ending (`retention/end.rs`) keeps a thing's own secrets rows, and for an ending by purge its record, value-less creation and `roles.0` parts for good; a thing ended while others name it first admin loses that chain link until step 8.
> Priority: normal
> Tags: engine

- **Secrets.** A thing with secrets of its own keeps its `k/` row after it ends: the delete keys for its blobs derive from it and node-sync deletes after the ending. Drop it once its blobs are deleted at hosts.
- **Record, edges and request.** An ending by purge keeps the record, the value-less creation, the `roles.0` parts and the request's `purge.0` part for good, since nothing drops a request: one record and its edges per purged thing (notes/growth.md row 5); `Core::exists` keeps it from reading as a thing.
- **Dependents.** Step 8 of notes/expiry-creation-design.md: until then, ending a plain thing that other things name as first admin leaves their record chain without its link. Only key actors are refused.
