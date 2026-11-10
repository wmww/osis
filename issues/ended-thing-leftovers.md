# What an ended thing still leaves at a node
> Summary: Ending (`retention/end.rs`) keeps a thing's own secrets rows, and its record, value-less creation and `roles.0` parts for good after a purge, or while a dependent is held; a record kept for a dependent that leaves by lost access stays.
> Priority: normal
> Tags: engine

- **Secrets.** A thing with secrets of its own keeps its `k/` row after it ends: the delete keys for its blobs derive from it and node-sync deletes after the ending. Drop it once its blobs are deleted at hosts.
- **Record, edges and request.** An ending by purge keeps the record, the value-less creation, the `roles.0` parts and the request's `purge.0` part for good, since nothing drops a request: one record and its edges per purged thing (notes/growth.md row 5); `Core::exists` keeps it from reading as a thing.
- **Kept for a dependent.** An ended thing keeps its record and edges while a dependent is held (spec/commits.md §5). A dependent that later goes by lost access (`retention/forget.rs`) does not re-check the ended thing: its record and edges stay, one per such thing. Fix: re-run the keep check for the first admins and authors of what `forget` drops.
