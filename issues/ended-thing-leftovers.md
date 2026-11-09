# What an ended thing still leaves at a node
> Summary: Ending (`retention/end.rs`) keeps a thing's own secrets rows, and for an ending by purge its record for good; a thing ended while others name it first admin loses that chain link until step 8; an ending's writes grow with the things beside it.
> Priority: normal
> Tags: engine

- **Secrets.** A thing with secrets of its own keeps its `k/` row after it ends: the delete keys for its blobs derive from it and node-sync deletes after the ending. Drop it once its blobs are deleted at hosts.
- **Record and request.** An ending by purge keeps the record and the request's `purge.0` part while the request is held, with nothing that ever drops them: about one record per purged thing (notes/growth.md row 6); `Core::exists` keeps it from reading as a thing.
- **Dependents.** Step 8 of notes/expiry-creation-design.md: until then, ending a plain thing that other things name as first admin leaves their record chain without its link. Only key actors are refused.
- **Cost.** An ending writes about 110 bytes per other thing on the node past what an ordinary purge writes (`repro_ending_bytes_flat_in_other_things`): source not found. A disappearing message ends often, so this is quadratic over a chat's life.
